//! 1Password items as `op` 2.x prints and accepts them (`op item get
//! --format json`, `op item create -`, `op item edit` with JSON on stdin),
//! mapped to and from the canonical [`Record`].
//!
//! Each canonical field has a slot: a built-in 1Password field where one
//! fits (a login's username, a card's number), otherwise a field in pq-sync's
//! own "Proton Pass" section. Custom fields go to a "Proton Pass custom
//! fields" section. Reading and editing share one binding of canonical keys
//! to the item's fields, so an edit changes exactly the fields a read named,
//! and keeps every other part of the item JSON as `op` returned it.
//!
//! Item JSON is untrusted: anyone who can edit the item can add fields. A
//! slot binds only to a field with its id in its section, pq-sync's
//! reference only to its own well-formed field, and an item where a
//! reserved field appears twice is [`OpItem::ambiguous`] and is not edited.
//!
//! What the CLI cannot show, it cannot keep: a JSON template edit overwrites
//! passkeys, and `op item get` does not list them. The engine decides from
//! the item's history whether an item is safe to edit.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::proton_json::{IDENTITY_FIELDS, identity_field_kind};
use super::record::{
    CUSTOM_PREFIX, FieldKind, Kind, Record, normalize_card_number, normalize_expiry,
};
use super::secret::SecretString;

/// pq-sync's section for fields 1Password has no built-in slot for.
pub const SECTION_ID: &str = "pq-sync";
const SECTION_LABEL: &str = "Proton Pass";
/// pq-sync's section for Proton's custom fields.
pub const CUSTOM_SECTION_ID: &str = "pq-sync-custom";
const CUSTOM_SECTION_LABEL: &str = "Proton Pass custom fields";
/// The field holding the Proton item's `share_id/item_id`, a hint for
/// pairing items again. Not a secret, and not to be trusted alone.
pub const REF_FIELD_ID: &str = "pqsync-ref";
/// Where a card expiry that is not a month of a year goes: 1Password's
/// month/year field would refuse it.
const EXPIRY_TEXT_ID: &str = "pqsync-expiration_date";

/// An item's raw JSON from `op`. It holds secrets.
#[derive(Clone)]
pub struct RawItem(pub Value);

impl fmt::Debug for RawItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawItem([REDACTED])")
    }
}

/// A 1Password item read with its secrets.
pub struct OpItem {
    pub record: Record,
    pub raw: RawItem,
    /// The Proton reference pq-sync stored on the item, if it is there,
    /// once, in pq-sync's section and well formed.
    pub proton_ref: Option<String>,
    /// Files are attached: a template edit might not keep them.
    pub has_files: bool,
    /// A field pq-sync relies on appears more than once: which one a read
    /// or an edit means is unclear, so the item is not edited.
    pub ambiguous: bool,
}

// Written by hand: the reference comes from item content.
impl fmt::Debug for OpItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpItem")
            .field("record", &self.record)
            .field("raw", &self.raw)
            .field(
                "proton_ref",
                &self.proton_ref.as_ref().map(|_| "[REDACTED]"),
            )
            .field("has_files", &self.has_files)
            .field("ambiguous", &self.ambiguous)
            .finish()
    }
}

/// The kind of an `op` category, or `None` for categories pq-sync does not
/// carry.
pub fn kind_of_category(category: &str) -> Option<Kind> {
    match category {
        "LOGIN" => Some(Kind::Login),
        "SECURE_NOTE" => Some(Kind::Note),
        "CREDIT_CARD" => Some(Kind::CreditCard),
        "IDENTITY" => Some(Kind::Identity),
        _ => None,
    }
}

fn category_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "LOGIN",
        Kind::Note => "SECURE_NOTE",
        Kind::CreditCard => "CREDIT_CARD",
        Kind::Identity => "IDENTITY",
    }
}

/// (id, label) of a field's section; `None` for top-level fields.
type Section = Option<(&'static str, &'static str)>;

/// Where one canonical field lives in a 1Password item.
struct Slot {
    key: &'static str,
    id: String,
    section: Section,
    op_type: &'static str,
    purpose: Option<&'static str>,
    label: String,
    kind: FieldKind,
}

impl Slot {
    fn new(
        key: &'static str,
        id: &str,
        section: Section,
        op_type: &'static str,
        label: &str,
        kind: FieldKind,
    ) -> Self {
        Slot {
            key,
            id: id.to_string(),
            section,
            op_type,
            purpose: None,
            label: label.to_string(),
            kind,
        }
    }

    fn purpose(mut self, purpose: &'static str) -> Self {
        self.purpose = Some(purpose);
        self
    }
}

const OWN_SECTION: Section = Some((SECTION_ID, SECTION_LABEL));

/// The slots of a kind. Built-in ids are 1Password's (`op item template get
/// <category>`); the rest are pq-sync's own, in its section.
fn slots(kind: Kind) -> Vec<Slot> {
    use FieldKind::{Concealed, Text, Totp};
    let mut slots =
        vec![Slot::new("note", "notesPlain", None, "STRING", "notesPlain", Text).purpose("NOTES")];
    match kind {
        Kind::Login => slots.extend([
            Slot::new("username", "username", None, "STRING", "username", Text).purpose("USERNAME"),
            Slot::new(
                "password",
                "password",
                None,
                "CONCEALED",
                "password",
                Concealed,
            )
            .purpose("PASSWORD"),
            Slot::new("email", "pqsync-email", OWN_SECTION, "EMAIL", "email", Text),
            Slot::new(
                "totp",
                "pqsync-totp",
                OWN_SECTION,
                "OTP",
                "one-time password",
                Totp,
            ),
        ]),
        Kind::Note => {}
        Kind::CreditCard => slots.extend([
            Slot::new(
                "cardholder_name",
                "cardholder",
                None,
                "STRING",
                "cardholder name",
                Text,
            ),
            Slot::new(
                "number",
                "ccnum",
                None,
                "CREDIT_CARD_NUMBER",
                "number",
                Concealed,
            ),
            Slot::new(
                "verification_number",
                "cvv",
                None,
                "CONCEALED",
                "verification number",
                Concealed,
            ),
            Slot::new(
                "expiration_date",
                "expiry",
                None,
                "MONTH_YEAR",
                "expiry date",
                Text,
            ),
            Slot::new(
                "pin",
                "pin",
                Some(("details", "Additional Details")),
                "CONCEALED",
                "PIN",
                Concealed,
            ),
        ]),
        Kind::Identity => {
            const NAME: Section = Some(("name", "Identification"));
            const ADDRESS: Section = Some(("address", "Address"));
            const INTERNET: Section = Some(("internet", "Internet Details"));
            let built_in: [(&str, &str, Section, &str, &str); 10] = [
                ("first_name", "firstname", NAME, "STRING", "first name"),
                ("last_name", "lastname", NAME, "STRING", "last name"),
                ("gender", "gender", NAME, "STRING", "gender"),
                ("company", "company", NAME, "STRING", "company"),
                ("job_title", "jobtitle", NAME, "STRING", "job title"),
                ("email", "email", INTERNET, "EMAIL", "email"),
                ("website", "website", INTERNET, "STRING", "website"),
                (
                    "phone_number",
                    "defphone",
                    ADDRESS,
                    "PHONE",
                    "default phone",
                ),
                ("second_phone_number", "cellphone", ADDRESS, "PHONE", "cell"),
                (
                    "work_phone_number",
                    "busphone",
                    ADDRESS,
                    "PHONE",
                    "business",
                ),
            ];
            for name in IDENTITY_FIELDS {
                let kind = identity_field_kind(name);
                slots.push(match built_in.iter().find(|slot| slot.0 == name) {
                    Some(&(key, id, section, op_type, label)) => {
                        Slot::new(key, id, section, op_type, label, kind)
                    }
                    None => Slot::new(
                        name,
                        &format!("pqsync-{name}"),
                        OWN_SECTION,
                        if kind == FieldKind::Concealed {
                            "CONCEALED"
                        } else {
                            "STRING"
                        },
                        &name.replace('_', " "),
                        kind,
                    ),
                });
            }
        }
    }
    slots
}

fn custom_type(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Concealed => "CONCEALED",
        FieldKind::Totp => "OTP",
        FieldKind::Text | FieldKind::Urls => "STRING",
    }
}

fn kind_of_type(op_type: &str) -> FieldKind {
    match op_type {
        "CONCEALED" | "CREDIT_CARD_NUMBER" => FieldKind::Concealed,
        "OTP" => FieldKind::Totp,
        _ => FieldKind::Text,
    }
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

/// The custom-field name of a field that is not in a slot: its label,
/// under its section's label unless it is in pq-sync's custom section. Never
/// the field's id: ids pq-sync generates must not become names.
fn custom_name(field: &Value) -> String {
    let label = str_of(field, "label");
    match field.get("section") {
        Some(section) if str_of(section, "id") == CUSTOM_SECTION_ID => label.to_string(),
        Some(section) if !str_of(section, "label").is_empty() => {
            format!("{}/{label}", str_of(section, "label"))
        }
        _ => label.to_string(),
    }
}

fn section_id(field: &Value) -> Option<&str> {
    field
        .get("section")
        .and_then(|section| section.get("id"))
        .and_then(Value::as_str)
}

fn in_own_section(field: &Value) -> bool {
    section_id(field) == Some(SECTION_ID)
}

/// What a Proton reference looks like: `share_id/item_id`, both pass-cli IDs.
fn looks_like_reference(value: &str) -> bool {
    let id = |part: &str| {
        !part.is_empty()
            && part.len() <= 200
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_=+".contains(c))
    };
    value
        .split_once('/')
        .is_some_and(|(share, item)| id(share) && id(item))
}

/// Which field of the raw item each canonical key reads from and writes
/// to, by index in `fields`.
#[derive(Default)]
struct Binding {
    slots: BTreeMap<&'static str, usize>,
    custom: BTreeMap<String, usize>,
    reference: Option<usize>,
    expiry_text: Option<usize>,
    ambiguous: bool,
}

fn fields_of(raw: &Value) -> Result<&[Value]> {
    match raw.get("fields") {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(fields)) => Ok(fields.as_slice()),
        Some(_) => bail!("op item output has malformed fields"),
    }
}

/// Read the raw item into a record, and bind each key to its field.
fn bind(raw: &Value, kind: Kind, slots: &[Slot]) -> Result<(Record, Binding, Option<String>)> {
    let fields = fields_of(raw)?;
    let mut record = Record::new(kind);
    record.set("title", str_of(raw, "title"), FieldKind::Text);
    let mut binding = Binding::default();
    let mut reference = None;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut custom_names: BTreeSet<String> = BTreeSet::new();
    for (index, field) in fields.iter().enumerate() {
        // An edit replaces a field's value and type: both must be what the
        // read takes them for.
        if !field.is_object()
            || field
                .get("type")
                .is_some_and(|t| !t.is_null() && !t.is_string())
        {
            binding.ambiguous = true;
            continue;
        }
        let id = str_of(field, "id");
        let section = section_id(field);
        let slot = slots
            .iter()
            .find(|slot| slot.id == id && slot.section.map(|(id, _)| id) == section);
        let reserved = slot.is_some()
            || (in_own_section(field)
                && (id == REF_FIELD_ID || (id == EXPIRY_TEXT_ID && kind == Kind::CreditCard)));
        if reserved && !seen.insert(id) {
            binding.ambiguous = true;
            continue;
        }
        // A field pq-sync writes to holding something it cannot read (not
        // text): an edit would overwrite what the read never showed.
        if reserved
            && field
                .get("value")
                .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            binding.ambiguous = true;
            continue;
        }
        // Values that are not text (an address) stay in the raw item only.
        let value = field.get("value").and_then(Value::as_str);
        if id == REF_FIELD_ID && in_own_section(field) {
            binding.reference = Some(index);
            reference = value
                .filter(|value| str_of(field, "type") == "STRING" && looks_like_reference(value))
                .map(str::to_string);
        } else if id == EXPIRY_TEXT_ID && in_own_section(field) && kind == Kind::CreditCard {
            binding.expiry_text = Some(index);
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                // Two expiries, in the month field and in the text one:
                // which is meant is unclear.
                if record.get("expiration_date").is_some() {
                    binding.ambiguous = true;
                }
                let value = normalize_expiry(value).unwrap_or_else(|| value.to_string());
                record.set("expiration_date", value, FieldKind::Text);
            }
        } else if let Some(slot) = slot {
            binding.slots.insert(slot.key, index);
            let Some(value) = value.filter(|value| !value.is_empty()) else {
                continue;
            };
            if slot.key == "expiration_date" && record.get("expiration_date").is_some() {
                binding.ambiguous = true;
            }
            let value = match slot.key {
                "expiration_date" => normalize_expiry(value).unwrap_or_else(|| value.to_string()),
                "number" => normalize_card_number(value),
                _ => value.to_string(),
            };
            record.set(slot.key, value, slot.kind);
        } else if let Some(value) = value.filter(|value| !value.is_empty()) {
            let name = custom_name(field);
            // Two fields of one name are numbered on reading, and removing
            // one renumbers the rest: which field a key means could shift
            // under an edit, so such an item is not edited.
            if !custom_names.insert(name.trim().to_string()) {
                binding.ambiguous = true;
            }
            if let Some(key) = record.add_custom(&name, value, kind_of_type(str_of(field, "type")))
            {
                binding.custom.insert(key, index);
            }
        }
    }
    // An edit touches the title, the URLs, the fields and the sections:
    // each must be something the read can represent, or an edit would
    // overwrite or drop what the read never showed.
    if raw
        .get("title")
        .is_some_and(|title| !title.is_null() && !title.is_string())
    {
        binding.ambiguous = true;
    }
    match raw.get("sections") {
        None | Some(Value::Null) => {}
        Some(Value::Array(sections)) if sections.iter().all(Value::is_object) => {}
        Some(_) => binding.ambiguous = true,
    }
    match raw.get("urls") {
        None | Some(Value::Null) => {}
        Some(Value::Array(urls)) => {
            let mut hrefs = BTreeSet::new();
            for url in urls {
                match url.get("href").and_then(Value::as_str) {
                    Some(href)
                        if url.is_object()
                            && url
                                .get("primary")
                                .is_none_or(|p| p.is_null() || p.is_boolean())
                            && !href.trim().is_empty()
                            && !href.contains(['\n', '\r'])
                            && hrefs.insert(href.trim()) => {}
                    _ => binding.ambiguous = true,
                }
            }
        }
        Some(_) => binding.ambiguous = true,
    }
    if binding.ambiguous {
        reference = None;
    }
    Ok((record, binding, reference))
}

/// Parse `op item get --format json`. `Ok(None)` for categories pq-sync does
/// not carry.
pub fn parse_item(json: &str) -> Result<Option<OpItem>> {
    // serde_json's errors quote no input, only positions.
    let root: Value = serde_json::from_str(json).context("op item output is not JSON")?;
    let category = root
        .get("category")
        .and_then(Value::as_str)
        .context("op item output has no category")?;
    let Some(kind) = kind_of_category(category) else {
        return Ok(None);
    };
    let (mut record, binding, proton_ref) = bind(&root, kind, &slots(kind))?;

    let mut urls: Vec<(bool, &str)> = root
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|url| {
            let primary = url.get("primary").and_then(Value::as_bool).unwrap_or(false);
            (primary, str_of(url, "href"))
        })
        .collect();
    // The primary URL first, the rest in their order.
    urls.sort_by_key(|(primary, _)| !primary);
    record.set_urls(&urls.iter().map(|(_, href)| *href).collect::<Vec<_>>());

    let has_files = root
        .get("files")
        .and_then(Value::as_array)
        .is_some_and(|files| !files.is_empty());
    Ok(Some(OpItem {
        record,
        raw: RawItem(root),
        proton_ref,
        has_files,
        ambiguous: binding.ambiguous,
    }))
}

/// The JSON for `op item create -`: the record in its slots, plus the
/// Proton reference.
pub fn create_json(record: &Record, proton_ref: &str) -> SecretString {
    let mut raw = RawItem(json!({
        "title": "",
        "category": category_of(record.kind),
        "fields": [],
        "sections": [],
    }));
    let mut keys: BTreeSet<String> = record.keys().map(str::to_string).collect();
    keys.insert("title".to_string());
    apply_edit(&mut raw, record, &keys).expect("a new item has no field twice");
    ensure_section(&mut raw.0, SECTION_ID, SECTION_LABEL);
    fields_mut(&mut raw.0).push(json!({
        "id": REF_FIELD_ID,
        "type": "STRING",
        "label": "Proton reference",
        "value": proton_ref,
        "section": { "id": SECTION_ID, "label": SECTION_LABEL },
    }));
    SecretString::new(raw.0.to_string())
}

fn ensure_section(raw: &mut Value, id: &str, label: &str) {
    let sections = raw
        .as_object_mut()
        .expect("an item is an object")
        .entry("sections")
        .or_insert_with(|| json!([]));
    if !sections.is_array() {
        *sections = json!([]);
    }
    let sections = sections.as_array_mut().expect("just made an array");
    if !sections.iter().any(|section| str_of(section, "id") == id) {
        sections.push(json!({ "id": id, "label": label }));
    }
}

fn fields_mut(raw: &mut Value) -> &mut Vec<Value> {
    let fields = raw
        .as_object_mut()
        .expect("an item is an object")
        .entry("fields")
        .or_insert_with(|| json!([]));
    if !fields.is_array() {
        *fields = json!([]);
    }
    fields.as_array_mut().expect("just made an array")
}

/// An id no field of the item has.
fn fresh_id(fields: &[Value], taken: &BTreeSet<String>) -> String {
    (0..)
        .map(|n| format!("pqsync-x{n}"))
        .find(|id| !taken.contains(id) && !fields.iter().any(|f| str_of(f, "id") == id))
        .expect("an unbounded range has a free id")
}

/// One change to the raw item's fields.
enum Change {
    Set {
        index: usize,
        value: String,
        op_type: String,
    },
    Remove(usize),
    Add(Value),
}

/// Write `keys` of `record` into the raw item: set, add or clear those
/// fields only, through the same binding a read uses. Everything else in
/// `raw` is kept. An ambiguous item is refused.
pub fn apply_edit(raw: &mut RawItem, record: &Record, keys: &BTreeSet<String>) -> Result<()> {
    if !raw.0.is_object() {
        bail!("the 1Password item is not a JSON object");
    }
    // The fields a key binds to depend on the category: a record of
    // another kind would write where a read of this item never looked.
    let category = raw.0.get("category").and_then(Value::as_str).unwrap_or("");
    if kind_of_category(category) != Some(record.kind) {
        bail!(
            "the 1Password item is not a {}; pq-sync will not edit it",
            record.kind.as_str()
        );
    }
    let slots = slots(record.kind);
    let (_, binding, _) = bind(&raw.0, record.kind, &slots)?;
    if binding.ambiguous {
        bail!("the 1Password item has a field pq-sync uses more than once; edit it in 1Password");
    }

    let mut changes = Vec::new();
    let mut new_ids = BTreeSet::new();
    let mut sections = BTreeSet::new();
    let fields_now = fields_of(&raw.0)?.to_vec();
    for key in keys {
        if key == "title" {
            raw.0["title"] = Value::String(record.title().to_string());
        } else if key == "urls" {
            let urls = record.urls();
            if urls.is_empty() {
                raw.0.as_object_mut().expect("an object").remove("urls");
            } else {
                // A URL that stays keeps what 1Password holds about it (its
                // label); only which one is primary changes.
                let mut old: Vec<Value> = raw
                    .0
                    .get("urls")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let edited = urls
                    .iter()
                    .enumerate()
                    .map(|(i, href)| {
                        let mut entry = match old
                            .iter()
                            .position(|url| str_of(url, "href").trim() == *href)
                        {
                            Some(position) if old[position].is_object() => old.remove(position),
                            _ => json!({ "href": href }),
                        };
                        entry["primary"] = Value::Bool(i == 0);
                        entry
                    })
                    .collect();
                raw.0["urls"] = Value::Array(edited);
            }
        } else if let Some(name) = key.strip_prefix(CUSTOM_PREFIX) {
            let field = record.get(key);
            match (binding.custom.get(key), field) {
                (Some(&index), Some(field)) => {
                    let current = str_of(&fields_now[index], "type");
                    let op_type = match field.kind {
                        FieldKind::Concealed => "CONCEALED",
                        FieldKind::Totp => "OTP",
                        // Text keeps a richer text type (EMAIL, URL, ...), never
                        // one that reads as concealed or a code.
                        FieldKind::Text | FieldKind::Urls => {
                            if current.is_empty() || kind_of_type(current) != FieldKind::Text {
                                "STRING"
                            } else {
                                current
                            }
                        }
                    };
                    changes.push(Change::Set {
                        index,
                        value: field.value.clone(),
                        op_type: op_type.to_string(),
                    });
                }
                (Some(&index), None) => changes.push(Change::Remove(index)),
                (None, Some(field)) => {
                    let id = fresh_id(&fields_now, &new_ids);
                    new_ids.insert(id.clone());
                    sections.insert((CUSTOM_SECTION_ID, CUSTOM_SECTION_LABEL));
                    changes.push(Change::Add(json!({
                        "id": id,
                        "type": custom_type(field.kind),
                        "label": name,
                        "value": field.value,
                        "section": { "id": CUSTOM_SECTION_ID, "label": CUSTOM_SECTION_LABEL },
                    })));
                }
                (None, None) => {}
            }
        } else if let Some(slot) = slots.iter().find(|slot| slot.key == key) {
            let value = record.value(key);
            if slot.key == "expiration_date" {
                write_expiry(
                    &fields_now,
                    &binding,
                    slot,
                    value,
                    &mut changes,
                    &mut sections,
                );
            } else {
                let value = if slot.key == "number" {
                    normalize_card_number(value)
                } else {
                    value.to_string()
                };
                write_slot(
                    &fields_now,
                    binding.slots.get(slot.key).copied(),
                    slot,
                    value,
                    &mut changes,
                    &mut sections,
                );
            }
        }
    }

    for (id, label) in sections {
        ensure_section(&mut raw.0, id, label);
    }
    let fields = fields_mut(&mut raw.0);
    let mut removed = BTreeSet::new();
    let mut added = Vec::new();
    for change in changes {
        match change {
            Change::Set {
                index,
                value,
                op_type,
            } => {
                fields[index]["value"] = Value::String(value);
                fields[index]["type"] = Value::String(op_type);
            }
            Change::Remove(index) => {
                removed.insert(index);
            }
            Change::Add(field) => added.push(field),
        }
    }
    for index in removed.into_iter().rev() {
        fields.remove(index);
    }
    fields.extend(added);
    Ok(())
}

/// Set, add or clear one slot's field. Clearing removes pq-sync's own
/// fields and empties built-in ones (even in a section, like a card's
/// PIN), so the item keeps its shape. The field gets the slot's type.
fn write_slot(
    fields: &[Value],
    bound: Option<usize>,
    slot: &Slot,
    value: String,
    changes: &mut Vec<Change>,
    sections: &mut BTreeSet<(&'static str, &'static str)>,
) {
    match bound {
        Some(index) if value.is_empty() && slot.section == OWN_SECTION => {
            changes.push(Change::Remove(index));
        }
        Some(index) => {
            // A field the owner concealed in 1Password stays concealed.
            let current = str_of(&fields[index], "type");
            let op_type =
                if slot.kind == FieldKind::Text && kind_of_type(current) == FieldKind::Concealed {
                    current
                } else {
                    slot.op_type
                };
            changes.push(Change::Set {
                index,
                value,
                op_type: op_type.to_string(),
            });
        }
        None if value.is_empty() => {}
        None => {
            let mut field = json!({
                "id": slot.id,
                "type": slot.op_type,
                "label": slot.label,
                "value": value,
            });
            if let Some(purpose) = slot.purpose {
                field["purpose"] = purpose.into();
            }
            if let Some((id, label)) = slot.section {
                field["section"] = json!({ "id": id, "label": label });
                sections.insert((id, label));
            }
            changes.push(Change::Add(field));
        }
    }
}

/// A month of a year goes in 1Password's month/year field; anything else
/// in a text field beside it, since the month/year field would refuse it.
fn write_expiry(
    fields: &[Value],
    binding: &Binding,
    slot: &Slot,
    value: &str,
    changes: &mut Vec<Change>,
    sections: &mut BTreeSet<(&'static str, &'static str)>,
) {
    let bound = binding.slots.get(slot.key).copied();
    let text = Slot::new(
        "expiration_date",
        EXPIRY_TEXT_ID,
        OWN_SECTION,
        "STRING",
        "expiry date",
        FieldKind::Text,
    );
    match normalize_expiry(value) {
        // The form op takes for a month/year field.
        Some(year_month) => {
            write_slot(
                fields,
                bound,
                slot,
                year_month.replace('-', "/"),
                changes,
                sections,
            );
            write_slot(
                fields,
                binding.expiry_text,
                &text,
                String::new(),
                changes,
                sections,
            );
        }
        None if !value.is_empty() => {
            write_slot(fields, bound, slot, String::new(), changes, sections);
            write_slot(
                fields,
                binding.expiry_text,
                &text,
                value.to_string(),
                changes,
                sections,
            );
        }
        None => {
            write_slot(fields, bound, slot, String::new(), changes, sections);
            write_slot(
                fields,
                binding.expiry_text,
                &text,
                String::new(),
                changes,
                sections,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_record() -> Record {
        let mut r = Record::new(Kind::Login);
        r.set("title", "Example", FieldKind::Text);
        r.set("username", "me", FieldKind::Text);
        r.set("email", "me@example.com", FieldKind::Text);
        r.set("password", "s3cret", FieldKind::Concealed);
        r.set("totp", "otpauth://totp/x?secret=ABC", FieldKind::Totp);
        r.set("note", "a note", FieldKind::Text);
        r.set_urls(&["https://example.com", "https://login.example.com"]);
        r.add_custom("API key", "k-123", FieldKind::Concealed);
        r.add_custom("Recovery", "codes", FieldKind::Text);
        r
    }

    /// What `op item get` might return for an item created from `json`:
    /// the same content plus fields op adds on its own.
    fn as_returned(json: &SecretString, category_extras: Value) -> String {
        let mut item: Value = serde_json::from_str(json.expose()).unwrap();
        item["id"] = "op-item-1".into();
        item["version"] = 1.into();
        item["vault"] = json!({ "id": "vault-1", "name": "Proton · Personal" });
        item["created_at"] = "2026-10-25T00:00:00Z".into();
        item["updated_at"] = "2026-10-25T00:00:00Z".into();
        item["last_edited_by"] = "USER".into();
        if let Some(fields) = item["fields"].as_array_mut() {
            for field in fields.iter_mut() {
                if field["type"] == "OTP" {
                    field["totp"] = "123456".into();
                }
                if field["purpose"] == "PASSWORD" {
                    field["password_details"] = json!({ "strength": "FANTASTIC" });
                }
            }
            for extra in category_extras.as_array().unwrap() {
                fields.push(extra.clone());
            }
        }
        item.to_string()
    }

    #[test]
    fn categories_map_to_synced_kinds() {
        assert_eq!(kind_of_category("LOGIN"), Some(Kind::Login));
        assert_eq!(kind_of_category("SECURE_NOTE"), Some(Kind::Note));
        assert_eq!(kind_of_category("CREDIT_CARD"), Some(Kind::CreditCard));
        assert_eq!(kind_of_category("IDENTITY"), Some(Kind::Identity));
        for other in [
            "PASSWORD",
            "DOCUMENT",
            "SSH_KEY",
            "API_CREDENTIAL",
            "login",
            "",
        ] {
            assert_eq!(kind_of_category(other), None, "{other}");
        }
    }

    #[test]
    fn a_login_round_trips_through_create_and_get() {
        let record = login_record();
        let json = create_json(&record, "share-1/item-1");
        let created: Value = serde_json::from_str(json.expose()).unwrap();
        assert_eq!(created["category"], "LOGIN");
        assert_eq!(created["title"], "Example");
        assert_eq!(
            created["urls"][0],
            json!({ "href": "https://example.com", "primary": true })
        );
        assert_eq!(created["urls"][1]["primary"], false);

        // An empty built-in field op adds by itself reads as absent.
        let returned = as_returned(
            &json,
            json!([{ "id": "unused", "type": "STRING", "label": "unused", "value": "" }]),
        );
        let item = parse_item(&returned).unwrap().unwrap();
        assert_eq!(item.record, record);
        assert_eq!(item.proton_ref.as_deref(), Some("share-1/item-1"));
        assert!(!item.has_files);
        assert!(!format!("{item:?}").contains("s3cret"));
    }

    #[test]
    fn credentials_go_in_the_built_in_slots() {
        let json = create_json(&login_record(), "s/i");
        let created: Value = serde_json::from_str(json.expose()).unwrap();
        let field = |id: &str| {
            created["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["id"] == id)
                .cloned()
                .unwrap_or_else(|| panic!("no field {id}"))
        };
        assert_eq!(field("username")["purpose"], "USERNAME");
        assert_eq!(field("password")["purpose"], "PASSWORD");
        assert_eq!(field("password")["type"], "CONCEALED");
        assert_eq!(field("notesPlain")["purpose"], "NOTES");
        assert_eq!(field("pqsync-totp")["type"], "OTP");
        assert_eq!(field("pqsync-email")["type"], "EMAIL");
        assert_eq!(field("pqsync-email")["section"]["id"], SECTION_ID);
        assert_eq!(field(REF_FIELD_ID)["value"], "s/i");
        let custom = created["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == "API key")
            .unwrap();
        assert_eq!(custom["type"], "CONCEALED");
        assert_eq!(custom["section"]["id"], CUSTOM_SECTION_ID);
        let sections: Vec<&str> = created["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap())
            .collect();
        assert_eq!(sections, [SECTION_ID, CUSTOM_SECTION_ID]);
    }

    #[test]
    fn cards_notes_and_identities_round_trip() {
        let mut card = Record::new(Kind::CreditCard);
        card.set("title", "Card", FieldKind::Text);
        card.set("cardholder_name", "A Person", FieldKind::Text);
        card.set("number", "4111111111111111", FieldKind::Concealed);
        card.set("verification_number", "123", FieldKind::Concealed);
        card.set("expiration_date", "2027-12", FieldKind::Text);
        card.set("pin", "0000", FieldKind::Concealed);
        card.set("note", "n", FieldKind::Text);
        let returned = as_returned(&create_json(&card, "s/c"), json!([]));
        assert_eq!(parse_item(&returned).unwrap().unwrap().record, card);

        // op may print the expiry as YYYYMM.
        let mut raw: Value = serde_json::from_str(&returned).unwrap();
        for field in raw["fields"].as_array_mut().unwrap() {
            if field["id"] == "expiry" {
                field["value"] = "202712".into();
            }
        }
        assert_eq!(
            parse_item(&raw.to_string())
                .unwrap()
                .unwrap()
                .record
                .value("expiration_date"),
            "2027-12"
        );

        let mut note = Record::new(Kind::Note);
        note.set("title", "Note", FieldKind::Text);
        note.set("note", "body", FieldKind::Text);
        let returned = as_returned(&create_json(&note, "s/n"), json!([]));
        assert_eq!(parse_item(&returned).unwrap().unwrap().record, note);

        let mut identity = Record::new(Kind::Identity);
        identity.set("title", "Me", FieldKind::Text);
        for name in IDENTITY_FIELDS {
            identity.set(name, format!("v-{name}"), identity_field_kind(name));
        }
        identity.add_custom("Travel/Frequent flyer", "FF1", FieldKind::Concealed);
        let returned = as_returned(&create_json(&identity, "s/id"), json!([]));
        assert_eq!(parse_item(&returned).unwrap().unwrap().record, identity);
    }

    #[test]
    fn fields_added_in_1password_read_as_custom_fields() {
        let returned = as_returned(
            &create_json(&login_record(), "s/i"),
            json!([
                { "id": "abc", "type": "STRING", "label": "PIN hint", "value": "blue",
                  "section": { "id": "s1", "label": "Extra" } },
                { "id": "def", "type": "CONCEALED", "label": "secret q", "value": "x" },
                { "id": "addr", "type": "ADDRESS", "label": "address",
                  "value": { "street": "1 Main" } }
            ]),
        );
        let item = parse_item(&returned).unwrap().unwrap();
        assert_eq!(item.record.value("x:Extra/PIN hint"), "blue");
        assert_eq!(
            item.record.get("x:secret q").unwrap().kind,
            FieldKind::Concealed
        );
        // A value that is not text is kept in the raw item, not read.
        assert!(item.record.keys().all(|key| !key.contains("address")));
    }

    #[test]
    fn unsupported_categories_and_files_are_reported() {
        let password = json!({ "id": "x", "title": "t", "category": "PASSWORD", "fields": [] });
        assert!(parse_item(&password.to_string()).unwrap().is_none());

        let mut raw: Value = serde_json::from_str(&as_returned(
            &create_json(&login_record(), "s/i"),
            json!([]),
        ))
        .unwrap();
        raw["files"] = json!([{ "id": "f1", "name": "scan.pdf", "size": 10 }]);
        assert!(parse_item(&raw.to_string()).unwrap().unwrap().has_files);

        let err = parse_item("{\"fields\": \"s3cret\"}").unwrap_err();
        assert!(!format!("{err:#}").contains("s3cret"), "{err:#}");
    }

    #[test]
    fn an_edit_writes_only_the_given_keys_and_keeps_the_rest() {
        let returned = as_returned(
            &create_json(&login_record(), "s/i"),
            json!([{ "id": "mine", "type": "STRING", "label": "kept", "value": "1P only",
                     "section": { "id": "s1", "label": "Mine" } }]),
        );
        let mut raw = parse_item(&returned).unwrap().unwrap().raw;
        raw.0["favorite"] = true.into();

        let mut changed = login_record();
        changed.set("password", "n3w", FieldKind::Concealed);
        changed.set("username", "other-not-written", FieldKind::Text);
        changed.set("note", "", FieldKind::Text);
        changed.set_urls(&["https://new.example.com"]);
        changed.add_custom("New field", "nv", FieldKind::Text);
        let keys: BTreeSet<String> = ["password", "note", "urls", "x:New field", "x:Recovery"]
            .into_iter()
            .map(String::from)
            .collect();
        let mut without_recovery = changed.clone();
        without_recovery.set("x:Recovery", "", FieldKind::Text);
        apply_edit(&mut raw, &without_recovery, &keys).unwrap();

        let item = parse_item(&raw.0.to_string()).unwrap().unwrap();
        let r = &item.record;
        assert_eq!(r.value("password"), "n3w");
        assert_eq!(r.value("username"), "me", "a key not written stays");
        assert_eq!(r.value("note"), "");
        assert_eq!(r.urls(), ["https://new.example.com"]);
        assert_eq!(r.value("x:New field"), "nv");
        assert!(r.get("x:Recovery").is_none(), "a removed custom field goes");
        assert_eq!(r.value("x:API key"), "k-123");
        assert_eq!(
            r.value("x:Mine/kept"),
            "1P only",
            "1Password's own fields stay"
        );
        assert_eq!(item.proton_ref.as_deref(), Some("s/i"));
        assert_eq!(raw.0["favorite"], true);
        assert_eq!(raw.0["id"], "op-item-1");
    }

    #[test]
    fn an_edit_of_an_item_created_in_1password_fills_its_slots() {
        // A login created in the 1Password app has the built-in fields but
        // no pq-sync sections yet.
        let raw = json!({
            "id": "native", "title": "Native", "category": "LOGIN", "version": 4,
            "fields": [
                { "id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "u" },
                { "id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "p" },
                { "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": "" }
            ]
        });
        let mut raw = RawItem(raw);
        let mut record = Record::new(Kind::Login);
        record.set("email", "e@example.com", FieldKind::Text);
        record.set("totp", "otpauth://totp/z", FieldKind::Totp);
        let keys: BTreeSet<String> = ["email", "totp"].into_iter().map(String::from).collect();
        apply_edit(&mut raw, &record, &keys).unwrap();
        let item = parse_item(&raw.0.to_string()).unwrap().unwrap();
        assert_eq!(item.record.value("email"), "e@example.com");
        assert_eq!(item.record.get("totp").unwrap().kind, FieldKind::Totp);
        assert_eq!(item.record.value("username"), "u");
        let sections = raw.0["sections"].as_array().unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0]["id"], SECTION_ID);
    }

    #[test]
    fn clearing_a_built_in_field_in_a_section_empties_it() {
        let mut card = Record::new(Kind::CreditCard);
        card.set("title", "Card", FieldKind::Text);
        card.set("pin", "0000", FieldKind::Concealed);
        let mut identity = Record::new(Kind::Identity);
        identity.set("title", "Me", FieldKind::Text);
        identity.set("first_name", "Ada", FieldKind::Text);
        for (record, key, id) in [(card, "pin", "pin"), (identity, "first_name", "firstname")] {
            let returned = as_returned(&create_json(&record, "s/x"), json!([]));
            let mut raw = parse_item(&returned).unwrap().unwrap().raw;
            let mut cleared = record.clone();
            cleared.set(key, "", FieldKind::Text);
            let keys: BTreeSet<String> = [key.to_string()].into();
            apply_edit(&mut raw, &cleared, &keys).unwrap();
            let field = raw.0["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["id"] == id)
                .unwrap_or_else(|| panic!("built-in {id} was removed"))
                .clone();
            assert_eq!(field["value"], "");
            assert!(
                parse_item(&raw.0.to_string())
                    .unwrap()
                    .unwrap()
                    .record
                    .get(key)
                    .is_none()
            );
        }
    }

    #[test]
    fn an_expiry_that_is_not_a_month_goes_to_a_text_field() {
        let mut card = Record::new(Kind::CreditCard);
        card.set("title", "Card", FieldKind::Text);
        card.set("expiration_date", "someday", FieldKind::Text);
        let created: Value = serde_json::from_str(create_json(&card, "s/c").expose()).unwrap();
        let fields = created["fields"].as_array().unwrap();
        assert!(
            !fields
                .iter()
                .any(|f| f["type"] == "MONTH_YEAR" && f["value"] == "someday"),
            "{fields:?}"
        );
        let returned = as_returned(&create_json(&card, "s/c"), json!([]));
        let item = parse_item(&returned).unwrap().unwrap();
        assert_eq!(item.record.value("expiration_date"), "someday");

        // A valid expiry later replaces the text field with the month field.
        let mut raw = item.raw;
        card.set("expiration_date", "2027-12", FieldKind::Text);
        let keys: BTreeSet<String> = ["expiration_date".to_string()].into();
        apply_edit(&mut raw, &card, &keys).unwrap();
        let fields = raw.0["fields"].as_array().unwrap();
        assert!(
            fields
                .iter()
                .any(|f| f["id"] == "expiry" && f["value"] == "2027/12")
        );
        assert!(
            !fields.iter().any(|f| f["value"] == "someday"),
            "{fields:?}"
        );
        assert_eq!(
            parse_item(&raw.0.to_string())
                .unwrap()
                .unwrap()
                .record
                .value("expiration_date"),
            "2027-12"
        );
    }

    fn custom_field(id: &str, label: &str, value: &str) -> Value {
        json!({ "id": id, "type": "STRING", "label": label, "value": value,
                "section": { "id": CUSTOM_SECTION_ID, "label": "Proton Pass custom fields" } })
    }

    fn note_with(fields: Value) -> RawItem {
        RawItem(
            json!({ "id": "n1", "title": "N", "category": "SECURE_NOTE", "version": 1,
                        "fields": fields }),
        )
    }

    fn values_by_id(raw: &RawItem) -> Vec<(String, String)> {
        raw.0["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| (str_of(f, "id").to_string(), str_of(f, "value").to_string()))
            .collect()
    }

    #[test]
    fn duplicate_custom_names_are_read_numbered_and_never_edited() {
        let mut raw = note_with(json!([
            custom_field("a", "dup", "first"),
            custom_field("b", "dup", "second"),
            custom_field("c", "dup #2", "literal"),
        ]));
        let item = parse_item(&raw.0.to_string()).unwrap().unwrap();
        assert_eq!(item.record.value("x:dup"), "first");
        assert_eq!(item.record.value("x:dup #2"), "second");
        assert_eq!(item.record.value("x:dup #2 #2"), "literal");
        assert!(item.ambiguous);

        let mut record = item.record.clone();
        record.set("x:dup #2", "changed", FieldKind::Text);
        let keys: BTreeSet<String> = ["x:dup #2".to_string()].into();
        assert!(apply_edit(&mut raw, &record, &keys).is_err());
        assert_eq!(
            values_by_id(&raw),
            [
                ("a".into(), "first".into()),
                ("b".into(), "second".into()),
                ("c".into(), "literal".into())
            ]
        );
    }

    #[test]
    fn unnamed_custom_fields_keep_their_values_and_names() {
        let mut note = Record::new(Kind::Note);
        note.set("title", "N", FieldKind::Text);
        note.add_custom("", "one", FieldKind::Text);
        note.add_custom("pqsync-x0", "two", FieldKind::Text);
        let returned = as_returned(&create_json(&note, "s/n"), json!([]));
        assert_eq!(parse_item(&returned).unwrap().unwrap().record, note);
    }

    #[test]
    fn the_proton_reference_is_only_taken_from_pq_syncs_own_field() {
        let item = |fields: Value| {
            let raw = json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1, "fields": fields });
            parse_item(&raw.to_string()).unwrap().unwrap()
        };
        let own = |value: &str, kind: &str| {
            json!({ "id": REF_FIELD_ID, "type": kind, "label": "Proton reference", "value": value,
                    "section": { "id": SECTION_ID, "label": "Proton Pass" } })
        };
        assert_eq!(
            item(json!([own("s1/i1", "STRING")])).proton_ref.as_deref(),
            Some("s1/i1")
        );

        // Concealed, elsewhere, malformed or twice: not a reference, and
        // never printed.
        let concealed = item(json!([own("SYNTHETIC-SECRET", "CONCEALED")]));
        assert_eq!(concealed.proton_ref, None);
        assert!(!format!("{concealed:?}").contains("SYNTHETIC-SECRET"));
        let elsewhere = json!({ "id": REF_FIELD_ID, "type": "STRING", "label": "x", "value": "s/i",
                                "section": { "id": "other", "label": "Other" } });
        assert_eq!(item(json!([elsewhere])).proton_ref, None);
        assert_eq!(
            item(json!([own("has spaces / x", "STRING")])).proton_ref,
            None
        );
        let twice = item(json!([own("s1/i1", "STRING"), own("s2/i2", "STRING")]));
        assert_eq!(twice.proton_ref, None);
        assert!(twice.ambiguous);
        let shown = format!("{:?}", item(json!([own("s1/i1", "STRING")])));
        assert!(!shown.contains("s1/i1"), "{shown}");
    }

    #[test]
    fn a_slot_is_written_with_its_type_and_only_in_its_section() {
        let mut identity = Record::new(Kind::Identity);
        identity.set("title", "Me", FieldKind::Text);
        identity.set("passport_number", "P-NEW", FieldKind::Concealed);
        let keys: BTreeSet<String> = ["passport_number".to_string()].into();

        // pq-sync's own field, but stored as text: written concealed.
        let mut raw = RawItem(
            json!({ "id": "i", "title": "Me", "category": "IDENTITY", "version": 1,
            "fields": [{ "id": "pqsync-passport_number", "type": "STRING", "label": "passport number",
                         "value": "P-OLD", "section": { "id": SECTION_ID, "label": "Proton Pass" } }] }),
        );
        apply_edit(&mut raw, &identity, &keys).unwrap();
        let field = &raw.0["fields"][0];
        assert_eq!(
            (field["value"].as_str(), field["type"].as_str()),
            (Some("P-NEW"), Some("CONCEALED"))
        );

        // The same id in another section is not the slot: left alone.
        let mut raw = RawItem(
            json!({ "id": "i", "title": "Me", "category": "IDENTITY", "version": 1,
            "fields": [{ "id": "pqsync-passport_number", "type": "STRING", "label": "decoy",
                         "value": "kept", "section": { "id": "other", "label": "Other" } }] }),
        );
        apply_edit(&mut raw, &identity, &keys).unwrap();
        let fields = raw.0["fields"].as_array().unwrap();
        assert_eq!(fields[0]["value"], "kept");
        assert!(fields.iter().any(|f| f["value"] == "P-NEW"
            && f["type"] == "CONCEALED"
            && f["section"]["id"] == SECTION_ID));
    }

    #[test]
    fn an_item_with_a_reserved_field_twice_is_not_edited() {
        let field = |value: &str| {
            json!({ "id": "password", "type": "CONCEALED", "purpose": "PASSWORD",
                                           "label": "password", "value": value })
        };
        let mut raw = RawItem(
            json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1,
                                      "fields": [field("one"), field("two")] }),
        );
        let item = parse_item(&raw.0.to_string()).unwrap().unwrap();
        assert!(item.ambiguous);
        let mut record = item.record.clone();
        record.set("password", "three", FieldKind::Concealed);
        let keys: BTreeSet<String> = ["password".to_string()].into();
        assert!(apply_edit(&mut raw, &record, &keys).is_err());
    }

    #[test]
    fn unnamed_duplicate_custom_fields_round_trip() {
        let mut note = Record::new(Kind::Note);
        note.set("title", "N", FieldKind::Text);
        note.add_custom("", "one", FieldKind::Text);
        note.add_custom("", "two", FieldKind::Concealed);
        let returned = as_returned(&create_json(&note, "s/n"), json!([]));
        let item = parse_item(&returned).unwrap().unwrap();
        assert_eq!(item.record, note);
        assert!(!item.ambiguous);
    }

    #[test]
    fn duplicate_custom_names_make_an_item_ambiguous() {
        let raw = note_with(json!([
            custom_field("a", "dup", "first"),
            custom_field("b", " dup ", "second"),
        ]));
        let item = parse_item(&raw.0.to_string()).unwrap().unwrap();
        assert!(item.ambiguous);
        let mut record = item.record.clone();
        record.set("x:dup", "", FieldKind::Text);
        let keys: BTreeSet<String> = ["x:dup".to_string()].into();
        let mut raw = raw;
        assert!(apply_edit(&mut raw, &record, &keys).is_err());
    }

    #[test]
    fn a_custom_field_edited_to_text_loses_a_concealed_type() {
        let mut raw = note_with(json!([
            { "id": "c", "type": "CREDIT_CARD_NUMBER", "label": "Card", "value": "4111" },
            { "id": "e", "type": "EMAIL", "label": "Mail", "value": "a@b.c" },
        ]));
        let mut record = parse_item(&raw.0.to_string()).unwrap().unwrap().record;
        record.set("x:Card", "plain text", FieldKind::Text);
        record.set("x:Mail", "d@e.f", FieldKind::Text);
        let keys: BTreeSet<String> = ["x:Card".to_string(), "x:Mail".to_string()].into();
        apply_edit(&mut raw, &record, &keys).unwrap();
        let reread = parse_item(&raw.0.to_string()).unwrap().unwrap().record;
        assert_eq!(reread.get("x:Card").unwrap().kind, FieldKind::Text);
        assert_eq!(
            raw.0["fields"][1]["type"], "EMAIL",
            "a richer text type stays"
        );
    }

    #[test]
    fn the_expiry_text_field_reads_like_the_month_field_and_both_is_ambiguous() {
        let text = |value: &str| {
            json!({ "id": EXPIRY_TEXT_ID, "type": "STRING", "label": "expiry date",
            "value": value, "section": { "id": SECTION_ID, "label": "Proton Pass" } })
        };
        let card = |fields: Value| {
            let raw = json!({ "id": "c", "title": "C", "category": "CREDIT_CARD", "version": 1, "fields": fields });
            parse_item(&raw.to_string()).unwrap().unwrap()
        };
        let only_text = card(json!([text("12/2027")]));
        assert_eq!(only_text.record.value("expiration_date"), "2027-12");
        assert!(!only_text.ambiguous);
        let both = card(json!([
            text("someday"),
            { "id": "expiry", "type": "MONTH_YEAR", "label": "expiry date", "value": "2027/12" },
        ]));
        assert!(both.ambiguous);
    }

    #[test]
    fn a_url_edit_keeps_the_labels_of_urls_that_stay() {
        let mut raw = RawItem(
            json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1,
            "fields": [],
            "urls": [
                { "label": "website", "primary": true, "href": "https://a.example" },
                { "label": "login page", "primary": false, "href": "https://b.example" }
            ] }),
        );
        let mut record = parse_item(&raw.0.to_string()).unwrap().unwrap().record;
        record.set_urls(&["https://b.example", "https://c.example"]);
        let keys: BTreeSet<String> = ["urls".to_string()].into();
        apply_edit(&mut raw, &record, &keys).unwrap();
        assert_eq!(
            raw.0["urls"],
            json!([
                { "label": "login page", "primary": true, "href": "https://b.example" },
                { "primary": false, "href": "https://c.example" }
            ])
        );
        assert_eq!(
            parse_item(&raw.0.to_string())
                .unwrap()
                .unwrap()
                .record
                .urls(),
            ["https://b.example", "https://c.example"]
        );
    }

    #[test]
    fn a_reserved_field_with_a_value_the_read_cannot_show_makes_an_item_ambiguous() {
        let raw = RawItem(
            json!({ "id": "c", "title": "C", "category": "CREDIT_CARD", "version": 1,
            "fields": [
                { "id": "expiry", "type": "MONTH_YEAR", "label": "expiry date", "value": "2027/12" },
                { "id": EXPIRY_TEXT_ID, "type": "STRING", "label": "expiry date",
                  "section": { "id": SECTION_ID }, "value": { "secret": "ONLY-IN-RAW" } }
            ] }),
        );
        let item = parse_item(&raw.0.to_string()).unwrap().unwrap();
        assert!(item.ambiguous);
        let keys: BTreeSet<String> = ["expiration_date".to_string()].into();
        let mut raw = raw;
        assert!(apply_edit(&mut raw, &item.record, &keys).is_err());
        assert_eq!(raw.0["fields"][1]["value"]["secret"], "ONLY-IN-RAW");

        // An address in a non-slot field is fine: it is not pq-sync's.
        let raw = json!({ "id": "i", "title": "I", "category": "IDENTITY", "version": 1,
            "fields": [{ "id": "address", "type": "ADDRESS", "label": "address",
                         "section": { "id": "address" }, "value": { "street": "1 Main" } }] });
        assert!(!parse_item(&raw.to_string()).unwrap().unwrap().ambiguous);
    }

    #[test]
    fn an_edit_of_another_category_is_refused() {
        let mut raw = RawItem(
            json!({ "id": "n", "title": "N", "category": "SECURE_NOTE", "version": 1,
            "fields": [{ "id": "password", "type": "STRING", "label": "Other", "value": "OLD" }] }),
        );
        let mut login = Record::new(Kind::Login);
        login.set("password", "NEW-SECRET", FieldKind::Concealed);
        let keys: BTreeSet<String> = ["password".to_string()].into();
        assert!(apply_edit(&mut raw, &login, &keys).is_err());
        assert_eq!(raw.0["fields"][0]["value"], "OLD");
    }

    #[test]
    fn urls_the_read_cannot_represent_make_an_item_ambiguous() {
        let login = |urls: Value| {
            let raw = json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1,
                              "fields": [], "urls": urls });
            parse_item(&raw.to_string()).unwrap().unwrap()
        };
        for urls in [
            json!([{ "href": "https://a.example", "primary": true }, { "href": { "secret": "RAW" } }]),
            json!([{ "href": "https://a.example", "primary": true }, "RAW_ONLY_STRING"]),
            json!({ "href": "https://a.example" }),
            json!([{ "href": "https://a.example", "label": "two" }, { "href": "https://a.example", "primary": true }]),
            json!([{ "href": "https://a.example\n https://b.example", "primary": true }]),
        ] {
            assert!(login(urls.clone()).ambiguous, "{urls}");
        }
        assert!(!login(json!([{ "href": "https://a.example", "primary": true }])).ambiguous);
        assert!(!login(json!([])).ambiguous);
        assert!(!login(Value::Null).ambiguous);
    }

    #[test]
    fn a_url_with_stray_spaces_keeps_its_label_on_an_edit() {
        let mut raw = RawItem(
            json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1,
            "fields": [],
            "urls": [{ "label": "login page", "primary": true, "href": " https://b.example " }] }),
        );
        let mut record = parse_item(&raw.0.to_string()).unwrap().unwrap().record;
        assert_eq!(record.urls(), ["https://b.example"]);
        record.set_urls(&["https://b.example", "https://c.example"]);
        let keys: BTreeSet<String> = ["urls".to_string()].into();
        apply_edit(&mut raw, &record, &keys).unwrap();
        assert_eq!(raw.0["urls"][0]["label"], "login page");
        assert_eq!(
            parse_item(&raw.0.to_string())
                .unwrap()
                .unwrap()
                .record
                .urls(),
            ["https://b.example", "https://c.example"]
        );
    }

    #[test]
    fn a_proton_url_listed_twice_gives_an_editable_copy() {
        let mut record = login_record();
        record.set_urls(&[
            "https://a.example",
            "https://b.example",
            "https://a.example",
        ]);
        assert_eq!(record.urls(), ["https://a.example", "https://b.example"]);
        let returned = as_returned(&create_json(&record, "s/i"), json!([]));
        let item = parse_item(&returned).unwrap().unwrap();
        assert!(!item.ambiguous);
        assert_eq!(item.record, record);
    }

    #[test]
    fn everything_an_edit_touches_must_be_readable() {
        let login = |extra: Value| {
            let mut raw =
                json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1, "fields": [] });
            for (key, value) in extra.as_object().unwrap() {
                raw[key] = value.clone();
            }
            parse_item(&raw.to_string()).unwrap().unwrap()
        };
        for extra in [
            json!({ "urls": [{ "href": " \t ", "label": "Recovery", "secret": "RAW" },
                             { "href": "https://a.test", "primary": true }] }),
            json!({ "urls": [{ "href": "" }] }),
            json!({ "title": { "secret": "RAW" } }),
            json!({ "sections": { "id": "other", "label": "Recovery" } }),
            json!({ "sections": ["not a section"] }),
            json!({ "fields": ["not a field"] }),
        ] {
            assert!(login(extra.clone()).ambiguous, "{extra}");
        }
        for fine in [
            json!({ "title": null }),
            json!({ "sections": null }),
            json!({ "sections": [{ "id": "s", "label": "S" }] }),
        ] {
            assert!(!login(fine.clone()).ambiguous, "{fine}");
        }
    }

    #[test]
    fn nested_properties_an_edit_overwrites_must_be_readable() {
        let cases = [
            (
                json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1,
                     "fields": [{ "id": "password", "purpose": "PASSWORD", "label": "password",
                                  "value": "OLD", "type": { "secret": "RAW-ONLY-TYPE" } }] }),
                "password",
            ),
            (
                json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1, "fields": [],
                     "urls": [{ "href": "https://a.test", "primary": { "secret": "RAW-ONLY-PRIMARY" } }] }),
                "urls",
            ),
        ];
        for (json, key) in cases {
            let item = parse_item(&json.to_string()).unwrap().unwrap();
            assert!(item.ambiguous, "{json}");
            let mut record = item.record.clone();
            record.set("password", "NEW", FieldKind::Concealed);
            record.set_urls(&["https://a.test", "https://b.test"]);
            let mut raw = RawItem(json.clone());
            let keys: BTreeSet<String> = [key.to_string()].into();
            assert!(apply_edit(&mut raw, &record, &keys).is_err());
            assert_eq!(raw.0, json, "a refused edit changes nothing");
        }
        // Ordinary items have text types and boolean primaries.
        let fine = json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1,
            "fields": [{ "id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "value": "x" }],
            "urls": [{ "href": "https://a.test", "primary": true, "label": "website" }] });
        assert!(!parse_item(&fine.to_string()).unwrap().unwrap().ambiguous);
    }

    #[test]
    fn an_edit_keeps_a_field_the_owner_concealed_concealed() {
        let mut raw = RawItem(
            json!({ "id": "i", "title": "T", "category": "LOGIN", "version": 1,
            "fields": [{ "id": "username", "type": "CONCEALED", "purpose": "USERNAME",
                         "label": "username", "value": "old-user" }] }),
        );
        let mut record = parse_item(&raw.0.to_string()).unwrap().unwrap().record;
        record.set("username", "new-user", FieldKind::Text);
        let keys: BTreeSet<String> = ["username".to_string()].into();
        apply_edit(&mut raw, &record, &keys).unwrap();
        assert_eq!(raw.0["fields"][0]["type"], "CONCEALED");
        assert_eq!(raw.0["fields"][0]["value"], "new-user");
        assert_eq!(
            parse_item(&raw.0.to_string()).unwrap().unwrap().record,
            record
        );
    }
}
