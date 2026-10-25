//! 1Password items as `op` 2.x prints and accepts them (`op item get
//! --format json`, `op item create -`, `op item edit` with JSON on stdin),
//! mapped to and from the canonical [`Record`].
//!
//! Each canonical field has a slot: a built-in 1Password field where one
//! fits (a login's username, a card's number), otherwise a field in pq-sync's
//! own "Proton Pass" section. Custom fields go to a "Proton Pass custom
//! fields" section. An edit changes only the slots it writes and keeps every
//! other part of the item JSON as `op` returned it.
//!
//! What the CLI cannot show, it cannot keep: a JSON template edit overwrites
//! passkeys, and `op item get` does not list them. Callers decide from
//! [`OpItem::has_files`] and [`visible_fingerprint`] whether an item is safe
//! to edit.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt;

use super::proton_json::{IDENTITY_FIELDS, identity_field_kind};
use super::record::{CUSTOM_PREFIX, FieldKind, Kind, Record, keyed_hash, normalize_expiry};
use super::secret::SecretString;

/// pq-sync's section for fields 1Password has no built-in slot for.
pub const SECTION_ID: &str = "pq-sync";
const SECTION_LABEL: &str = "Proton Pass";
/// pq-sync's section for Proton's custom fields.
pub const CUSTOM_SECTION_ID: &str = "pq-sync-custom";
const CUSTOM_SECTION_LABEL: &str = "Proton Pass custom fields";
/// The field holding the Proton item's `share_id/item_id`, so a lost state
/// file can be rebuilt. Not a secret.
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
#[derive(Debug)]
pub struct OpItem {
    pub record: Record,
    pub raw: RawItem,
    /// The Proton reference pq-sync stored on the item, if any.
    pub proton_ref: Option<String>,
    /// Files are attached: a template edit might not keep them.
    pub has_files: bool,
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

/// The custom-field name of a field that is not in a slot: its label, under
/// its section's label unless it is in pq-sync's custom section.
fn custom_name(field: &Value) -> String {
    let label = match str_of(field, "label") {
        "" => str_of(field, "id"),
        label => label,
    };
    match field.get("section") {
        Some(section) if str_of(section, "id") == CUSTOM_SECTION_ID => label.to_string(),
        Some(section) if !str_of(section, "label").is_empty() => {
            format!("{}/{label}", str_of(section, "label"))
        }
        _ => label.to_string(),
    }
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
    let fields = match root.get("fields") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(fields)) => fields.as_slice(),
        Some(_) => anyhow::bail!("op item output has malformed fields"),
    };

    let slots = slots(kind);
    let mut record = Record::new(kind);
    record.set("title", str_of(&root, "title"), FieldKind::Text);
    let mut proton_ref = None;
    for field in fields {
        // Values that are not text (an address) stay in the raw item only.
        let Some(value) = field.get("value").and_then(Value::as_str) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let id = str_of(field, "id");
        if id == REF_FIELD_ID {
            proton_ref = Some(value.to_string());
        } else if id == EXPIRY_TEXT_ID && kind == Kind::CreditCard {
            record.set("expiration_date", value, FieldKind::Text);
        } else if let Some(slot) = slots.iter().find(|slot| slot.id == id) {
            let value = if slot.key == "expiration_date" {
                normalize_expiry(value).unwrap_or_else(|| value.to_string())
            } else {
                value.to_string()
            };
            record.set(slot.key, value, slot.kind);
        } else {
            record.add_custom(
                &custom_name(field),
                value,
                kind_of_type(str_of(field, "type")),
            );
        }
    }

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
    apply_edit(&mut raw, record, &keys);
    ensure_section(&mut raw.0, SECTION_ID, SECTION_LABEL);
    push_field(
        &mut raw.0,
        json!({
            "id": REF_FIELD_ID,
            "type": "STRING",
            "label": "Proton reference",
            "value": proton_ref,
            "section": { "id": SECTION_ID, "label": SECTION_LABEL },
        }),
    );
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

fn push_field(raw: &mut Value, field: Value) {
    fields_mut(raw).push(field);
}

/// Write `keys` of `record` into the raw item: set, add or clear those
/// slots only. Everything else in `raw` is kept.
pub fn apply_edit(raw: &mut RawItem, record: &Record, keys: &BTreeSet<String>) {
    let raw = &mut raw.0;
    if !raw.is_object() {
        *raw = json!({});
    }
    let slots = slots(record.kind);
    for key in keys {
        let value = record.value(key);
        if key == "title" {
            raw["title"] = Value::String(value.to_string());
        } else if key == "urls" {
            let urls = record.urls();
            if urls.is_empty() {
                raw.as_object_mut().expect("an object").remove("urls");
            } else {
                raw["urls"] = Value::Array(
                    urls.iter()
                        .enumerate()
                        .map(|(i, href)| json!({ "href": href, "primary": i == 0 }))
                        .collect(),
                );
            }
        } else if let Some(name) = key.strip_prefix(CUSTOM_PREFIX) {
            write_custom(raw, &slots, name, record.get(key));
        } else if let Some(slot) = slots.iter().find(|slot| slot.key == key) {
            write_slot(raw, slot, value);
        }
    }
}

fn write_slot(raw: &mut Value, slot: &Slot, value: &str) {
    if slot.key != "expiration_date" {
        return set_slot(raw, slot, value.to_string());
    }
    match normalize_expiry(value) {
        // The form op takes for a month/year field.
        Some(year_month) => {
            remove_field(raw, EXPIRY_TEXT_ID);
            set_slot(raw, slot, year_month.replace('-', "/"));
        }
        None if !value.is_empty() => {
            set_slot(raw, slot, String::new());
            let text = Slot::new(
                "expiration_date",
                EXPIRY_TEXT_ID,
                OWN_SECTION,
                "STRING",
                "expiry date",
                FieldKind::Text,
            );
            set_slot(raw, &text, value.to_string());
        }
        None => {
            remove_field(raw, EXPIRY_TEXT_ID);
            set_slot(raw, slot, String::new());
        }
    }
}

fn remove_field(raw: &mut Value, id: &str) {
    fields_mut(raw).retain(|field| str_of(field, "id") != id);
}

/// Set, add or clear the field of `slot`.
fn set_slot(raw: &mut Value, slot: &Slot, value: String) {
    let fields = fields_mut(raw);
    if let Some(index) = fields
        .iter()
        .position(|field| str_of(field, "id") == slot.id)
    {
        // pq-sync's own fields go; a built-in one (even in a section, like
        // a card's PIN) is emptied, so the item keeps its shape.
        if value.is_empty() && slot.section == OWN_SECTION {
            fields.remove(index);
        } else {
            // A built-in field is emptied, not removed.
            fields[index]["value"] = Value::String(value);
        }
        return;
    }
    if value.is_empty() {
        return;
    }
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
        ensure_section(raw, id, label);
    }
    push_field(raw, field);
}

fn write_custom(raw: &mut Value, slots: &[Slot], name: &str, field: Option<&super::record::Field>) {
    let is_custom = |candidate: &Value| {
        let id = str_of(candidate, "id");
        id != REF_FIELD_ID
            && id != EXPIRY_TEXT_ID
            && !slots.iter().any(|slot| slot.id == id)
            && candidate.get("value").is_none_or(Value::is_string)
            && custom_name(candidate) == name
    };
    let fields = fields_mut(raw);
    match (fields.iter().position(is_custom), field) {
        (Some(index), Some(field)) => {
            fields[index]["value"] = Value::String(field.value.clone());
            fields[index]["type"] = custom_type(field.kind).into();
        }
        (Some(index), None) => {
            fields.remove(index);
        }
        (None, Some(field)) => {
            let mut n = fields.len();
            let id = loop {
                let id = format!("pqsync-x{n}");
                if !fields.iter().any(|f| str_of(f, "id") == id) {
                    break id;
                }
                n += 1;
            };
            fields.push(json!({
                "id": id,
                "type": custom_type(field.kind),
                "label": name,
                "value": field.value,
                "section": { "id": CUSTOM_SECTION_ID, "label": CUSTOM_SECTION_LABEL },
            }));
            ensure_section(raw, CUSTOM_SECTION_ID, CUSTOM_SECTION_LABEL);
        }
        (None, None) => {}
    }
}

/// A keyed fingerprint of everything the CLI shows of an item, minus what
/// changes on its own (version, timestamps, current TOTP codes, password
/// strength). When an item's version moves but this does not, something the
/// CLI cannot show changed (a passkey), and the item is no longer safe to
/// edit from a template.
pub fn visible_fingerprint(raw: &RawItem, key: &[u8]) -> String {
    let mut visible = raw.0.clone();
    if let Some(item) = visible.as_object_mut() {
        for volatile in [
            "version",
            "created_at",
            "updated_at",
            "last_edited_by",
            "additional_information",
        ] {
            item.remove(volatile);
        }
        if let Some(Value::Array(fields)) = item.get_mut("fields") {
            for field in fields.iter_mut().filter_map(Value::as_object_mut) {
                field.remove("totp");
                field.remove("password_details");
            }
        }
    }
    // serde_json's maps are sorted, so equal items serialize equally.
    keyed_hash(key, "op item", visible.to_string().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

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
        apply_edit(&mut raw, &without_recovery, &keys);

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
        apply_edit(&mut raw, &record, &keys);
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
            apply_edit(&mut raw, &cleared, &keys);
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
        apply_edit(&mut raw, &card, &keys);
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

    #[test]
    fn the_visible_fingerprint_ignores_what_changes_on_its_own() {
        let returned = as_returned(&create_json(&login_record(), "s/i"), json!([]));
        let raw = parse_item(&returned).unwrap().unwrap().raw;
        let base = visible_fingerprint(&raw, KEY);

        let mut later = raw.clone();
        later.0["version"] = 7.into();
        later.0["updated_at"] = "2026-10-26T00:00:00Z".into();
        for field in later.0["fields"].as_array_mut().unwrap() {
            if field["type"] == "OTP" {
                field["totp"] = "654321".into();
            }
        }
        assert_eq!(visible_fingerprint(&later, KEY), base);

        let mut edited = raw.clone();
        edited.0["title"] = "Renamed".into();
        assert_ne!(visible_fingerprint(&edited, KEY), base);
        assert_ne!(visible_fingerprint(&raw, b"other key"), base);
        assert!(!base.contains("s3cret"));
    }
}
