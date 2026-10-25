//! Proton Pass items as pass-cli 2.5.1 prints and accepts them, mapped to
//! and from the canonical [`Record`].
//!
//! Read: `item view --output json` (`{item:{content:{title, note,
//! content:{<Kind>:{...}}, extra_fields}, state}}`), whose shapes come from
//! proton-pass-common's item model. Write: the `--from-template` JSON of
//! `item create login|note|credit-card|identity`, which carries fewer fields
//! than an item holds (no custom fields; no note on logins). What a template
//! cannot carry is reported, never silently dropped.

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};

use super::record::{FieldKind, Kind, Record, normalize_card_number, normalize_expiry};
use super::secret::SecretString;

/// A Proton item read with its secrets.
#[derive(Debug)]
pub struct ProtonItem {
    pub record: Record,
    /// Not in the trash.
    pub active: bool,
    /// Proton passkeys stay in Proton: 1Password's CLI cannot create them.
    pub has_passkeys: bool,
    pub attachments: usize,
}

/// The kind of a summary's `item_type` (`item list --output json`), or
/// `None` for kinds pq-sync does not carry (alias, ssh_key, wifi, custom).
pub fn kind_of_summary(item_type: &str) -> Option<Kind> {
    match item_type {
        "login" => Some(Kind::Login),
        "note" => Some(Kind::Note),
        "credit_card" => Some(Kind::CreditCard),
        "identity" => Some(Kind::Identity),
        _ => None,
    }
}

/// Parse `item view --output json`. `Ok(None)` for kinds pq-sync does not
/// carry.
pub fn parse_view(json: &str) -> Result<Option<ProtonItem>> {
    // serde_json's errors quote no input, only positions.
    let root: Value = serde_json::from_str(json).context("item view output is not JSON")?;
    let item = root.get("item").context("item view output has no item")?;
    let data = item
        .get("content")
        .context("item view output has no content")?;
    let content = data
        .get("content")
        .and_then(Value::as_object)
        .context("item view output has no item content")?;
    let (variant, body) = content
        .iter()
        .next()
        .context("item view output has an empty item content")?;
    let kind = match variant.as_str() {
        "Login" => Kind::Login,
        "Note" => Kind::Note,
        "CreditCard" => Kind::CreditCard,
        "Identity" => Kind::Identity,
        _ => return Ok(None),
    };

    let mut record = Record::new(kind);
    record.set("title", text(data, "title"), FieldKind::Text);
    record.set("note", text(data, "note"), FieldKind::Text);
    let mut has_passkeys = false;
    match kind {
        Kind::Login => {
            record.set("username", text(body, "username"), FieldKind::Text);
            record.set("email", text(body, "email"), FieldKind::Text);
            record.set("password", text(body, "password"), FieldKind::Concealed);
            record.set("totp", text(body, "totp_uri"), FieldKind::Totp);
            let urls: Vec<&str> = body
                .get("urls")
                .and_then(Value::as_array)
                .map(|urls| urls.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            record.set_urls(&urls);
            has_passkeys = body
                .get("passkeys")
                .and_then(Value::as_array)
                .is_some_and(|passkeys| !passkeys.is_empty());
        }
        Kind::Note => {}
        Kind::CreditCard => {
            record.set(
                "cardholder_name",
                text(body, "cardholder_name"),
                FieldKind::Text,
            );
            record.set(
                "number",
                normalize_card_number(text(body, "number")),
                FieldKind::Concealed,
            );
            record.set(
                "verification_number",
                text(body, "verification_number"),
                FieldKind::Concealed,
            );
            let expiry = text(body, "expiration_date");
            let expiry = normalize_expiry(expiry).unwrap_or_else(|| expiry.to_string());
            record.set("expiration_date", expiry, FieldKind::Text);
            record.set("pin", text(body, "pin"), FieldKind::Concealed);
        }
        Kind::Identity => {
            for name in IDENTITY_FIELDS {
                record.set(name, text(body, name), identity_field_kind(name));
            }
            for (key, section) in IDENTITY_EXTRA_SECTIONS {
                add_extra_fields(&mut record, body.get(key), Some(section));
            }
            for section in body
                .get("extra_sections")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                add_extra_fields(
                    &mut record,
                    section.get("section_fields"),
                    Some(text(section, "section_name")),
                );
            }
        }
    }
    add_extra_fields(&mut record, data.get("extra_fields"), None);

    Ok(Some(ProtonItem {
        record,
        active: matches!(
            item.get("state").and_then(Value::as_str),
            None | Some("Active")
        ),
        has_passkeys,
        attachments: root
            .get("attachments")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    }))
}

/// The identity's built-in sections of extra fields, and the name each
/// gets as a prefix of its custom fields.
const IDENTITY_EXTRA_SECTIONS: [(&str, &str); 4] = [
    ("extra_personal_details", "Personal details"),
    ("extra_address_details", "Address details"),
    ("extra_contact_details", "Contact details"),
    ("extra_work_details", "Work details"),
];

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Add Proton extra fields (`[{name, content:{Text|Hidden|Totp|Timestamp}}]`)
/// as custom fields, named `<section>/<name>` inside a section.
fn add_extra_fields(record: &mut Record, fields: Option<&Value>, section: Option<&str>) {
    for field in fields.and_then(Value::as_array).into_iter().flatten() {
        let name = text(field, "name");
        let name = match section {
            Some(section) if !section.is_empty() => format!("{section}/{name}"),
            _ => name.to_string(),
        };
        let Some((variant, value)) = field
            .get("content")
            .and_then(Value::as_object)
            .and_then(|content| content.iter().next())
        else {
            continue;
        };
        let (value, kind) = match (variant.as_str(), value) {
            ("Text", Value::String(v)) => (v.clone(), FieldKind::Text),
            ("Hidden", Value::String(v)) => (v.clone(), FieldKind::Concealed),
            ("Totp", Value::String(v)) => (v.clone(), FieldKind::Totp),
            ("Timestamp", Value::Number(n)) => (n.to_string(), FieldKind::Text),
            _ => continue,
        };
        record.add_custom(&name, value, kind);
    }
}

/// The `pass-cli item create <subcommand> --from-template -` input for a
/// record, and the keys of the fields it could not carry.
#[derive(Debug)]
pub struct CreateTemplate {
    pub subcommand: &'static str,
    pub json: SecretString,
    pub missing: Vec<String>,
}

pub fn create_template(record: &Record) -> CreateTemplate {
    let mut template = Map::new();
    let mut carried: Vec<&str> = vec!["title"];
    let put = |template: &mut Map<String, Value>, name: &str, value: &str| {
        if !value.is_empty() {
            template.insert(name.to_string(), Value::String(value.to_string()));
        }
    };
    put(&mut template, "title", record.title());
    let subcommand = match record.kind {
        Kind::Login => {
            for (key, name) in [
                ("username", "username"),
                ("email", "email"),
                ("password", "password"),
                ("totp", "totp_uri"),
            ] {
                put(&mut template, name, record.value(key));
                carried.push(key);
            }
            let urls = record.urls();
            if !urls.is_empty() {
                template.insert("urls".to_string(), json!(urls));
            }
            carried.push("urls");
            "login"
        }
        Kind::Note => {
            put(&mut template, "note", record.value("note"));
            carried.push("note");
            "note"
        }
        Kind::CreditCard => {
            for (key, name) in [
                ("cardholder_name", "cardholder_name"),
                ("number", "number"),
                ("verification_number", "cvv"),
                ("pin", "pin"),
                ("note", "note"),
            ] {
                put(&mut template, name, record.value(key));
                carried.push(key);
            }
            // pass-cli takes only YYYY-MM, in years 2000 to 9999.
            if let Some(expiry) = normalize_expiry(record.value("expiration_date"))
                .filter(|expiry| expiry.as_str() >= "2000")
            {
                template.insert("expiration_date".to_string(), Value::String(expiry));
                carried.push("expiration_date");
            }
            "credit-card"
        }
        Kind::Identity => {
            for name in IDENTITY_FIELDS {
                put(&mut template, name, record.value(name));
                carried.push(name);
            }
            put(&mut template, "note", record.value("note"));
            carried.push("note");
            "identity"
        }
    };
    let missing = record
        .keys()
        .filter(|key| !carried.contains(key))
        .map(str::to_string)
        .collect();
    CreateTemplate {
        subcommand,
        json: SecretString::new(Value::Object(template).to_string()),
        missing,
    }
}

/// Identity fields, by their Proton (and canonical) names. The three
/// document numbers are secrets.
pub const IDENTITY_FIELDS: [&str; 32] = [
    "full_name",
    "email",
    "phone_number",
    "first_name",
    "middle_name",
    "last_name",
    "birthdate",
    "gender",
    "organization",
    "street_address",
    "zip_or_postal_code",
    "city",
    "state_or_province",
    "country_or_region",
    "floor",
    "county",
    "social_security_number",
    "passport_number",
    "license_number",
    "website",
    "x_handle",
    "second_phone_number",
    "linkedin",
    "reddit",
    "facebook",
    "yahoo",
    "instagram",
    "company",
    "job_title",
    "personal_website",
    "work_phone_number",
    "work_email",
];

pub fn identity_field_kind(name: &str) -> FieldKind {
    match name {
        "social_security_number" | "passport_number" | "license_number" => FieldKind::Concealed,
        _ => FieldKind::Text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(content: Value, extra_fields: Value) -> String {
        json!({
            "item": {
                "id": "item-1",
                "share_id": "share-1",
                "vault_id": "vault-1",
                "content": {
                    "title": "Example",
                    "note": "a note",
                    "item_uuid": "uuid",
                    "content": content,
                    "extra_fields": extra_fields,
                    "platform_specific": null,
                    "custom_icon": null
                },
                "state": "Active",
                "flags": [],
                "create_time": "2026-01-01T00:00:00",
                "modify_time": "2026-01-02T00:00:00"
            },
            "attachments": []
        })
        .to_string()
    }

    fn login() -> Value {
        json!({ "Login": {
            "email": "me@example.com",
            "username": "me",
            "password": "s3cret",
            "urls": ["https://example.com", "https://login.example.com"],
            "totp_uri": "otpauth://totp/x?secret=ABC",
            "passkeys": [],
            "autofill_urls": []
        }})
    }

    #[test]
    fn summary_types_map_to_synced_kinds() {
        assert_eq!(kind_of_summary("login"), Some(Kind::Login));
        assert_eq!(kind_of_summary("note"), Some(Kind::Note));
        assert_eq!(kind_of_summary("credit_card"), Some(Kind::CreditCard));
        assert_eq!(kind_of_summary("identity"), Some(Kind::Identity));
        for other in ["alias", "ssh_key", "wifi", "custom", "", "Login"] {
            assert_eq!(kind_of_summary(other), None, "{other}");
        }
    }

    #[test]
    fn a_login_view_maps_every_field() {
        let extras = json!([
            { "name": "API key", "content": { "Hidden": "k-123" } },
            { "name": "Recovery", "content": { "Text": "codes" } },
            { "name": "Backup 2FA", "content": { "Totp": "otpauth://totp/y" } },
            { "name": "Since", "content": { "Timestamp": 1700000000 } }
        ]);
        let item = parse_view(&view(login(), extras)).unwrap().unwrap();
        let r = &item.record;
        assert_eq!(r.kind, Kind::Login);
        assert!(item.active && !item.has_passkeys);
        assert_eq!(r.title(), "Example");
        assert_eq!(r.value("note"), "a note");
        assert_eq!(r.value("username"), "me");
        assert_eq!(r.value("email"), "me@example.com");
        assert_eq!(r.get("password").unwrap().kind, FieldKind::Concealed);
        assert_eq!(r.value("password"), "s3cret");
        assert_eq!(r.get("totp").unwrap().kind, FieldKind::Totp);
        assert_eq!(
            r.urls(),
            ["https://example.com", "https://login.example.com"]
        );
        assert_eq!(r.get("x:API key").unwrap().kind, FieldKind::Concealed);
        assert_eq!(r.value("x:Recovery"), "codes");
        assert_eq!(r.get("x:Backup 2FA").unwrap().kind, FieldKind::Totp);
        assert_eq!(r.value("x:Since"), "1700000000");
    }

    #[test]
    fn notes_cards_and_identities_parse() {
        let note = parse_view(&view(json!({ "Note": null }), json!([])))
            .unwrap()
            .unwrap();
        assert_eq!(note.record.kind, Kind::Note);
        assert_eq!(note.record.value("note"), "a note");

        let card = json!({ "CreditCard": {
            "cardholder_name": "A Person", "card_type": "Visa", "number": "4111111111111111",
            "verification_number": "123", "expiration_date": "2027-12", "pin": "0000"
        }});
        let card = parse_view(&view(card, json!([]))).unwrap().unwrap().record;
        assert_eq!(card.kind, Kind::CreditCard);
        assert_eq!(card.value("cardholder_name"), "A Person");
        assert_eq!(card.get("number").unwrap().kind, FieldKind::Concealed);
        assert_eq!(
            card.get("verification_number").unwrap().kind,
            FieldKind::Concealed
        );
        assert_eq!(card.value("expiration_date"), "2027-12");
        assert_eq!(card.get("pin").unwrap().kind, FieldKind::Concealed);
        assert!(card.get("card_type").is_none());

        let mut identity: Map<String, Value> = IDENTITY_FIELDS
            .iter()
            .map(|name| (name.to_string(), Value::String(String::new())))
            .collect();
        identity.insert("first_name".into(), "Ada".into());
        identity.insert("passport_number".into(), "P123".into());
        identity.insert(
            "extra_personal_details".into(),
            json!([{ "name": "Nickname", "content": { "Text": "Countess" } }]),
        );
        identity.insert(
            "extra_sections".into(),
            json!([{ "section_name": "Travel", "section_fields": [
                { "name": "Frequent flyer", "content": { "Hidden": "FF1" } }
            ]}]),
        );
        for empty in [
            "extra_address_details",
            "extra_contact_details",
            "extra_work_details",
        ] {
            identity.insert(empty.into(), json!([]));
        }
        let identity = parse_view(&view(json!({ "Identity": identity }), json!([])))
            .unwrap()
            .unwrap()
            .record;
        assert_eq!(identity.kind, Kind::Identity);
        assert_eq!(identity.value("first_name"), "Ada");
        assert_eq!(
            identity.get("passport_number").unwrap().kind,
            FieldKind::Concealed
        );
        assert_eq!(identity.value("x:Personal details/Nickname"), "Countess");
        assert_eq!(
            identity.get("x:Travel/Frequent flyer").unwrap().kind,
            FieldKind::Concealed
        );
        assert!(identity.get("last_name").is_none());
    }

    #[test]
    fn unsupported_kinds_are_skipped_and_state_and_passkeys_are_read() {
        let alias = parse_view(&view(json!({ "Alias": null }), json!([]))).unwrap();
        assert!(alias.is_none());

        let mut with_passkey = login();
        with_passkey["Login"]["passkeys"] = json!([{ "key_id": "k" }]);
        let mut json: Value = serde_json::from_str(&view(with_passkey, json!([]))).unwrap();
        json["item"]["state"] = "Trashed".into();
        json["attachments"] = json!([{ "id": "a1" }, { "id": "a2" }]);
        let item = parse_view(&json.to_string()).unwrap().unwrap();
        assert!(!item.active);
        assert!(item.has_passkeys);
        assert_eq!(item.attachments, 2);
    }

    #[test]
    fn unreadable_json_is_an_error_without_its_contents() {
        let err = parse_view("{\"item\": {\"content\": \"s3cret\"}}").unwrap_err();
        assert!(!format!("{err:#}").contains("s3cret"), "{err:#}");
        assert!(parse_view("not json").is_err());
    }

    fn template_value(template: &CreateTemplate) -> Value {
        serde_json::from_str(template.json.expose()).unwrap()
    }

    #[test]
    fn a_login_template_carries_what_pass_cli_accepts_and_reports_the_rest() {
        let mut record = Record::new(Kind::Login);
        record.set("title", "Example", FieldKind::Text);
        record.set("username", "me", FieldKind::Text);
        record.set("email", "me@example.com", FieldKind::Text);
        record.set("password", "s3cret", FieldKind::Concealed);
        record.set("totp", "otpauth://totp/x", FieldKind::Totp);
        record.set_urls(&["https://example.com", "https://b.example.com"]);
        record.set("note", "a note", FieldKind::Text);
        record.add_custom("API key", "k", FieldKind::Concealed);

        let template = create_template(&record);
        assert_eq!(template.subcommand, "login");
        assert_eq!(
            template_value(&template),
            json!({
                "title": "Example", "username": "me", "email": "me@example.com",
                "password": "s3cret", "totp_uri": "otpauth://totp/x",
                "urls": ["https://example.com", "https://b.example.com"]
            })
        );
        assert_eq!(template.missing, ["note", "x:API key"]);
        assert!(!format!("{template:?}").contains("s3cret"));
    }

    #[test]
    fn note_card_and_identity_templates() {
        let mut note = Record::new(Kind::Note);
        note.set("title", "N", FieldKind::Text);
        note.set("note", "body", FieldKind::Text);
        let template = create_template(&note);
        assert_eq!(template.subcommand, "note");
        assert_eq!(
            template_value(&template),
            json!({ "title": "N", "note": "body" })
        );
        assert!(template.missing.is_empty());

        let mut card = Record::new(Kind::CreditCard);
        card.set("title", "C", FieldKind::Text);
        card.set("cardholder_name", "A", FieldKind::Text);
        card.set("number", "4111", FieldKind::Concealed);
        card.set("verification_number", "123", FieldKind::Concealed);
        card.set("expiration_date", "12/2027", FieldKind::Text);
        card.set("pin", "0000", FieldKind::Concealed);
        card.set("note", "n", FieldKind::Text);
        let template = create_template(&card);
        assert_eq!(template.subcommand, "credit-card");
        assert_eq!(
            template_value(&template),
            json!({
                "title": "C", "cardholder_name": "A", "number": "4111", "cvv": "123",
                "expiration_date": "2027-12", "pin": "0000", "note": "n"
            })
        );
        assert!(template.missing.is_empty());

        card.set("expiration_date", "someday", FieldKind::Text);
        let template = create_template(&card);
        assert!(template_value(&template).get("expiration_date").is_none());
        assert_eq!(template.missing, ["expiration_date"]);

        let mut identity = Record::new(Kind::Identity);
        identity.set("title", "Me", FieldKind::Text);
        identity.set("first_name", "Ada", FieldKind::Text);
        identity.set("passport_number", "P1", FieldKind::Concealed);
        identity.add_custom("Travel/Frequent flyer", "FF", FieldKind::Concealed);
        let template = create_template(&identity);
        assert_eq!(template.subcommand, "identity");
        assert_eq!(
            template_value(&template),
            json!({ "title": "Me", "first_name": "Ada", "passport_number": "P1" })
        );
        assert_eq!(template.missing, ["x:Travel/Frequent flyer"]);
    }

    #[test]
    fn a_parsed_item_round_trips_through_its_template_fields() {
        // What a template carries reads back the same after pass-cli
        // creates the item.
        let item = parse_view(&view(login(), json!([]))).unwrap().unwrap();
        let template = create_template(&item.record);
        let created = template_value(&template);
        let mut content = login();
        for (key, value) in created.as_object().unwrap() {
            if key == "totp_uri"
                || key == "urls"
                || key == "username"
                || key == "email"
                || key == "password"
            {
                content["Login"][key] = value.clone();
            }
        }
        let mut reread = parse_view(&view(content, json!([])))
            .unwrap()
            .unwrap()
            .record;
        reread.set("note", "a note", FieldKind::Text);
        assert_eq!(reread, item.record);
    }

    #[test]
    fn a_formatted_card_number_reads_as_its_digits() {
        let card = json!({ "CreditCard": {
            "cardholder_name": "", "card_type": "Unspecified", "number": "4111 1111 1111 1111",
            "verification_number": "", "expiration_date": "", "pin": ""
        }});
        let card = parse_view(&view(card, json!([]))).unwrap().unwrap().record;
        assert_eq!(card.value("number"), "4111111111111111");
    }

    #[test]
    fn an_expiry_pass_cli_would_refuse_is_reported_missing() {
        let mut card = Record::new(Kind::CreditCard);
        card.set("title", "C", FieldKind::Text);
        card.set("expiration_date", "1999-12", FieldKind::Text);
        let template = create_template(&card);
        assert!(template_value(&template).get("expiration_date").is_none());
        assert_eq!(template.missing, ["expiration_date"]);

        card.set("expiration_date", "2100-01", FieldKind::Text);
        let template = create_template(&card);
        assert_eq!(template_value(&template)["expiration_date"], "2100-01");
        assert!(template.missing.is_empty());
    }
}
