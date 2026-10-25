//! The canonical form of a synced item, the same whichever side it was read
//! from: a kind and a map of named fields. Field names are Proton's
//! (`username`, `password`, `totp`, `number`, ...); custom fields are
//! `x:<name>`. An empty value is the same as an absent field.
//!
//! A record holds secrets. Its `Debug` shows field names only, and its
//! values never reach the state file: only keyed hashes of them do.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;

/// The item kinds pq-sync carries between Proton Pass and 1Password.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Login,
    Note,
    CreditCard,
    Identity,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Note => "note",
            Kind::CreditCard => "credit card",
            Kind::Identity => "identity",
        }
    }
}

/// How a field's value is meant to be shown and stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldKind {
    /// Plain text.
    Text,
    /// A secret: stored concealed in 1Password, hidden in Proton.
    Concealed,
    /// An `otpauth://` URI (or bare TOTP secret).
    Totp,
    /// A list of URLs, one per line, in order.
    Urls,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Field {
    pub value: String,
    pub kind: FieldKind,
}

// Written by hand: the value may be a password.
impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("value", &"[REDACTED]")
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: Kind,
    fields: BTreeMap<String, Field>,
}

// Written by hand: field values are secrets; their names are not.
impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("kind", &self.kind)
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The prefix of custom field keys.
pub const CUSTOM_PREFIX: &str = "x:";

impl Record {
    pub fn new(kind: Kind) -> Self {
        Record {
            kind,
            fields: BTreeMap::new(),
        }
    }

    /// Set `key` to `value`; an empty value removes the field.
    pub fn set(&mut self, key: &str, value: impl Into<String>, kind: FieldKind) {
        let value = value.into();
        if key == "urls" {
            // One URL per line, whatever the value's line breaks.
            return self.set_urls(&value.split(['\r', '\n']).collect::<Vec<_>>());
        }
        if value.is_empty() {
            self.fields.remove(key);
        } else {
            self.fields.insert(key.to_string(), Field { value, kind });
        }
    }

    /// Set the URL list: split at line breaks, empty entries dropped, each
    /// URL once (where it first appears), order kept. So a URL list never
    /// holds a line break or a URL twice, and neither is ever written.
    pub fn set_urls<S: AsRef<str>>(&mut self, urls: &[S]) {
        let mut seen = std::collections::BTreeSet::new();
        let joined = urls
            .iter()
            .flat_map(|url| url.as_ref().split(['\r', '\n']))
            .map(str::trim)
            .filter(|url| !url.is_empty() && seen.insert(*url))
            .collect::<Vec<_>>()
            .join("\n");
        if joined.is_empty() {
            self.fields.remove("urls");
        } else {
            self.fields.insert(
                "urls".to_string(),
                Field {
                    value: joined,
                    kind: FieldKind::Urls,
                },
            );
        }
    }

    /// Add a custom field named `name` and return the key it got. A name
    /// already taken gets " #2", " #3", ... so no value is lost. An empty
    /// value adds nothing.
    pub fn add_custom(
        &mut self,
        name: &str,
        value: impl Into<String>,
        kind: FieldKind,
    ) -> Option<String> {
        let value = value.into();
        if value.is_empty() {
            return None;
        }
        let name = name.trim();
        let base = format!("{CUSTOM_PREFIX}{name}");
        let mut key = base.clone();
        let mut n = 2;
        while self.fields.contains_key(&key) {
            // An unnamed field's numbered name is "#2", with no leading space
            // a reader would trim.
            key = if name.is_empty() {
                format!("{base}#{n}")
            } else {
                format!("{base} #{n}")
            };
            n += 1;
        }
        self.fields.insert(key.clone(), Field { value, kind });
        Some(key)
    }

    pub fn get(&self, key: &str) -> Option<&Field> {
        self.fields.get(key)
    }

    /// The value of `key`, or "" when absent.
    pub fn value(&self, key: &str) -> &str {
        self.fields
            .get(key)
            .map_or("", |field| field.value.as_str())
    }

    pub fn urls(&self) -> Vec<&str> {
        let urls = self.value("urls");
        if urls.is_empty() {
            Vec::new()
        } else {
            urls.split('\n').collect()
        }
    }

    pub fn title(&self) -> &str {
        self.value("title")
    }

    pub fn fields(&self) -> impl Iterator<Item = (&str, &Field)> {
        self.fields.iter().map(|(key, field)| (key.as_str(), field))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }

    /// Custom fields: (name without the prefix, field).
    pub fn custom(&self) -> impl Iterator<Item = (&str, &Field)> {
        self.fields()
            .filter_map(|(key, field)| Some((key.strip_prefix(CUSTOM_PREFIX)?, field)))
    }

    /// A keyed hash of each field, for the state file: equal values give
    /// equal hashes under the same key, and the hashes say nothing about the
    /// values without it.
    pub fn field_hashes(&self, key: &[u8]) -> BTreeMap<String, FieldHash> {
        self.fields
            .iter()
            .map(|(name, field)| (name.clone(), field_hash(key, name, field)))
            .collect()
    }
}

/// HMAC-SHA256 of one field, as lowercase hex.
pub type FieldHash = String;

/// The hash of `field` stored under `name`. The kind is part of the input,
/// so a text field turned concealed counts as a change; the name and value
/// are length-prefixed, so no two (name, value) pairs share an input.
pub fn field_hash(key: &[u8], name: &str, field: &Field) -> FieldHash {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(b"pq-sync field v2\0");
    mac.update(&(name.len() as u64).to_be_bytes());
    mac.update(name.as_bytes());
    mac.update(&[kind_byte(field.kind)]);
    mac.update(&(field.value.len() as u64).to_be_bytes());
    mac.update(field.value.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// A keyed hash of arbitrary bytes under a domain label (for whole-item
/// fingerprints and the key check).
pub fn keyed_hash(key: &[u8], label: &str, data: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(b"pq-sync ");
    mac.update(label.as_bytes());
    mac.update(&[0]);
    mac.update(data);
    hex(&mac.finalize().into_bytes())
}

fn kind_byte(kind: FieldKind) -> u8 {
    match kind {
        FieldKind::Text => 1,
        FieldKind::Concealed => 2,
        FieldKind::Totp => 3,
        FieldKind::Urls => 4,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A credit card expiry as `YYYY-MM`, from the forms the two services use:
/// `2027-12`, `2027/12`, `202712`, `12/2027`, `122027`. `None` for anything
/// else, including dates and two-digit years: only an exact month of a
/// four-digit year is read as one.
pub fn normalize_expiry(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.is_ascii() {
        return None;
    }
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let year_month = |year: &str, month: &str| -> Option<String> {
        let valid_year = year.len() == 4 && digits(year) && !year.starts_with('0');
        let valid_month =
            month.len() == 2 && digits(month) && (1..=12).contains(&month.parse::<u32>().ok()?);
        (valid_year && valid_month).then(|| format!("{year}-{month}"))
    };
    let bytes = value.as_bytes();
    let separator = |at: usize| matches!(bytes.get(at), Some(b'-' | b'/'));
    match value.len() {
        7 if separator(4) => year_month(&value[..4], &value[5..]),
        7 if separator(2) => year_month(&value[3..], &value[..2]),
        6 if digits(value) => {
            year_month(&value[..4], &value[4..]).or_else(|| year_month(&value[2..], &value[..2]))
        }
        _ => None,
    }
}

/// A card number as its digits, when it is digits with spaces or dashes
/// (pass-cli keeps only the digits); anything else as it is.
pub fn normalize_card_number(value: &str) -> String {
    let formatted = value.chars().any(|c| c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || c == ' ' || c == '-');
    if formatted {
        value.chars().filter(char::is_ascii_digit).collect()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn empty_values_are_absent() {
        let mut record = Record::new(Kind::Login);
        record.set("username", "", FieldKind::Text);
        record.set("password", "pw", FieldKind::Concealed);
        record.set("password", "", FieldKind::Concealed);
        assert_eq!(record.keys().count(), 0);
        assert_eq!(record, Record::new(Kind::Login));
    }

    #[test]
    fn urls_keep_order_and_drop_blanks() {
        let mut record = Record::new(Kind::Login);
        record.set_urls(&[
            "https://b.example",
            " ",
            "https://a.example ",
            "https://b.example",
        ]);
        assert_eq!(record.urls(), ["https://b.example", "https://a.example"]);
        record.set_urls::<&str>(&[]);
        assert!(record.get("urls").is_none());
    }

    #[test]
    fn duplicate_custom_names_are_numbered() {
        let mut record = Record::new(Kind::Note);
        record.add_custom("API key", "one", FieldKind::Concealed);
        record.add_custom("API key", "two", FieldKind::Concealed);
        record.add_custom("empty", "", FieldKind::Text);
        let names: Vec<_> = record.custom().map(|(name, _)| name).collect();
        assert_eq!(names, ["API key", "API key #2"]);
    }

    #[test]
    fn debug_never_shows_values() {
        let mut record = Record::new(Kind::Login);
        record.set("password", "hunter2-secret", FieldKind::Concealed);
        record.set("username", "alice@example.com", FieldKind::Text);
        let shown = format!("{record:?} {:?}", record.get("password"));
        assert!(!shown.contains("hunter2-secret"), "{shown}");
        assert!(!shown.contains("alice@example.com"), "{shown}");
        assert!(shown.contains("password"), "{shown}");
    }

    #[test]
    fn field_hashes_depend_on_key_name_kind_and_value() {
        let field = Field {
            value: "pw".to_string(),
            kind: FieldKind::Concealed,
        };
        let base = field_hash(KEY, "password", &field);
        assert_eq!(base.len(), 64);
        assert_eq!(base, field_hash(KEY, "password", &field));
        assert_ne!(base, field_hash(b"another key", "password", &field));
        assert_ne!(base, field_hash(KEY, "pin", &field));
        let text = Field {
            kind: FieldKind::Text,
            ..field.clone()
        };
        assert_ne!(base, field_hash(KEY, "password", &text));
        let other = Field {
            value: "pw2".to_string(),
            ..field
        };
        assert_ne!(base, field_hash(KEY, "password", &other));
        assert!(!base.contains("pw"));
    }

    #[test]
    fn expiry_forms_normalize_to_year_month() {
        for form in [
            "2027-12",
            "2027/12",
            "202712",
            "12/2027",
            "122027",
            " 2027-12 ",
        ] {
            assert_eq!(normalize_expiry(form).as_deref(), Some("2027-12"), "{form}");
        }
        // Any four-digit year: whether a service takes it is its business.
        assert_eq!(normalize_expiry("2100-01").as_deref(), Some("2100-01"));
        assert_eq!(normalize_expiry("1999-12").as_deref(), Some("1999-12"));
        for bad in [
            "",
            "2027",
            "2027-13",
            "13/2027",
            "2027-00",
            "abc",
            "2027-1",
            "2027-1-2",
            "2027/1/2",
            "20-27-12",
            "2027--12",
            "2027-12-01",
            "12/27",
        ] {
            assert_eq!(normalize_expiry(bad), None, "{bad}");
        }
    }

    #[test]
    fn field_hashes_do_not_collide_across_name_and_value() {
        let field = |value: &str| Field {
            value: value.to_string(),
            kind: FieldKind::Concealed,
        };
        assert_ne!(
            field_hash(KEY, "x:a", &field("b\0\u{2}c")),
            field_hash(KEY, "x:a\0\u{2}b", &field("c"))
        );
    }

    #[test]
    fn card_numbers_are_kept_as_digits() {
        assert_eq!(
            normalize_card_number("4111 1111-1111 1111"),
            "4111111111111111"
        );
        assert_eq!(
            normalize_card_number("4111111111111111"),
            "4111111111111111"
        );
        // Anything else is not a formatted number: kept as it is.
        assert_eq!(normalize_card_number("ask the bank"), "ask the bank");
    }

    #[test]
    fn add_custom_returns_the_key_it_used() {
        let mut record = Record::new(Kind::Note);
        assert_eq!(
            record.add_custom(" dup ", "a", FieldKind::Text).as_deref(),
            Some("x:dup")
        );
        assert_eq!(
            record.add_custom("dup", "b", FieldKind::Text).as_deref(),
            Some("x:dup #2")
        );
        assert_eq!(record.add_custom("dup", "", FieldKind::Text), None);
        assert_eq!(
            record.add_custom("", "c", FieldKind::Text).as_deref(),
            Some("x:")
        );
    }

    #[test]
    fn a_url_list_never_holds_a_line_break_or_a_url_twice() {
        let mut record = Record::new(Kind::Login);
        record.set_urls(&[
            "https://a.example\rhttps://b.example",
            "https://c.example\r\n",
            "https://a.example",
        ]);
        assert_eq!(
            record.urls(),
            [
                "https://a.example",
                "https://b.example",
                "https://c.example"
            ]
        );
        // Set as a plain field, the same rules hold.
        record.set(
            "urls",
            "https://x.example\r\nhttps://x.example",
            FieldKind::Urls,
        );
        assert_eq!(record.urls(), ["https://x.example"]);
        assert!(record.value("urls").chars().all(|c| c != '\r'));
    }
}
