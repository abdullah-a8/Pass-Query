//! The canonical form of a synced item, the same whichever side it was read
//! from: a kind and a map of named fields. Field names are Proton's
//! (`username`, `password`, `totp`, `number`, ...); custom fields are
//! `x:<name>`. An empty value is the same as an absent field.
//!
//! A record holds secrets. Its `Debug` shows field names only, and its
//! values never reach the state file: only keyed hashes of them do.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;

/// The item kinds pq-sync carries between Proton Pass and 1Password.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        if value.is_empty() {
            self.fields.remove(key);
        } else {
            self.fields.insert(key.to_string(), Field { value, kind });
        }
    }

    /// Set the URL list (empty entries dropped, order kept).
    pub fn set_urls<S: AsRef<str>>(&mut self, urls: &[S]) {
        let joined = urls
            .iter()
            .map(|url| url.as_ref().trim())
            .filter(|url| !url.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        self.set("urls", joined, FieldKind::Urls);
    }

    /// Add a custom field named `name`. A name already taken gets " #2",
    /// " #3", ... so no value is lost.
    pub fn add_custom(&mut self, name: &str, value: impl Into<String>, kind: FieldKind) {
        let value = value.into();
        if value.is_empty() {
            return;
        }
        let name = name.trim();
        let base = format!("{CUSTOM_PREFIX}{name}");
        let mut key = base.clone();
        let mut n = 2;
        while self.fields.contains_key(&key) {
            key = format!("{base} #{n}");
            n += 1;
        }
        self.fields.insert(key, Field { value, kind });
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
/// so a text field turned concealed counts as a change.
pub fn field_hash(key: &[u8], name: &str, field: &Field) -> FieldHash {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(b"pq-sync field v1\0");
    mac.update(name.as_bytes());
    mac.update(&[0, kind_byte(field.kind)]);
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

/// A credit card expiry as `YYYY-MM`, from the forms the two services use
/// (`2027-12`, `2027/12`, `202712`, `12/2027`, `122027`). `None` when it is
/// not a month of a year.
pub fn normalize_expiry(value: &str) -> Option<String> {
    let value = value.trim();
    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 6
        || !value
            .chars()
            .all(|c| c.is_ascii_digit() || "-/ .".contains(c))
    {
        return None;
    }
    let year_month = |year: &str, month: &str| {
        let month_number: u32 = month.parse().ok()?;
        ((year.starts_with("19") || year.starts_with("20")) && (1..=12).contains(&month_number))
            .then(|| format!("{year}-{month}"))
    };
    // A separator says which part is the year; six bare digits are read
    // year-first, then month-first.
    match value.find(|c: char| !c.is_ascii_digit()) {
        Some(4) => year_month(&digits[..4], &digits[4..]),
        Some(2) => year_month(&digits[2..], &digits[..2]),
        Some(_) => None,
        None => year_month(&digits[..4], &digits[4..])
            .or_else(|| year_month(&digits[2..], &digits[..2])),
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
        record.set_urls(&["https://b.example", " ", "https://a.example "]);
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
        for bad in ["", "2027", "2027-13", "13/2027", "2027-00", "abc", "2027-1"] {
            assert_eq!(normalize_expiry(bad), None, "{bad}");
        }
    }
}
