//! In-memory Proton and 1Password for the engine's tests: each keeps items
//! the way its service does (Proton as records with a modify time,
//! 1Password as raw item JSON with a version), so the engine runs against
//! the same shapes it meets through the CLIs.

#![cfg(test)]

use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::api::{OpApi, OpSummary, ProtonApi, ProtonSummary, Vault};
use super::onepassword::OpProblem;
use super::op_json::{self, OpItem, RawItem};
use super::proton_json::{CreateTemplate, IDENTITY_FIELDS, ProtonItem, identity_field_kind};
use super::record::{FieldKind, Kind, Record};
use super::secret::SecretString;

pub struct ProtonItemState {
    pub record: Record,
    pub modified: u64,
    pub active: bool,
}

#[derive(Default)]
pub struct MemoryProton {
    pub vaults: Vec<Vault>,
    pub items: BTreeMap<(String, String), ProtonItemState>,
    clock: u64,
    next_id: usize,
    pub views: usize,
    pub writes: Vec<String>,
}

impl MemoryProton {
    pub fn vault(&mut self, id: &str, name: &str) -> &mut Self {
        self.vaults.push(Vault {
            id: id.into(),
            name: name.into(),
        });
        self
    }

    pub fn add(&mut self, share: &str, record: Record) -> String {
        self.next_id += 1;
        self.clock += 1;
        let id = format!("p{}", self.next_id);
        self.items.insert(
            (share.into(), id.clone()),
            ProtonItemState {
                record,
                modified: self.clock,
                active: true,
            },
        );
        id
    }

    /// The owner edits an item in Proton.
    pub fn edit(&mut self, share: &str, id: &str, change: impl FnOnce(&mut Record)) {
        self.clock += 1;
        let item = self.items.get_mut(&(share.into(), id.into())).unwrap();
        change(&mut item.record);
        item.modified = self.clock;
    }

    pub fn trash_item(&mut self, share: &str, id: &str) {
        self.clock += 1;
        let item = self.items.get_mut(&(share.into(), id.into())).unwrap();
        item.active = false;
        item.modified = self.clock;
    }

    /// The owner moves an item to another vault (its ID changes).
    pub fn move_by_owner(&mut self, from: &str, id: &str, to: &str) -> String {
        let item = self.items.remove(&(from.into(), id.into())).unwrap();
        self.add(to, item.record)
    }

    pub fn record(&self, share: &str, id: &str) -> &Record {
        &self.items[&(share.to_string(), id.to_string())].record
    }

    pub fn active_in(&self, share: &str) -> Vec<(&String, &ProtonItemState)> {
        self.items
            .iter()
            .filter(|((s, _), item)| s == share && item.active)
            .map(|((_, id), item)| (id, item))
            .collect()
    }
}

/// What pass-cli makes of a create template.
fn record_from_template(template: &CreateTemplate) -> Record {
    let json: Value = serde_json::from_str(template.json.expose()).unwrap();
    let text = |key: &str| {
        json.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let kind = match template.subcommand {
        "login" => Kind::Login,
        "note" => Kind::Note,
        "credit-card" => Kind::CreditCard,
        "identity" => Kind::Identity,
        other => panic!("unexpected subcommand {other}"),
    };
    let mut record = Record::new(kind);
    record.set("title", text("title"), FieldKind::Text);
    match kind {
        Kind::Login => {
            record.set("username", text("username"), FieldKind::Text);
            record.set("email", text("email"), FieldKind::Text);
            record.set("password", text("password"), FieldKind::Concealed);
            record.set("totp", text("totp_uri"), FieldKind::Totp);
            let urls: Vec<String> = json
                .get("urls")
                .and_then(Value::as_array)
                .map(|urls| {
                    urls.iter()
                        .filter_map(|u| u.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            record.set_urls(&urls);
        }
        Kind::Note => record.set("note", text("note"), FieldKind::Text),
        Kind::CreditCard => {
            record.set("cardholder_name", text("cardholder_name"), FieldKind::Text);
            record.set("number", text("number"), FieldKind::Concealed);
            record.set("verification_number", text("cvv"), FieldKind::Concealed);
            record.set("expiration_date", text("expiration_date"), FieldKind::Text);
            record.set("pin", text("pin"), FieldKind::Concealed);
            record.set("note", text("note"), FieldKind::Text);
        }
        Kind::Identity => {
            for name in IDENTITY_FIELDS {
                record.set(name, text(name), identity_field_kind(name));
            }
            record.set("note", text("note"), FieldKind::Text);
        }
    }
    record
}

impl ProtonApi for MemoryProton {
    fn vaults(&mut self) -> Result<Vec<Vault>> {
        Ok(self.vaults.clone())
    }

    fn items(&mut self, share: &str) -> Result<Vec<ProtonSummary>> {
        Ok(self
            .items
            .iter()
            .filter(|((s, _), _)| s == share)
            .map(|((_, id), item)| ProtonSummary {
                id: id.clone(),
                title: item.record.title().to_string(),
                kind: Some(item.record.kind),
                modified: format!("t{}", item.modified),
                active: item.active,
            })
            .collect())
    }

    fn view(&mut self, share: &str, item: &str) -> Result<Option<ProtonItem>> {
        self.views += 1;
        Ok(self
            .items
            .get(&(share.to_string(), item.to_string()))
            .map(|state| ProtonItem {
                record: state.record.clone(),
                active: state.active,
                has_passkeys: false,
                attachments: 0,
            }))
    }

    fn create(&mut self, share: &str, template: &CreateTemplate) -> Result<String> {
        self.writes.push(format!("create {share}"));
        Ok(self.add(share, record_from_template(template)))
    }

    fn trash(&mut self, share: &str, item: &str) -> Result<()> {
        self.writes.push(format!("trash {share}/{item}"));
        if self
            .items
            .contains_key(&(share.to_string(), item.to_string()))
        {
            self.trash_item(share, item);
        }
        Ok(())
    }

    fn move_item(&mut self, from: &str, item: &str, to: &str) -> Result<String> {
        self.writes.push(format!("move {from}/{item} {to}"));
        Ok(self.move_by_owner(from, item, to))
    }
}

#[derive(Default)]
pub struct MemoryOp {
    pub vaults: Vec<Vault>,
    pub items: BTreeMap<(String, String), Value>,
    pub archived: Vec<(String, String)>,
    next_id: usize,
    requests: usize,
    pub gets: usize,
    pub writes: Vec<String>,
    /// Store URLs lowercased, as a service might normalise them.
    pub lowercase_urls: bool,
    /// Answer with a rate limit once this many requests were made.
    pub rate_limit_at: Option<usize>,
}

impl MemoryOp {
    pub fn vault(&mut self, id: &str, name: &str) -> &mut Self {
        self.vaults.push(Vault {
            id: id.into(),
            name: name.into(),
        });
        self
    }

    fn count(&mut self, weight: usize) -> Result<()> {
        if let Some(limit) = self.rate_limit_at
            && self.requests >= limit
        {
            return Err(anyhow::Error::new(OpProblem::RateLimited));
        }
        self.requests += weight;
        Ok(())
    }

    fn store(&mut self, vault: &str, id: &str, mut raw: Value, version: u64) -> OpItem {
        raw["id"] = id.into();
        raw["version"] = version.into();
        raw["vault"] = json!({ "id": vault });
        if self.lowercase_urls
            && let Some(urls) = raw.get_mut("urls").and_then(Value::as_array_mut)
        {
            for url in urls {
                let lower = url["href"].as_str().unwrap_or("").to_lowercase();
                url["href"] = lower.into();
            }
        }
        self.items.insert((vault.into(), id.into()), raw.clone());
        op_json::parse_item(&raw.to_string()).unwrap().unwrap()
    }

    /// An item created in the 1Password app.
    pub fn add_native(&mut self, vault: &str, record: &Record) -> String {
        self.next_id += 1;
        let id = format!("o{}", self.next_id);
        let mut raw: Value =
            serde_json::from_str(op_json::create_json(record, "x").expose()).unwrap();
        // The app knows nothing of Proton: no reference.
        if let Some(fields) = raw["fields"].as_array_mut() {
            fields.retain(|f| f["id"] != op_json::REF_FIELD_ID);
        }
        self.store(vault, &id, raw, 1);
        id
    }

    /// The owner edits an item in the 1Password app.
    pub fn edit_by_owner(&mut self, vault: &str, id: &str, change: impl FnOnce(&mut Record)) {
        let raw = self.items[&(vault.to_string(), id.to_string())].clone();
        let item = op_json::parse_item(&raw.to_string()).unwrap().unwrap();
        let mut record = item.record.clone();
        change(&mut record);
        let keys = record
            .keys()
            .chain(item.record.keys())
            .map(String::from)
            .collect();
        let mut raw = item.raw;
        op_json::apply_edit(&mut raw, &record, &keys).unwrap();
        let version = raw.0["version"].as_u64().unwrap() + 1;
        self.store(vault, id, raw.0, version);
    }

    /// A passkey saved in the app: the version moves, nothing visible does.
    pub fn add_passkey(&mut self, vault: &str, id: &str) {
        let item = self
            .items
            .get_mut(&(vault.to_string(), id.to_string()))
            .unwrap();
        let version = item["version"].as_u64().unwrap() + 1;
        item["version"] = version.into();
    }

    pub fn archive_by_owner(&mut self, vault: &str, id: &str) {
        self.items.remove(&(vault.to_string(), id.to_string()));
        self.archived.push((vault.into(), id.into()));
    }

    pub fn record(&self, vault: &str, id: &str) -> Record {
        let raw = &self.items[&(vault.to_string(), id.to_string())];
        op_json::parse_item(&raw.to_string())
            .unwrap()
            .unwrap()
            .record
    }

    pub fn in_vault(&self, vault: &str) -> Vec<String> {
        self.items
            .keys()
            .filter(|(v, _)| v == vault)
            .map(|(_, id)| id.clone())
            .collect()
    }
}

impl OpApi for MemoryOp {
    fn vaults(&mut self) -> Result<Vec<Vault>> {
        self.count(1)?;
        Ok(self.vaults.clone())
    }

    fn items(&mut self, vault: &str) -> Result<Vec<OpSummary>> {
        self.count(1)?;
        Ok(self
            .items
            .iter()
            .filter(|((v, _), _)| v == vault)
            .map(|((_, id), raw)| OpSummary {
                id: id.clone(),
                title: raw["title"].as_str().unwrap_or("").to_string(),
                kind: op_json::kind_of_category(raw["category"].as_str().unwrap_or("")),
                version: raw["version"].as_u64().unwrap_or(0),
            })
            .collect())
    }

    fn get(&mut self, vault: &str, item: &str) -> Result<Option<OpItem>> {
        self.count(1)?;
        self.gets += 1;
        Ok(self
            .items
            .get(&(vault.to_string(), item.to_string()))
            .map(|raw| op_json::parse_item(&raw.to_string()).unwrap().unwrap()))
    }

    fn create(&mut self, vault: &str, json: &SecretString) -> Result<OpItem> {
        self.count(2)?;
        self.writes.push(format!("create {vault}"));
        self.next_id += 1;
        let id = format!("o{}", self.next_id);
        let raw: Value = serde_json::from_str(json.expose()).unwrap();
        Ok(self.store(vault, &id, raw, 1))
    }

    fn edit(&mut self, vault: &str, item: &str, raw: &RawItem) -> Result<OpItem> {
        self.count(2)?;
        self.writes.push(format!("edit {vault}/{item}"));
        let Some(current) = self.items.get(&(vault.to_string(), item.to_string())) else {
            bail!("no such item");
        };
        let version = current["version"].as_u64().unwrap() + 1;
        Ok(self.store(vault, item, raw.0.clone(), version))
    }

    fn archive(&mut self, vault: &str, item: &str) -> Result<()> {
        self.count(2)?;
        self.writes.push(format!("archive {vault}/{item}"));
        if self
            .items
            .remove(&(vault.to_string(), item.to_string()))
            .is_some()
        {
            self.archived.push((vault.into(), item.into()));
        }
        Ok(())
    }

    fn move_item(&mut self, item: &str, from: &str, to: &str) -> Result<String> {
        self.count(3)?;
        self.writes.push(format!("move {from}/{item} {to}"));
        let raw = self
            .items
            .remove(&(from.to_string(), item.to_string()))
            .unwrap();
        self.next_id += 1;
        let id = format!("o{}", self.next_id);
        let version = raw["version"].as_u64().unwrap();
        self.store(to, &id, raw, version);
        Ok(id)
    }

    fn create_vault(&mut self, name: &str) -> Result<Vault> {
        self.count(1)?;
        let vault = Vault {
            id: format!("ov{}", self.vaults.len() + 1),
            name: name.into(),
        };
        self.vaults.push(vault.clone());
        Ok(vault)
    }

    fn requests(&self) -> usize {
        self.requests
    }
}
