//! What the sync engine needs from each side, as traits: the engine is
//! tested against in-memory implementations, and runs against the
//! `pass-cli` and `op` adapters.

use anyhow::Result;

use super::op_json::{OpItem, RawItem};
use super::proton_json::{CreateTemplate, ProtonItem};
use super::record::Kind;
use super::secret::SecretString;

/// A vault: a Proton share (`id` is its share ID) or a 1Password vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub id: String,
    pub name: String,
}

/// A Proton item as `item list` shows it: no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtonSummary {
    pub id: String,
    pub title: String,
    /// `None` for kinds pq-sync does not carry.
    pub kind: Option<Kind>,
    pub modified: String,
    pub active: bool,
}

/// A 1Password item as `op item list` shows it: no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpSummary {
    pub id: String,
    pub title: String,
    pub kind: Option<Kind>,
    pub version: u64,
}

pub trait ProtonApi {
    fn vaults(&mut self) -> Result<Vec<Vault>>;
    /// Every item in the vault, trashed ones included (with `active` false).
    fn items(&mut self, share: &str) -> Result<Vec<ProtonSummary>>;
    /// The item with its secrets; `None` when it is gone or of a kind
    /// pq-sync does not carry.
    fn view(&mut self, share: &str, item: &str) -> Result<Option<ProtonItem>>;
    /// Create an item; returns its ID.
    fn create(&mut self, share: &str, template: &CreateTemplate) -> Result<String>;
    /// Move an item to the trash (reversible). An item already gone is not
    /// an error.
    fn trash(&mut self, share: &str, item: &str) -> Result<()>;
    /// Move an item to another vault; returns its new ID.
    fn move_item(&mut self, from: &str, item: &str, to: &str) -> Result<String>;
}

pub trait OpApi {
    fn vaults(&mut self) -> Result<Vec<Vault>>;
    /// Every item in the vault that is not archived or deleted.
    fn items(&mut self, vault: &str) -> Result<Vec<OpSummary>>;
    /// The item with its secrets; `None` when it is gone or of a category
    /// pq-sync does not carry.
    fn get(&mut self, vault: &str, item: &str) -> Result<Option<OpItem>>;
    fn create(&mut self, vault: &str, json: &SecretString) -> Result<OpItem>;
    /// Replace the item with `raw` (a template edit).
    fn edit(&mut self, vault: &str, item: &str, raw: &RawItem) -> Result<OpItem>;
    /// Move an item to the Archive (reversible). An item already gone is
    /// not an error.
    fn archive(&mut self, vault: &str, item: &str) -> Result<()>;
    /// Move an item to another vault; returns its new ID.
    fn move_item(&mut self, item: &str, from: &str, to: &str) -> Result<String>;
    fn create_vault(&mut self, name: &str) -> Result<Vault>;
    /// Requests sent to 1Password so far (an estimate: one command may
    /// make several).
    fn requests(&self) -> usize;
}
