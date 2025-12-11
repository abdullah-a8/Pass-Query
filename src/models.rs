use serde::Deserialize;

/// Vault list response from `pass-cli vault list --output json`
#[derive(Debug, Deserialize)]
pub struct VaultList {
    pub vaults: Vec<Vault>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Vault {
    pub name: String,
    #[allow(dead_code)]
    pub vault_id: String,
    #[allow(dead_code)]
    pub share_id: String,
}

/// Item list response from `pass-cli item list <vault> --output json`
#[derive(Debug, Deserialize)]
pub struct ItemList {
    pub items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
pub struct Item {
    pub content: ItemContent,
}

#[derive(Debug, Deserialize)]
pub struct ItemContent {
    pub title: String,
}

/// Internal search result
#[derive(Debug, Clone)]
pub struct Match {
    pub title: String,
    pub vault_name: String,
}
