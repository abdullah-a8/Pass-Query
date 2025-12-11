use serde::{Deserialize, Serialize};

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
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ItemList {
    pub items: Vec<Item>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Item {
    pub content: ItemContent,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ItemContent {
    pub title: String,
    // Don't serialize 'content' - keeps passwords out of cache!
    #[serde(default)]
    #[serde(skip_serializing)]  // ← Never write passwords to cache
    pub content: Option<serde_json::Value>,
}

// Helper to extract password from any item type (only in memory, never cached)
impl ItemContent {
    pub fn get_password(&self) -> Option<String> {
        let content = self.content.as_ref()?;
        
        // Try to extract password from Login type
        if let Some(login) = content.get("Login")
            && let Some(password) = login.get("password")
        {
            return password.as_str().map(|s| s.to_string());
        }
        
        // Could add other item types here (CreditCard, etc.)
        
        None
    }
}

// Separate Serialize implementation to exclude passwords from cache
impl serde::Serialize for ItemContent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ItemContent", 1)?;
        state.serialize_field("title", &self.title)?;
        // Deliberately skip 'content' field - no passwords in cache!
        state.end()
    }
}

/// Internal search result
#[derive(Debug, Clone)]
pub struct Match {
    pub title: String,
    pub vault_name: String,
    pub password: Option<String>,
}
