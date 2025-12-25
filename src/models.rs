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
    // Cache username separately (safe to cache, unlike passwords)
    #[serde(default)]
    pub cached_username: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ItemContent {
    pub title: String,
    // Don't serialize 'content' - keeps passwords out of cache!
    #[serde(default)]
    #[serde(skip_serializing)]  // ← Never write passwords to cache
    pub content: Option<serde_json::Value>,
}

// Helper to extract fields from any item type (only in memory, never cached)
impl ItemContent {
    pub fn get_password(&self) -> Option<String> {
        let content = self.content.as_ref()?;
        
        // Try to extract password from Login type
        if let Some(login) = content.get("Login")
            && let Some(password) = login.get("password")
        {
            return password.as_str().map(|s| s.to_string());
        }
        
        None
    }
    
    pub fn get_username(&self) -> Option<String> {
        let content = self.content.as_ref()?;
        
        if let Some(login) = content.get("Login") {
            // Try username first, then email as fallback
            if let Some(username) = login.get("username") {
                let u = username.as_str().unwrap_or("").to_string();
                if !u.is_empty() {
                    return Some(u);
                }
            }
            if let Some(email) = login.get("email") {
                let e = email.as_str().unwrap_or("").to_string();
                if !e.is_empty() {
                    return Some(e);
                }
            }
        }
        
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

impl Item {
    /// Get username from either cached value or by extracting from content
    pub fn get_username(&self) -> Option<String> {
        // Prefer cached username if available
        if let Some(ref username) = self.cached_username {
            return Some(username.clone());
        }
        // Otherwise extract from content (when data is fresh from pass-cli)
        self.content.get_username()
    }
}

/// Internal search result
#[derive(Debug, Clone)]
pub struct Match {
    pub title: String,
    pub vault_name: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Response from `pass-cli item view --output json`
#[derive(Debug, Deserialize)]
pub struct ItemView {
    pub item: ItemViewItem,
}

#[derive(Debug, Deserialize)]
pub struct ItemViewItem {
    pub content: ItemViewContent,
}

#[derive(Debug, Deserialize)]
pub struct ItemViewContent {
    pub content: Option<serde_json::Value>,
}

impl ItemViewContent {
    pub fn get_password(&self) -> Option<String> {
        let content = self.content.as_ref()?;

        if let Some(login) = content.get("Login")
            && let Some(password) = login.get("password")
        {
            return password.as_str().map(|s| s.to_string());
        }

        None
    }

    pub fn get_username(&self) -> Option<String> {
        let content = self.content.as_ref()?;

        if let Some(login) = content.get("Login") {
            // Try username first
            if let Some(username) = login.get("username") {
                let u = username.as_str().unwrap_or("").to_string();
                if !u.is_empty() {
                    return Some(u);
                }
            }
            // Fallback to email
            if let Some(email) = login.get("email") {
                let e = email.as_str().unwrap_or("").to_string();
                if !e.is_empty() {
                    return Some(e);
                }
            }
        }

        None
    }
}
