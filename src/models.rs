use serde::{Deserialize, Serialize};

/// Vault list response from `pass-cli vault list --output json`
#[derive(Debug, Deserialize)]
pub struct VaultList {
    pub vaults: Vec<Vault>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Vault {
    pub name: String,
    // pass-cli also emits `vault_id` and `share_id`; pq only addresses vaults by
    // name, so those keys are intentionally ignored by serde.
}

/// Item list response from `pass-cli item list <vault> --output json`.
///
/// As of pass-cli 2.0.3 the default JSON output is a secret-free *summary*:
/// each entry exposes `title` and `item_type` at the top level and carries no
/// credentials (the `--show-secrets` flag is required to include them). We
/// deliberately do not request secrets here — credentials are fetched on demand
/// for the single selected item via `item view` (see `pass_cli::get_item_credentials`).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ItemList {
    pub items: Vec<Item>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Item {
    pub title: String,
    // Item kind reported by pass-cli ("login", "note", "alias", ...). Used only
    // for display in the picker. Defaulted so a future rename can never break search.
    #[serde(default)]
    pub item_type: String,
}

/// Internal search result. The password is intentionally absent: the list output
/// carries no secrets, so it is always fetched fresh via `item view`.
#[derive(Debug, Clone)]
pub struct Match {
    pub title: String,
    pub vault_name: String,
    pub item_type: String,
    /// Account identifier (username, or email as fallback) shown in the picker to
    /// disambiguate same-titled items. Populated lazily via `item view --field`
    /// only when there are multiple matches; never holds the password.
    pub account: Option<String>,
}

impl Match {
    /// Label shown after the title in the picker. Prefers the account identifier,
    /// falls back to the item type, then a generic placeholder.
    pub fn picker_detail(&self) -> &str {
        if let Some(account) = self.account.as_deref()
            && !account.is_empty()
        {
            return account;
        }
        if !self.item_type.is_empty() {
            return &self.item_type;
        }
        "item"
    }
}

/// Response from `pass-cli item view --output json`.
///
/// The full item is serialized with credentials nested at
/// `item.content.content.Login` (the `ItemContent` enum is externally tagged).
/// Additional top-level fields (`attachments`, item metadata, etc.) are ignored.
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

#[cfg(test)]
mod tests {
    use super::*;

    // Sample of `pass-cli item list <vault> --output json` as of pass-cli 2.0.3+.
    // The default output is a secret-free summary: `title` and `item_type` are
    // top-level and there is no nested `content` object or credentials.
    const ITEM_LIST_JSON: &str = r#"{
      "items": [
        {
          "id": "item-abc",
          "share_id": "share-xyz",
          "vault_id": "vault-123",
          "state": "Active",
          "flags": [],
          "create_time": "2026-01-01T00:00:00",
          "modify_time": "2026-01-02T00:00:00",
          "title": "reddit",
          "item_type": "login"
        },
        {
          "id": "item-def",
          "share_id": "share-xyz",
          "vault_id": "vault-123",
          "state": "Active",
          "flags": [],
          "create_time": "2026-01-01T00:00:00",
          "modify_time": "2026-01-02T00:00:00",
          "title": "personal note",
          "item_type": "note"
        }
      ]
    }"#;

    #[test]
    fn item_list_parses_new_summary_shape() {
        let list: ItemList =
            serde_json::from_str(ITEM_LIST_JSON).expect("should parse new item list summary");
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].title, "reddit");
        assert_eq!(list.items[0].item_type, "login");
        assert_eq!(list.items[1].title, "personal note");
        assert_eq!(list.items[1].item_type, "note");
    }

    #[test]
    fn item_list_tolerates_missing_item_type() {
        // Defensive: a future pass-cli could rename or drop item_type. Title is the
        // only field search depends on, so a missing type must never break parsing.
        let json = r#"{ "items": [ { "title": "github" } ] }"#;
        let list: ItemList = serde_json::from_str(json).expect("should parse with only title");
        assert_eq!(list.items[0].title, "github");
        assert_eq!(list.items[0].item_type, "");
    }

    #[test]
    fn item_list_round_trips_through_cache_without_secrets() {
        let list: ItemList = serde_json::from_str(ITEM_LIST_JSON).unwrap();
        let serialized = serde_json::to_string(&list).unwrap();
        // The cached form must never contain credential material.
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("Login"));
        let reparsed: ItemList = serde_json::from_str(&serialized).unwrap();
        assert_eq!(reparsed.items[0].title, "reddit");
    }

    // Sample of `pass-cli item view --output json` (structure unchanged across 2.x):
    // the full item is serialized with credentials nested at item.content.content.Login.
    const ITEM_VIEW_JSON: &str = r#"{
      "item": {
        "id": "item-abc",
        "share_id": "share-xyz",
        "vault_id": "vault-123",
        "content": {
          "title": "reddit",
          "note": "",
          "item_uuid": "uuid-1",
          "content": {
            "Login": {
              "email": "me@example.com",
              "username": "myuser",
              "password": "s3cr3t",
              "urls": ["https://reddit.com"],
              "totp_uri": "",
              "passkeys": []
            }
          },
          "extra_fields": []
        },
        "state": "Active",
        "flags": [],
        "create_time": "2026-01-01T00:00:00",
        "modify_time": "2026-01-02T00:00:00"
      },
      "attachments": []
    }"#;

    #[test]
    fn item_view_extracts_login_credentials() {
        let view: ItemView = serde_json::from_str(ITEM_VIEW_JSON).expect("should parse item view");
        assert_eq!(view.item.content.get_username().as_deref(), Some("myuser"));
        assert_eq!(view.item.content.get_password().as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn item_view_username_falls_back_to_email() {
        let json = r#"{
          "item": { "content": { "content": { "Login": {
            "email": "fallback@example.com", "username": "", "password": "pw",
            "urls": [], "totp_uri": "", "passkeys": []
          } } } }
        }"#;
        let view: ItemView = serde_json::from_str(json).expect("should parse");
        assert_eq!(
            view.item.content.get_username().as_deref(),
            Some("fallback@example.com")
        );
        assert_eq!(view.item.content.get_password().as_deref(), Some("pw"));
    }

    #[test]
    fn vault_list_parses() {
        let json = r#"{ "vaults": [ { "name": "Personal", "vault_id": "v1", "share_id": "s1" } ] }"#;
        let vl: VaultList = serde_json::from_str(json).expect("should parse vault list");
        assert_eq!(vl.vaults[0].name, "Personal");
    }

    fn make_match(account: Option<&str>, item_type: &str) -> Match {
        Match {
            title: "reddit".to_string(),
            vault_name: "Personal".to_string(),
            item_type: item_type.to_string(),
            account: account.map(|s| s.to_string()),
        }
    }

    #[test]
    fn picker_detail_prefers_account() {
        assert_eq!(
            make_match(Some("alice@example.com"), "login").picker_detail(),
            "alice@example.com"
        );
    }

    #[test]
    fn picker_detail_falls_back_to_item_type_when_no_account() {
        assert_eq!(make_match(None, "login").picker_detail(), "login");
    }

    #[test]
    fn picker_detail_ignores_empty_account() {
        assert_eq!(make_match(Some(""), "note").picker_detail(), "note");
    }

    #[test]
    fn picker_detail_defaults_to_item_when_nothing_known() {
        assert_eq!(make_match(None, "").picker_detail(), "item");
    }
}
