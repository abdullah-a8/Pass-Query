use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::models::{Item, ItemList, Vault, VaultList};

const CACHE_TTL_SECONDS: u64 = 300; // 5 minutes

#[derive(Serialize, Deserialize)]
struct CachedVault {
    vault_name: String,
    #[serde(default)]
    login_only: bool,
    items: ItemList,
    timestamp: u64,
}

#[derive(Serialize, Deserialize)]
struct CachedVaultList {
    vaults: VaultList,
    timestamp: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Cache {
    #[serde(default)]
    vault_list: Option<CachedVaultList>,
    #[serde(default)]
    vaults: Vec<CachedVault>,
}

fn get_cache_path() -> Result<PathBuf> {
    let cache_dir = if let Ok(xdg_cache) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg_cache)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache")
    } else {
        anyhow::bail!("Could not determine cache directory");
    };

    Ok(cache_dir.join("pp-pass-cli").join("vault-cache.json"))
}

fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn cache_entry_is_usable(timestamp: u64) -> bool {
    let strict_ttl = std::env::var("PQ_STRICT_CACHE_TTL")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    !strict_ttl || get_current_timestamp() - timestamp < CACHE_TTL_SECONDS
}

fn cache_safe_item_list(items: &ItemList) -> ItemList {
    ItemList {
        items: items
            .items
            .iter()
            .map(|item| Item {
                id: item.id.clone(),
                share_id: item.share_id.clone(),
                title: item.title.clone(),
                item_type: item.item_type.clone(),
            })
            .collect(),
    }
}

fn cache_safe_vault_list(vaults: &VaultList) -> VaultList {
    VaultList {
        vaults: vaults
            .vaults
            .iter()
            .map(|vault| Vault {
                name: vault.name.clone(),
                share_id: vault.share_id.clone(),
            })
            .collect(),
    }
}

fn write_cache_file(cache_path: &PathBuf, cache_json: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(cache_path)
        .context("Failed to open cache file for writing")?;
    file.write_all(cache_json.as_bytes())
        .context("Failed to write cache file")?;

    #[cfg(unix)]
    fs::set_permissions(cache_path, fs::Permissions::from_mode(0o600))
        .context("Failed to restrict cache file permissions")?;

    Ok(())
}

pub fn get_cached_vault(vault_name: &str, login_only: bool) -> Option<ItemList> {
    let cache_path = get_cache_path().ok()?;
    if !cache_path.exists() {
        return None;
    }

    let cache_data = fs::read_to_string(&cache_path).ok()?;
    let cache: Cache = serde_json::from_str(&cache_data).ok()?;

    for cached_vault in cache.vaults {
        if cached_vault.vault_name == vault_name {
            let exact_scope = cached_vault.login_only == login_only;
            let broader_all_scope = login_only && !cached_vault.login_only;
            if !(exact_scope || broader_all_scope) {
                continue;
            }
            // By default, stale metadata is still usable: it contains no secrets
            // and avoids a slow network refresh. Set PQ_STRICT_CACHE_TTL=1 to
            // restore the 5-minute freshness window.
            if cache_entry_is_usable(cached_vault.timestamp) {
                return Some(cached_vault.items);
            }
        }
    }

    None
}

pub fn set_cached_vault(vault_name: &str, login_only: bool, items: &ItemList) -> Result<()> {
    let cache_path = get_cache_path()?;

    // Create cache directory if it doesn't exist
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).context("Failed to create cache directory")?;
    }

    // Load existing cache or create new one
    let mut cache = if cache_path.exists() {
        let cache_data = fs::read_to_string(&cache_path)?;
        serde_json::from_str(&cache_data).unwrap_or_default()
    } else {
        Cache::default()
    };

    let timestamp = get_current_timestamp();

    // Persist only the searchable metadata pq needs. This keeps the cache safe
    // even if ItemList grows new fields in the future.
    let items_to_cache = cache_safe_item_list(items);

    // Update or add this vault's cache
    let mut found = false;
    for cached_vault in &mut cache.vaults {
        if cached_vault.vault_name == vault_name && cached_vault.login_only == login_only {
            cached_vault.items = items_to_cache.clone();
            cached_vault.timestamp = timestamp;
            found = true;
            break;
        }
    }

    if !found {
        cache.vaults.push(CachedVault {
            vault_name: vault_name.to_string(),
            login_only,
            items: items_to_cache,
            timestamp,
        });
    }

    // Write cache back to disk
    let cache_json = serde_json::to_string(&cache)?;
    write_cache_file(&cache_path, &cache_json)?;

    Ok(())
}

pub fn get_cached_vault_list() -> Option<VaultList> {
    let cache_path = get_cache_path().ok()?;
    if !cache_path.exists() {
        return None;
    }

    let cache_data = fs::read_to_string(&cache_path).ok()?;
    let cache: Cache = serde_json::from_str(&cache_data).ok()?;
    let cached = cache.vault_list?;

    if cache_entry_is_usable(cached.timestamp) {
        Some(cached.vaults)
    } else {
        None
    }
}

pub fn set_cached_vault_list(vaults: &VaultList) -> Result<()> {
    let cache_path = get_cache_path()?;

    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).context("Failed to create cache directory")?;
    }

    let mut cache = if cache_path.exists() {
        let cache_data = fs::read_to_string(&cache_path)?;
        serde_json::from_str(&cache_data).unwrap_or_default()
    } else {
        Cache::default()
    };

    cache.vault_list = Some(CachedVaultList {
        vaults: cache_safe_vault_list(vaults),
        timestamp: get_current_timestamp(),
    });

    let cache_json = serde_json::to_string(&cache)?;
    write_cache_file(&cache_path, &cache_json)?;

    Ok(())
}

pub fn clear_cache() -> Result<()> {
    let cache_path = get_cache_path()?;
    if cache_path.exists() {
        fs::remove_file(&cache_path).context("Failed to remove cache file")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_safe_item_list_keeps_only_search_metadata() {
        let items = ItemList {
            items: vec![Item {
                id: Some("item-1".to_string()),
                share_id: Some("share-1".to_string()),
                title: "github".to_string(),
                item_type: "login".to_string(),
            }],
        };

        let safe = cache_safe_item_list(&items);
        let serialized = serde_json::to_string(&safe).unwrap();

        assert_eq!(safe.items[0].title, "github");
        assert_eq!(safe.items[0].item_type, "login");
        assert_eq!(safe.items[0].id.as_deref(), Some("item-1"));
        assert_eq!(safe.items[0].share_id.as_deref(), Some("share-1"));
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("username"));
        assert!(!serialized.contains("email"));
        assert!(!serialized.contains("content"));
    }
}
