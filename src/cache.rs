use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::models::{Item, ItemList, Vault, VaultList};

/// Cached metadata older than this is fetched again. Items added or changed
/// within the day are still found: a search with no cached match, or a
/// cached item that has gone, triggers one fresh search (see `lookup`).
const MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Bumped whenever cached contents change meaning, so caches written by an
/// older pq are discarded instead of misread. 2: item lists exclude trashed
/// items. 3: item lists are keyed by the vault's share ID, not its name,
/// which can move to another vault.
const CACHE_FORMAT_VERSION: u32 = 3;

#[derive(Serialize, Deserialize)]
struct CachedVault {
    /// `search::cache_key` of the vault: its share ID when pass-cli gives one.
    vault_key: String,
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

#[derive(Serialize, Deserialize)]
struct Cache {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    vault_list: Option<CachedVaultList>,
    #[serde(default)]
    vaults: Vec<CachedVault>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            version: CACHE_FORMAT_VERSION,
            vault_list: None,
            vaults: Vec::new(),
        }
    }
}

/// Parse a cache file, treating one from another format version as empty.
fn parse_cache(data: &str) -> Option<Cache> {
    serde_json::from_str::<Cache>(data)
        .ok()
        .filter(|cache| cache.version == CACHE_FORMAT_VERSION)
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

fn is_fresh(timestamp: u64) -> bool {
    // A timestamp in the future (a clock moved back, or an edited cache) is
    // not trusted: it would never expire.
    get_current_timestamp()
        .checked_sub(timestamp)
        .is_some_and(|age| age < MAX_AGE_SECONDS)
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
                // Lists are filtered to active items before caching, so the
                // state adds nothing and stays out of the cache.
                state: None,
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

/// Create the cache directory if needed and make it private to the user.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).context("Failed to create cache directory")?;
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .context("Failed to restrict cache directory permissions")?;
    Ok(())
}

/// Replace the cache file with `cache_json`. The JSON goes to a new 0600 file
/// beside it, which is then renamed over it: a reader never sees a partial
/// file, and a link planted at the cache path is replaced, not followed.
fn write_cache_file(cache_path: &Path, cache_json: &str) -> Result<()> {
    static WRITES: AtomicUsize = AtomicUsize::new(0);
    let dir = cache_path.parent().context("Cache path has no directory")?;
    let temp = dir.join(format!(
        ".vault-cache.{}.{}.tmp",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));

    let written = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temp)?;
        file.write_all(cache_json.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, cache_path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written.context("Failed to write cache file")
}

/// A vault's cached item list, if one was written within the last day.
pub fn get_cached_vault(vault_key: &str, login_only: bool) -> Option<ItemList> {
    let cache_path = get_cache_path().ok()?;
    if !cache_path.exists() {
        return None;
    }

    let cache_data = fs::read_to_string(&cache_path).ok()?;
    let cache = parse_cache(&cache_data)?;

    // The newest fresh entry wins: a list for all item types also serves a
    // login-only search, but not when a newer login-only list exists (the
    // older one may hold titles that have changed since).
    cache
        .vaults
        .into_iter()
        .filter(|cached| {
            cached.vault_key == vault_key
                && (cached.login_only == login_only || (login_only && !cached.login_only))
                && is_fresh(cached.timestamp)
        })
        .max_by_key(|cached| (cached.timestamp, cached.login_only == login_only))
        .map(|cached| cached.items)
}

pub fn set_cached_vault(vault_key: &str, login_only: bool, items: &ItemList) -> Result<()> {
    let cache_path = get_cache_path()?;

    // Create cache directory if it doesn't exist
    if let Some(parent) = cache_path.parent() {
        ensure_private_dir(parent)?;
    }

    // Load existing cache or create new one
    let mut cache = if cache_path.exists() {
        let cache_data = fs::read_to_string(&cache_path)?;
        parse_cache(&cache_data).unwrap_or_default()
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
        if cached_vault.vault_key == vault_key && cached_vault.login_only == login_only {
            cached_vault.items = items_to_cache.clone();
            cached_vault.timestamp = timestamp;
            found = true;
            break;
        }
    }

    if !found {
        cache.vaults.push(CachedVault {
            vault_key: vault_key.to_string(),
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
    let cache = parse_cache(&cache_data)?;
    let cached = cache.vault_list?;

    if is_fresh(cached.timestamp) {
        Some(cached.vaults)
    } else {
        None
    }
}

pub fn set_cached_vault_list(vaults: &VaultList) -> Result<()> {
    let cache_path = get_cache_path()?;

    if let Some(parent) = cache_path.parent() {
        ensure_private_dir(parent)?;
    }

    let mut cache = if cache_path.exists() {
        let cache_data = fs::read_to_string(&cache_path)?;
        parse_cache(&cache_data).unwrap_or_default()
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
                state: Some("Active".to_string()),
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
        assert!(!serialized.contains("state"));
    }
}
