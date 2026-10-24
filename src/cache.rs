use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
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

/// Create the cache directory if needed and make it private to the user. An
/// existing path that is a link or belongs to someone else is left alone.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).context("Failed to create cache directory")?;
    #[cfg(unix)]
    {
        let meta = fs::symlink_metadata(dir).context("Failed to inspect cache directory")?;
        if !meta.file_type().is_dir() || !owned_by_user(&meta) {
            anyhow::bail!("Cache directory is a link or not yours");
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .context("Failed to restrict cache directory permissions")?;
    }
    Ok(())
}

/// The cache file's contents, if the cache can be trusted: a regular file,
/// not reached through a link, in a real directory, both the user's and
/// writable by no one else. Anything else may have been written by someone
/// else, who could pair a title with another item's IDs. Such a cache is
/// treated as missing, so pq fetches fresh metadata.
fn read_cache_file(cache_path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        let dir = fs::symlink_metadata(cache_path.parent()?).ok()?;
        if !(dir.file_type().is_dir() && is_private(&dir)) {
            return None;
        }
        // O_NOFOLLOW refuses a link at the cache path; the checks then apply
        // to the file actually opened.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(cache_path)
            .ok()?;
        let meta = file.metadata().ok()?;
        if !(meta.file_type().is_file() && is_private(&meta)) {
            return None;
        }
        let mut data = String::new();
        file.read_to_string(&mut data).ok()?;
        Some(data)
    }
    #[cfg(not(unix))]
    fs::read_to_string(cache_path).ok()
}

#[cfg(unix)]
fn owned_by_user(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid takes no arguments and cannot fail.
    meta.uid() == unsafe { libc::getuid() }
}

/// The user's, and writable by no one else.
#[cfg(unix)]
fn is_private(meta: &fs::Metadata) -> bool {
    owned_by_user(meta) && meta.permissions().mode() & 0o022 == 0
}

/// Replace the cache file with `cache_json`. The JSON goes to a new 0600 file
/// beside it, which is then renamed over it: a reader never sees a partial
/// file, and a link planted at the cache path is replaced, not followed.
fn write_cache_file(cache_path: &Path, cache_json: &str) -> Result<()> {
    let dir = cache_path.parent().context("Cache path has no directory")?;
    let (temp, mut file) = create_temp_file(dir).context("Failed to write cache file")?;
    let written = file
        .write_all(cache_json.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp, cache_path));
    if written.is_err() {
        // Only ever the file this run created.
        let _ = fs::remove_file(&temp);
    }
    written.context("Failed to write cache file")
}

/// Cache writes by this process, numbering its temporary files.
static WRITES: AtomicUsize = AtomicUsize::new(0);

/// A new 0600 file beside the cache, under a name no one else holds: a name
/// left by a crashed pq, or taken by a concurrent writer, is skipped, never
/// reused or removed.
fn create_temp_file(dir: &Path) -> std::io::Result<(PathBuf, fs::File)> {
    let mut attempts = 0;
    loop {
        let temp = dir.join(format!(
            ".vault-cache.{}.{}.tmp",
            std::process::id(),
            WRITES.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temp) {
            Ok(file) => return Ok((temp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempts < 16 => {
                attempts += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// The cache to update, and its directory made ready for the write. The
/// existing contents are judged before the directory is made private:
/// contents found in a directory that others could write are dropped, not
/// carried into the new file.
fn load_for_update(cache_path: &Path) -> Result<Cache> {
    let existing = read_cache_file(cache_path).and_then(|data| parse_cache(&data));
    ensure_private_dir(cache_path.parent().context("Cache path has no directory")?)?;
    Ok(existing.unwrap_or_default())
}

/// A vault's cached item list, if one was written within the last day.
pub fn get_cached_vault(vault_key: &str, login_only: bool) -> Option<ItemList> {
    let cache_path = get_cache_path().ok()?;
    let cache = parse_cache(&read_cache_file(&cache_path)?)?;

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

    let mut cache = load_for_update(&cache_path)?;

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
    let cache = parse_cache(&read_cache_file(&cache_path)?)?;
    let cached = cache.vault_list?;

    if is_fresh(cached.timestamp) {
        Some(cached.vaults)
    } else {
        None
    }
}

pub fn set_cached_vault_list(vaults: &VaultList) -> Result<()> {
    let cache_path = get_cache_path()?;

    let mut cache = load_for_update(&cache_path)?;

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
    fn a_taken_temporary_name_is_skipped_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        // Left by a crashed pq with this pid, or by another writer.
        let next = WRITES.load(Ordering::Relaxed);
        let taken: Vec<_> = (next..next + 4)
            .map(|n| {
                dir.path()
                    .join(format!(".vault-cache.{}.{n}.tmp", std::process::id()))
            })
            .collect();
        for path in &taken {
            fs::write(path, "someone else's").unwrap();
        }
        let cache = dir.path().join("vault-cache.json");

        write_cache_file(&cache, "{}").unwrap();

        assert_eq!(fs::read_to_string(&cache).unwrap(), "{}");
        for path in &taken {
            assert_eq!(fs::read_to_string(path).unwrap(), "someone else's");
        }
    }

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
