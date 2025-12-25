use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::ItemList;

const CACHE_TTL_SECONDS: u64 = 300; // 5 minutes

#[derive(Serialize, Deserialize)]
struct CachedVault {
    vault_name: String,
    items: ItemList,
    timestamp: u64,
}

#[derive(Serialize, Deserialize)]
struct Cache {
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

pub fn get_cached_vault(vault_name: &str) -> Option<ItemList> {
    let cache_path = get_cache_path().ok()?;
    if !cache_path.exists() {
        return None;
    }

    let cache_data = fs::read_to_string(&cache_path).ok()?;
    let cache: Cache = serde_json::from_str(&cache_data).ok()?;

    let current_time = get_current_timestamp();
    
    for cached_vault in cache.vaults {
        if cached_vault.vault_name == vault_name {
            // Check if cache is still valid
            if current_time - cached_vault.timestamp < CACHE_TTL_SECONDS {
                return Some(cached_vault.items);
            }
        }
    }

    None
}

pub fn set_cached_vault(vault_name: &str, items: &ItemList) -> Result<()> {
    let cache_path = get_cache_path()?;
    
    // Create cache directory if it doesn't exist
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).context("Failed to create cache directory")?;
    }

    // Load existing cache or create new one
    let mut cache = if cache_path.exists() {
        let cache_data = fs::read_to_string(&cache_path)?;
        serde_json::from_str(&cache_data).unwrap_or(Cache { vaults: Vec::new() })
    } else {
        Cache { vaults: Vec::new() }
    };

    let timestamp = get_current_timestamp();

    // Prepare items for caching: extract and store usernames
    let mut items_to_cache = items.clone();
    for item in &mut items_to_cache.items {
        // Extract username from content and store in cached_username field
        if item.cached_username.is_none() {
            item.cached_username = item.content.get_username();
        }
    }

    // Update or add this vault's cache
    let mut found = false;
    for cached_vault in &mut cache.vaults {
        if cached_vault.vault_name == vault_name {
            cached_vault.items = items_to_cache.clone();
            cached_vault.timestamp = timestamp;
            found = true;
            break;
        }
    }

    if !found {
        cache.vaults.push(CachedVault {
            vault_name: vault_name.to_string(),
            items: items_to_cache,
            timestamp,
        });
    }

    // Write cache back to disk
    let cache_json = serde_json::to_string(&cache)?;
    fs::write(&cache_path, cache_json).context("Failed to write cache file")?;

    Ok(())
}

pub fn clear_cache() -> Result<()> {
    let cache_path = get_cache_path()?;
    if cache_path.exists() {
        fs::remove_file(&cache_path).context("Failed to remove cache file")?;
    }
    Ok(())
}

