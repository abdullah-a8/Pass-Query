use anyhow::Result;
use futures::stream::{self, StreamExt};

use crate::cache;
use crate::models::{Vault, Match};
use crate::pass_cli;

/// Search a single vault for items matching the query (case-insensitive)
/// Uses caching to speed up repeated searches
async fn search_vault(vault: Vault, query: String) -> Result<Vec<Match>> {
    // Try to get from cache first
    let item_list = if let Some(cached) = cache::get_cached_vault(&vault.name) {
        cached
    } else {
        // Not in cache, fetch from pass-cli
        let items = pass_cli::list_vault_items(&vault.name).await?;
        // Store in cache for future use
        let _ = cache::set_cached_vault(&vault.name, &items);
        items
    };

    let query_lower = query.to_lowercase();
    let matches: Vec<Match> = item_list
        .items
        .into_iter()
        .filter(|item| item.content.title.to_lowercase().contains(&query_lower))
        .map(|item| {
            // Extract password from the item (works for any item type)
            let password = item.content.get_password();
            
            Match {
                title: item.content.title,
                vault_name: vault.name.clone(),
                password,
            }
        })
        .collect();

    Ok(matches)
}

/// Search all vaults with LIMITED concurrency and caching for best performance
/// First run: ~8-10 seconds (with 10 concurrent pass-cli processes)
/// Subsequent runs: <1 second (from cache, valid for 5 minutes)
pub async fn search_all_vaults_limited(vaults: Vec<Vault>, query: String) -> Result<Vec<Match>> {
    const MAX_CONCURRENT: usize = 10;  // Increased from 4 to 10 for faster first run
    
    let results = stream::iter(vaults)
        .map(|vault| {
            let query = query.clone();
            async move {
                search_vault(vault, query).await
            }
        })
        .buffer_unordered(MAX_CONCURRENT)
        .collect::<Vec<_>>()
        .await;

    // Collect all matches, filtering out errors
    let mut all_matches = Vec::new();
    for result in results {
        match result {
            Ok(matches) => all_matches.extend(matches),
            Err(e) => eprintln!("Warning: vault search failed: {}", e),
        }
    }

    Ok(all_matches)
}
