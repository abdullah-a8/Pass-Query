use anyhow::Result;
use colored::Colorize;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};

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
            // Extract credentials from the item
            // Use Item::get_username() which checks cached_username first
            let username = item.get_username();
            let password = item.content.get_password();
            
            Match {
                title: item.content.title,
                vault_name: vault.name.clone(),
                username,
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

    let vault_count = vaults.len() as u64;

    // Create progress bar
    let pb = ProgressBar::new(vault_count);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg} [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("█▓░")
    );
    pb.set_message("Searching vaults");

    let results = stream::iter(vaults)
        .map(|vault| {
            let query = query.clone();
            let pb = pb.clone();
            async move {
                let result = search_vault(vault, query).await;
                pb.inc(1);
                result
            }
        })
        .buffer_unordered(MAX_CONCURRENT)
        .collect::<Vec<_>>()
        .await;

    // Clear progress bar
    pb.finish_and_clear();

    // Collect all matches, filtering out errors
    let mut all_matches = Vec::new();
    for result in results {
        match result {
            Ok(matches) => all_matches.extend(matches),
            Err(e) => eprintln!("{} vault search failed: {}", "⚠".yellow(), e.to_string().dimmed()),
        }
    }

    Ok(all_matches)
}
