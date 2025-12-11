use anyhow::Result;
use futures::future::join_all;

use crate::models::{Vault, Match};
use crate::pass_cli;

/// Search a single vault for items matching the query (case-insensitive)
async fn search_vault(vault: Vault, query: String) -> Result<Vec<Match>> {
    let item_list = pass_cli::list_vault_items(&vault.name).await?;

    let query_lower = query.to_lowercase();
    let matches: Vec<Match> = item_list
        .items
        .into_iter()
        .filter(|item| item.content.title.to_lowercase().contains(&query_lower))
        .map(|item| Match {
            title: item.content.title,
            vault_name: vault.name.clone(),
        })
        .collect();

    Ok(matches)
}

/// Search all vaults in parallel for items matching the query
pub async fn search_all_vaults(vaults: Vec<Vault>, query: String) -> Result<Vec<Match>> {
    // Spawn concurrent search tasks for each vault
    let mut tasks = Vec::new();

    for vault in vaults {
        let query_clone = query.clone();
        let task = tokio::spawn(async move {
            search_vault(vault, query_clone).await
        });
        tasks.push(task);
    }

    // Wait for all tasks to complete
    let results = join_all(tasks).await;

    // Collect all matches, filtering out errors
    let mut all_matches = Vec::new();
    for result in results {
        match result {
            Ok(Ok(matches)) => all_matches.extend(matches),
            Ok(Err(e)) => eprintln!("Warning: vault search failed: {}", e),
            Err(e) => eprintln!("Warning: task panicked: {}", e),
        }
    }

    Ok(all_matches)
}
