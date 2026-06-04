use anyhow::Result;
use colored::Colorize;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::cache;
use crate::models::{Item, Match, Vault};
use crate::pass_cli;

/// Whether an item should appear in results: its title must contain the query
/// (case-insensitive), and when `login_only` is set it must be a login item.
/// Items with an unknown/empty type are kept defensively (so a future pass-cli
/// change to the type field can never silently hide everything).
fn item_matches(item: &Item, query_lower: &str, login_only: bool) -> bool {
    if !item.title.to_lowercase().contains(query_lower) {
        return false;
    }
    if login_only && !item.item_type.is_empty() && item.item_type != "login" {
        return false;
    }
    true
}

/// Order matches deterministically by title, then vault (both case-insensitive),
/// so the picker list is stable between runs instead of following vault-completion order.
fn sort_matches(matches: &mut [Match]) {
    matches.sort_by(|a, b| {
        a.title
            .to_lowercase()
            .cmp(&b.title.to_lowercase())
            .then_with(|| {
                a.vault_name
                    .to_lowercase()
                    .cmp(&b.vault_name.to_lowercase())
            })
    });
}

fn title_key(title: &str) -> String {
    title.trim().to_lowercase()
}

/// Search a single vault for items matching the query (case-insensitive)
/// Uses caching to speed up repeated searches
async fn search_vault(vault: Vault, query: String, login_only: bool) -> Result<Vec<Match>> {
    // Try to get from cache first
    let item_list = if let Some(cached) = cache::get_cached_vault(&vault.name, login_only) {
        cached
    } else {
        // Not in cache, fetch from pass-cli
        let items = pass_cli::list_vault_items(&vault, login_only).await?;
        // Store in cache for future use
        let _ = cache::set_cached_vault(&vault.name, login_only, &items);
        items
    };

    let query_lower = query.to_lowercase();
    let matches: Vec<Match> = item_list
        .items
        .into_iter()
        .filter(|item| item_matches(item, &query_lower, login_only))
        .map(|item| Match {
            item_id: item.id,
            share_id: item.share_id.or_else(|| vault.share_id.clone()),
            title: item.title,
            vault_name: vault.name.clone(),
            item_type: item.item_type,
            account: None,
        })
        .collect();

    Ok(matches)
}

/// Search all vaults with LIMITED concurrency and caching for best performance
/// First run: ~8-10 seconds (with 10 concurrent pass-cli processes)
/// Subsequent runs: <1 second (from cache, valid for 5 minutes)
pub async fn search_all_vaults_limited(
    vaults: Vec<Vault>,
    query: String,
    login_only: bool,
) -> Result<Vec<Match>> {
    const MAX_CONCURRENT: usize = 10; // Increased from 4 to 10 for faster first run

    let vault_count = vaults.len() as u64;

    // Create progress bar
    let pb = ProgressBar::new(vault_count);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg} [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb.set_message("Searching vaults");

    let results = stream::iter(vaults)
        .map(|vault| {
            let query = query.clone();
            let pb = pb.clone();
            async move {
                let result = search_vault(vault, query, login_only).await;
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
            Err(e) => eprintln!(
                "{} vault search failed: {}",
                "⚠".yellow(),
                e.to_string().dimmed()
            ),
        }
    }

    // Deterministic order so the picker is stable across runs.
    sort_matches(&mut all_matches);

    Ok(all_matches)
}

fn duplicate_title_keys(matches: &[Match]) -> HashSet<String> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for m in matches {
        *counts.entry(title_key(&m.title)).or_default() += 1;
    }

    counts
        .into_iter()
        .filter_map(|(title, count)| (count > 1).then_some(title))
        .collect()
}

/// Populate account identifiers only when the visible title is ambiguous.
/// The labels are fetched for the picker, kept in memory, and never cached.
pub async fn enrich_duplicate_titles_with_accounts(matches: Vec<Match>) -> Vec<Match> {
    const MAX_CONCURRENT: usize = 10;
    let duplicate_titles = Arc::new(duplicate_title_keys(&matches));

    stream::iter(matches)
        .map(|mut m| {
            let duplicate_titles = Arc::clone(&duplicate_titles);
            async move {
                if duplicate_titles.contains(&title_key(&m.title)) {
                    m.account = pass_cli::get_item_account(&m)
                        .await
                        .or_else(|| fallback_duplicate_label(&m));
                }
                m
            }
        })
        .buffered(MAX_CONCURRENT)
        .collect::<Vec<_>>()
        .await
}

fn fallback_duplicate_label(item: &Match) -> Option<String> {
    let id = item.item_id.as_deref()?;
    let short_id: String = id
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if short_id.is_empty() {
        None
    } else {
        Some(format!("id {short_id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Item;

    fn item(title: &str, item_type: &str) -> Item {
        Item {
            id: Some(format!("item-{title}")),
            share_id: Some("share-1".to_string()),
            title: title.to_string(),
            item_type: item_type.to_string(),
        }
    }

    fn m(title: &str, vault: &str) -> Match {
        Match {
            item_id: Some(format!("item-{title}-{vault}")),
            share_id: Some("share-1".to_string()),
            title: title.to_string(),
            vault_name: vault.to_string(),
            item_type: "login".to_string(),
            account: None,
        }
    }

    #[test]
    fn item_matches_filters_by_title_case_insensitively() {
        assert!(item_matches(&item("Reddit", "login"), "red", false));
        assert!(!item_matches(&item("GitHub", "login"), "red", false));
    }

    #[test]
    fn login_only_excludes_non_login_types() {
        assert!(!item_matches(&item("Shared Note", "note"), "note", true));
        assert!(item_matches(&item("Shared Note", "note"), "note", false));
        assert!(item_matches(&item("My Account", "login"), "account", true));
    }

    #[test]
    fn login_only_keeps_items_with_unknown_type() {
        // Defensive: if pass-cli stops sending item_type, don't hide everything.
        assert!(item_matches(&item("Mystery", ""), "myst", true));
    }

    #[test]
    fn sort_matches_orders_by_title_then_vault() {
        let mut v = vec![
            m("reddit", "Work"),
            m("github", "Personal"),
            m("reddit", "Personal"),
        ];
        sort_matches(&mut v);
        let order: Vec<_> = v
            .iter()
            .map(|x| (x.title.as_str(), x.vault_name.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("github", "Personal"),
                ("reddit", "Personal"),
                ("reddit", "Work")
            ]
        );
    }

    #[test]
    fn duplicate_title_keys_finds_only_ambiguous_titles() {
        let matches = vec![
            m(" reddit ", "Personal"),
            m("Reddit", "Work"),
            m("github", "Personal"),
        ];

        let duplicates = duplicate_title_keys(&matches);
        assert!(duplicates.contains("reddit"));
        assert!(!duplicates.contains("github"));
    }

    #[test]
    fn fallback_duplicate_label_uses_short_item_id() {
        assert_eq!(
            fallback_duplicate_label(&m("reddit", "Personal")).as_deref(),
            Some("id Personal")
        );
    }
}
