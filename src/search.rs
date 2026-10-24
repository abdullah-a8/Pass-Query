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

/// The key a vault's item list is cached under: its share ID, which never
/// changes, so a renamed vault cannot lend its list to another vault that
/// now has its name. The name is a fallback for a pass-cli that gives none.
fn cache_key(vault: &Vault) -> String {
    match &vault.share_id {
        Some(share_id) => format!("share:{share_id}"),
        None => format!("name:{}", vault.name),
    }
}

/// Which cached item lists a search may use.
pub enum CacheUse {
    /// Any list cached within the last day.
    Any,
    /// Only the lists of these vaults, by `cache_key` (those fetched earlier
    /// in this run).
    OnlyVaults(HashSet<String>),
    /// None: fetch every list from pass-cli.
    Never,
}

/// The matches of one search, whether any of them came from the cache (and
/// so may be out of date), and the vaults (by `cache_key`) whose lists were
/// fetched fresh.
pub struct SearchResults {
    pub matches: Vec<Match>,
    pub from_cache: bool,
    pub fetched_vaults: HashSet<String>,
}

/// Search one vault's titles for `query` (case-insensitive), from its cached
/// item list when `cache_use` allows, otherwise from pass-cli (and cache what
/// was fetched). Returns the matches and whether they came from the cache.
async fn search_vault(
    vault: Vault,
    query: String,
    login_only: bool,
    cache_use: &CacheUse,
) -> Result<(Vec<Match>, bool)> {
    // Cached lists were filtered when written; filtering again keeps a cache
    // edited by hand or by another tool from offering trashed items.
    let key = cache_key(&vault);
    let cached = match cache_use {
        CacheUse::Any => cache::get_cached_vault(&key, login_only),
        CacheUse::OnlyVaults(keys) if keys.contains(&key) => {
            cache::get_cached_vault(&key, login_only)
        }
        _ => None,
    };
    let from_cache = cached.is_some();
    let item_list = match cached {
        Some(items) => items.into_active(),
        None => {
            let items = pass_cli::list_vault_items(&vault, login_only)
                .await?
                .into_active();
            let _ = cache::set_cached_vault(&key, login_only, &items);
            items
        }
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

    Ok((matches, from_cache))
}

/// Search every vault, at most 10 at a time. A fetch from pass-cli takes
/// seconds per vault; a vault `cache_use` lets the search read from the cache
/// is searched instantly instead.
pub async fn search_all_vaults_limited(
    vaults: Vec<Vault>,
    query: String,
    login_only: bool,
    cache_use: CacheUse,
) -> Result<SearchResults> {
    const MAX_CONCURRENT: usize = 10; // Increased from 4 to 10 for faster first run

    if vaults.is_empty() {
        anyhow::bail!("{} No vaults found in your Proton Pass account.", "✗".red());
    }
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

    let mut searches = stream::iter(vaults)
        .map(|vault| {
            let query = query.clone();
            let pb = pb.clone();
            let cache_use = &cache_use;
            async move {
                let key = cache_key(&vault);
                let result = search_vault(vault, query, login_only, cache_use).await;
                pb.inc(1);
                (key, result)
            }
        })
        .buffer_unordered(MAX_CONCURRENT);

    let mut all_matches = Vec::new();
    let mut from_cache = false;
    let mut fetched_vaults = HashSet::new();
    let mut failures = Vec::new();
    while let Some((key, result)) = searches.next().await {
        match result {
            Ok((matches, cached)) => {
                all_matches.extend(matches);
                from_cache |= cached;
                if !cached {
                    fetched_vaults.insert(key);
                }
            }
            // A session problem affects every vault: report it at once, with
            // its fix. Dropping `searches` cancels (and kills) the others.
            Err(e) => {
                if let Some(problem) = e.downcast_ref::<pass_cli::SessionProblem>() {
                    pb.finish_and_clear();
                    return Err(anyhow::Error::new(*problem));
                }
                failures.push(e);
            }
        }
    }
    pb.finish_and_clear();

    // With no vault searched, "no items found" would be misleading.
    if !failures.is_empty() && failures.len() as u64 == vault_count {
        anyhow::bail!(
            "{} Could not search any vault: {:#}",
            "✗".red(),
            failures[0]
        );
    }
    for e in &failures {
        eprintln!(
            "{} vault search failed: {}",
            "⚠".yellow(),
            e.to_string().dimmed()
        );
    }

    // Deterministic order so the picker is stable across runs.
    sort_matches(&mut all_matches);

    Ok(SearchResults {
        matches: all_matches,
        from_cache,
        fetched_vaults,
    })
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
pub async fn enrich_duplicate_titles_with_accounts(matches: Vec<Match>) -> Result<Vec<Match>> {
    const MAX_CONCURRENT: usize = 10;
    let duplicate_titles = Arc::new(duplicate_title_keys(&matches));
    let count = matches.len();

    let mut lookups = stream::iter(matches.into_iter().enumerate())
        .map(|(index, mut m)| {
            let duplicate_titles = Arc::clone(&duplicate_titles);
            async move {
                // An account already known (from earlier in this run) is not read again.
                if m.account.is_none() && duplicate_titles.contains(&title_key(&m.title)) {
                    m.account = match pass_cli::get_item_account(&m).await? {
                        Some(account) => Some(account),
                        None => fallback_duplicate_label(&m),
                    };
                }
                Ok::<_, anyhow::Error>((index, m))
            }
        })
        .buffer_unordered(MAX_CONCURRENT);

    // Results arrive in completion order. The first error (a session
    // problem) is returned at once; dropping `lookups` kills the others.
    let mut labelled = Vec::with_capacity(count);
    while let Some(result) = lookups.next().await {
        labelled.push(result?);
    }
    labelled.sort_by_key(|(index, _)| *index);
    Ok(labelled.into_iter().map(|(_, m)| m).collect())
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
            state: None,
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
