//! From a query to the chosen item's credentials: search the vaults, let
//! the user pick a match, then fetch that one item's credentials fresh.
//!
//! The metadata cache makes searches instant but can be up to a day old. When
//! a search that used it finds nothing, or the item picked from it can no
//! longer be read, the lookup runs once more on fresh data from pass-cli.

use anyhow::Result;
use colored::Colorize;
use std::collections::{HashMap, HashSet};

use crate::cache;
use crate::models::VaultList;
use crate::pass_cli::{self, SessionProblem};
use crate::search::{self, CacheUse};
use crate::selection;
use crate::text::printable;

pub struct Credentials {
    pub username: Option<String>,
    pub password: String,
}

/// Find `query` and return the credentials of the item the user picks.
/// `refresh` skips the cache from the start.
pub async fn find_credentials(query: &str, login_only: bool, refresh: bool) -> Result<Credentials> {
    // First pass: any cache entry from the last day. The one retry fetches the
    // vault list again and reuses only item lists fetched during this run.
    let mut pass = if refresh { Pass::Fresh } else { Pass::Cached };
    let mut fetched_this_run = HashSet::new();
    // Picker labels already read in this run, by share and item ID, so the
    // retry does not read the same accounts again (on Business plans every
    // read is reported to the organisation).
    let mut known_accounts: HashMap<(Option<String>, Option<String>), String> = HashMap::new();
    let mut pick_failed = false;
    loop {
        let (vaults, vaults_cached) = load_vaults(pass == Pass::Cached).await?;
        // A cached list with no vaults may be stale; only a fresh one is final.
        if vaults.vaults.is_empty() && vaults_cached {
            pass = Pass::Retry;
            continue;
        }
        let cache_use = match pass {
            Pass::Cached => CacheUse::Any,
            Pass::Retry => CacheUse::OnlyVaults(std::mem::take(&mut fetched_this_run)),
            Pass::Fresh => CacheUse::Never,
        };
        let results = search::search_all_vaults_limited(
            vaults.vaults,
            query.to_string(),
            login_only,
            cache_use,
        )
        .await?;
        let may_retry = pass == Pass::Cached && (vaults_cached || results.from_cache);
        fetched_this_run = results.fetched_vaults;

        if results.matches.is_empty() && may_retry {
            eprintln!(
                "{} No cached match; checking Proton Pass for new items",
                "⟳".cyan()
            );
            pass = Pass::Retry;
            continue;
        }

        // Only duplicate visible titles need account identifiers in the
        // picker. They are kept in memory and never cached.
        let mut matches = results.matches;
        if matches.len() > 1 {
            for m in &mut matches {
                m.account = known_accounts.get(&account_key(m)).cloned();
            }
            matches = search::enrich_duplicate_titles_with_accounts(matches).await?;
            for m in &matches {
                if let Some(account) = &m.account {
                    known_accounts.insert(account_key(m), account.clone());
                }
            }
        }
        // After the user's pick failed, another item is never used without
        // asking, even when it is the only match left.
        let selected = selection::select_item(matches, pick_failed)?;

        match pass_cli::get_item_credentials(&selected).await {
            Ok((username, password)) => return Ok(Credentials { username, password }),
            // A cached match may since have been deleted or moved. A session
            // problem is not about the cache, so it is reported as is.
            Err(e) if may_retry && e.downcast_ref::<SessionProblem>().is_none() => {
                eprintln!(
                    "{} '{}' could not be read; searching again with fresh data",
                    "⟳".cyan(),
                    printable(&selected.title)
                );
                pass = Pass::Retry;
                pick_failed = true;
            }
            Err(e) => return Err(e),
        }
    }
}

fn account_key(m: &crate::models::Match) -> (Option<String>, Option<String>) {
    (m.share_id.clone(), m.item_id.clone())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// Use the cache wherever it has fresh data.
    Cached,
    /// The single retry after the cache may have been stale.
    Retry,
    /// `--refresh`: fetch everything.
    Fresh,
}

/// The vault list, from the cache when `use_cache` and it has one. Also says
/// whether it was cached.
async fn load_vaults(use_cache: bool) -> Result<(VaultList, bool)> {
    if use_cache && let Some(cached) = cache::get_cached_vault_list() {
        return Ok((cached, true));
    }
    let vaults = pass_cli::fetch_vaults().await?;
    cache::set_cached_vault_list(&vaults)?;
    Ok((vaults, false))
}
