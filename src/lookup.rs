//! From a query to the chosen item's credentials: search the vaults, let
//! the user pick a match, then fetch that one item's credentials fresh.

use anyhow::Result;

use crate::cache;
use crate::pass_cli;
use crate::search;
use crate::selection;

pub struct Credentials {
    pub username: Option<String>,
    pub password: String,
}

/// Find `query` and return the credentials of the item the user picks.
/// `refresh` clears the cache first.
pub async fn find_credentials(query: &str, login_only: bool, refresh: bool) -> Result<Credentials> {
    if refresh {
        cache::clear_cache()?;
    }

    // Fetch all vaults, using a metadata-only cache when it is still fresh.
    let vault_list = if let Some(cached) = cache::get_cached_vault_list() {
        cached
    } else {
        let vaults = pass_cli::fetch_vaults().await?;
        cache::set_cached_vault_list(&vaults)?;
        vaults
    };

    let mut matches =
        search::search_all_vaults_limited(vault_list.vaults, query.to_string(), login_only).await?;

    // Only duplicate visible titles need account identifiers in the picker.
    // These labels are kept in memory and never written to the cache.
    if matches.len() > 1 {
        matches = search::enrich_duplicate_titles_with_accounts(matches).await?;
    }

    let selected = selection::select_item(matches)?;

    // Fetch credentials fresh via `item view`. The `item list` output is a
    // secret-free summary (pass-cli 2.0.3+), so credentials are never cached
    // and are only ever read for the single item the user selected.
    let (username, password) = pass_cli::get_item_credentials(&selected).await?;
    Ok(Credentials { username, password })
}
