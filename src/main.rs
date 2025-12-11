use anyhow::Result;
use clap::Parser;

mod cache;
mod models;
mod pass_cli;
mod search;
mod selection;

/// Fast Proton Pass password search with intelligent caching
#[derive(Parser)]
#[command(name = "pp")]
#[command(about = "Search Proton Pass and print password to stdout")]
#[command(version)]
struct Cli {
    /// Search query (item name)
    query: String,
    
    /// Force refresh cache (ignore cached data)
    #[arg(short, long)]
    refresh: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Clear cache if refresh flag is set
    if cli.refresh {
        cache::clear_cache()?;
    }

    // Fetch all vaults
    let vault_list = pass_cli::fetch_vaults().await?;

    // Search with caching and limited concurrency (10 parallel max)
    // First run: ~8-10 seconds (fetches from pass-cli with 10 concurrent processes)
    // Cached runs: <1 second (reads from local cache, valid for 5 minutes)
    let matches = search::search_all_vaults_limited(vault_list.vaults, cli.query.clone()).await?;

    // Handle selection
    let selected = selection::select_item(matches)?;

    // Get password - ALWAYS fetch fresh (never cached for security!)
    // If password was in memory from fresh fetch, use it; otherwise fetch it
    let password = match selected.password {
        Some(pwd) => pwd,  // From fresh fetch (not from cache)
        None => {
            // Fetch password using pass-cli (happens when loaded from cache)
            pass_cli::get_password(&selected.vault_name, &selected.title).await?
        }
    };

    // Print to stdout
    println!("{}", password);

    Ok(())
}
