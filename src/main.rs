use anyhow::Result;
use clap::Parser;

mod models;
mod pass_cli;
mod search;
mod selection;

/// Fast Proton Pass password search
#[derive(Parser)]
#[command(name = "pp")]
#[command(about = "Search Proton Pass and print password to stdout")]
#[command(version)]
struct Cli {
    /// Search query (item name)
    query: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Fetch all vaults
    let vault_list = pass_cli::fetch_vaults().await?;

    // Search all vaults in parallel
    let matches = search::search_all_vaults(vault_list.vaults, cli.query.clone()).await?;

    // Handle selection
    let selected = selection::select_item(matches)?;

    // Get password
    let password = pass_cli::get_password(&selected.vault_name, &selected.title).await?;

    // Print to stdout
    println!("{}", password);

    Ok(())
}
