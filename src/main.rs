use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use std::process::{Command, Stdio};
use std::io::Write;
use std::time::Duration;
use std::thread;

mod cache;
mod models;
mod pass_cli;
mod search;
mod selection;

/// Fast Proton Pass password search with intelligent caching
#[derive(Parser)]
#[command(name = "pq")]
#[command(about = "Search Proton Pass and copy credentials to clipboard")]
#[command(long_about = "Fast fuzzy password search for Proton Pass CLI.

EXAMPLES:
    pq reddit               Search for reddit
    pq gmail -p             Search gmail, print to stdout
    pq github -r            Refresh cache, search github")]
#[command(version)]
struct Cli {
    /// Search query (item name)
    query: String,

    /// Force refresh cache (ignore cached data)
    #[arg(short, long)]
    refresh: bool,

    /// Print to stdout instead of copying to clipboard
    #[arg(short, long)]
    print: bool,
}

/// Copy text to the system clipboard using the platform's native tool:
/// `pbcopy` on macOS, `wl-copy` (wl-clipboard) on Linux/Wayland.
fn copy_to_clipboard(text: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let (tool, install_hint) = ("pbcopy", "pbcopy ships with macOS.");
    #[cfg(not(target_os = "macos"))]
    let (tool, install_hint) = ("wl-copy", "Install: sudo apt install wl-clipboard");

    let mut child = Command::new(tool)
        .stdin(Stdio::piped())
        .spawn()
        .context(format!(
            "{} Failed to run {tool}. {install_hint}",
            "✗".red()
        ))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }

    child.wait()?;
    Ok(())
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
    let mut matches = search::search_all_vaults_limited(vault_list.vaults, cli.query.clone()).await?;

    // When several items match, fetch each one's account identifier (username/email)
    // so the picker can tell them apart. This reads only that field, never the password.
    if matches.len() > 1 {
        matches = search::enrich_with_accounts(matches).await;
    }

    // Handle selection with fzf
    let selected = selection::select_item(matches)?;

    // Fetch credentials fresh via `item view`. The `item list` output is a
    // secret-free summary (pass-cli 2.0.3+), so credentials are never cached
    // and are only ever read for the single item the user selected.
    let (username, password) =
        pass_cli::get_item_credentials(&selected.vault_name, &selected.title).await?;

    if cli.print {
        // Print mode: output to stdout
        if let Some(ref u) = username {
            println!("Username: {}", u);
        }
        println!("Password: {}", password);
    } else {
        // Clipboard mode: copy username then password
        if let Some(ref u) = username {
            copy_to_clipboard(u)?;
            eprintln!("{} Username copied!", "✓".green());
            thread::sleep(Duration::from_millis(500));
        }

        copy_to_clipboard(&password)?;
        eprintln!("{} Password copied!", "✓".green());
    }

    Ok(())
}
