use anyhow::{Context, Result};
use clap::Parser;
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

fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .spawn()
        .context("Failed to run wl-copy. Is wl-clipboard installed?")?;
    
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
    let matches = search::search_all_vaults_limited(vault_list.vaults, cli.query.clone()).await?;

    // Handle selection with fzf
    let selected = selection::select_item(matches)?;

    // Get credentials - fetch fresh if not available (from cache)
    let (username, password) = match (&selected.username, &selected.password) {
        (Some(u), Some(p)) => (Some(u.clone()), p.clone()),
        _ => {
            // Fetch fresh using pass-cli
            let pwd = pass_cli::get_password(&selected.vault_name, &selected.title).await?;
            let user = pass_cli::get_username(&selected.vault_name, &selected.title).await.ok();
            (user, pwd)
        }
    };

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
            eprintln!("✓ Username copied! Paste now, password in 3s...");
            thread::sleep(Duration::from_secs(3));
        }
        
        copy_to_clipboard(&password)?;
        eprintln!("✓ Password copied!");
    }

    Ok(())
}
