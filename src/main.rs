use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

mod cache;
mod lookup;
mod models;
mod pass_cli;
mod search;
mod selection;
mod text;

/// Fast Proton Pass password search with intelligent caching
#[derive(Parser)]
#[command(name = "pq")]
#[command(about = "Search Proton Pass and copy credentials to clipboard")]
#[command(long_about = "Fast fuzzy password search for Proton Pass CLI.

EXAMPLES:
    pq reddit               Search logins for reddit
    pq gmail -p             Search gmail, print to stdout
    pq github -r            Refresh cache, search github
    pq aws -a               Search all item types, not just logins")]
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

    /// Search all item types (default: logins only)
    #[arg(short, long)]
    all: bool,
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

/// Print mode. On a terminal, control characters in a credential are shown
/// escaped (with a warning), so a crafted value cannot drive the terminal; to
/// a pipe or file the values are written exactly.
fn print_credentials(username: Option<&str>, password: &str) {
    let to_terminal = std::io::stdout().is_terminal();
    let mut escaped = false;
    if let Some(username) = username {
        let (shown, was_escaped) = text::for_stdout(username, to_terminal);
        escaped |= was_escaped;
        println!("Username: {shown}");
    }
    let (shown, was_escaped) = text::for_stdout(password, to_terminal);
    escaped |= was_escaped;
    println!("Password: {shown}");
    if escaped {
        eprintln!(
            "{} The credentials contain control characters, shown escaped. \
             Use clipboard mode, or pipe the output, for the exact value.",
            "⚠".yellow()
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let lookup::Credentials { username, password } =
        lookup::find_credentials(&cli.query, !cli.all, cli.refresh).await?;

    if cli.print {
        print_credentials(username.as_deref(), &password);
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
