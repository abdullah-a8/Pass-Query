use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::io::{BufRead, IsTerminal};
use std::time::Duration;

mod cache;
mod clipboard;
mod lookup;
mod models;
mod pass_cli;
mod search;
mod selection;
mod text;

use clipboard::Clipboard;
use lookup::Credentials;

/// Fast Proton Pass password search with intelligent caching
#[derive(Parser)]
#[command(name = "pq")]
#[command(about = "Search Proton Pass and copy credentials to clipboard")]
#[command(long_about = "Fast fuzzy password search for Proton Pass CLI.

Copies the username, waits for Enter, then copies the password, which is
cleared from the clipboard after --clear-after seconds unless something
else has been copied since.

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

    /// Clear the copied password from the clipboard after this many seconds (0: never)
    #[arg(long, value_name = "SECONDS", default_value_t = 45)]
    clear_after: u64,
}

fn main() -> Result<()> {
    let mut args = std::env::args();
    if args.nth(1).as_deref() == Some(clipboard::CLEAR_HELPER_ARG) {
        return clipboard::run_clear_helper(args);
    }

    let cli = Cli::parse();
    // Find the clipboard first, so a session without one fails before the search.
    let clipboard = if cli.print {
        None
    } else {
        Some(Clipboard::detect()?)
    };

    let credentials = tokio::runtime::Runtime::new()?.block_on(lookup::find_credentials(
        &cli.query,
        !cli.all,
        cli.refresh,
    ))?;

    match clipboard {
        None => print_credentials(&credentials),
        Some(clipboard) => copy_credentials(&clipboard, &credentials, cli.clear_after)?,
    }
    Ok(())
}

/// Print mode. On a terminal, control characters in a credential are shown
/// escaped (with a warning), so a crafted value cannot drive the terminal; to
/// a pipe or file the values are written exactly.
fn print_credentials(credentials: &Credentials) {
    let to_terminal = std::io::stdout().is_terminal();
    let mut escaped = false;
    if let Some(username) = &credentials.username {
        let (shown, was_escaped) = text::for_stdout(username, to_terminal);
        escaped |= was_escaped;
        println!("Username: {shown}");
    }
    let (shown, was_escaped) = text::for_stdout(&credentials.password, to_terminal);
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

/// Copy the username, wait for Enter, then copy the password and schedule
/// its removal from the clipboard.
fn copy_credentials(
    clipboard: &Clipboard,
    credentials: &Credentials,
    clear_after: u64,
) -> Result<()> {
    if let Some(username) = &credentials.username {
        clipboard.copy(username)?;
        eprint!(
            "{} Username copied. Press Enter to copy the password... ",
            "✓".green()
        );
        wait_for_enter()?;
    }

    // The clear helper starts first, so the password is cleared even if pq
    // dies or the clipboard tool hangs once the password is on the clipboard.
    let clearing = (clear_after > 0)
        .then(|| clipboard.clear_later(&credentials.password, Duration::from_secs(clear_after)));
    clipboard.copy(&credentials.password)?;
    match clearing {
        None => eprintln!("{} Password copied", "✓".green()),
        Some(Ok(pending)) => {
            pending.copied();
            eprintln!("{} Password copied (clears in {clear_after}s)", "✓".green());
        }
        Some(Err(e)) => eprintln!(
            "{} Password copied, but clearing it later failed to start: {e:#}",
            "⚠".yellow()
        ),
    }
    Ok(())
}

/// Read one line from stdin. At end of input (stdin not a terminal) carry on.
fn wait_for_enter() -> Result<()> {
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        eprintln!();
    }
    Ok(())
}
