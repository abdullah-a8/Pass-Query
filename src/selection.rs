use anyhow::{Context, Result};
use colored::Colorize;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::models::Match;
use crate::text::printable;

/// Select an item from search results using fzf for fuzzy selection
/// - 0 matches: return error
/// - 1 match: auto-select, unless `always_ask` (the user's earlier pick
///   failed, so another item must not be used without asking)
/// - 2+ matches: use fzf to select
pub fn select_item(matches: Vec<Match>, always_ask: bool) -> Result<Match> {
    match matches.len() {
        0 => anyhow::bail!("{} No items found matching query", "✗".red()),
        1 if !always_ask => Ok(matches.into_iter().next().unwrap()),
        _ => {
            // Build fzf input: "index|[vault] title — account"
            // The account identifier (username/email) is fetched per match for
            // disambiguation; it falls back to the item type when unavailable.
            let fzf_input: String = matches
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    format!(
                        "{}|{} {} {} {}",
                        i,
                        format!("[{}]", printable(&m.vault_name)).dimmed(),
                        printable(&m.title),
                        "—".dimmed(),
                        printable(m.picker_detail()).dimmed()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");

            // fzf shows and searches only the fields --with-nth names. Field 1
            // is the index; "2.." keeps a title that itself contains "|" whole.
            // The delimiter is a regex, escaped: fzf before 0.58 reads a bare
            // "|" as an empty alternation, not as a literal pipe.
            let mut fzf = Command::new("fzf")
                .args([
                    "--height=40%",
                    "--reverse",
                    "--delimiter=\\|",
                    "--with-nth=2..",
                    "--ansi",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .context(format!("{} Failed to run fzf. Is it installed?\n  Install: sudo apt install fzf  (or brew install fzf)", "✗".red()))?;

            // Write matches to fzf stdin
            if let Some(mut stdin) = fzf.stdin.take() {
                stdin.write_all(fzf_input.as_bytes())?;
            }

            let output = fzf.wait_with_output().context("fzf failed")?;

            if !output.status.success() {
                anyhow::bail!("{} Selection cancelled", "✗".red());
            }

            // Parse selected index from "index|[vault] title — username"
            let selected = crate::json::utf8(output.stdout, "fzf's selection")?;
            let index: usize = selected
                .split('|')
                .next()
                .context("Invalid fzf output")?
                .trim()
                .parse()
                .context("Failed to parse selection index")?;

            matches
                .into_iter()
                .nth(index)
                .with_context(|| format!("{} fzf returned an unknown selection", "✗".red()))
        }
    }
}
