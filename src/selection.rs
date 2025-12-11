use anyhow::{Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

use crate::models::Match;

/// Select an item from search results using fzf for fuzzy selection
/// - 0 matches: return error
/// - 1 match: auto-select
/// - 2+ matches: use fzf to select
pub fn select_item(matches: Vec<Match>) -> Result<Match> {
    match matches.len() {
        0 => anyhow::bail!("No items found matching query"),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => {
            // Build fzf input: "index|[vault] title"
            let fzf_input: String = matches
                .iter()
                .enumerate()
                .map(|(i, m)| format!("{}|[{}] {}", i, m.vault_name, m.title))
                .collect::<Vec<_>>()
                .join("\n");

            // Run fzf
            let mut fzf = Command::new("fzf")
                .args(["--height=40%", "--reverse", "--delimiter=|", "--with-nth=2"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .context("Failed to run fzf. Is it installed?")?;

            // Write matches to fzf stdin
            if let Some(mut stdin) = fzf.stdin.take() {
                stdin.write_all(fzf_input.as_bytes())?;
            }

            let output = fzf.wait_with_output().context("fzf failed")?;

            if !output.status.success() {
                anyhow::bail!("Selection cancelled");
            }

            // Parse selected index from "index|[vault] title"
            let selected = String::from_utf8(output.stdout)?;
            let index: usize = selected
                .split('|')
                .next()
                .context("Invalid fzf output")?
                .trim()
                .parse()
                .context("Failed to parse selection index")?;

            Ok(matches.into_iter().nth(index).unwrap())
        }
    }
}
