use anyhow::{Context, Result};
use std::io::{self, Write};

use crate::models::Match;

/// Select an item from search results
/// - 0 matches: return error
/// - 1 match: auto-select
/// - 2+ matches: prompt user to choose
pub fn select_item(matches: Vec<Match>) -> Result<Match> {
    match matches.len() {
        0 => anyhow::bail!("No items found matching query"),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => {
            // Print matches with numbers
            eprintln!("Multiple matches found:");
            for (i, m) in matches.iter().enumerate() {
                eprintln!("{}. [{}] {}", i + 1, m.vault_name, m.title);
            }

            // Prompt for selection
            eprint!("Select (1-{}): ", matches.len());
            io::stderr().flush()?;

            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .context("Failed to read user input")?;

            let choice: usize = input
                .trim()
                .parse()
                .context("Invalid number entered")?;

            if choice < 1 || choice > matches.len() {
                anyhow::bail!("Selection out of range (must be 1-{})", matches.len());
            }

            Ok(matches.into_iter().nth(choice - 1).unwrap())
        }
    }
}
