use anyhow::{Context, Result};
use colored::Colorize;
use tokio::process::Command;

use crate::models::{VaultList, ItemList, ItemView};

/// Heuristic: does pass-cli stderr indicate the user simply isn't logged in?
fn is_auth_error(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("authenticated") || s.contains("no session") || s.contains("not logged in")
}

/// Fetch all vaults using `pass-cli vault list --output json`
pub async fn fetch_vaults() -> Result<VaultList> {
    let output = Command::new("pass-cli")
        .args(["vault", "list", "--output", "json"])
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "{} pass-cli not found. Install it: https://protonpass.github.io/pass-cli/",
                    "✗".red()
                )
            } else {
                anyhow::anyhow!("Failed to execute pass-cli vault list: {}", e)
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_auth_error(&stderr) {
            anyhow::bail!(
                "{} Not logged in to Proton Pass. Run: {}",
                "✗".red(),
                "pass-cli login".bold()
            );
        }
        anyhow::bail!("pass-cli vault list failed: {}", stderr);
    }

    let stdout = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in pass-cli output")?;

    let vault_list: VaultList = serde_json::from_str(&stdout)
        .context("Failed to parse vault list JSON")?;

    Ok(vault_list)
}

/// List items in a specific vault using `pass-cli item list <vault> --output json`
pub async fn list_vault_items(vault_name: &str) -> Result<ItemList> {
    let output = Command::new("pass-cli")
        .args(["item", "list", vault_name, "--output", "json"])
        .output()
        .await
        .context(format!("Failed to execute pass-cli item list for vault '{}'", vault_name))?;

    // Don't fail on non-zero exit - vault might be empty or inaccessible
    // Just return empty list
    if !output.status.success() {
        return Ok(ItemList { items: Vec::new() });
    }

    let stdout = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in pass-cli item list output")?;

    let item_list: ItemList = serde_json::from_str(&stdout)
        .context(format!("Failed to parse item list JSON for vault '{}'", vault_name))?;

    Ok(item_list)
}

/// Fetch only the account identifier (username, falling back to email) for an item
/// using `pass-cli item view --field`. This reads a single field and never retrieves
/// the password, so it is safe to call for every match shown in the picker.
/// Returns `None` if the item has neither a username nor an email (e.g. a note).
pub async fn get_item_account(vault_name: &str, item_title: &str) -> Option<String> {
    for field in ["username", "email"] {
        if let Some(value) = view_single_field(vault_name, item_title, field).await {
            return Some(value);
        }
    }
    None
}

/// Run `pass-cli item view ... --field <field>`, which prints the raw field value.
/// Returns `None` on failure or when the field is absent/empty (pass-cli exits
/// non-zero for a field that isn't set on the item).
async fn view_single_field(vault_name: &str, item_title: &str, field: &str) -> Option<String> {
    let output = Command::new("pass-cli")
        .args([
            "item",
            "view",
            "--vault-name",
            vault_name,
            "--item-title",
            item_title,
            "--field",
            field,
        ])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Get both username and password in ONE call using `pass-cli item view --output json`
/// This replaces the old approach of making 2-3 separate --field calls
pub async fn get_item_credentials(vault_name: &str, item_title: &str) -> Result<(Option<String>, String)> {
    let output = Command::new("pass-cli")
        .args([
            "item", "view",
            "--vault-name", vault_name,
            "--item-title", item_title,
            "--output", "json"
        ])
        .output()
        .await
        .context(format!(
            "Failed to execute pass-cli item view for '{}' in vault '{}'",
            item_title, vault_name
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to get item: {}", stderr);
    }

    let stdout = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in item view output")?;

    let item_view: ItemView = serde_json::from_str(&stdout)
        .context("Failed to parse item view JSON")?;

    let username = item_view.item.content.get_username();
    let password = item_view.item.content.get_password()
        .context("No password found in item")?;

    Ok((username, password))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_authentication_errors() {
        assert!(is_auth_error("Error: This operation requires an authenticated client"));
        assert!(is_auth_error("Command is not logout there is no session"));
        assert!(!is_auth_error("failed to connect to host: timed out"));
    }
}
