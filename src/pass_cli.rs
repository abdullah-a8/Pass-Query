use anyhow::{Context, Result};
use tokio::process::Command;

use crate::models::{VaultList, ItemList, ItemView};

/// Fetch all vaults using `pass-cli vault list --output json`
pub async fn fetch_vaults() -> Result<VaultList> {
    let output = Command::new("pass-cli")
        .args(["vault", "list", "--output", "json"])
        .output()
        .await
        .context("Failed to execute pass-cli vault list")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
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
