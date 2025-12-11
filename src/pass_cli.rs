use anyhow::{Context, Result};
use tokio::process::Command;

use crate::models::{VaultList, ItemList};

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

/// Get password for a specific item using `pass-cli item view`
pub async fn get_password(vault_name: &str, item_title: &str) -> Result<String> {
    let output = Command::new("pass-cli")
        .args([
            "item", "view",
            "--vault-name", vault_name,
            "--item-title", item_title,
            "--field", "password"
        ])
        .output()
        .await
        .context(format!(
            "Failed to execute pass-cli item view for '{}' in vault '{}'",
            item_title, vault_name
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to get password: {}", stderr);
    }

    let password = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in password output")?;

    Ok(password.trim().to_string())
}

/// Get username for a specific item using `pass-cli item view`
pub async fn get_username(vault_name: &str, item_title: &str) -> Result<String> {
    // Try username field first
    let output = Command::new("pass-cli")
        .args([
            "item", "view",
            "--vault-name", vault_name,
            "--item-title", item_title,
            "--field", "username"
        ])
        .output()
        .await?;

    if output.status.success() {
        let username = String::from_utf8(output.stdout)?.trim().to_string();
        if !username.is_empty() {
            return Ok(username);
        }
    }

    // Fallback to email field
    let output = Command::new("pass-cli")
        .args([
            "item", "view",
            "--vault-name", vault_name,
            "--item-title", item_title,
            "--field", "email"
        ])
        .output()
        .await?;

    if output.status.success() {
        let email = String::from_utf8(output.stdout)?.trim().to_string();
        if !email.is_empty() {
            return Ok(email);
        }
    }

    anyhow::bail!("No username or email found")
}
