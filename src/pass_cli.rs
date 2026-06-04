use anyhow::{Context, Result};
use colored::Colorize;
use tokio::process::Command;

use crate::models::{ItemList, ItemView, Match, Vault, VaultList};

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

    let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in pass-cli output")?;

    let vault_list: VaultList =
        serde_json::from_str(&stdout).context("Failed to parse vault list JSON")?;

    Ok(vault_list)
}

/// List items in a specific vault using `pass-cli item list --output json`.
/// Login-only searches ask pass-cli to filter before pq parses/caches results.
pub async fn list_vault_items(vault: &Vault, login_only: bool) -> Result<ItemList> {
    let mut args = vec![
        "item".to_string(),
        "list".to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];

    if login_only {
        args.extend(["--filter-type".to_string(), "login".to_string()]);
    }

    if let Some(share_id) = vault.share_id.as_deref() {
        args.push(format!("--share-id={share_id}"));
    } else {
        args.push("--".to_string());
        args.push(vault.name.clone());
    }

    let output = Command::new("pass-cli")
        .args(args)
        .output()
        .await
        .context(format!(
            "Failed to execute pass-cli item list for vault '{}'",
            vault.name
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("pass-cli item list failed for '{}': {}", vault.name, stderr);
    }

    let stdout =
        String::from_utf8(output.stdout).context("Invalid UTF-8 in pass-cli item list output")?;

    let item_list: ItemList = serde_json::from_str(&stdout).context(format!(
        "Failed to parse item list JSON for vault '{}'",
        vault.name
    ))?;

    Ok(item_list)
}

/// Fetch only the account identifier (username, falling back to email) for an item
/// using `pass-cli item view --field`. This reads a single field and never retrieves
/// the password, so it is safe to call for every match shown in the picker.
/// Returns `None` if the item has neither a username nor an email (e.g. a note).
pub async fn get_item_account(item: &Match) -> Option<String> {
    for field in ["username", "email"] {
        if let Some(value) = view_single_field(item, field).await {
            return Some(value);
        }
    }
    None
}

fn item_view_args(item: &Match) -> Vec<String> {
    let mut args = vec!["item".to_string(), "view".to_string()];

    if let Some(share_id) = item.share_id.as_deref() {
        args.push(format!("--share-id={share_id}"));
    } else {
        args.push(format!("--vault-name={}", item.vault_name));
    }

    if let Some(item_id) = item.item_id.as_deref() {
        args.push(format!("--item-id={item_id}"));
    } else {
        args.push(format!("--item-title={}", item.title));
    }

    args
}

/// Run `pass-cli item view ... --field <field>`, which prints the raw field value.
/// Returns `None` on failure or when the field is absent/empty (pass-cli exits
/// non-zero for a field that isn't set on the item).
async fn view_single_field(item: &Match, field: &str) -> Option<String> {
    let mut args = item_view_args(item);
    args.extend(["--field".to_string(), field.to_string()]);

    let output = Command::new("pass-cli").args(args).output().await.ok()?;

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
pub async fn get_item_credentials(item: &Match) -> Result<(Option<String>, String)> {
    let mut args = item_view_args(item);
    args.extend(["--output".to_string(), "json".to_string()]);

    let output = Command::new("pass-cli")
        .args(args)
        .output()
        .await
        .context(format!(
            "Failed to execute pass-cli item view for '{}' in vault '{}'",
            item.title, item.vault_name
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to get item: {}", stderr);
    }

    let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in item view output")?;

    let item_view: ItemView =
        serde_json::from_str(&stdout).context("Failed to parse item view JSON")?;

    let username = item_view.item.content.get_username();
    let password = item_view
        .item
        .content
        .get_password()
        .context("No password found in item")?;

    Ok((username, password))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item_ref(item_id: Option<&str>, share_id: Option<&str>) -> Match {
        Match {
            item_id: item_id.map(|s| s.to_string()),
            share_id: share_id.map(|s| s.to_string()),
            title: "reddit".to_string(),
            vault_name: "Personal".to_string(),
            item_type: "login".to_string(),
            account: None,
        }
    }

    #[test]
    fn detects_authentication_errors() {
        assert!(is_auth_error(
            "Error: This operation requires an authenticated client"
        ));
        assert!(is_auth_error("Command is not logout there is no session"));
        assert!(!is_auth_error("failed to connect to host: timed out"));
    }

    #[test]
    fn item_view_args_pass_ids_as_single_equals_args() {
        let args = item_view_args(&item_ref(Some("-item-id"), Some("-share-id")));
        assert!(args.contains(&"--share-id=-share-id".to_string()));
        assert!(args.contains(&"--item-id=-item-id".to_string()));
    }

    #[test]
    fn item_view_args_falls_back_to_title_without_positional_parsing() {
        let args = item_view_args(&item_ref(None, None));
        assert!(args.contains(&"--vault-name=Personal".to_string()));
        assert!(args.contains(&"--item-title=reddit".to_string()));
    }
}
