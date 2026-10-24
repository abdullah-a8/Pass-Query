use anyhow::{Context, Result};
use colored::Colorize;
use std::fmt;
use tokio::process::Command;

use crate::models::{ItemList, ItemView, Match, Vault, VaultList};

/// A pass-cli failure the user fixes by acting on their Proton Pass session,
/// recognised from pass-cli's stderr. It is returned as the error itself, so
/// callers can tell it apart from other failures with `downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProblem {
    /// The session lock (pass-cli 2.2+) is engaged.
    Locked,
    /// Proton ended the session; pass-cli has logged out.
    Invalidated,
    NotLoggedIn,
}

impl SessionProblem {
    fn from_stderr(stderr: &str) -> Option<Self> {
        let s = stderr.to_lowercase();
        // An ended session wins: pass-cli can print a lock diagnostic early
        // (during startup telemetry) and then exit because the session was
        // invalidated, and unlocking an ended session does not help.
        if s.contains("session has been invalidated") {
            Some(Self::Invalidated)
        } else if s.contains("session is locked") || s.contains("sessionlocked") {
            Some(Self::Locked)
        } else if s.contains("requires an authenticated client")
            || s.contains("no session")
            || s.contains("not logged in")
        {
            Some(Self::NotLoggedIn)
        } else {
            None
        }
    }
}

impl fmt::Display for SessionProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (problem, hint) = match self {
            Self::Locked => (
                "Your Proton Pass session is locked.",
                "pass-cli session unlock",
            ),
            Self::Invalidated => ("Your Proton Pass session has ended.", "pass-cli login"),
            Self::NotLoggedIn => ("Not logged in to Proton Pass.", "pass-cli login"),
        };
        write!(f, "{} {problem} Run: {}", "✗".red(), hint.bold())
    }
}

impl std::error::Error for SessionProblem {}

/// The error for a failed pass-cli call: its session problem when stderr
/// shows one, otherwise `what` with pass-cli's own message.
fn failure(what: &str, stderr: &[u8]) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(stderr);
    match SessionProblem::from_stderr(&stderr) {
        Some(problem) => anyhow::Error::new(problem),
        None => anyhow::anyhow!("{what} failed: {}", stderr.trim_end()),
    }
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
        return Err(failure("pass-cli vault list", &output.stderr));
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

    // Killed if the search is abandoned (e.g. on a session problem elsewhere).
    let output = Command::new("pass-cli")
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .context(format!(
            "Failed to execute pass-cli item list for vault '{}'",
            vault.name
        ))?;

    if !output.status.success() {
        return Err(failure(
            &format!("pass-cli item list for '{}'", vault.name),
            &output.stderr,
        ));
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
/// Returns `None` if the item has neither a username nor an email (e.g. a note),
/// and an error only for a session problem, which the user has to fix.
pub async fn get_item_account(item: &Match) -> Result<Option<String>> {
    for field in ["username", "email"] {
        if let Some(value) = view_single_field(item, field).await? {
            return Ok(Some(value));
        }
    }
    Ok(None)
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
/// `None` when the field is absent or empty (pass-cli exits non-zero for a field
/// that isn't set) or the read fails for another reason: the picker then falls
/// back to another label. A session problem is returned as the error.
async fn view_single_field(item: &Match, field: &str) -> Result<Option<String>> {
    let mut args = item_view_args(item);
    args.extend(["--field".to_string(), field.to_string()]);

    let output = Command::new("pass-cli")
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .context("Failed to execute pass-cli item view")?;

    if !output.status.success() {
        return match failure("pass-cli item view", &output.stderr).downcast::<SessionProblem>() {
            Ok(problem) => Err(problem.into()),
            Err(_) => Ok(None),
        };
    }

    let value = String::from_utf8_lossy(&output.stdout);
    let trimmed = value.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
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
        return Err(failure(
            &format!("pass-cli item view for '{}'", item.title),
            &output.stderr,
        ));
    }

    let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in item view output")?;

    let item_view: ItemView =
        serde_json::from_str(&stdout).context("Failed to parse item view JSON")?;
    if !item_view.item.is_active() {
        anyhow::bail!(
            "{} '{}' is in the trash. Run pq with {} to refresh the cache.",
            "✗".red(),
            item.title,
            "-r".bold()
        );
    }

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
    fn recognises_session_problems_in_pass_cli_stderr() {
        let cases = [
            (
                "Session is locked. Please unlock your session and try again.\nError: Error listing vaults",
                Some(SessionProblem::Locked),
            ),
            (
                "Error: Could not perform operation. Reason: SessionLocked",
                Some(SessionProblem::Locked),
            ),
            (
                "Your session has been invalidated and you have been logged out automatically.",
                Some(SessionProblem::Invalidated),
            ),
            (
                "Error: This operation requires an authenticated client",
                Some(SessionProblem::NotLoggedIn),
            ),
            (
                "Command is not logout there is no session",
                Some(SessionProblem::NotLoggedIn),
            ),
            ("failed to connect to host: timed out", None),
            ("Error: Could not perform operation. Reason: NotFound", None),
        ];
        for (stderr, expected) in cases {
            assert_eq!(SessionProblem::from_stderr(stderr), expected, "{stderr}");
        }
    }

    #[test]
    fn an_ended_session_wins_over_an_earlier_lock_diagnostic() {
        // pass-cli can report the lock during startup telemetry, then exit
        // because the session was invalidated: the session has ended.
        let stderr = "Session is locked. Please unlock your session and try again.\n\
            Your session has been invalidated and you have been logged out automatically.\n\
            Please log in again with: pass login";
        assert_eq!(
            SessionProblem::from_stderr(stderr),
            Some(SessionProblem::Invalidated)
        );
    }

    #[test]
    fn failure_keeps_session_problems_as_their_own_error() {
        let err = failure("pass-cli vault list", b"Reason: SessionLocked");
        assert_eq!(
            err.downcast_ref::<SessionProblem>(),
            Some(&SessionProblem::Locked)
        );

        let err = failure("pass-cli vault list", b"Error: boom\n");
        assert!(err.downcast_ref::<SessionProblem>().is_none());
        assert_eq!(err.to_string(), "pass-cli vault list failed: Error: boom");
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
