use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::fmt;
use tokio::process::Command;

use crate::models::{ItemList, ItemView, Match, Vault, VaultList};
use crate::text::printable;

/// A pass-cli failure the user fixes by acting on their Proton Pass session,
/// recognised from pass-cli's stderr. It is returned as the error itself, so
/// callers can tell it apart from other failures with `downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProblem {
    /// The session lock (pass-cli 2.2+) is engaged.
    Locked,
    /// Proton ended the session, or pass-cli logged out by itself (its local
    /// key went missing, or PROTON_PASS_ENVIRONMENT changed).
    Invalidated,
    NotLoggedIn,
    /// The system keyring asked for permission and it was not given.
    KeyringDenied,
}

impl SessionProblem {
    fn from_stderr(stderr: &str) -> Option<Self> {
        let s = stderr.to_lowercase();
        // An ended session wins: pass-cli can print a lock diagnostic early
        // (during startup telemetry) and then exit because the session was
        // invalidated, and unlocking an ended session does not help.
        if s.contains("session has been invalidated")
            || s.contains("forcing logout")
            || s.contains("logging you out")
        {
            Some(Self::Invalidated)
        } else if s.contains("please authorize access to the system keyring") {
            Some(Self::KeyringDenied)
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
        let (problem, command) = match self {
            Self::Locked => (
                "Your Proton Pass session is locked.",
                "pass-cli session unlock",
            ),
            Self::Invalidated => ("Your Proton Pass session has ended.", "pass-cli login"),
            Self::NotLoggedIn => ("Not logged in to Proton Pass.", "pass-cli login"),
            Self::KeyringDenied => {
                return write!(
                    f,
                    "{} pass-cli was not allowed to use the system keyring. \
                     Unlock your keyring or allow the access request, then try again.",
                    "✗".red()
                );
            }
        };
        write!(f, "{} {problem} Run: {}", "✗".red(), command.bold())
    }
}

impl std::error::Error for SessionProblem {}

/// The item behind a match is gone (deleted, trashed, or its vault was
/// removed) since the match was found, typically in cached metadata. A
/// fresh search can resolve this; other read failures it cannot.
#[derive(Debug)]
pub struct ItemUnavailable {
    title: String,
    reason: &'static str,
}

impl ItemUnavailable {
    fn new(item: &Match, reason: &'static str) -> Self {
        ItemUnavailable {
            title: printable(&item.title),
            reason,
        }
    }
}

impl fmt::Display for ItemUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} '{}' {}. Run pq with {} to refresh the cache.",
            "✗".red(),
            self.title,
            self.reason,
            "-r".bold()
        )
    }
}

impl std::error::Error for ItemUnavailable {}

/// Whether a failed `item view` says the item, or the vault holding it, is
/// gone or no longer shared with this account: Proton's NotExists or
/// DeletedShare codes, a vault deleted between fetching the item and opening
/// it, or a bare HTTP status when pass-cli printed only that (it does for
/// item revisions).
fn item_is_gone(stderr: &str) -> bool {
    const MARKERS: [&str; 6] = [
        "Reason: NotExists",
        "Reason: DeletedShare",
        "Invalid status code: 403",
        "Invalid status code: 404",
        "Invalid status code: 410",
        "Invalid status code: 422",
    ];
    MARKERS.iter().any(|marker| stderr.contains(marker))
        || stderr
            .lines()
            .any(|line| line.contains("Share with id ") && line.ends_with(" not found"))
}

/// A `pass-cli` command with its logging off and killed if dropped. With
/// MUON_LOG_LEVEL or PASS_LOG_LEVEL set in the user's environment, pass-cli
/// logs whole HTTP requests, bearer tokens included, to stderr. A dropped
/// command (a search abandoned on a session problem) must not keep running.
fn pass_cli_command() -> Command {
    let mut command = Command::new("pass-cli");
    command
        .env("MUON_LOG_LEVEL", "off")
        .env("PASS_LOG_LEVEL", "off")
        .kill_on_drop(true);
    command
}

/// The error for a failed pass-cli call: its session problem when stderr
/// shows one, otherwise `what` with a summary of pass-cli's message.
fn failure(what: &str, stderr: &[u8]) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(stderr);
    match SessionProblem::from_stderr(&stderr) {
        Some(problem) => anyhow::Error::new(problem),
        None => anyhow::anyhow!("{what} failed: {}", summarize(&stderr)),
    }
}

/// What pq shows of a failed call's stderr: pass-cli's top-level error
/// message and the Proton error code, escaped and shortened. Never the raw
/// text, which can hold log lines with tokens or response bodies.
fn summarize(stderr: &str) -> String {
    const MAX_CHARS: usize = 200;
    let message = stderr
        .lines()
        .find_map(|line| line.trim().strip_prefix("Error: "))
        .map(str::trim);
    let reason = stderr.rfind("Reason: ").map(|start| {
        stderr[start + "Reason: ".len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>()
    });
    let summary = match (message, reason.filter(|r| !r.is_empty())) {
        (Some(message), Some(reason)) if !message.contains(&reason) => {
            format!("{message} ({reason})")
        }
        (Some(message), _) => message.to_string(),
        (None, Some(reason)) => format!("Reason: {reason}"),
        (None, None) => "pass-cli reported no error message".to_string(),
    };
    printable(&summary).chars().take(MAX_CHARS).collect()
}

/// The oldest pass-cli whose `item list` JSON is the secret-free summary pq
/// parses (title and item_type at the top level).
const MIN_VERSION: (u32, u32, u32) = (2, 0, 3);

/// A warning when the installed pass-cli is older than pq supports. Best
/// effort: no warning when pass-cli is missing or its version is unreadable.
pub async fn version_warning() -> Option<String> {
    let output = pass_cli_command().arg("--version").output().await.ok()?;
    let version = parse_version(&String::from_utf8_lossy(&output.stdout))?;
    (version < MIN_VERSION).then(|| {
        let show = |(major, minor, patch): (u32, u32, u32)| format!("{major}.{minor}.{patch}");
        format!(
            "{} pass-cli {} is older than {}, the oldest version pq supports; searches may fail. \
             Update it: https://protonpass.github.io/pass-cli/",
            "⚠".yellow(),
            show(version),
            show(MIN_VERSION)
        )
    })
}

/// The first `major.minor.patch` word in `pass-cli --version` output
/// ("Proton Pass CLI 2.5.1 (0a1b2c3)").
fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    text.split_whitespace().find_map(|word| {
        let mut parts = word.split('.');
        let version = (
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        );
        parts.next().is_none().then_some(version)
    })
}

/// Fetch all vaults using `pass-cli vault list --output json`
pub async fn fetch_vaults() -> Result<VaultList> {
    let output = pass_cli_command()
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

    let output = pass_cli_command()
        .args(args)
        .output()
        .await
        .context(format!(
            "Failed to execute pass-cli item list for vault '{}'",
            printable(&vault.name)
        ))?;

    if !output.status.success() {
        return Err(failure(
            &format!("pass-cli item list for '{}'", printable(&vault.name)),
            &output.stderr,
        ));
    }

    let stdout =
        String::from_utf8(output.stdout).context("Invalid UTF-8 in pass-cli item list output")?;

    let item_list: ItemList = serde_json::from_str(&stdout).context(format!(
        "Failed to parse item list JSON for vault '{}'",
        printable(&vault.name)
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

/// The `item view` arguments naming the picked item by its share and item
/// IDs. Never by vault name and title: a title can match another item, whose
/// credentials pq would then copy.
fn item_view_args(item: &Match) -> Result<Vec<String>> {
    let (Some(share_id), Some(item_id)) = (item.share_id.as_deref(), item.item_id.as_deref())
    else {
        bail!(
            "{} pass-cli listed '{}' without its IDs, so pq cannot fetch it safely. \
             Update pass-cli, then run pq with {}.",
            "✗".red(),
            printable(&item.title),
            "-r".bold()
        );
    };
    Ok(vec![
        "item".to_string(),
        "view".to_string(),
        format!("--share-id={share_id}"),
        format!("--item-id={item_id}"),
    ])
}

/// Run `pass-cli item view ... --field <field>`, which prints the raw field value.
/// `None` when the field is absent or empty (pass-cli exits non-zero for a field
/// that isn't set) or the read fails for another reason: the picker then falls
/// back to another label. A session problem is returned as the error.
async fn view_single_field(item: &Match, field: &str) -> Result<Option<String>> {
    let mut args = item_view_args(item)?;
    args.extend(["--field".to_string(), field.to_string()]);

    let output = pass_cli_command()
        .args(args)
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
    let mut args = item_view_args(item)?;
    args.extend(["--output".to_string(), "json".to_string()]);

    let output = pass_cli_command()
        .args(args)
        .output()
        .await
        .context(format!(
            "Failed to execute pass-cli item view for '{}' in vault '{}'",
            printable(&item.title),
            printable(&item.vault_name)
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if SessionProblem::from_stderr(&stderr).is_none() && item_is_gone(&stderr) {
            return Err(ItemUnavailable::new(item, "is no longer available").into());
        }
        return Err(failure(
            &format!("pass-cli item view for '{}'", printable(&item.title)),
            &output.stderr,
        ));
    }

    let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in item view output")?;

    let item_view: ItemView =
        serde_json::from_str(&stdout).context("Failed to parse item view JSON")?;
    if !item_view.item.is_active() {
        return Err(ItemUnavailable::new(item, "is in the trash").into());
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
            (
                "Please authorize access to the system keyring",
                Some(SessionProblem::KeyringDenied),
            ),
            (
                "Error: Local encryption key not found but local data exists. Forcing logout for security.",
                Some(SessionProblem::Invalidated),
            ),
            (
                "PROTON_PASS_ENVIRONMENT has switched! Logging you out. Please log back in again",
                Some(SessionProblem::Invalidated),
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
    fn recognises_an_item_that_no_longer_exists() {
        assert!(item_is_gone(
            "Error: Error retrieving item\n\nCaused by:\n    Could not perform operation. Reason: NotExists"
        ));
        assert!(item_is_gone("Reason: DeletedShare"));
        assert!(item_is_gone("Error: Invalid status code: 404 Not Found"));
        assert!(item_is_gone("Error: Invalid status code: 403 Forbidden"));
        assert!(item_is_gone("Error: Invalid status code: 410 Gone"));
        assert!(item_is_gone(
            "Error: Invalid status code: 422 Unprocessable Entity"
        ));
        assert!(item_is_gone(
            "Error: Error retrieving item\n\nCaused by:\n    Share with id abc not found"
        ));
        assert!(!item_is_gone(
            "Error: Invalid status code: 500 Internal Server Error"
        ));
        assert!(!item_is_gone(
            "Error: Invalid status code: 401 Unauthorized"
        ));
        assert!(!item_is_gone("Error: Error opening item"));
        assert!(!item_is_gone("Reason: NotAllowed"));
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
        assert_eq!(err.to_string(), "pass-cli vault list failed: boom");
    }

    #[test]
    fn stderr_is_summarised_to_the_error_and_its_reason() {
        let stderr = "DEBUG muon: Authorization: Bearer tok\n\
            Error: Error listing items\n\nCaused by:\n    0: Error fetching items\n    \
            1: Could not perform operation. Reason: NotFound\n";
        assert_eq!(summarize(stderr), "Error listing items (NotFound)");
        assert_eq!(summarize("Reason: NotFound"), "Reason: NotFound");
        assert_eq!(
            summarize("thread panicked"),
            "pass-cli reported no error message"
        );
        assert_eq!(summarize("Error: a\u{1b}[2Kb"), "a\\u{1b}[2Kb");
        assert_eq!(summarize(&format!("Error: {}", "x".repeat(500))).len(), 200);
    }

    #[test]
    fn parses_the_version_from_pass_cli_version_output() {
        assert_eq!(
            parse_version("Proton Pass CLI 2.5.1 (0a1b2c3)\n"),
            Some((2, 5, 1))
        );
        assert_eq!(parse_version("Proton Pass CLI 2.10.0"), Some((2, 10, 0)));
        assert_eq!(parse_version("Proton Pass CLI nightly"), None);
        assert_eq!(parse_version("Proton Pass CLI 2.5.1-beta"), None);
        assert_eq!(parse_version("Proton Pass CLI 2.5"), None);
        assert!((2, 0, 2) < MIN_VERSION && (2, 10, 0) > MIN_VERSION);
    }

    #[test]
    fn item_view_args_pass_ids_as_single_equals_args() {
        let args = item_view_args(&item_ref(Some("-item-id"), Some("-share-id"))).unwrap();
        assert!(args.contains(&"--share-id=-share-id".to_string()));
        assert!(args.contains(&"--item-id=-item-id".to_string()));
    }

    #[test]
    fn an_item_without_ids_is_never_looked_up_by_title() {
        // A title can match another item; only IDs name the picked one.
        for item in [
            item_ref(None, None),
            item_ref(Some("item-1"), None),
            item_ref(None, Some("share-1")),
        ] {
            let err = item_view_args(&item).unwrap_err().to_string();
            assert!(err.contains("'reddit'"), "{err}");
        }
    }
}
