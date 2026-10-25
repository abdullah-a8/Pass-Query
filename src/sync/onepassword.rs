//! The 1Password side of pq-sync, through `op`.
//!
//! Unattended runs authenticate with a service account token in the
//! environment (`OP_SERVICE_ACCOUNT_TOKEN`); without one, `op` uses the
//! desktop app's sign-in (for a first bulk run at the keyboard). Item JSON
//! goes in through stdin, never as assignment arguments, which other
//! processes can see. `OP_DEBUG` is cleared so `op` never logs request
//! detail. Errors are summarised to `op`'s message, escaped.

use anyhow::{Result, bail};
use serde::Deserialize;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use super::api::{OpApi, OpSummary, Vault, op_requests};
use super::exec::{Command, Output};
use super::op_json::{self, OpItem, RawItem};
use super::secret::{SecretString, parse_json};
use crate::text::printable;

const TIMEOUT: Duration = Duration::from_secs(120);

pub struct OnePassword {
    pub program: PathBuf,
    /// A service account token; `None` uses the desktop app's sign-in.
    pub token: Option<SecretString>,
    requests: usize,
}

/// A failure the run cannot work around by skipping one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpProblem {
    /// 1Password refused more requests for now (HTTP 429).
    RateLimited,
    /// The token was refused, or `op` is not signed in.
    NotSignedIn,
}

impl fmt::Display for OpProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OpProblem::RateLimited => {
                "1Password's rate limit was reached; the rest waits for the next run"
            }
            OpProblem::NotSignedIn => {
                "1Password refused the request: the service account token is missing, \
                 expired or revoked (or op is not signed in). Run: pq-sync setup"
            }
        })
    }
}

impl std::error::Error for OpProblem {}

/// `op`'s own message from its stderr (`[ERROR] 2026/10/25 10:00:00 <msg>`),
/// escaped and shortened.
fn summarize(stderr: &[u8]) -> String {
    const MAX_CHARS: usize = 200;
    let stderr = String::from_utf8_lossy(stderr);
    let message = stderr
        .lines()
        .rev()
        .find_map(|line| {
            let rest = line.split_once("[ERROR]")?.1.trim_start();
            // Skip the date and the time.
            let mut words = rest.splitn(3, ' ');
            let (date, time, message) = (words.next()?, words.next()?, words.next());
            let looks_dated = date.contains('/') && time.contains(':');
            Some(match (looks_dated, message) {
                (true, Some(message)) => message.trim().to_string(),
                _ => rest.trim().to_string(),
            })
        })
        .unwrap_or_else(|| "op reported no error message".to_string());
    printable(&message).chars().take(MAX_CHARS).collect()
}

fn problem(stderr: &[u8]) -> Option<OpProblem> {
    let text = String::from_utf8_lossy(stderr).to_lowercase();
    if text.contains("(429)")
        || text.contains("status 429")
        || text.contains("rate limit")
        || text.contains("rate-limited")
        || text.contains("too many requests")
    {
        Some(OpProblem::RateLimited)
    } else if text.contains("not currently signed in")
        || text.contains("no accounts configured")
        || text.contains("authorization prompt dismissed")
        || text.contains("invalid service account token")
        || text.contains("service account token is invalid")
        || text.contains("(401)")
        || text.contains("unauthorized")
    {
        Some(OpProblem::NotSignedIn)
    } else {
        None
    }
}

fn is_missing(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr).to_lowercase();
    text.contains("isn't an item") || text.contains("item not found") || text.contains("(404)")
}

fn failure(what: &str, stderr: &[u8]) -> anyhow::Error {
    match problem(stderr) {
        Some(problem) => anyhow::Error::new(problem),
        None => anyhow::anyhow!("{what} failed: {}", summarize(stderr)),
    }
}

#[derive(Deserialize)]
struct VaultJson {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct ItemJson {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    version: u64,
    /// Absent or ACTIVE for a live item; ARCHIVED or DELETED when op was
    /// told to include those (OP_INCLUDE_ARCHIVE, for one).
    #[serde(default)]
    state: Option<String>,
}

impl OnePassword {
    pub fn new(program: impl Into<PathBuf>, token: Option<SecretString>) -> Self {
        OnePassword {
            program: program.into(),
            token,
            requests: 0,
        }
    }

    fn command(&self) -> Command {
        // Nothing of Proton's (its access token above all) reaches op.
        let mut command = Command::new(&self.program, TIMEOUT)
            .env_remove_prefix("PROTON_PASS_")
            .env_remove("OP_DEBUG")
            .env_remove("OP_FORMAT")
            .env_remove("OP_SERVICE_ACCOUNT_TOKEN");
        if let Some(token) = &self.token {
            command = command.env("OP_SERVICE_ACCOUNT_TOKEN", token.clone());
        }
        command
    }

    /// Run a command that counts as `weight` requests against the budget.
    fn send(&mut self, command: Command, weight: usize) -> Result<Output> {
        self.requests += weight;
        command.run()
    }

    fn ok(&mut self, what: &str, command: Command, weight: usize) -> Result<Output> {
        let output = self.send(command, weight)?;
        if !output.status.success() {
            return Err(failure(what, &output.stderr));
        }
        Ok(output)
    }

    fn parse_item(output: &Output, what: &str) -> Result<OpItem> {
        match op_json::parse_item(output.stdout.expose())? {
            Some(item) => Ok(item),
            None => bail!("{what} returned an item of a category pq-sync does not carry"),
        }
    }
}

impl OpApi for OnePassword {
    fn vaults(&mut self) -> Result<Vec<Vault>> {
        let command = self.command().args(["vault", "list", "--format", "json"]);
        let output = self.ok("op vault list", command, op_requests::VAULT_LIST)?;
        let vaults: Vec<VaultJson> = parse_json(output.stdout.expose(), "op vault list output")?;
        Ok(vaults
            .into_iter()
            .filter(|vault| !vault.id.is_empty())
            .map(|vault| Vault {
                id: vault.id,
                name: vault.name,
            })
            .collect())
    }

    fn items(&mut self, vault: &str) -> Result<Vec<OpSummary>> {
        let command = self
            .command()
            .args(["item", "list", "--vault", vault, "--format", "json"]);
        let output = self.ok("op item list", command, op_requests::ITEM_LIST)?;
        // An empty vault prints nothing, not [].
        let text = output.stdout.expose().trim();
        let items: Vec<ItemJson> = if text.is_empty() {
            Vec::new()
        } else {
            parse_json(text, "op item list output")?
        };
        Ok(items
            .into_iter()
            .filter(|item| {
                !item.id.is_empty() && item.state.as_deref().is_none_or(|s| s == "ACTIVE")
            })
            .map(|item| OpSummary {
                kind: op_json::kind_of_category(&item.category),
                id: item.id,
                title: item.title,
                version: item.version,
            })
            .collect())
    }

    fn get(&mut self, vault: &str, item: &str) -> Result<Option<OpItem>> {
        let command = self.command().args([
            "item", "get", item, "--vault", vault, "--format", "json", "--reveal",
        ]);
        let output = self.send(command, op_requests::ITEM_GET)?;
        if !output.status.success() {
            if problem(&output.stderr).is_none() && is_missing(&output.stderr) {
                return Ok(None);
            }
            return Err(failure("op item get", &output.stderr));
        }
        op_json::parse_item(output.stdout.expose())
    }

    fn create(&mut self, vault: &str, json: &SecretString) -> Result<OpItem> {
        let command = self
            .command()
            .args(["item", "create", "--vault", vault, "--format", "json", "-"])
            .stdin(json.clone());
        let output = self.ok("op item create", command, op_requests::ITEM_CREATE)?;
        Self::parse_item(&output, "op item create")
    }

    fn edit(&mut self, vault: &str, item: &str, raw: &RawItem) -> Result<OpItem> {
        let command = self
            .command()
            .args(["item", "edit", item, "--vault", vault, "--format", "json"])
            .stdin(SecretString::new(raw.0.to_string()));
        let output = self.ok("op item edit", command, op_requests::ITEM_EDIT)?;
        Self::parse_item(&output, "op item edit")
    }

    fn archive(&mut self, vault: &str, item: &str) -> Result<()> {
        let command = self
            .command()
            .args(["item", "delete", item, "--vault", vault, "--archive"]);
        let output = self.send(command, op_requests::ITEM_ARCHIVE)?;
        if output.status.success()
            || (problem(&output.stderr).is_none() && is_missing(&output.stderr))
        {
            return Ok(());
        }
        Err(failure("op item delete --archive", &output.stderr))
    }

    fn move_item(&mut self, item: &str, from: &str, to: &str) -> Result<String> {
        let command = self.command().args([
            "item",
            "move",
            item,
            "--current-vault",
            from,
            "--destination-vault",
            to,
            "--format",
            "json",
        ]);
        let output = self.ok("op item move", command, op_requests::ITEM_MOVE)?;
        #[derive(Deserialize)]
        struct Moved {
            id: String,
        }
        let moved: Moved = parse_json(output.stdout.expose(), "op item move output")?;
        Ok(moved.id)
    }

    fn create_vault(&mut self, name: &str) -> Result<Vault> {
        let command = self
            .command()
            .args(["vault", "create", name, "--format", "json"]);
        let output = self.ok("op vault create", command, op_requests::VAULT_CREATE)?;
        let vault: VaultJson = parse_json(output.stdout.expose(), "op vault create output")?;
        if vault.id.is_empty() {
            bail!("op vault create did not return the vault's ID");
        }
        Ok(Vault {
            id: vault.id,
            name: vault.name,
        })
    }

    fn requests(&self) -> usize {
        self.requests
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sync::fake_cli::FakeCli;
    use crate::sync::record::{FieldKind, Kind, Record};

    fn op(fake: &FakeCli, token: Option<&str>) -> OnePassword {
        OnePassword::new(fake.program(), token.map(SecretString::new))
    }

    const ITEM: &str = r#"{"id":"op1","title":"Site","version":2,"category":"LOGIN",
        "vault":{"id":"v1"},"fields":[
        {"id":"username","type":"STRING","purpose":"USERNAME","label":"username","value":"alice"},
        {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"s3cret-pw"}]}"#;

    #[test]
    fn the_token_goes_in_the_environment_and_debug_is_off() {
        let fake = FakeCli::new();
        fake.respond("vault-list", r#"[{"id":"v1","name":"Proton · Personal"}]"#);
        let mut op = op(&fake, Some("ops_secret_token"));
        let vaults = op.vaults().unwrap();
        assert_eq!(vaults[0].name, "Proton · Personal");
        let call = &fake.calls()[0];
        assert_eq!(call.args, ["vault", "list", "--format", "json"]);
        assert!(
            call.env
                .lines()
                .any(|l| l == "OP_SERVICE_ACCOUNT_TOKEN=ops_secret_token")
        );
        assert!(call.env.lines().any(|l| l == "OP_DEBUG=<unset>"));
        assert!(!fake.all_args().contains("ops_secret_token"));
        assert_eq!(op.requests(), op_requests::VAULT_LIST);
    }

    #[test]
    fn without_a_token_none_is_passed_on() {
        let fake = FakeCli::new();
        fake.respond("vault-list", "[]");
        op(&fake, None).vaults().unwrap();
        assert!(
            fake.calls()[0]
                .env
                .lines()
                .any(|l| l == "OP_SERVICE_ACCOUNT_TOKEN=<unset>")
        );
    }

    #[test]
    fn items_list_their_versions_and_an_empty_vault_lists_nothing() {
        let fake = FakeCli::new();
        fake.respond(
            "item-list",
            r#"[{"id":"op1","title":"Site","version":4,"category":"LOGIN","vault":{"id":"v1"}},
                {"id":"op2","title":"Doc","version":1,"category":"DOCUMENT","vault":{"id":"v1"}}]"#,
        );
        let items = op(&fake, None).items("v1").unwrap();
        assert_eq!(items[0].version, 4);
        assert_eq!(items[0].kind, Some(Kind::Login));
        assert_eq!(items[1].kind, None);
        assert_eq!(
            fake.calls()[0].args,
            ["item", "list", "--vault", "v1", "--format", "json"]
        );

        let fake = FakeCli::new();
        fake.respond("item-list", "");
        assert!(op(&fake, None).items("v1").unwrap().is_empty());
    }

    #[test]
    fn archived_and_deleted_items_are_not_listed_however_they_got_there() {
        // OP_INCLUDE_ARCHIVE in the environment adds them, marked.
        let fake = FakeCli::new();
        fake.respond(
            "item-list",
            r#"[{"id":"op1","title":"Site","version":4,"category":"LOGIN"},
                {"id":"op2","title":"Old","version":2,"category":"LOGIN","state":"ARCHIVED"},
                {"id":"op3","title":"Gone","version":2,"category":"LOGIN","state":"DELETED"},
                {"id":"op4","title":"Here","version":1,"category":"LOGIN","state":"ACTIVE"}]"#,
        );
        let ids: Vec<String> = op(&fake, None)
            .items("v1")
            .unwrap()
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(ids, ["op1", "op4"]);
    }

    #[test]
    fn op_gets_none_of_proton_s_settings() {
        assert!(
            op(&FakeCli::new(), None)
                .command()
                .removes_prefix("PROTON_PASS_")
        );
    }

    #[test]
    fn creates_and_edits_go_through_stdin() {
        let fake = FakeCli::new();
        fake.respond("item-create", ITEM);
        fake.respond("item-edit", ITEM);
        let mut record = Record::new(Kind::Login);
        record.set("title", "Site", FieldKind::Text);
        record.set("username", "alice", FieldKind::Text);
        record.set("password", "s3cret-pw", FieldKind::Concealed);
        let mut op = op(&fake, None);
        let created = op
            .create("v1", &op_json::create_json(&record, "s/i"))
            .unwrap();
        assert_eq!(created.record.value("password"), "s3cret-pw");
        op.edit("v1", "op1", &created.raw).unwrap();
        let calls = fake.calls();
        assert_eq!(
            calls[0].args,
            ["item", "create", "--vault", "v1", "--format", "json", "-"]
        );
        assert_eq!(
            calls[1].args,
            ["item", "edit", "op1", "--vault", "v1", "--format", "json"]
        );
        assert!(calls[0].stdin.contains("s3cret-pw") && calls[1].stdin.contains("s3cret-pw"));
        assert!(!fake.all_args().contains("s3cret-pw"));
        assert!(!fake.all_args().contains("alice"));
        assert_eq!(
            op.requests(),
            op_requests::ITEM_CREATE + op_requests::ITEM_EDIT
        );
    }

    #[test]
    fn a_missing_item_reads_as_none_and_archives_as_done() {
        let fake = FakeCli::new();
        let gone = "[ERROR] 2026/10/25 10:00:00 \"op9\" isn't an item in the \"Proton\" vault.";
        fake.fail("item-get", gone);
        fake.fail("item-delete", gone);
        let mut op = op(&fake, None);
        assert!(op.get("v1", "op9").unwrap().is_none());
        op.archive("v1", "op9").unwrap();
        assert!(fake.calls()[0].args.contains(&"--reveal".to_string()));
        assert!(fake.calls()[1].args.contains(&"--archive".to_string()));
    }

    #[test]
    fn rate_limits_and_refused_tokens_are_their_own_errors() {
        let fake = FakeCli::new();
        fake.fail(
            "item-list",
            "[ERROR] 2026/10/25 10:00:00 Too many requests. Your client has been rate-limited (429)",
        );
        fake.fail(
            "vault-list",
            "[ERROR] 2026/10/25 10:00:00 invalid service account token",
        );
        let mut op = op(&fake, Some("ops_x"));
        let err = op.items("v1").unwrap_err();
        assert_eq!(
            err.downcast_ref::<OpProblem>(),
            Some(&OpProblem::RateLimited)
        );
        let err = op.vaults().unwrap_err();
        assert_eq!(
            err.downcast_ref::<OpProblem>(),
            Some(&OpProblem::NotSignedIn)
        );
    }

    #[test]
    fn other_errors_show_only_ops_message_escaped() {
        assert_eq!(
            summarize(b"some log line\n[ERROR] 2026/10/25 10:00:00 vault \"x\x1b[2K\" not found\n"),
            "vault \"x\\u{1b}[2K\" not found"
        );
        assert_eq!(summarize(b"panic"), "op reported no error message");
        let fake = FakeCli::new();
        fake.fail("item-create", "[ERROR] 2026/10/25 10:00:00 something broke");
        let err = op(&fake, None)
            .create("v1", &SecretString::new("{}"))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "op item create failed: something broke");
    }

    #[test]
    fn a_move_returns_the_new_id_and_a_vault_can_be_created() {
        let fake = FakeCli::new();
        fake.respond("item-move", r#"{"id":"new-op-id","title":"Site"}"#);
        fake.respond("vault-create", r#"{"id":"v9","name":"Proton · Work"}"#);
        let mut op = op(&fake, None);
        assert_eq!(op.move_item("op1", "v1", "v2").unwrap(), "new-op-id");
        assert_eq!(op.create_vault("Proton · Work").unwrap().id, "v9");
        assert_eq!(
            fake.calls()[0].args,
            [
                "item",
                "move",
                "op1",
                "--current-vault",
                "v1",
                "--destination-vault",
                "v2",
                "--format",
                "json"
            ]
        );
    }
}
