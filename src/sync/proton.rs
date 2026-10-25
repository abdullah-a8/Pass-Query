//! The Proton side of pq-sync, through `pass-cli`.
//!
//! pq-sync keeps its own pass-cli session (`PROTON_PASS_SESSION_DIR`), apart
//! from the owner's interactive one, and logs it in with a personal access
//! token handed over in the environment (`PROTON_PASS_PERSONAL_ACCESS_TOKEN`),
//! never on the command line. Every call runs with pass-cli's logging off
//! (with it on, pass-cli logs whole requests, tokens included), its update
//! check and telemetry off, and, where Proton is blocked, through the
//! configured HTTP proxy. Item content goes in through stdin templates.

use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

use super::api::{ProtonApi, ProtonSummary, Vault};
use super::exec::{Command, Output};
use super::proton_json::{self, CreateTemplate, ProtonItem};
use super::secret::{SecretString, parse_json};
use crate::pass_cli::{SessionProblem, failure, item_is_certainly_gone};
use crate::text::printable;

/// How long one pass-cli call may take: a vault's items are downloaded and
/// decrypted on every call, through a proxy.
const TIMEOUT: Duration = Duration::from_secs(180);

pub struct Proton {
    pub program: PathBuf,
    pub session_dir: PathBuf,
    /// `http://host:port`, for `HTTPS_PROXY`/`HTTP_PROXY`.
    pub proxy: Option<String>,
    /// The personal access token, to log the session in when needed.
    pub token: Option<SecretString>,
}

impl Proton {
    fn command(&self) -> Command {
        let mut command = Command::new(&self.program, TIMEOUT)
            .env("MUON_LOG_LEVEL", "off")
            .env("PASS_LOG_LEVEL", "off")
            .env("PROTON_PASS_NO_UPDATE_CHECK", "1")
            .env("PROTON_PASS_DISABLE_TELEMETRY", "1")
            .env(
                "PROTON_PASS_SESSION_DIR",
                self.session_dir.display().to_string(),
            )
            // Only `login` gets the token.
            .env_remove("PROTON_PASS_PERSONAL_ACCESS_TOKEN")
            // pass-cli reads the lowercase forms too; only ours apply.
            .env_remove("https_proxy")
            .env_remove("http_proxy")
            .env_remove("HTTPS_PROXY")
            .env_remove("HTTP_PROXY");
        if let Some(proxy) = &self.proxy {
            command = command
                .env("HTTPS_PROXY", proxy.as_str())
                .env("HTTP_PROXY", proxy.as_str());
        }
        command
    }

    fn run(&self, what: &str, command: Command) -> Result<Output> {
        let output = command.run()?;
        if !output.status.success() {
            return Err(failure(what, &output.stderr));
        }
        Ok(output)
    }

    /// Make sure the session is logged in: log in with the token when
    /// pass-cli says there is no session or it ended.
    pub fn ensure_session(&self) -> Result<()> {
        let info = self.command().args(["info", "--output", "json"]).run()?;
        if info.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&info.stderr);
        match SessionProblem::from_stderr(&stderr) {
            Some(SessionProblem::NotLoggedIn | SessionProblem::Invalidated) => {}
            _ => return Err(failure("pass-cli info", &info.stderr)),
        }
        let Some(token) = &self.token else {
            bail!(
                "pq-sync's Proton session is not logged in and no personal access token \
                 is stored. Run: pq-sync setup"
            );
        };
        let login = self
            .command()
            .arg("login")
            .env("PROTON_PASS_PERSONAL_ACCESS_TOKEN", token.clone())
            .run()?;
        if !login.status.success() {
            // pass-cli may repeat a token it refused; the error must not.
            let stderr = String::from_utf8_lossy(&login.stderr).replace(token.expose(), "[token]");
            return Err(failure("pass-cli login", stderr.as_bytes()));
        }
        self.run(
            "pass-cli info",
            self.command().args(["info", "--output", "json"]),
        )?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct VaultListJson {
    #[serde(default)]
    vaults: Vec<VaultJson>,
}

#[derive(Deserialize)]
struct VaultJson {
    #[serde(default)]
    name: String,
    #[serde(default)]
    share_id: String,
}

#[derive(Deserialize)]
struct ItemListJson {
    #[serde(default)]
    items: Vec<ItemJson>,
}

#[derive(Deserialize)]
struct ItemJson {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    item_type: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    modify_time: String,
}

/// A pass-cli ID as it prints them: one word of URL-safe base64.
fn looks_like_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 200
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_=+/".contains(c))
}

/// The single ID a create or move printed.
fn printed_id(output: &Output, what: &str) -> Result<String> {
    let id = output.stdout.expose().trim();
    if looks_like_id(id) {
        Ok(id.to_string())
    } else {
        bail!("{what} did not print the new item's ID")
    }
}

impl ProtonApi for Proton {
    fn vaults(&mut self) -> Result<Vec<Vault>> {
        let output = self.run(
            "pass-cli vault list",
            self.command().args(["vault", "list", "--output", "json"]),
        )?;
        let list: VaultListJson = parse_json(output.stdout.expose(), "pass-cli vault list output")?;
        Ok(list
            .vaults
            .into_iter()
            .filter(|vault| !vault.share_id.is_empty())
            .map(|vault| Vault {
                id: vault.share_id,
                name: vault.name,
            })
            .collect())
    }

    fn items(&mut self, share: &str) -> Result<Vec<ProtonSummary>> {
        let output = self.run(
            "pass-cli item list",
            self.command().args([
                "item".to_string(),
                "list".to_string(),
                "--output".to_string(),
                "json".to_string(),
                format!("--share-id={share}"),
            ]),
        )?;
        let list: ItemListJson = parse_json(output.stdout.expose(), "pass-cli item list output")?;
        Ok(list
            .items
            .into_iter()
            .filter(|item| !item.id.is_empty())
            .map(|item| ProtonSummary {
                kind: proton_json::kind_of_summary(&item.item_type),
                active: matches!(item.state.as_deref(), None | Some("Active")),
                id: item.id,
                title: item.title,
                modified: item.modify_time,
            })
            .collect())
    }

    fn view(&mut self, share: &str, item: &str) -> Result<Option<ProtonItem>> {
        let output = self
            .command()
            .args([
                "item".to_string(),
                "view".to_string(),
                format!("--share-id={share}"),
                format!("--item-id={item}"),
                "--output".to_string(),
                "json".to_string(),
            ])
            .run()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if SessionProblem::from_stderr(&stderr).is_none() && item_is_certainly_gone(&stderr) {
                return Ok(None);
            }
            return Err(failure("pass-cli item view", &output.stderr));
        }
        proton_json::parse_view(output.stdout.expose())
    }

    fn create(&mut self, share: &str, template: &CreateTemplate) -> Result<String> {
        let what = format!("pass-cli item create {}", template.subcommand);
        let output = self.run(
            &what,
            self.command()
                .args([
                    "item".to_string(),
                    "create".to_string(),
                    template.subcommand.to_string(),
                    format!("--share-id={share}"),
                    "--from-template".to_string(),
                    "-".to_string(),
                ])
                .stdin(template.json.clone()),
        )?;
        printed_id(&output, &what)
    }

    fn trash(&mut self, share: &str, item: &str) -> Result<()> {
        let output = self
            .command()
            .args([
                "item".to_string(),
                "trash".to_string(),
                format!("--share-id={share}"),
                format!("--item-id={item}"),
            ])
            .run()?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if SessionProblem::from_stderr(&stderr).is_none() && item_is_certainly_gone(&stderr) {
            return Ok(());
        }
        Err(failure("pass-cli item trash", &output.stderr))
    }

    fn move_item(&mut self, from: &str, item: &str, to: &str) -> Result<String> {
        let output = self.run(
            "pass-cli item move",
            self.command().args([
                "item".to_string(),
                "move".to_string(),
                format!("--from-share-id={from}"),
                format!("--item-id={item}"),
                format!("--to-share-id={to}"),
            ]),
        )?;
        printed_id(&output, "pass-cli item move")
    }
}

/// A short, escaped name for an item in a message.
pub fn shown(title: &str) -> String {
    let title = printable(title);
    if title.chars().count() > 80 {
        format!("{}…", title.chars().take(79).collect::<String>())
    } else {
        title
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sync::fake_cli::FakeCli;
    use crate::sync::record::{FieldKind, Kind, Record};

    fn proton(fake: &FakeCli, token: Option<&str>) -> Proton {
        Proton {
            program: fake.program(),
            session_dir: fake.dir().join("session"),
            proxy: Some("http://100.94.76.106:8888".to_string()),
            token: token.map(SecretString::new),
        }
    }

    fn env_has(env: &str, line: &str) -> bool {
        env.lines().any(|l| l == line)
    }

    #[test]
    fn every_call_runs_quietly_through_the_proxy_in_its_own_session() {
        let fake = FakeCli::new();
        fake.respond(
            "vault-list",
            r#"{"vaults":[{"name":"Personal","vault_id":"v","share_id":"s1"}]}"#,
        );
        let vaults = proton(&fake, Some("pst_token::key")).vaults().unwrap();
        assert_eq!(
            vaults,
            [Vault {
                id: "s1".into(),
                name: "Personal".into()
            }]
        );
        let call = &fake.calls()[0];
        assert_eq!(call.args, ["vault", "list", "--output", "json"]);
        for line in [
            "MUON_LOG_LEVEL=off",
            "PASS_LOG_LEVEL=off",
            "PROTON_PASS_NO_UPDATE_CHECK=1",
            "PROTON_PASS_DISABLE_TELEMETRY=1",
            "HTTPS_PROXY=http://100.94.76.106:8888",
            "HTTP_PROXY=http://100.94.76.106:8888",
            "PROTON_PASS_PERSONAL_ACCESS_TOKEN=<unset>",
        ] {
            assert!(env_has(&call.env, line), "{line} in\n{}", call.env);
        }
        assert!(call.env.contains("PROTON_PASS_SESSION_DIR="));
        assert!(call.env.contains("/session"));
    }

    #[test]
    fn an_ended_session_is_logged_in_with_the_token_from_the_environment() {
        let fake = FakeCli::new();
        fake.fail_once(
            "info---output",
            "Error: This operation requires an authenticated client",
        );
        proton(&fake, Some("pst_token::key"))
            .ensure_session()
            .unwrap();
        let calls = fake.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[1].args, ["login"]);
        assert!(env_has(
            &calls[1].env,
            "PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_token::key"
        ));
        assert!(
            !fake.all_args().contains("pst_token"),
            "the token never goes on argv"
        );
        assert!(env_has(
            &calls[2].env,
            "PROTON_PASS_PERSONAL_ACCESS_TOKEN=<unset>"
        ));
    }

    #[test]
    fn a_refused_login_never_repeats_the_token() {
        let fake = FakeCli::new();
        fake.fail_once(
            "info---output",
            "Error: This operation requires an authenticated client",
        );
        fake.fail("login-", "Error: invalid token pst_token::key");
        let err = proton(&fake, Some("pst_token::key"))
            .ensure_session()
            .unwrap_err();
        assert!(!format!("{err:#}").contains("pst_token"), "{err:#}");
    }

    #[test]
    fn a_locked_session_is_reported_not_logged_in_again() {
        let fake = FakeCli::new();
        fake.fail(
            "info---output",
            "Session is locked. Please unlock your session",
        );
        let err = proton(&fake, Some("pst_t")).ensure_session().unwrap_err();
        assert_eq!(
            err.downcast_ref::<SessionProblem>(),
            Some(&SessionProblem::Locked)
        );
        assert_eq!(fake.calls().len(), 1);

        let fake = FakeCli::new();
        fake.fail("info---output", "not logged in");
        let err = proton(&fake, None).ensure_session().unwrap_err();
        assert!(err.to_string().contains("pq-sync setup"), "{err}");
    }

    #[test]
    fn items_are_listed_with_their_state_kind_and_modify_time() {
        let fake = FakeCli::new();
        fake.respond(
            "item-list",
            r#"{"items":[
              {"id":"i1","share_id":"s1","title":"Site","item_type":"login","state":"Active","modify_time":"2026-10-25T10:00:00"},
              {"id":"i2","share_id":"s1","title":"Old","item_type":"login","state":"Trashed","modify_time":"2026-10-24T10:00:00"},
              {"id":"i3","share_id":"s1","title":"Alias","item_type":"alias","state":"Active","modify_time":"x"}
            ]}"#,
        );
        let items = proton(&fake, None).items("s1").unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].kind, Some(Kind::Login));
        assert!(items[0].active && !items[1].active);
        assert_eq!(items[2].kind, None);
        assert_eq!(items[0].modified, "2026-10-25T10:00:00");
        assert!(fake.calls()[0].args.contains(&"--share-id=s1".to_string()));
    }

    #[test]
    fn a_create_pipes_the_template_and_returns_the_printed_id() {
        let fake = FakeCli::new();
        fake.respond("item-create", "new-item-id_123==\n");
        let mut record = Record::new(Kind::Login);
        record.set("title", "Site", FieldKind::Text);
        record.set("password", "s3cret-pw", FieldKind::Concealed);
        record.set("username", "alice", FieldKind::Text);
        let template = proton_json::create_template(&record);
        let id = proton(&fake, None).create("s1", &template).unwrap();
        assert_eq!(id, "new-item-id_123==");
        let call = &fake.calls()[0];
        assert_eq!(
            call.args,
            [
                "item",
                "create",
                "login",
                "--share-id=s1",
                "--from-template",
                "-"
            ]
        );
        assert!(call.stdin.contains("s3cret-pw"));
        assert!(!fake.all_args().contains("s3cret-pw"));
        assert!(!fake.all_args().contains("alice"));
    }

    #[test]
    fn a_create_that_prints_no_id_is_an_error() {
        let fake = FakeCli::new();
        fake.respond("item-create", "Item created successfully\n");
        let template = proton_json::create_template(&Record::new(Kind::Note));
        let err = proton(&fake, None).create("s1", &template).unwrap_err();
        assert!(err.to_string().contains("did not print"), "{err}");
    }

    #[test]
    fn a_gone_item_reads_as_none_and_trashes_as_done() {
        let fake = FakeCli::new();
        fake.fail(
            "item-view",
            "Error: Error retrieving item\nCaused by:\n Reason: NotExists",
        );
        fake.fail("item-trash", "Error: x\nReason: NotExists");
        let mut proton = proton(&fake, None);
        assert!(proton.view("s1", "gone").unwrap().is_none());
        proton.trash("s1", "gone").unwrap();
    }

    #[test]
    fn a_view_returns_the_parsed_item() {
        let fake = FakeCli::new();
        fake.respond(
            "item-view",
            r#"{"item":{"content":{"title":"Site","note":"","content":{"Login":{"username":"u","email":"","password":"p","urls":[],"totp_uri":"","passkeys":[]}},"extra_fields":[]},"state":"Active"},"attachments":[]}"#,
        );
        let item = proton(&fake, None).view("s1", "i1").unwrap().unwrap();
        assert_eq!(item.record.value("password"), "p");
        let args = &fake.calls()[0].args;
        assert!(args.contains(&"--share-id=s1".to_string()));
        assert!(args.contains(&"--item-id=i1".to_string()));
    }

    #[test]
    fn errors_are_summarised_and_escaped() {
        let fake = FakeCli::new();
        fake.fail(
            "item-list",
            "DEBUG Authorization: Bearer tok\nError: Error listing \u{1b}[2Kitems\n",
        );
        let err = proton(&fake, None).items("s1").unwrap_err().to_string();
        assert!(!err.contains("Bearer"), "{err}");
        assert!(!err.contains('\u{1b}'), "{err}");
    }

    #[test]
    fn a_move_returns_the_new_id() {
        let fake = FakeCli::new();
        fake.respond("item-move", "moved-id\n");
        let id = proton(&fake, None).move_item("s1", "i1", "s2").unwrap();
        assert_eq!(id, "moved-id");
        assert_eq!(
            fake.calls()[0].args,
            [
                "item",
                "move",
                "--from-share-id=s1",
                "--item-id=i1",
                "--to-share-id=s2"
            ]
        );
    }
}
