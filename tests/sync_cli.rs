//! `pq-sync` end to end against fake `pass-cli` and `op` scripts, with its
//! secrets from the environment and its config and state in a temporary
//! directory. Every argument any fake receives is logged, and checked for
//! the tokens and the item's secrets.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PROTON_TOKEN: &str = "pst_fake-proton-token::key";
const OP_TOKEN: &str = "ops_fake-service-account-token";
const STATE_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const PASSWORD: &str = "s3cret-Pa55";
const USERNAME: &str = "alice-user";

/// pass-cli 2.5.1 as far as pq-sync uses it: one vault, one login.
const FAKE_PASS_CLI: &str = r#"#!/bin/sh
d="$FAKE_DIR"
printf '%s\n' "pass-cli $*" >> "$d/args"
printf '%s\n' "${PROTON_PASS_PERSONAL_ACCESS_TOKEN:-}" >> "$d/pass-cli-token-env"
printf '%s\n' "${PROTON_PASS_SESSION_DIR:-unset}" >> "$d/pass-cli-session-env"
env | grep '^PQ_SYNC_' >> "$d/leaked-env"
case "$1 $2" in
"info --output") echo '{"release_track":"stable","id":"u"}' ;;
"vault list") echo '{"vaults":[{"name":"Personal","vault_id":"v1","share_id":"ps1"}]}' ;;
"item list") echo '{"items":[{"id":"p1","share_id":"ps1","vault_id":"v1","state":"Active","flags":[],"create_time":"2026-10-01T00:00:00","modify_time":"2026-10-02T00:00:00","title":"Site","item_type":"login"}]}' ;;
"item view") cat "$d/view.json" ;;
*) echo "unexpected pass-cli call: $*" >&2; exit 2 ;;
esac
"#;

/// op 2.x as far as pq-sync uses it, with items kept as files.
const FAKE_OP: &str = r#"#!/bin/sh
d="$FAKE_DIR"
printf '%s\n' "op $*" >> "$d/args"
printf '%s\n' "${OP_SERVICE_ACCOUNT_TOKEN:-}" >> "$d/op-token-env"
env | grep '^PQ_SYNC_' >> "$d/leaked-env"
mkdir -p "$d/items"
case "$1 $2" in
"vault list")
    if [ -f "$d/vaults.json" ]; then cat "$d/vaults.json"; else echo '[{"id":"ov1","name":"Proton · Personal"}]'; fi
    ;;
"vault create")
    printf '[{"id":"ov1","name":"%s"}]' "$3" > "$d/vaults.json"
    printf '{"id":"ov1","name":"%s"}' "$3"
    ;;
"item list")
    printf '['
    first=1
    for f in "$d"/items/*.json; do
        [ -e "$f" ] || continue
        [ $first = 1 ] || printf ','
        first=0
        cat "$f"
    done
    echo ']'
    ;;
"item get") cat "$d/items/$3.json" ;;
"item create")
    n=$(ls "$d/items" | wc -l | tr -d ' ')
    id="o$((n + 1))"
    cat > "$d/create-stdin"
    sed "1s/^{/{\"id\":\"$id\",\"version\":1,\"vault\":{\"id\":\"ov1\"},/" "$d/create-stdin" > "$d/items/$id.json"
    cat "$d/items/$id.json"
    ;;
*) echo "[ERROR] 2026/10/25 10:00:00 unexpected op call: $*" >&2; exit 2 ;;
esac
"#;

const VIEW: &str = r#"{"item":{"id":"p1","share_id":"ps1","vault_id":"v1","content":{"title":"Site","note":"","item_uuid":"u","content":{"Login":{"email":"","username":"USERNAME","password":"PASSWORD","urls":["https://example.com"],"totp_uri":"","passkeys":[],"autofill_urls":[]}},"extra_fields":[],"platform_specific":null,"custom_icon":null},"state":"Active","flags":[],"create_time":"2026-10-01T00:00:00","modify_time":"2026-10-02T00:00:00"},"attachments":[]}"#;

struct World {
    root: tempfile::TempDir,
}

impl World {
    fn new(proxy: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let world = World { root };
        for dir in ["bin", "fake", "home"] {
            fs::create_dir_all(world.path(dir)).unwrap();
        }
        world.install("pass-cli", FAKE_PASS_CLI);
        world.install("op", FAKE_OP);
        fs::write(
            world.path("fake/view.json"),
            VIEW.replace("USERNAME", USERNAME)
                .replace("PASSWORD", PASSWORD),
        )
        .unwrap();
        // The config pq-sync setup would write: private, absolute programs.
        let config_dir = world.path("config/pq-sync");
        fs::create_dir_all(&config_dir).unwrap();
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let config = serde_json::json!({
            "pass_cli": world.path("bin/pass-cli"),
            "op": world.path("bin/op"),
            "proton_proxy": proxy,
            "notify": false,
        });
        let config_file = config_dir.join("config.json");
        fs::write(&config_file, config.to_string()).unwrap();
        fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
        world
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    fn install(&self, name: &str, script: &str) {
        let path = self.path("bin").join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pq-sync"));
        command.args(args);
        self.finish(command, true)
    }

    /// Run pq-sync in a pseudo-terminal, as the owner at the keyboard, with
    /// none of pq-sync's tokens: only the state key.
    fn run_at_terminal(&self, args: &[&str]) -> Output {
        let program = env!("CARGO_BIN_EXE_pq-sync");
        let mut command = Command::new("script");
        if cfg!(target_os = "macos") {
            command.args(["-q", "/dev/null", program]).args(args);
        } else {
            let line = std::iter::once(program)
                .chain(args.iter().copied())
                .map(|word| format!("'{word}'"))
                .collect::<Vec<_>>()
                .join(" ");
            command.args(["-qec", &line, "/dev/null"]);
        }
        self.finish(command, false)
    }

    fn finish(&self, mut command: Command, tokens: bool) -> Output {
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("FAKE_DIR", self.path("fake"))
            .env("PQ_SYNC_SECRETS_FROM_ENV", "1")
            .env("PQ_SYNC_STATE_KEY", STATE_KEY);
        if tokens {
            command
                .env("PQ_SYNC_PROTON_TOKEN", PROTON_TOKEN)
                .env("PQ_SYNC_OP_TOKEN", OP_TOKEN);
        }
        let output = command.stdin(std::process::Stdio::null()).output().unwrap();
        self.assert_no_leaks(&output);
        output
    }

    fn args(&self) -> String {
        fs::read_to_string(self.path("fake/args")).unwrap_or_default()
    }

    fn assert_no_leaks(&self, output: &Output) {
        let leaked = read(&self.path("fake/leaked-env")).unwrap_or_default();
        assert!(leaked.is_empty(), "pq-sync's own variables reached a CLI");
        let args = self.args();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        for secret in [PROTON_TOKEN, OP_TOKEN, STATE_KEY, PASSWORD, USERNAME] {
            assert!(
                !args.contains(secret),
                "{secret} on a command line:\n{args}"
            );
            assert!(!stderr.contains(secret), "{secret} on stderr");
            assert!(!stdout.contains(secret), "{secret} on stdout");
        }
        if let Some(state) = read(&self.path("state/pq-sync/state.json")) {
            for secret in [PASSWORD, USERNAME, PROTON_TOKEN, OP_TOKEN, STATE_KEY] {
                assert!(!state.contains(secret), "{secret} in the state file");
            }
        }
    }
}

fn read(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_dry_run_reports_the_copy_and_writes_nothing() {
    let world = World::new("");
    let output = world.run(&["run", "--dry-run"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown = stdout(&output);
    assert!(shown.contains("Dry run"), "{shown}");
    assert!(
        shown.contains("copied 'Site' into 'Proton · Personal'"),
        "{shown}"
    );
    assert!(!world.args().contains("op item create"));
    assert!(read(&world.path("state/pq-sync/state.json")).is_none());
}

#[test]
fn a_run_copies_the_login_through_stdin_and_the_next_is_in_step() {
    let world = World::new("");
    let output = world.run(&["run"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout(&output).contains("+ 1Password: copied 'Site'"),
        "{}",
        stdout(&output)
    );

    let sent = read(&world.path("fake/create-stdin")).unwrap();
    assert!(sent.contains(PASSWORD) && sent.contains(USERNAME));
    assert!(
        sent.contains("ps1/p1"),
        "the copy points back to the Proton item"
    );
    // Tokens only ever in the environment, never on a command line.
    assert!(
        read(&world.path("fake/op-token-env"))
            .unwrap()
            .contains(OP_TOKEN)
    );
    assert!(
        !read(&world.path("fake/pass-cli-token-env"))
            .unwrap()
            .contains(PROTON_TOKEN)
    );

    let state = world.path("state/pq-sync/state.json");
    assert_eq!(mode(&state), 0o600);
    assert_eq!(mode(&world.path("state/pq-sync")), 0o700);

    let output = world.run(&["run"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout(&output).contains("In step"), "{}", stdout(&output));
    assert_eq!(world.args().matches("op item create").count(), 1);

    let status = world.run(&["status"]);
    let shown = stdout(&status);
    assert!(shown.contains("1 vaults, 1 items"), "{shown}");
    assert!(shown.contains("In step"), "{shown}");
}

#[test]
fn an_unreachable_proxy_stops_the_run_before_any_call() {
    // Port 9 on localhost: nothing listens there.
    let world = World::new("http://127.0.0.1:9");
    let output = world.run(&["run"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unreachable"), "{stderr}");
    assert!(world.args().is_empty(), "no CLI ran:\n{}", world.args());
}

#[test]
fn a_config_others_can_write_is_refused() {
    let world = World::new("");
    let config = world.path("config/pq-sync/config.json");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o666)).unwrap();
    let output = world.run(&["run"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not private"));
    assert!(world.args().is_empty());
}

#[test]
fn what_needs_the_owner_is_kept_until_cleared() {
    let world = World::new("");
    // No 1Password vault for Proton's "Personal" yet.
    world.install(
        "op",
        &FAKE_OP.replace(
            r#"echo '[{"id":"ov1","name":"Proton · Personal"}]'"#,
            "echo '[]'",
        ),
    );
    assert!(world.run(&["run", "--quiet"]).status.success());
    world.install("op", FAKE_OP);
    assert!(world.run(&["run", "--quiet"]).status.success());

    let shown = stdout(&world.run(&["status"]));
    assert!(!shown.contains("In step"), "the second run copied: {shown}");
    assert!(shown.contains("Needs you, from earlier runs"), "{shown}");
    assert!(
        shown.contains("no 1Password vault for Proton's 'Personal'"),
        "{shown}"
    );

    assert!(world.run(&["status", "--clear"]).status.success());
    let shown = stdout(&world.run(&["status"]));
    assert!(!shown.contains("Needs you"), "{shown}");
}

#[test]
fn a_quiet_dry_run_that_fails_keeps_nothing() {
    let world = World::new("http://127.0.0.1:9");
    let output = world.run(&["run", "--dry-run", "--quiet"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unreachable"));
    assert!(!world.path("state/pq-sync/last-run.txt").exists());
}

#[test]
fn a_config_with_a_relative_program_is_refused() {
    let world = World::new("");
    let config = world.path("config/pq-sync/config.json");
    let text = fs::read_to_string(&config).unwrap();
    let relative = text.replace(world.path("bin/op").to_str().unwrap(), "bin/op");
    assert_ne!(text, relative);
    fs::write(&config, relative).unwrap();
    let output = world.run(&["run"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("absolute path"));
    assert!(world.args().is_empty());
}

#[test]
fn as_me_needs_no_tokens_and_creates_the_missing_vault() {
    let world = World::new("");
    fs::write(world.path("fake/vaults.json"), "[]").unwrap();

    let setup = world.run_at_terminal(&["setup", "--as-me"]);
    let shown = stdout(&setup);
    assert!(setup.status.success(), "{shown}");
    assert!(shown.contains("created on the first run"), "{shown}");

    let output = world.run_at_terminal(&["run", "--as-me"]);
    let shown = stdout(&output);
    assert!(output.status.success(), "{shown}");
    assert!(
        world
            .args()
            .contains("op vault create Proton · Personal --format json"),
        "{}",
        world.args()
    );
    assert_eq!(fs::read_dir(world.path("fake/items")).unwrap().count(), 1);
    // The owner's own sign-ins: no service account token, no session of
    // pq-sync's own.
    let op_tokens = read(&world.path("fake/op-token-env")).unwrap();
    assert!(op_tokens.lines().all(str::is_empty), "{op_tokens}");
    let sessions = read(&world.path("fake/pass-cli-session-env")).unwrap();
    assert!(sessions.lines().all(|l| l == "unset"), "{sessions}");
}

#[test]
fn as_me_is_refused_away_from_a_terminal() {
    let world = World::new("");
    let output = world.run(&["run", "--as-me"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("at the keyboard"));
}

#[test]
fn setup_names_a_paired_vault_this_sign_in_cannot_reach() {
    let world = World::new("");
    assert!(world.run(&["run"]).status.success());
    // The 1Password vault it paired with is out of the token's reach now.
    fs::write(world.path("fake/vaults.json"), "[]").unwrap();
    let setup = world.run(&["setup", "--create-vaults"]);
    let shown = stdout(&setup);
    assert!(setup.status.success(), "{shown}");
    assert!(
        shown.contains("paired, but this sign-in cannot reach"),
        "{shown}"
    );
    assert!(!shown.contains("created on the first run"), "{shown}");
}
