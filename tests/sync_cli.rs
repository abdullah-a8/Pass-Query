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
mkdir -p "$d/items"
case "$1 $2" in
"vault list") echo '[{"id":"ov1","name":"Proton · Personal"}]' ;;
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
        let output = Command::new(env!("CARGO_BIN_EXE_pq-sync"))
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("FAKE_DIR", self.path("fake"))
            .env("PQ_SYNC_SECRETS_FROM_ENV", "1")
            .env("PQ_SYNC_PROTON_TOKEN", PROTON_TOKEN)
            .env("PQ_SYNC_OP_TOKEN", OP_TOKEN)
            .env("PQ_SYNC_STATE_KEY", STATE_KEY)
            .output()
            .unwrap();
        self.assert_no_leaks(&output);
        output
    }

    fn args(&self) -> String {
        fs::read_to_string(self.path("fake/args")).unwrap_or_default()
    }

    fn assert_no_leaks(&self, output: &Output) {
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
