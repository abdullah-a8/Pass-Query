//! End-to-end harness: runs the real `pq` binary against fake `pass-cli`,
//! `fzf` and clipboard tools placed first on `PATH`.
//!
//! A test describes vaults and items, runs pq, then inspects what pq did: the
//! pass-cli calls it made, what it showed fzf, what it copied and what it
//! cached. The JSON written for the fake follows pass-cli 2.5.1.

#![allow(dead_code)] // each test binary uses a different subset

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

const FAKE_PASS_CLI: &str = include_str!("bin/pass-cli");
const FAKE_FZF: &str = include_str!("bin/fzf");
const FAKE_CLIPBOARD: &str = include_str!("bin/clipboard");
/// The external commands the fake tools run.
const FAKE_UTILS: [&str; 6] = ["cat", "find", "mkdir", "sed", "tr", "wc"];

#[derive(Clone)]
pub struct Login {
    pub id: &'static str,
    pub title: &'static str,
    pub username: &'static str,
    pub email: &'static str,
    pub password: &'static str,
}

#[derive(Clone)]
enum Content {
    Login(Login),
    Note,
}

#[derive(Clone)]
struct Item {
    share_id: &'static str,
    id: &'static str,
    title: &'static str,
    content: Content,
}

pub struct Harness {
    root: TempDir,
    vaults: Vec<(&'static str, &'static str)>,
    items: Vec<Item>,
}

impl Harness {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("create temp dir");
        let harness = Self {
            root,
            vaults: Vec::new(),
            items: Vec::new(),
        };
        for dir in [
            harness.bin_dir(),
            harness.utils_dir(),
            harness.fake_dir(),
            harness.home_dir(),
        ] {
            fs::create_dir_all(dir).expect("create harness dir");
        }
        harness.link_utils();
        harness.install("pass-cli", FAKE_PASS_CLI);
        harness.install("fzf", FAKE_FZF);
        harness.install("wl-copy", FAKE_CLIPBOARD);
        harness.install("pbcopy", FAKE_CLIPBOARD);
        harness
    }

    pub fn vault(&mut self, name: &'static str, share_id: &'static str) -> &mut Self {
        self.vaults.push((name, share_id));
        self
    }

    pub fn login(&mut self, share_id: &'static str, login: Login) -> &mut Self {
        self.items.push(Item {
            share_id,
            id: login.id,
            title: login.title,
            content: Content::Login(login),
        });
        self
    }

    pub fn note(
        &mut self,
        share_id: &'static str,
        id: &'static str,
        title: &'static str,
    ) -> &mut Self {
        self.items.push(Item {
            share_id,
            id,
            title,
            content: Content::Note,
        });
        self
    }

    /// Make `pass-cli <command>` (e.g. "vault-list") print `stderr` and exit 1.
    pub fn fail(&self, command: &str, stderr: &str) {
        let dir = self.fake_dir().join("fail");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(command), stderr).unwrap();
    }

    /// Make `pass-cli item list` fail for one vault only.
    pub fn fail_vault(&self, share_id: &str, stderr: &str) {
        let dir = self.fake_dir().join("fail");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("item-list.{share_id}")), stderr).unwrap();
    }

    /// Choose the 1-based picker line fzf returns.
    pub fn pick(&self, line: usize) {
        fs::write(self.fake_dir().join("fzf-pick"), line.to_string()).unwrap();
    }

    pub fn cancel_picker(&self) {
        fs::write(self.fake_dir().join("fzf-pick"), "cancel").unwrap();
    }

    pub fn remove_tool(&self, name: &str) {
        fs::remove_file(self.bin_dir().join(name)).unwrap();
    }

    /// Run pq with `args` and return its output. Every run is checked for
    /// leaks: no username, email or password may appear on stderr or in the
    /// arguments of any process pq started (pass-cli, fzf, clipboard).
    pub fn run(&self, args: &[&str]) -> Output {
        self.write_scenario();
        // A permissive umask, so the cache's 0600 mode is pq's doing and not
        // inherited from the developer's shell.
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"umask 022 && exec "$0" "$@""#)
            .arg(env!("CARGO_BIN_EXE_pq"))
            .args(args)
            .env_clear()
            .env("PATH", self.path_var())
            .env("HOME", self.home_dir())
            .env("XDG_CACHE_HOME", self.cache_dir())
            .env("PQ_FAKE_DIR", self.fake_dir())
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .expect("run pq");
        self.assert_no_leaks(&output);
        output
    }

    /// The argument logs of every fake tool, as raw bytes: neither split into
    /// lines (a secret may contain a newline) nor decoded (one non-UTF-8 byte
    /// must not hide the rest of a log). A log that exists but cannot be read
    /// fails the test.
    fn raw_argument_logs(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let fake = self.fake_dir();
        let mut paths = vec![fake.join("calls"), fake.join("fzf-args")];
        match fs::read_dir(fake.join("clipboard")) {
            Ok(entries) => paths.extend(
                entries
                    .map(|entry| entry.expect("read clipboard log dir").path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "args")),
            ),
            // Nothing was copied.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("read clipboard log dir: {e}"),
        }
        paths
            .into_iter()
            .filter_map(|path| match fs::read(&path) {
                Ok(bytes) => Some((path, bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => panic!("read {}: {e}", path.display()),
            })
            .collect()
    }

    /// Every username, email and password in the scenario.
    pub fn secrets(&self) -> Vec<&'static str> {
        self.items
            .iter()
            .filter_map(|item| match &item.content {
                Content::Login(login) => Some([login.username, login.email, login.password]),
                Content::Note => None,
            })
            .flatten()
            .filter(|secret| !secret.is_empty())
            .collect()
    }

    fn assert_no_leaks(&self, output: &Output) {
        let argument_logs = self.raw_argument_logs();
        for secret in self.secrets() {
            assert!(
                !contains(&output.stderr, secret.as_bytes()),
                "stderr leaks {secret:?}:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            for (path, log) in &argument_logs {
                assert!(
                    !contains(log, secret.as_bytes()),
                    "{secret:?} passed as an argument ({})",
                    path.display()
                );
            }
        }
    }

    /// Every pass-cli invocation so far, as argument lists.
    pub fn calls(&self) -> Vec<Vec<String>> {
        let log = fs::read_to_string(self.fake_dir().join("calls")).unwrap_or_default();
        log.lines()
            .map(|line| {
                line.split('\t')
                    .filter(|arg| !arg.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .collect()
    }

    /// The pass-cli calls whose first two arguments are `command` (e.g. "item list").
    pub fn calls_to(&self, command: &str) -> Vec<Vec<String>> {
        self.calls()
            .into_iter()
            .filter(|call| call.len() >= 2 && call[..2].join(" ") == command)
            .collect()
    }

    pub fn clear_calls(&self) {
        let _ = fs::remove_file(self.fake_dir().join("calls"));
    }

    /// Everything copied to the clipboard, in order, with the arguments of each copy.
    pub fn copies(&self) -> Vec<(String, String)> {
        let dir = self.fake_dir().join("clipboard");
        (0..)
            .map_while(|n| {
                let text = fs::read_to_string(dir.join(format!("{n}.txt"))).ok()?;
                let args = fs::read_to_string(dir.join(format!("{n}.args"))).unwrap_or_default();
                Some((text, args))
            })
            .collect()
    }

    /// The arguments of the last fzf invocation, tab-separated.
    pub fn fzf_args(&self) -> Option<String> {
        let log = fs::read_to_string(self.fake_dir().join("fzf-args")).ok()?;
        log.lines().last().map(str::to_string)
    }

    pub fn fzf_input(&self) -> Option<String> {
        fs::read_to_string(self.fake_dir().join("fzf-input")).ok()
    }

    /// The cache file, parsed, after checking that it holds only searchable
    /// metadata: its keys must be the known ones and no string in it (after
    /// JSON unescaping) may contain a username, email or password.
    pub fn cache_json(&self) -> Value {
        let text = fs::read_to_string(self.cache_file()).expect("cache written");
        let cache: Value = serde_json::from_str(&text).expect("cache is JSON");
        assert_only_keys(&cache, &["vault_list", "vaults"]);
        if let Some(list) = cache.get("vault_list").filter(|v| !v.is_null()) {
            assert_only_keys(list, &["vaults", "timestamp"]);
            assert_only_keys(&list["vaults"], &["vaults"]);
            for vault in list["vaults"]["vaults"].as_array().unwrap() {
                assert_only_keys(vault, &["name", "share_id"]);
            }
        }
        for vault in cache["vaults"].as_array().unwrap() {
            assert_only_keys(vault, &["vault_name", "login_only", "items", "timestamp"]);
            assert_only_keys(&vault["items"], &["items"]);
            for item in vault["items"]["items"].as_array().unwrap() {
                assert_only_keys(item, &["id", "share_id", "title", "item_type"]);
            }
        }
        let mut strings = Vec::new();
        collect_strings(&cache, &mut strings);
        for secret in self.secrets() {
            for s in &strings {
                assert!(!s.contains(secret), "cache leaks {secret:?} in {s:?}");
            }
        }
        cache
    }

    pub fn write_cache(&self, contents: &str) {
        let path = self.cache_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    pub fn cache_file(&self) -> PathBuf {
        self.cache_dir()
            .join("pp-pass-cli")
            .join("vault-cache.json")
    }

    fn write_scenario(&self) {
        let fake = self.fake_dir();
        // Rebuilt on every run, so nothing from an earlier run lingers.
        for dir in ["items", "views", "fields"] {
            let _ = fs::remove_dir_all(fake.join(dir));
            fs::create_dir_all(fake.join(dir)).unwrap();
        }

        let vaults: Vec<Value> = self
            .vaults
            .iter()
            .map(|(name, share_id)| {
                json!({ "name": name, "vault_id": format!("vault-{share_id}"), "share_id": share_id })
            })
            .collect();
        write_json(&fake.join("vaults.json"), &json!({ "vaults": vaults }));

        for (_, share_id) in &self.vaults {
            let in_vault: Vec<&Item> = self
                .items
                .iter()
                .filter(|item| item.share_id == *share_id)
                .collect();
            let all: Vec<Value> = in_vault.iter().map(|item| summary(item)).collect();
            let logins: Vec<Value> = in_vault
                .iter()
                .filter(|item| matches!(item.content, Content::Login(_)))
                .map(|item| summary(item))
                .collect();
            write_json(
                &fake.join("items").join(format!("{share_id}.json")),
                &json!({ "items": all }),
            );
            write_json(
                &fake.join("items").join(format!("{share_id}.login.json")),
                &json!({ "items": logins }),
            );
        }

        // Items are stored under their vault's share ID, so a view with the
        // wrong share finds nothing.
        for item in &self.items {
            let views = fake.join("views").join(item.share_id);
            fs::create_dir_all(&views).unwrap();
            write_json(&views.join(format!("{}.json", item.id)), &view(item));
            let fields = fake.join("fields").join(item.share_id).join(item.id);
            fs::create_dir_all(&fields).unwrap();
            if let Content::Login(login) = &item.content {
                // pass-cli prints the value followed by a newline and omits empty fields.
                for (name, value) in [
                    ("username", login.username),
                    ("email", login.email),
                    ("password", login.password),
                ] {
                    if !value.is_empty() {
                        fs::write(fields.join(name), format!("{value}\n")).unwrap();
                    }
                }
            }
        }
    }

    fn install(&self, name: &str, script: &str) {
        let path = self.bin_dir().join(name);
        fs::write(&path, script).expect("write fake tool");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// Only the fakes and the few utilities they need are on PATH, so pq can
    /// never reach a real pass-cli, fzf or clipboard tool on the host.
    fn path_var(&self) -> String {
        format!(
            "{}:{}",
            self.bin_dir().display(),
            self.utils_dir().display()
        )
    }

    fn link_utils(&self) {
        for util in FAKE_UTILS {
            let target = ["/usr/bin", "/bin"]
                .iter()
                .map(|dir| Path::new(dir).join(util))
                .find(|path| path.exists())
                .unwrap_or_else(|| panic!("{util} not found in /usr/bin or /bin"));
            std::os::unix::fs::symlink(target, self.utils_dir().join(util)).unwrap();
        }
    }

    fn utils_dir(&self) -> PathBuf {
        self.root.path().join("utils")
    }

    fn bin_dir(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    fn fake_dir(&self) -> PathBuf {
        self.root.path().join("fake")
    }

    fn home_dir(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn cache_dir(&self) -> PathBuf {
        self.root.path().join("cache")
    }
}

fn summary(item: &Item) -> Value {
    let item_type = match item.content {
        Content::Login(_) => "login",
        Content::Note => "note",
    };
    json!({
        "id": item.id,
        "share_id": item.share_id,
        "vault_id": format!("vault-{}", item.share_id),
        "state": "Active",
        "flags": [],
        "create_time": "2026-01-01T00:00:00",
        "modify_time": "2026-01-02T00:00:00",
        "title": item.title,
        "item_type": item_type,
    })
}

fn view(item: &Item) -> Value {
    let content = match &item.content {
        Content::Login(login) => json!({ "Login": {
            "email": login.email,
            "username": login.username,
            "password": login.password,
            "urls": [],
            "totp_uri": "",
            "passkeys": [],
            "autofill_urls": [],
        }}),
        Content::Note => json!({ "Note": null }),
    };
    json!({
        "item": {
            "id": item.id,
            "share_id": item.share_id,
            "vault_id": format!("vault-{}", item.share_id),
            "content": {
                "title": item.title,
                "note": "",
                "item_uuid": format!("uuid-{}", item.id),
                "content": content,
                "extra_fields": [],
                "platform_specific": null,
                "custom_icon": null,
            },
            "state": "Active",
            "flags": [],
            "create_time": "2026-01-01T00:00:00",
            "modify_time": "2026-01-02T00:00:00",
        },
        "attachments": [],
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_only_keys(value: &Value, allowed: &[&str]) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"));
    for key in object.keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "unexpected cache key {key:?} in {value}"
        );
    }
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(map) => map.iter().for_each(|(k, v)| {
            out.push(k.clone());
            collect_strings(v, out);
        }),
        _ => {}
    }
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
