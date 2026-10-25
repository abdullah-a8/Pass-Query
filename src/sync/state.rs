//! pq-sync's state file: which Proton vault and item each 1Password vault
//! and item mirrors, each side's change marker at the last sync, and the
//! keyed hash of every field at the last point both sides agreed.
//!
//! It holds IDs, titles' hashes and field hashes, never a value; still, it
//! is an inventory of accounts, so it lives in a private file
//! (`private_file`): 0600 in a 0700 directory, ignored if anyone else could
//! have written it. The field hashes are only comparable under the key that
//! made them, so the state records a check of that key and refuses to run
//! under another one.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::record::{FieldHash, Kind, keyed_hash};
use super::secret::parse_json;
use crate::private_file::{ensure_private_dir, read_private, write_private};

/// Bumped when the meaning of a field changes; an older file is refused,
/// not misread.
pub const STATE_FORMAT_VERSION: u32 = 1;

/// How long recorded 1Password requests count against the daily budget.
const DAY_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub version: u32,
    /// `keyed_hash(key, "key check", "")`: the key the hashes were made with.
    pub key_check: String,
    #[serde(default)]
    pub vaults: Vec<VaultPair>,
    #[serde(default)]
    pub items: Vec<ItemPair>,
    /// Unix times of 1Password requests in the last day, for the budget.
    #[serde(default)]
    pub op_requests: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultPair {
    pub proton_share: String,
    pub op_vault: String,
}

/// Where a pair's item was first created.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Proton,
    OnePassword,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemPair {
    pub kind: Kind,
    pub origin: Origin,
    pub proton_share: String,
    pub proton_item: String,
    pub op_vault: String,
    pub op_item: String,
    /// Proton's `modify_time` at the last sync; empty when not known yet.
    #[serde(default)]
    pub proton_modified: String,
    /// 1Password's item `version` at the last sync; 0 when not known yet.
    #[serde(default)]
    pub op_version: u64,
    /// Each field's keyed hash at the last point both sides agreed.
    #[serde(default)]
    pub base: BTreeMap<String, FieldHash>,
    /// `op_json::visible_fingerprint` of the 1Password item at the last sync.
    #[serde(default)]
    pub op_visible: String,
    /// Fields Proton could not receive when the item came from 1Password.
    #[serde(default)]
    pub proton_missing: BTreeSet<String>,
    /// Never edit the 1Password item from a template: it may hold data the
    /// CLI cannot show (a passkey) or keep (files).
    #[serde(default)]
    pub op_guarded: bool,
    /// The hash of each 1Password-only change already reported, so a run
    /// reports a change once, not every time.
    #[serde(default)]
    pub reported: BTreeMap<String, FieldHash>,
}

impl State {
    pub fn new(key: &[u8]) -> Self {
        State {
            version: STATE_FORMAT_VERSION,
            key_check: key_check(key),
            vaults: Vec::new(),
            items: Vec::new(),
            op_requests: Vec::new(),
        }
    }

    /// The state at `path`: a fresh one when there is none, an error when
    /// it is unreadable, from another format, or made under another key.
    pub fn load(path: &Path, key: &[u8]) -> Result<Self> {
        let Some(data) = read_private(path) else {
            if path.exists() {
                bail!(
                    "{} is not private to you (a link, someone else's, or writable by others); \
                     pq-sync will not trust it. Inspect it, then move it away to start over.",
                    path.display()
                );
            }
            return Ok(State::new(key));
        };
        let state: State = parse_json(&data, &format!("{}", path.display()))?;
        if state.version != STATE_FORMAT_VERSION {
            bail!(
                "{} is format {}, this pq-sync reads format {STATE_FORMAT_VERSION}",
                path.display(),
                state.version
            );
        }
        if state.key_check != key_check(key) {
            bail!(
                "{} was written with another state key. Restore that key in the Keychain, \
                 or move the file away to pair items again from scratch.",
                path.display()
            );
        }
        Ok(state)
    }

    /// Write the state atomically into its private directory.
    pub fn save(&self, path: &Path) -> Result<()> {
        ensure_private_dir(
            path.parent().context("State path has no directory")?,
            "state",
        )?;
        let json = serde_json::to_string_pretty(self).context("Failed to serialize the state")?;
        write_private(path, &json, "state")
    }

    pub fn vault_for_proton(&self, share: &str) -> Option<&VaultPair> {
        self.vaults.iter().find(|pair| pair.proton_share == share)
    }

    pub fn pair_by_proton(&self, share: &str, item: &str) -> Option<usize> {
        self.items
            .iter()
            .position(|pair| pair.proton_share == share && pair.proton_item == item)
    }

    pub fn pair_by_op(&self, vault: &str, item: &str) -> Option<usize> {
        self.items
            .iter()
            .position(|pair| pair.op_vault == vault && pair.op_item == item)
    }

    /// Record `count` 1Password requests made at `now`, dropping those
    /// older than a day.
    pub fn record_op_requests(&mut self, count: usize, now: u64) {
        self.op_requests
            .retain(|&at| at <= now && now - at < DAY_SECONDS);
        self.op_requests.extend(std::iter::repeat_n(now, count));
    }

    /// 1Password requests made in the day before `now`.
    pub fn op_requests_today(&self, now: u64) -> usize {
        self.op_requests
            .iter()
            .filter(|&&at| at <= now && now - at < DAY_SECONDS)
            .count()
    }
}

fn key_check(key: &[u8]) -> String {
    keyed_hash(key, "key check", b"")
}

/// `$XDG_STATE_HOME/pq-sync/state.json`, else `~/.local/state/pq-sync/state.json`.
pub fn default_path() -> Result<PathBuf> {
    let dir = match std::env::var_os("XDG_STATE_HOME").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?)
            .join(".local")
            .join("state"),
    };
    Ok(dir.join("pq-sync").join("state.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn pair() -> ItemPair {
        ItemPair {
            kind: Kind::Login,
            origin: Origin::Proton,
            proton_share: "share-1".into(),
            proton_item: "item-1".into(),
            op_vault: "vault-1".into(),
            op_item: "op-1".into(),
            proton_modified: "2026-10-25T00:00:00".into(),
            op_version: 3,
            base: BTreeMap::from([("title".to_string(), "ab".repeat(32))]),
            op_visible: "cd".repeat(32),
            proton_missing: BTreeSet::from(["note".to_string()]),
            op_guarded: false,
            reported: BTreeMap::new(),
        }
    }

    fn path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("pq-sync").join("state.json")
    }

    #[test]
    fn a_missing_state_is_a_fresh_one() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::load(&path(&dir), KEY).unwrap();
        assert_eq!(state, State::new(KEY));
        assert!(state.items.is_empty());
    }

    #[test]
    fn the_state_round_trips_privately() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = State::new(KEY);
        state.vaults.push(VaultPair {
            proton_share: "share-1".into(),
            op_vault: "vault-1".into(),
        });
        state.items.push(pair());
        state.save(&path(&dir)).unwrap();
        assert_eq!(State::load(&path(&dir), KEY).unwrap(), state);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path(&dir)), 0o600);
            assert_eq!(mode(path(&dir).parent().unwrap()), 0o700);
        }
        assert_eq!(state.pair_by_proton("share-1", "item-1"), Some(0));
        assert_eq!(state.pair_by_op("vault-1", "op-1"), Some(0));
        assert_eq!(state.pair_by_op("vault-1", "item-1"), None);
        assert!(state.vault_for_proton("share-1").is_some());
    }

    #[test]
    fn another_key_or_format_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        State::new(KEY).save(&path(&dir)).unwrap();
        let err = State::load(&path(&dir), b"another key").unwrap_err();
        assert!(err.to_string().contains("another state key"), "{err}");

        let mut old = State::new(KEY);
        old.version = 0;
        old.save(&path(&dir)).unwrap();
        let err = State::load(&path(&dir), KEY).unwrap_err();
        assert!(err.to_string().contains("format 0"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_state_others_could_write_is_refused_not_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        State::new(KEY).save(&path(&dir)).unwrap();
        std::fs::set_permissions(path(&dir), std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = State::load(&path(&dir), KEY).unwrap_err();
        assert!(err.to_string().contains("not private"), "{err}");
    }

    #[test]
    fn a_corrupt_state_is_an_error_without_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        State::new(KEY).save(&path(&dir)).unwrap();
        write_private(&path(&dir), "{\"version\": \"s3cret\"", "state").unwrap();
        let err = State::load(&path(&dir), KEY).unwrap_err();
        assert!(!format!("{err:#}").contains("s3cret"), "{err:#}");
    }

    #[test]
    fn op_requests_count_for_a_day() {
        let mut state = State::new(KEY);
        state.record_op_requests(3, 1_000);
        state.record_op_requests(2, 1_000 + DAY_SECONDS - 1);
        assert_eq!(state.op_requests_today(1_000 + DAY_SECONDS - 1), 5);
        assert_eq!(state.op_requests_today(1_000 + DAY_SECONDS), 2);
        state.record_op_requests(1, 1_000 + DAY_SECONDS);
        assert_eq!(
            state.op_requests.len(),
            3,
            "requests older than a day are dropped"
        );
        // A clock moved back does not count future requests.
        assert_eq!(state.op_requests_today(500), 0);
    }
}
