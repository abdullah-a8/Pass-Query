//! pq-sync's settings and where it keeps its files.
//!
//! The config names the programs pq-sync runs and the proxy pass-cli goes
//! through, so whoever can change it can make pq-sync hand the tokens to
//! another program: it is read only from a private file (`private_file`),
//! like the state.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::PathBuf;

use super::engine;
use super::secret::parse_json;
use crate::private_file::{ensure_private_dir, read_private, write_private};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The `pass-cli` program (an absolute path, set by `pq-sync setup`).
    pub pass_cli: String,
    /// The `op` program.
    pub op: String,
    /// `http://host:port` pass-cli goes through; empty: none.
    pub proton_proxy: String,
    pub vault_prefix: String,
    pub include_vaults: Vec<String>,
    pub exclude_vaults: Vec<String>,
    pub create_op_vaults: bool,
    pub op_requests_per_day: usize,
    pub op_writes_per_run: usize,
    /// Show a macOS notification when a run needs the owner.
    pub notify: bool,
}

impl Default for Config {
    fn default() -> Self {
        let engine = engine::Config::default();
        Config {
            pass_cli: "pass-cli".to_string(),
            op: "op".to_string(),
            proton_proxy: String::new(),
            vault_prefix: engine.vault_prefix,
            include_vaults: Vec::new(),
            exclude_vaults: Vec::new(),
            create_op_vaults: engine.create_op_vaults,
            op_requests_per_day: engine.op_requests_per_day,
            op_writes_per_run: engine.op_writes_per_run,
            notify: true,
        }
    }
}

impl Config {
    /// The config at `path`; the defaults when there is none.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        match read_private(path) {
            Some(data) => parse_json(&data, &path.display().to_string()),
            None if path.exists() => anyhow::bail!(
                "{} is not private to you (a link, someone else's, or writable by others); \
                 pq-sync will not use it",
                path.display()
            ),
            None => Ok(Config::default()),
        }
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        ensure_private_dir(
            path.parent().context("Config path has no directory")?,
            "config",
        )?;
        let json = serde_json::to_string_pretty(self).context("Failed to serialize the config")?;
        write_private(path, &json, "config")
    }

    /// The engine's settings for a run.
    pub fn engine(&self) -> engine::Config {
        engine::Config {
            vault_prefix: self.vault_prefix.clone(),
            include_vaults: self.include_vaults.clone(),
            exclude_vaults: self.exclude_vaults.clone(),
            create_op_vaults: self.create_op_vaults,
            op_requests_per_day: self.op_requests_per_day,
            op_writes_per_run: self.op_writes_per_run,
            ..engine::Config::default()
        }
    }
}

fn home() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME").context("HOME is not set")?,
    ))
}

fn xdg(var: &str, fallback: &[&str]) -> Result<PathBuf> {
    base_dir(std::env::var_os(var), fallback)
}

/// The XDG directory `value` names, or the home default. The XDG spec says
/// to ignore a relative value: it would move with the working directory,
/// and a run from elsewhere would find no state and start over.
fn base_dir(value: Option<OsString>, fallback: &[&str]) -> Result<PathBuf> {
    match value.map(PathBuf::from).filter(|dir| dir.is_absolute()) {
        Some(dir) => Ok(dir),
        None => Ok(fallback.iter().fold(home()?, |path, part| path.join(part))),
    }
}

/// `$XDG_CONFIG_HOME/pq-sync/config.json`, else `~/.config/pq-sync/config.json`.
pub fn config_path() -> Result<PathBuf> {
    Ok(xdg("XDG_CONFIG_HOME", &[".config"])?
        .join("pq-sync")
        .join("config.json"))
}

/// `$XDG_STATE_HOME/pq-sync`, else `~/.local/state/pq-sync`: the state, the
/// run lock, the last report and pass-cli's session for pq-sync.
pub fn state_dir() -> Result<PathBuf> {
    Ok(xdg("XDG_STATE_HOME", &[".local", "state"])?.join("pq-sync"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_absolute_xdg_directory_is_used() {
        let default = home().unwrap().join(".config");
        assert_eq!(
            base_dir(Some("/x/conf".into()), &[".config"]).unwrap(),
            PathBuf::from("/x/conf")
        );
        for ignored in [None, Some("".into()), Some("relative/conf".into())] {
            assert_eq!(base_dir(ignored, &[".config"]).unwrap(), default);
        }
    }

    #[test]
    fn a_missing_config_is_the_defaults_and_a_saved_one_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pq-sync").join("config.json");
        assert_eq!(Config::load(&path).unwrap(), Config::default());

        let config = Config {
            proton_proxy: "http://100.94.76.106:8888".into(),
            exclude_vaults: vec!["Shared".into()],
            ..Config::default()
        };
        config.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), config);
        assert_eq!(config.engine().exclude_vaults, ["Shared"]);
    }

    #[test]
    fn unknown_keys_and_open_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pq-sync").join("config.json");
        Config::default().save(&path).unwrap();
        write_private(&path, r#"{"op_path": "/tmp/evil"}"#, "config").unwrap();
        assert!(
            Config::load(&path).is_err(),
            "a misspelt key is not ignored"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Config::default().save(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            let err = Config::load(&path).unwrap_err();
            assert!(err.to_string().contains("not private"), "{err}");
        }
    }
}
