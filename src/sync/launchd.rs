//! Running pq-sync on a schedule on macOS: a LaunchAgent in the owner's
//! session, so the login Keychain is unlocked and macOS can ask about it.
//! launchd runs a timer missed during sleep once on wake.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

pub const LABEL: &str = "io.github.abdullah-a8.pq-sync";

pub fn plist_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The agent's plist: `program run --quiet` every `interval` seconds, with
/// no output of its own (pq-sync keeps its report in its private state
/// directory) and at background priority.
pub fn plist(program: &Path, interval: u64, env: &[(String, String)]) -> String {
    let env = if env.is_empty() {
        String::new()
    } else {
        let entries: String = env
            .iter()
            .map(|(key, value)| {
                format!(
                    "        <key>{}</key>\n        <string>{}</string>\n",
                    escape(key),
                    escape(value)
                )
            })
            .collect();
        format!("    <key>EnvironmentVariables</key>\n    <dict>\n{entries}    </dict>\n")
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{program}</string>
        <string>run</string>
        <string>--quiet</string>
    </array>
    <key>StartInterval</key>
    <integer>{interval}</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
{env}</dict>
</plist>
"#,
        program = escape(&program.display().to_string())
    )
}

fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    std::process::Command::new("/bin/launchctl")
        .args(args)
        .output()
        .context("Failed to run launchctl")
}

fn domain() -> String {
    // SAFETY: getuid takes no arguments and cannot fail.
    format!("gui/{}", unsafe { libc::getuid() })
}

/// The XDG directories this shell sets, for the agent to use the same
/// config and state (launchd does not pass the shell's environment on).
fn xdg_env() -> Vec<(String, String)> {
    ["XDG_CONFIG_HOME", "XDG_STATE_HOME"]
        .into_iter()
        .filter_map(|key| {
            let value = std::env::var(key).ok()?;
            Path::new(&value)
                .is_absolute()
                .then(|| (key.to_string(), value))
        })
        .collect()
}

/// Write the agent and load it (replacing a loaded one).
pub fn install(program: &Path, interval: u64) -> Result<PathBuf> {
    if interval < 300 {
        bail!("an interval under 5 minutes would exhaust 1Password's daily request budget");
    }
    if super::secrets::from_env() {
        bail!(
            "the agent reads its tokens from the Keychain, not this shell's environment: \
             run `pq-sync setup` without PQ_SYNC_SECRETS_FROM_ENV first"
        );
    }
    let path = plist_path()?;
    std::fs::create_dir_all(path.parent().context("plist path has no directory")?)?;
    std::fs::write(&path, plist(program, interval, &xdg_env()))
        .with_context(|| format!("Failed to write {}", path.display()))?;
    unload(&path)?;
    let output = launchctl(&["bootstrap", &domain(), &path.display().to_string()])?;
    if !output.status.success() {
        bail!(
            "launchctl bootstrap failed: {}",
            crate::text::printable(String::from_utf8_lossy(&output.stderr).trim())
        );
    }
    Ok(path)
}

/// launchctl's exit codes for a service that is not loaded: ESRCH, and
/// "could not find specified service".
fn not_loaded(code: Option<i32>) -> bool {
    matches!(code, Some(3 | 113))
}

/// Unload the agent if it is loaded; an error if it stays loaded.
fn unload(path: &Path) -> Result<()> {
    let output = launchctl(&["bootout", &domain(), &path.display().to_string()])?;
    if output.status.success() || not_loaded(output.status.code()) {
        return Ok(());
    }
    bail!(
        "launchctl bootout failed, so the agent may still be loaded: {}",
        crate::text::printable(String::from_utf8_lossy(&output.stderr).trim())
    )
}

pub fn uninstall() -> Result<Option<PathBuf>> {
    let path = plist_path()?;
    if !path.exists() {
        return Ok(None);
    }
    unload(&path)?;
    std::fs::remove_file(&path).with_context(|| format!("Failed to remove {}", path.display()))?;
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plist_runs_quietly_on_an_interval() {
        let plist = plist(Path::new("/Users/me/.cargo/bin/pq-sync"), 1800, &[]);
        assert!(plist.contains("<string>/Users/me/.cargo/bin/pq-sync</string>"));
        assert!(plist.contains("<string>run</string>\n        <string>--quiet</string>"));
        assert!(plist.contains("<integer>1800</integer>"));
        assert!(plist.contains("<string>/dev/null</string>"));
        assert!(plist.contains(LABEL));
        assert!(!plist.contains("EnvironmentVariables"));
    }

    #[test]
    fn the_shells_xdg_directories_reach_the_agent() {
        let env = [("XDG_STATE_HOME".to_string(), "/Users/me/st&te".to_string())];
        let plist = plist(Path::new("/bin/pq-sync"), 1800, &env);
        assert!(plist.contains(
            "<key>EnvironmentVariables</key>\n    <dict>\n        \
             <key>XDG_STATE_HOME</key>\n        <string>/Users/me/st&amp;te</string>\n    </dict>\n</dict>"
        ));
    }

    #[test]
    fn only_an_agent_that_is_not_loaded_counts_as_unloaded() {
        assert!(not_loaded(Some(3)) && not_loaded(Some(113)));
        assert!(!not_loaded(Some(1)) && !not_loaded(Some(5)) && !not_loaded(None));
    }

    #[test]
    fn a_path_is_escaped_in_the_plist() {
        let plist = plist(Path::new("/tmp/a&b<c>/pq-sync"), 1800, &[]);
        assert!(plist.contains("/tmp/a&amp;b&lt;c&gt;/pq-sync"));
    }
}
