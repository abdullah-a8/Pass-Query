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
pub fn plist(program: &Path, interval: u64) -> String {
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
</dict>
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

/// Write the agent and load it (replacing a loaded one).
pub fn install(program: &Path, interval: u64) -> Result<PathBuf> {
    if interval < 300 {
        bail!("an interval under 5 minutes would exhaust 1Password's daily request budget");
    }
    let path = plist_path()?;
    std::fs::create_dir_all(path.parent().context("plist path has no directory")?)?;
    std::fs::write(&path, plist(program, interval))
        .with_context(|| format!("Failed to write {}", path.display()))?;
    let _ = launchctl(&["bootout", &domain(), &path.display().to_string()]);
    let output = launchctl(&["bootstrap", &domain(), &path.display().to_string()])?;
    if !output.status.success() {
        bail!(
            "launchctl bootstrap failed: {}",
            crate::text::printable(String::from_utf8_lossy(&output.stderr).trim())
        );
    }
    Ok(path)
}

pub fn uninstall() -> Result<Option<PathBuf>> {
    let path = plist_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let _ = launchctl(&["bootout", &domain(), &path.display().to_string()]);
    std::fs::remove_file(&path).with_context(|| format!("Failed to remove {}", path.display()))?;
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plist_runs_quietly_on_an_interval() {
        let plist = plist(Path::new("/Users/me/.cargo/bin/pq-sync"), 1800);
        assert!(plist.contains("<string>/Users/me/.cargo/bin/pq-sync</string>"));
        assert!(plist.contains("<string>run</string>\n        <string>--quiet</string>"));
        assert!(plist.contains("<integer>1800</integer>"));
        assert!(plist.contains("<string>/dev/null</string>"));
        assert!(plist.contains(LABEL));
    }

    #[test]
    fn a_path_is_escaped_in_the_plist() {
        let plist = plist(Path::new("/tmp/a&b<c>/pq-sync"), 1800);
        assert!(plist.contains("/tmp/a&amp;b&lt;c&gt;/pq-sync"));
    }
}
