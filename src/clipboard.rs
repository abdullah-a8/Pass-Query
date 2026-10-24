//! The system clipboard, through the platform's command-line tool, and the
//! detached helper that clears a copied password after a while.
//!
//! Text always reaches the tool through its stdin, never on a command line.
//! The helper gets only a salted SHA-256 fingerprint of the password, through
//! a pipe, and clears the clipboard only if it still holds that password.

use anyhow::{Context, Result, bail};
use colored::Colorize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The hidden first argument that runs pq as the clear helper.
pub const CLEAR_HELPER_ARG: &str = "__clear-clipboard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tool {
    WlClipboard,
    Xclip,
    Xsel,
    Pbcopy,
}

impl Tool {
    fn copy_command(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Tool::WlClipboard => ("wl-copy", &[]),
            Tool::Xclip => ("xclip", &["-selection", "clipboard"]),
            Tool::Xsel => ("xsel", &["--clipboard", "--input"]),
            Tool::Pbcopy => ("pbcopy", &[]),
        }
    }

    fn paste_command(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Tool::WlClipboard => ("wl-paste", &["--no-newline"]),
            Tool::Xclip => ("xclip", &["-selection", "clipboard", "-o"]),
            Tool::Xsel => ("xsel", &["--clipboard", "--output"]),
            Tool::Pbcopy => ("pbpaste", &[]),
        }
    }

    /// A dedicated clear command, where the tool has one; otherwise the
    /// clipboard is cleared by copying an empty string.
    fn clear_command(self) -> Option<(&'static str, &'static [&'static str])> {
        match self {
            Tool::WlClipboard => Some(("wl-copy", &["--clear"])),
            Tool::Xsel => Some(("xsel", &["--clipboard", "--clear"])),
            Tool::Xclip | Tool::Pbcopy => None,
        }
    }

    fn install_hint(self) -> &'static str {
        match self {
            Tool::WlClipboard => "Install wl-clipboard (e.g. sudo apt install wl-clipboard)",
            Tool::Xclip | Tool::Xsel => "Install xclip or xsel (e.g. sudo apt install xclip)",
            Tool::Pbcopy => "pbcopy ships with macOS",
        }
    }
}

pub struct Clipboard {
    tool: Tool,
}

impl Clipboard {
    /// The clipboard of the current session: pbcopy on macOS; elsewhere
    /// Wayland when WAYLAND_DISPLAY is set, then X11 when DISPLAY is set
    /// (xclip, or xsel when xclip is not installed).
    pub fn detect() -> Result<Self> {
        if cfg!(target_os = "macos") {
            return Ok(Clipboard { tool: Tool::Pbcopy });
        }
        let set = |var: &str| std::env::var_os(var).is_some_and(|value| !value.is_empty());
        let tool = if set("WAYLAND_DISPLAY") {
            Tool::WlClipboard
        } else if set("DISPLAY") {
            if !on_path("xclip") && on_path("xsel") {
                Tool::Xsel
            } else {
                Tool::Xclip
            }
        } else {
            bail!(
                "{} No clipboard: neither WAYLAND_DISPLAY nor DISPLAY is set. Use {} to print the credentials instead.",
                "✗".red(),
                "-p".bold()
            );
        };
        let (program, _) = tool.copy_command();
        if !on_path(program) {
            bail!(
                "{} {program} not found. {}, or use {} to print the credentials instead.",
                "✗".red(),
                tool.install_hint(),
                "-p".bold()
            );
        }
        Ok(Clipboard { tool })
    }

    pub fn copy(&self, text: &str) -> Result<()> {
        let (program, args) = self.tool.copy_command();
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            // wl-copy, xclip and xsel fork to keep serving the selection in
            // the background; they must not hold on to pq's stdout or stderr,
            // or a script reading pq's output waits for them. pq reports a
            // failure from the exit status instead.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| {
                format!(
                    "{} Failed to run {program}. {}",
                    "✗".red(),
                    self.tool.install_hint()
                )
            })?;
        // A tool that exits early (xclip without a display) closes the pipe
        // before the write; its exit status says more than "broken pipe".
        // Dropping stdin after the write gives the tool its end of input.
        let written = child
            .stdin
            .take()
            .map(|mut stdin| stdin.write_all(text.as_bytes()))
            .transpose();
        let status = child.wait()?;
        if !status.success() {
            bail!("{} {program} failed ({status})", "✗".red());
        }
        written.with_context(|| format!("{} write to {program}", "✗".red()))?;
        Ok(())
    }

    /// Read the clipboard. Only the clear helper reads it.
    fn paste(&self) -> Result<Vec<u8>> {
        let (program, args) = self.tool.paste_command();
        run_bounded(program, args, true)
    }

    /// Empty the clipboard: with the tool's clear command, or by copying
    /// nothing (an empty stdin) where it has none.
    fn clear(&self) -> Result<()> {
        let (program, args) = self
            .tool
            .clear_command()
            .unwrap_or_else(|| self.tool.copy_command());
        run_bounded(program, args, false).map(drop)
    }

    /// Start a detached helper that clears the clipboard `delay` after now,
    /// or `delay` after [`PendingClear::copied`] if that comes first, if it
    /// still holds `secret`. pq does not wait for it.
    pub fn clear_later(&self, secret: &str, delay: Duration) -> Result<PendingClear> {
        let salt = random_salt()?;
        let fingerprint = fingerprint(&salt, secret.as_bytes());
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([CLEAR_HELPER_ARG, &delay.as_secs().to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Its own process group, so a Ctrl-C at the terminal after pq exits
        // does not reach it.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut helper = command
            .spawn()
            .context("start the clipboard clear helper")?;
        let mut stdin = helper.stdin.take().context("helper stdin")?;
        writeln!(stdin, "{} {}", hex(&salt), hex(&fingerprint))?;
        Ok(PendingClear { stdin })
    }
}

/// A started clear helper, still listening to pq.
pub struct PendingClear {
    stdin: ChildStdin,
}

impl PendingClear {
    /// Tell the helper the secret is on the clipboard now, so its delay
    /// starts again from here: a slow copy is still cleared a full delay
    /// after it lands.
    pub fn copied(mut self) {
        // If the helper is gone there is nothing to tell.
        let _ = writeln!(self.stdin, "{COPIED}");
    }
}

/// The line pq sends the helper once the secret is on the clipboard.
const COPIED: &str = "copied";

/// The clear helper: `pq __clear-clipboard <seconds>`, with "<salt> <fingerprint>"
/// (hex) on stdin, then "copied" once pq has copied the secret. Never prints:
/// its output goes nowhere.
///
/// A check clears the clipboard if it still holds the fingerprinted text.
/// While pq is still copying, the helper checks every `seconds`, so a pq that
/// dies or hangs mid-copy is covered; a failed check (an empty clipboard makes
/// wl-paste fail) settles nothing. "copied" schedules the final check
/// `seconds` later, so a slow copy is still cleared a full delay after it
/// lands. If pq goes away without it, the next check is the last.
pub fn run_clear_helper(mut args: impl Iterator<Item = String>) -> Result<()> {
    let delay = Duration::from_secs(
        args.next()
            .context("missing delay")?
            .parse()
            .context("invalid delay")?,
    );
    let mut deadline = Instant::now() + delay;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let salt = unhex(parts.next().context("missing salt")?)?;
    let expected = unhex(parts.next().context("missing fingerprint")?)?;
    let clear_if_unchanged = || -> Result<()> {
        let clipboard = Clipboard::detect()?;
        // If the clipboard cannot be read, leave it alone rather than risk
        // clearing something the user copied since.
        let current = clipboard.paste()?;
        if fingerprint(&salt, &current).as_slice() == expected.as_slice() {
            clipboard.clear()?;
        }
        Ok(())
    };

    let (to_helper, from_pq) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            match line {
                Ok(line) if line == COPIED => {
                    let _ = to_helper.send(());
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let mut copied = false;
    loop {
        match from_pq.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(()) => {
                copied = true;
                deadline = Instant::now() + delay;
            }
            Err(RecvTimeoutError::Timeout) if copied => return clear_if_unchanged(),
            Err(RecvTimeoutError::Timeout) => {
                let _ = clear_if_unchanged();
                deadline = Instant::now() + delay;
            }
            Err(RecvTimeoutError::Disconnected) => {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                return clear_if_unchanged();
            }
        }
    }
}

/// How long the clear helper lets a clipboard command run. A stalled
/// clipboard owner can make one hang, and the helper must still end.
const HELPER_COMMAND_LIMIT: Duration = Duration::from_secs(5);

/// Run a clipboard command with no input, returning its stdout if `capture`,
/// and kill it if it runs past [`HELPER_COMMAND_LIMIT`].
fn run_bounded(program: &str, args: &[&str], capture: bool) -> Result<Vec<u8>> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .spawn()?;
    // The reader hands its result over a channel, so a process left behind
    // holding stdout open cannot keep the helper waiting past the deadline.
    let output = child.stdout.take().map(|mut stdout| {
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = send.send(stdout.read_to_end(&mut bytes).map(|_| bytes));
        });
        receive
    });
    let deadline = Instant::now() + HELPER_COMMAND_LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !status.success() {
        bail!("{program} failed ({status})");
    }
    match output {
        Some(output) => {
            match output.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(bytes) => Ok(bytes?),
                Err(_) => bail!("{program} left its output open"),
            }
        }
        None => Ok(Vec::new()),
    }
}

fn fingerprint(salt: &[u8], text: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(text);
    hasher.finalize().into()
}

fn random_salt() -> Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut salt))
        .context("read /dev/urandom")?;
    Ok(salt)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("invalid hex"))
        .collect()
}

/// Whether `program` is an executable file in a PATH directory.
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| is_executable(&dir.join(program)))
    })
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x7f, 0xff, 0x10];
        assert_eq!(hex(&bytes), "007fff10");
        assert_eq!(unhex("007fff10").unwrap(), bytes);
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
    }

    #[test]
    fn the_fingerprint_depends_on_the_salt_and_the_text() {
        let a = fingerprint(b"salt-a", b"secret");
        assert_eq!(a, fingerprint(b"salt-a", b"secret"));
        assert_ne!(a, fingerprint(b"salt-b", b"secret"));
        assert_ne!(a, fingerprint(b"salt-a", b"secret2"));
    }

    #[test]
    fn every_tool_has_copy_and_paste_commands() {
        for tool in [Tool::WlClipboard, Tool::Xclip, Tool::Xsel, Tool::Pbcopy] {
            assert!(!tool.copy_command().0.is_empty());
            assert!(!tool.paste_command().0.is_empty());
        }
    }
}
