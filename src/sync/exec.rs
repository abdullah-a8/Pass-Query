//! Running `pass-cli` and `op` for pq-sync: secrets go in through stdin or
//! the environment, never the command line; output is captured, never
//! inherited; and a command that hangs is killed at its deadline, so an
//! unattended run always ends.

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command as StdCommand, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::secret::SecretString;

/// One command to run.
pub struct Command {
    program: PathBuf,
    args: Vec<String>,
    env: Vec<(String, SecretString)>,
    env_remove: Vec<String>,
    env_remove_prefixes: Vec<String>,
    stdin: Option<SecretString>,
    timeout: Duration,
}

/// A finished command. Stdout may hold secrets (item JSON); stderr is the
/// tool's diagnostics, to be summarised before it is shown.
pub struct Output {
    pub status: ExitStatus,
    pub stdout: SecretString,
    pub stderr: Vec<u8>,
}

impl Command {
    pub fn new(program: impl Into<PathBuf>, timeout: Duration) -> Self {
        Command {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            env_remove: Vec::new(),
            // pq-sync's own secrets, when they come from the environment,
            // are no tool's business: each gets only what it is given.
            env_remove_prefixes: vec!["PQ_SYNC_".to_string()],
            stdin: None,
            timeout,
        }
    }

    /// An argument. Only ever IDs, flags and names: never a secret.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<S: Into<String>>(mut self, args: impl IntoIterator<Item = S>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, key: &str, value: impl Into<SecretString>) -> Self {
        self.env.push((key.to_string(), value.into()));
        self
    }

    pub fn env_remove(mut self, key: &str) -> Self {
        self.env_remove.push(key.to_string());
        self
    }

    /// Leave out every inherited variable whose name starts with `prefix`
    /// (one set with [`Command::env`] still goes in).
    pub fn env_remove_prefix(mut self, prefix: &str) -> Self {
        self.env_remove_prefixes.push(prefix.to_string());
        self
    }

    /// Whether the inherited `key` is left out (and not set again).
    #[cfg(test)]
    pub fn removes(&self, key: &str) -> bool {
        self.env_remove.iter().any(|k| k == key) && !self.env.iter().any(|(k, _)| k == key)
    }

    #[cfg(test)]
    pub fn removes_prefix(&self, prefix: &str) -> bool {
        self.env_remove_prefixes.iter().any(|p| p == prefix)
    }

    pub fn stdin(mut self, input: SecretString) -> Self {
        self.stdin = Some(input);
        self
    }

    pub fn program(&self) -> &std::path::Path {
        &self.program
    }

    /// Run to completion or to the deadline, whichever comes first.
    pub fn run(self) -> Result<Output> {
        let name = self.program.display().to_string();
        let mut command = StdCommand::new(&self.program);
        command
            .args(&self.args)
            .stdin(if self.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if self
                .env_remove_prefixes
                .iter()
                .any(|p| name.starts_with(p.as_str()))
            {
                command.env_remove(&key);
            }
        }
        for key in &self.env_remove {
            command.env_remove(key);
        }
        for (key, value) in &self.env {
            command.env(key, OsString::from(value.expose()));
        }
        let mut child = spawn(&mut command).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("{name} not found")
            } else {
                anyhow::anyhow!("Failed to run {name}: {e}")
            }
        })?;

        // Write stdin and read both outputs on their own threads, so a tool
        // that fills one pipe while pq-sync writes the other cannot stall
        // either side; the results come back over channels, so a pipe held
        // open by a leftover process cannot hold the run past its deadline.
        let writer = self.stdin.and_then(|input| {
            let mut stdin = child.stdin.take()?;
            let (send, receive) = mpsc::channel();
            std::thread::spawn(move || {
                // A tool that exits without reading gives EPIPE; its exit
                // status says more.
                let _ = stdin.write_all(input.expose().as_bytes());
                let _ = send.send(());
            });
            Some(receive)
        });
        let stdout = read_in_background(child.stdout.take().context("stdout")?);
        let stderr = read_in_background(child.stderr.take().context("stderr")?);

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{name} did not finish within {}s", self.timeout.as_secs());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // Once the tool has exited, its input and output are waited for only
        // until the deadline (and a second more for the threads to finish).
        let left = || deadline.saturating_duration_since(Instant::now()) + Duration::from_secs(1);
        if let Some(writer) = writer {
            writer
                .recv_timeout(left())
                .map_err(|_| anyhow::anyhow!("{name} left its input open"))?;
        }
        let stdout = stdout
            .recv_timeout(left())
            .map_err(|_| anyhow::anyhow!("{name} left its output open"))??;
        let stderr = stderr
            .recv_timeout(left())
            .map_err(|_| anyhow::anyhow!("{name} left its error output open"))??;
        let stdout = String::from_utf8(stdout)
            .map_err(|_| anyhow::anyhow!("{name} printed output that is not UTF-8"))?;
        Ok(Output {
            status,
            stdout: SecretString::new(stdout),
            stderr,
        })
    }
}

/// Spawn, trying again for a moment while the program is busy being written
/// (ETXTBSY on Linux): just after it was installed or upgraded, or while
/// another thread's freshly forked child still holds it open for writing.
fn spawn(command: &mut StdCommand) -> std::io::Result<std::process::Child> {
    let mut tries = 0;
    loop {
        match command.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 20 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            result => return result,
        }
    }
}

fn read_in_background(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<Result<Vec<u8>>> {
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = pipe.read_to_end(&mut bytes).map(|_| bytes);
        let _ = send.send(result.context("read output"));
    });
    receive
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &tempfile::TempDir, body: &str) -> PathBuf {
        let path = dir.path().join("tool");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn stdin_and_environment_reach_the_tool_and_output_comes_back() {
        let dir = tempfile::tempdir().unwrap();
        let tool = script(
            &dir,
            r#"cat; printf ' %s %s' "$1" "$PQ_TEST_SECRET"; echo oops >&2"#,
        );
        let output = Command::new(&tool, Duration::from_secs(5))
            .arg("flag")
            .env("PQ_TEST_SECRET", "from-env")
            .stdin(SecretString::new("from-stdin"))
            .run()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.expose(), "from-stdin flag from-env");
        assert_eq!(output.stderr, b"oops\n");
    }

    #[test]
    fn removed_variables_are_not_inherited() {
        let dir = tempfile::tempdir().unwrap();
        let tool = script(&dir, r#"printf '%s' "${HOME:-unset}""#);
        let output = Command::new(&tool, Duration::from_secs(5))
            .env_remove("HOME")
            .run()
            .unwrap();
        assert_eq!(output.stdout.expose(), "unset");
    }

    #[test]
    fn variables_by_prefix_are_not_inherited_but_set_ones_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let tool = script(
            &dir,
            r#"printf '%s %s' "${HOME:-unset}" "${HOMELY:-unset}""#,
        );
        let output = Command::new(&tool, Duration::from_secs(5))
            .env_remove_prefix("HOM")
            .env("HOMELY", "mine")
            .run()
            .unwrap();
        assert_eq!(output.stdout.expose(), "unset mine");
    }

    #[test]
    fn a_hung_tool_is_killed_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let tool = script(&dir, "sleep 30");
        let started = Instant::now();
        let err = Command::new(&tool, Duration::from_millis(300))
            .run()
            .err()
            .unwrap();
        assert!(err.to_string().contains("did not finish"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_leftover_process_holding_stdout_does_not_hold_the_run() {
        let dir = tempfile::tempdir().unwrap();
        // The tool exits at once, leaving a child that keeps stdout open.
        let tool = script(&dir, "sleep 8 & echo done");
        let started = Instant::now();
        let result = Command::new(&tool, Duration::from_secs(2)).run();
        // Waited for the output only to the deadline (plus a second), not
        // for the leftover to exit.
        assert!(started.elapsed() < Duration::from_secs(6));
        let err = result.err().unwrap().to_string();
        assert!(err.contains("left its output open"), "{err}");
    }

    #[test]
    fn a_leftover_process_holding_stdin_does_not_hold_the_run() {
        let dir = tempfile::tempdir().unwrap();
        // The tool exits at once, leaving a child that keeps stdin open
        // without reading it, so a large input never finishes writing. The
        // pipe goes through fd 3: a shell without job control (dash) points
        // a background job's stdin at /dev/null before its redirections.
        let tool = script(&dir, "exec 3<&0; sleep 8 <&3 >/dev/null 2>&1 &");
        let started = Instant::now();
        let result = Command::new(&tool, Duration::from_secs(2))
            .stdin(SecretString::new("x".repeat(1 << 20)))
            .run();
        assert!(started.elapsed() < Duration::from_secs(6));
        let err = result.err().unwrap().to_string();
        assert!(err.contains("left its input open"), "{err}");
    }

    #[test]
    fn a_missing_tool_is_named() {
        let err = Command::new("/nonexistent/pq-sync-tool", Duration::from_secs(1))
            .run()
            .err()
            .unwrap();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn a_tool_that_exits_without_reading_stdin_is_reported_by_status() {
        let dir = tempfile::tempdir().unwrap();
        let tool = script(&dir, "exit 3");
        let output = Command::new(&tool, Duration::from_secs(5))
            .stdin(SecretString::new("x".repeat(1 << 20)))
            .run()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
    }
}
