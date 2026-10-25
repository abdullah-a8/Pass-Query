//! A scriptable stand-in for `pass-cli` and `op` in unit tests: it records
//! each call's arguments, chosen environment variables and stdin, and
//! answers from canned responses keyed by its first two arguments.

#![cfg(all(test, unix))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub struct FakeCli {
    dir: tempfile::TempDir,
}

/// One recorded call.
#[derive(Debug)]
pub struct Call {
    pub args: Vec<String>,
    pub env: String,
    pub stdin: String,
}

/// The environment variables the fake writes down for each call.
const WATCHED_ENV: [&str; 12] = [
    "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
    "PROTON_PASS_SESSION_DIR",
    "PROTON_PASS_NO_UPDATE_CHECK",
    "PROTON_PASS_DISABLE_TELEMETRY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "MUON_LOG_LEVEL",
    "PASS_LOG_LEVEL",
    "OP_SERVICE_ACCOUNT_TOKEN",
    "OP_DEBUG",
    "OP_FORMAT",
    "PROTON_PASS_AGENT_REASON",
];

impl FakeCli {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["out", "err", "code", "calls"] {
            fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        let env_dump: String = WATCHED_ENV
            .iter()
            .map(|var| format!("printf '{var}=%s\\n' \"${{{var}-<unset>}}\""))
            .collect::<Vec<_>>()
            .join("; ");
        let script = format!(
            r#"#!/bin/sh
d='{dir}'
# Three files per call.
n=$(( $(ls "$d/calls" | wc -l) / 3 ))
for a in "$@"; do printf '%s\n' "$a"; done > "$d/calls/$n.args"
{{ {env_dump}; }} > "$d/calls/$n.env"
cat > "$d/calls/$n.stdin"
key="${{1:-}}-${{2:-}}"
# A one-shot answer for the next call with this key wins over the standing one.
if [ -e "$d/out/$key.once" ]; then
    cat "$d/out/$key.once"; cat "$d/err/$key.once" >&2 2>/dev/null
    code=$(cat "$d/code/$key.once" 2>/dev/null || echo 0)
    rm -f "$d/out/$key.once" "$d/err/$key.once" "$d/code/$key.once"
    exit "$code"
fi
[ -e "$d/out/$key" ] && cat "$d/out/$key"
[ -e "$d/err/$key" ] && cat "$d/err/$key" >&2
exit "$(cat "$d/code/$key" 2>/dev/null || echo 0)"
"#,
            dir = dir.path().display()
        );
        let tool = dir.path().join("tool");
        fs::write(&tool, script).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        FakeCli { dir }
    }

    pub fn program(&self) -> PathBuf {
        self.dir.path().join("tool")
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Answer calls whose first two arguments are `a b` with `stdout`.
    pub fn respond(&self, key: &str, stdout: &str) {
        fs::write(self.dir.path().join("out").join(key), stdout).unwrap();
    }

    /// Fail calls with `key` with `stderr` and exit code 1.
    pub fn fail(&self, key: &str, stderr: &str) {
        fs::write(self.dir.path().join("err").join(key), stderr).unwrap();
        fs::write(self.dir.path().join("code").join(key), "1").unwrap();
    }

    /// Fail only the next call with `key`.
    pub fn fail_once(&self, key: &str, stderr: &str) {
        fs::write(self.dir.path().join("out").join(format!("{key}.once")), "").unwrap();
        fs::write(
            self.dir.path().join("err").join(format!("{key}.once")),
            stderr,
        )
        .unwrap();
        fs::write(
            self.dir.path().join("code").join(format!("{key}.once")),
            "1",
        )
        .unwrap();
    }

    pub fn calls(&self) -> Vec<Call> {
        let count = fs::read_dir(self.dir.path().join("calls")).unwrap().count() / 3;
        (0..count)
            .map(|n| {
                let read = |ext: &str| {
                    fs::read_to_string(self.dir.path().join("calls").join(format!("{n}.{ext}")))
                        .unwrap()
                };
                Call {
                    args: read("args").lines().map(str::to_string).collect(),
                    env: read("env"),
                    stdin: read("stdin"),
                }
            })
            .collect()
    }

    /// Every argument of every call, for leak checks.
    pub fn all_args(&self) -> String {
        self.calls()
            .iter()
            .map(|call| call.args.join("\n"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
