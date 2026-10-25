//! One pq-sync run at a time: a scheduled run and one started by hand must
//! not interleave their writes to the same items and state.

use anyhow::{Context, Result, bail};
use std::fs::{File, OpenOptions};
use std::path::Path;

/// Held for the life of a run; released when dropped (or when the process
/// ends, however it ends).
pub struct RunLock {
    _file: File,
}

impl RunLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .with_context(|| format!("Failed to open the run lock {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: flock takes a descriptor this File owns.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                bail!("another pq-sync run is in progress");
            }
        }
        Ok(RunLock { _file: file })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_second_run_is_refused_until_the_first_ends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let first = RunLock::acquire(&path).unwrap();
        let err = RunLock::acquire(&path).err().unwrap();
        assert!(err.to_string().contains("in progress"), "{err}");
        drop(first);
        // Another test's child process, between fork and exec, can hold the
        // descriptor (and so the lock) for a moment.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while RunLock::acquire(&path).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "the lock was never released"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
