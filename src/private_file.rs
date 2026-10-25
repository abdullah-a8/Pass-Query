//! Files only the user can read or write: pq's metadata cache and pq-sync's
//! state. Both hold an inventory of account names and IDs, and pq trusts
//! what they say about which ID belongs to which title, so a file someone
//! else could have written is treated as missing.

use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Create `dir` if needed and make it private to the user. An existing path
/// that is a link or belongs to someone else is left alone, with an error.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).context("Failed to create directory")?;
    #[cfg(unix)]
    {
        // Checked and changed through one handle, opened without following a
        // link, so the path cannot be swapped for a link in between.
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(dir)
            .context("Directory is a link or cannot be opened")?;
        let meta = handle.metadata().context("Failed to inspect directory")?;
        if !owned_by_user(&meta) {
            anyhow::bail!("Directory {} is not yours", dir.display());
        }
        handle
            .set_permissions(fs::Permissions::from_mode(0o700))
            .context("Failed to restrict directory permissions")?;
    }
    Ok(())
}

/// The file's contents, if it can be trusted: a regular file, not reached
/// through a link, in a real directory, both the user's and writable by no
/// one else. Anything else may have been written by someone else and is
/// treated as missing.
pub fn read_private(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        let dir = fs::symlink_metadata(path.parent()?).ok()?;
        if !(dir.file_type().is_dir() && is_private(&dir)) {
            return None;
        }
        // O_NOFOLLOW refuses a link at the path; the checks then apply to
        // the file actually opened.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .ok()?;
        let meta = file.metadata().ok()?;
        if !(meta.file_type().is_file() && is_private(&meta)) {
            return None;
        }
        let mut data = String::new();
        file.read_to_string(&mut data).ok()?;
        Some(data)
    }
    #[cfg(not(unix))]
    fs::read_to_string(path).ok()
}

#[cfg(unix)]
pub fn owned_by_user(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid takes no arguments and cannot fail.
    meta.uid() == unsafe { libc::getuid() }
}

/// The user's, and writable by no one else.
#[cfg(unix)]
fn is_private(meta: &fs::Metadata) -> bool {
    owned_by_user(meta) && meta.permissions().mode() & 0o022 == 0
}

/// Replace `path` with `contents`. They go to a new 0600 file beside it,
/// which is then renamed over it: a reader never sees a partial file, and a
/// link planted at the path is replaced, not followed.
pub fn write_private(path: &Path, contents: &str) -> Result<()> {
    let dir = path.parent().context("Path has no directory")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Path has no file name")?;
    let (temp, mut file) = create_temp_file(dir, name).context("Failed to write file")?;
    let written = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp, path));
    if written.is_err() {
        // Only ever the file this run created.
        let _ = fs::remove_file(&temp);
    }
    written.context("Failed to write file")
}

/// Writes by this process, numbering its temporary files.
static WRITES: AtomicUsize = AtomicUsize::new(0);

/// A new 0600 file beside the target, under a name no one else holds: a name
/// left by a crashed run, or taken by a concurrent writer, is skipped, never
/// reused or removed.
fn create_temp_file(dir: &Path, name: &str) -> std::io::Result<(PathBuf, fs::File)> {
    let stem = name.strip_suffix(".json").unwrap_or(name);
    let mut attempts = 0;
    loop {
        let temp = dir.join(format!(
            ".{stem}.{}.{}.tmp",
            std::process::id(),
            WRITES.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temp) {
            Ok(file) => return Ok((temp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempts < 16 => {
                attempts += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_temporary_name_is_skipped_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        // Left by a crashed pq with this pid, or by another writer.
        let next = WRITES.load(Ordering::Relaxed);
        let taken: Vec<_> = (next..next + 4)
            .map(|n| {
                dir.path()
                    .join(format!(".vault-cache.{}.{n}.tmp", std::process::id()))
            })
            .collect();
        for path in &taken {
            fs::write(path, "someone else's").unwrap();
        }
        let cache = dir.path().join("vault-cache.json");

        write_private(&cache, "{}").unwrap();

        assert_eq!(fs::read_to_string(&cache).unwrap(), "{}");
        for path in &taken {
            assert_eq!(fs::read_to_string(path).unwrap(), "someone else's");
        }
    }
}
