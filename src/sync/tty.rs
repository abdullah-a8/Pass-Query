//! Reading a token at the terminal without showing it.

use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Write};

use super::secret::SecretString;

/// Ask for a secret on the controlling terminal with echo off. It is read
/// from the terminal itself, not stdin, so it never passes through a pipe.
#[cfg(unix)]
pub fn read_secret(prompt: &str) -> Result<SecretString> {
    use std::os::unix::io::AsRawFd;

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("no terminal to ask on; run pq-sync setup in a terminal")?;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is plain data, filled by tcgetattr.
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd is the open terminal; original is a valid termios.
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        bail!("could not read the terminal settings");
    }
    let mut silent = original;
    silent.c_lflag &= !libc::ECHO;
    silent.c_lflag |= libc::ECHONL;
    // SAFETY: as above.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &silent) } != 0 {
        bail!("could not turn terminal echo off");
    }
    // Echo comes back on however the read ends.
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restores the settings read above on the same fd.
            unsafe {
                libc::tcsetattr(self.0, libc::TCSANOW, &self.1);
            }
        }
    }
    let _restore = Restore(fd, original);

    let mut writer = &tty;
    write!(writer, "{prompt}: ")?;
    writer.flush()?;
    let mut line = String::new();
    BufReader::new(&tty).read_line(&mut line)?;
    let value = line.trim_end_matches(['\r', '\n']).trim().to_string();
    if value.is_empty() {
        bail!("nothing entered");
    }
    Ok(SecretString::new(value))
}

#[cfg(not(unix))]
pub fn read_secret(_prompt: &str) -> Result<SecretString> {
    bail!("reading a secret at the terminal is not supported here")
}
