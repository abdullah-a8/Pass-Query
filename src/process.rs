//! pq holds passwords in memory. This keeps that memory out of core files
//! and away from the user's other processes.

/// Protect pq's own memory: on Linux, make pq non-dumpable, so the kernel
/// writes no core dump of it (unless fs.suid_dumpable is set to allow
/// root-only dumps) and other
/// processes of the same user cannot read its memory through /proc or attach
/// a debugger; and set the core size limit to zero, which also stops
/// file-based core dumps on macOS. Programs pq starts (pass-cli, fzf, the
/// clipboard tools) inherit the zero limit, but Linux makes them dumpable
/// again when they start, and a dump handler ignores the limit: their memory
/// is theirs to protect. Best effort: pq runs on if the system refuses.
pub fn protect_memory() {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit only reads the rlimit struct passed by reference.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
    }
    // SAFETY: PR_SET_DUMPABLE takes plain integer arguments.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}
