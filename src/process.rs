//! pq holds passwords in memory. This keeps that memory out of core files
//! and away from the user's other processes.

/// Turn core dumps off for pq and everything it starts, and on Linux make pq
/// non-dumpable, which also stops other processes of the same user from
/// reading its memory through /proc or attaching a debugger. Best effort: pq
/// runs on if the system refuses.
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
