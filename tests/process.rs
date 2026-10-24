//! pq holds passwords in memory, so its memory must not end up in a core
//! file or be readable by the user's other processes.

mod support;

use support::{Harness, Login, stderr};

const GITHUB: Login = Login {
    id: "item-github",
    title: "github",
    username: "octocat",
    email: "",
    password: "github-secret",
};

fn run_pq() -> Harness {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", GITHUB);
    let out = h.run(&["github", "-p"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    h
}

#[test]
fn pq_turns_core_dumps_off() {
    let h = run_pq();

    // pass-cli inherits pq's limit.
    assert!(
        h.process_probe().starts_with("core=0"),
        "{}",
        h.process_probe()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn other_processes_of_the_user_cannot_read_pq_through_proc() {
    let h = run_pq();

    assert!(
        h.process_probe().contains("proc=protected"),
        "{}",
        h.process_probe()
    );
}
