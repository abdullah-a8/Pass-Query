//! pq warns when the installed pass-cli is older than the oldest it supports.

mod support;

use support::{Harness, Login, stderr, stdout};

const GITHUB: Login = Login {
    id: "item-github",
    title: "github",
    username: "octocat",
    email: "",
    password: "github-secret",
};

fn harness() -> Harness {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", GITHUB);
    h
}

#[test]
fn a_pass_cli_older_than_2_0_3_gets_an_upgrade_warning() {
    let h = harness();
    h.pass_cli_version("2.0.2");

    let out = h.run(&["github", "-p"]);

    let err = stderr(&out);
    assert!(err.contains("pass-cli 2.0.2 is older than 2.0.3"), "{err}");
    assert!(
        err.contains("https://protonpass.github.io/pass-cli/"),
        "{err}"
    );
    // A warning, not a refusal.
    assert!(out.status.success(), "{err}");
    assert_eq!(stdout(&out), "Username: octocat\nPassword: github-secret\n");
}

#[test]
fn supported_versions_get_no_warning() {
    for version in ["2.0.3", "2.5.1", "3.0.0", "2.10.0"] {
        let h = harness();
        h.pass_cli_version(version);

        let out = h.run(&["github", "-p"]);

        assert!(out.status.success(), "{version}: {}", stderr(&out));
        assert!(
            !stderr(&out).contains("older than"),
            "{version}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn an_unrecognised_version_string_is_ignored() {
    let h = harness();
    h.pass_cli_version("nightly");

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!stderr(&out).contains("older than"));
}

#[test]
fn the_version_is_checked_only_when_vaults_are_fetched_fresh() {
    let h = harness();
    assert!(h.run(&["github", "-p"]).status.success());
    let first: Vec<_> = h
        .calls()
        .into_iter()
        .filter(|c| c[0] == "--version")
        .collect();
    assert_eq!(first.len(), 1);
    h.clear_calls();

    assert!(h.run(&["github", "-p"]).status.success());

    assert!(h.calls().iter().all(|c| c[0] != "--version"));
}
