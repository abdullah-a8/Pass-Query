//! Session problems (locked, ended, not logged in) are explained with their fix,
//! and a search that could not reach any vault says so.

mod support;

use support::{Harness, Login, stderr, stdout};

const GITHUB: Login = Login {
    id: "item-github",
    title: "github",
    username: "octocat",
    email: "",
    password: "github-secret",
};

fn personal_vault() -> Harness {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", GITHUB);
    h
}

// stderr of pass-cli 2.5.1 when the session lock is engaged.
const LOCKED: &str = "Session is locked. Please unlock your session and try again.\n\
Error: Error listing vaults\n\nCaused by:\n    Could not perform operation. Reason: SessionLocked\n";
// stderr of pass-cli 2.5.1 after Proton invalidated the session.
const INVALIDATED: &str = "Your session has been invalidated and you have been logged out automatically.\n\
Please log in again with: pass login\n";
const NOT_LOGGED_IN: &str = "Error: This operation requires an authenticated client\n";

#[test]
fn a_locked_session_gives_an_unlock_hint() {
    let h = personal_vault();
    h.fail("vault-list", LOCKED);

    let out = h.run(&["reddit", "-p"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("session is locked"), "{err}");
    assert!(err.contains("pass-cli session unlock"), "{err}");
}

#[test]
fn an_invalidated_session_gives_a_login_hint() {
    let h = personal_vault();
    h.fail("vault-list", INVALIDATED);

    let out = h.run(&["reddit", "-p"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("session has ended"), "{err}");
    assert!(err.contains("pass-cli login"), "{err}");
    assert!(
        !err.contains("pass login\n"),
        "repeats pass-cli's wrong command name: {err}"
    );
}

#[test]
fn a_session_problem_while_listing_items_stops_the_search_with_its_hint() {
    let mut h = personal_vault();
    h.vault("Work", "share-work");
    assert!(h.run(&["github", "-p"]).status.success()); // caches the vault list
    std::fs::remove_file(h.cache_file()).unwrap();
    h.fail("item-list", LOCKED);

    let out = h.run(&["github", "-p"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("pass-cli session unlock"), "{err}");
    assert!(!err.contains("vault search failed"), "{err}");
    assert!(!err.contains("No items found"), "{err}");
}

#[test]
fn not_logged_in_while_listing_items_from_a_cached_vault_list_gives_a_login_hint() {
    let h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success());
    // Keep the cached vault list but force the item lists to be fetched again.
    let cache = std::fs::read_to_string(h.cache_file()).unwrap();
    let mut cache: serde_json::Value = serde_json::from_str(&cache).unwrap();
    cache["vaults"] = serde_json::json!([]);
    h.write_cache(&cache.to_string());
    h.fail("item-list", NOT_LOGGED_IN);

    let out = h.run(&["github", "-p"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("Not logged in"), "{err}");
    assert!(err.contains("pass-cli login"), "{err}");
}

#[test]
fn a_locked_session_when_fetching_credentials_gives_an_unlock_hint() {
    let h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success()); // lists now cached
    h.fail("item-view", LOCKED);

    let out = h.run(&["github", "-p"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("pass-cli session unlock"), "{err}");
    assert!(stdout(&out).is_empty());
}

#[test]
fn every_vault_failing_is_reported_as_an_error_not_as_no_match() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .vault("Work", "share-work");
    h.fail_vault(
        "share-personal",
        "Error: Could not perform operation. Reason: NotFound\n",
    );
    h.fail_vault(
        "share-work",
        "Error: Could not perform operation. Reason: NotFound\n",
    );

    let out = h.run(&["github", "-p"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("Could not search any vault"), "{err}");
    assert!(err.contains("NotFound"), "{err}");
    assert!(!err.contains("No items found"), "{err}");
}

#[test]
fn a_locked_session_while_labelling_duplicate_titles_gives_an_unlock_hint() {
    let mut h = personal_vault();
    h.vault("Work", "share-work").login(
        "share-work",
        Login {
            id: "item-github-work",
            ..GITHUB
        },
    );
    h.pick(1);
    assert!(h.run(&["github", "-p"]).status.success()); // caches both lists
    h.clear_calls();
    h.fail("item-view", LOCKED);

    let out = h.run(&["github", "-p"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("pass-cli session unlock"), "{err}");
    assert!(
        h.fzf_input().is_none(),
        "picker opened despite the locked session"
    );
}

#[test]
fn a_session_problem_is_reported_without_waiting_for_slow_vaults() {
    let mut h = personal_vault();
    h.vault("Slow", "share-slow");
    h.fail_vault("share-personal", LOCKED);
    h.slow_vault("share-slow", 10);

    let started = std::time::Instant::now();
    let out = h.run(&["github", "-p"]);
    let took = started.elapsed();

    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("pass-cli session unlock"),
        "{}",
        stderr(&out)
    );
    assert!(
        took < std::time::Duration::from_secs(5),
        "waited {took:?} for a slow vault"
    );
}
