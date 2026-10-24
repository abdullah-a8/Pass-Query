//! The metadata cache is used for up to a day; a search it cannot answer, or a
//! cached item that has gone, triggers one search on fresh data.

mod support;

use support::{Harness, Login, stderr, stdout};

const REDDIT: Login = Login {
    id: "item-reddit",
    title: "reddit",
    username: "redditor",
    email: "me@example.com",
    password: "reddit-secret",
};

const GITHUB: Login = Login {
    id: "item-github",
    title: "github",
    username: "octocat",
    email: "",
    password: "github-secret",
};

// stderr of pass-cli 2.5.1 when the session lock is engaged.
const LOCKED: &str = "Session is locked. Please unlock your session and try again.\n\
Error: Error listing vaults\n\nCaused by:\n    Could not perform operation. Reason: SessionLocked\n";

fn personal_vault() -> Harness {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", REDDIT)
        .login("share-personal", GITHUB);
    h
}

fn has_arg(call: &[String], arg: &str) -> bool {
    call.iter().any(|a| a == arg)
}

const HOUR: u64 = 60 * 60;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A current-format cache of the Personal vault holding only `github`, written `age` seconds ago.
fn cache_of_github(age: u64) -> String {
    let ts = now() - age;
    serde_json::json!({
        "version": 2,
        "vault_list": { "vaults": { "vaults": [{ "name": "Personal", "share_id": "share-personal" }] }, "timestamp": ts },
        "vaults": [{
            "vault_name": "Personal", "login_only": true, "timestamp": ts,
            "items": { "items": [{ "id": "item-github", "share_id": "share-personal",
                                    "title": "github", "item_type": "login", "state": "Active" }] }
        }]
    })
    .to_string()
}

#[test]
fn a_cache_younger_than_a_day_is_used_even_when_hours_old() {
    let h = personal_vault();
    h.write_cache(&cache_of_github(23 * HOUR));

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(h.calls_to("vault list").is_empty());
    assert!(h.calls_to("item list").is_empty());
}

#[test]
fn a_cache_older_than_a_day_is_refetched() {
    let h = personal_vault();
    h.write_cache(&cache_of_github(25 * HOUR));

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(h.calls_to("vault list").len(), 1);
    assert_eq!(h.calls_to("item list").len(), 1);
}

#[test]
fn a_cache_timestamp_in_the_future_does_not_crash() {
    let h = personal_vault();
    let future = cache_of_github(0).replace(&now().to_string(), &(now() + 10 * HOUR).to_string());
    h.write_cache(&future);

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
}

#[test]
fn an_item_added_since_the_cache_was_written_is_found_by_one_refresh() {
    let mut h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success());
    h.login(
        "share-personal",
        Login {
            id: "item-gitea",
            title: "gitea",
            ..GITHUB
        },
    );
    h.clear_calls();

    let out = h.run(&["gitea", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "Username: octocat\nPassword: github-secret\n");
    assert_eq!(h.calls_to("vault list").len(), 1);
    assert_eq!(h.calls_to("item list").len(), 1);
}

#[test]
fn a_query_that_matches_nothing_refreshes_only_once() {
    let h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success());
    h.clear_calls();

    let out = h.run(&["nothing-matches-this", "-p"]);

    assert!(!out.status.success());
    assert!(stderr(&out).contains("No items found"));
    assert_eq!(h.calls_to("vault list").len(), 1);
    assert_eq!(h.calls_to("item list").len(), 1);
}

#[test]
fn a_fresh_search_with_no_match_does_not_refresh_again() {
    let h = personal_vault();

    let out = h.run(&["nothing-matches-this", "-p"]);

    assert!(!out.status.success());
    assert_eq!(h.calls_to("vault list").len(), 1);
    assert_eq!(h.calls_to("item list").len(), 1);
}

#[test]
fn a_cached_item_deleted_in_proton_is_searched_again_with_fresh_data() {
    let mut h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success());
    // Deleted and recreated with a new ID since pq cached it.
    h.remove("item-github").login(
        "share-personal",
        Login {
            id: "item-github-new",
            password: "rotated",
            ..GITHUB
        },
    );
    h.clear_calls();

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "Username: octocat\nPassword: rotated\n");
    assert_eq!(h.calls_to("item list").len(), 1);
    let views = h.calls_to("item view");
    assert_eq!(views.len(), 2);
    assert!(has_arg(&views[1], "--item-id=item-github-new"));
}

#[test]
fn a_session_problem_on_a_cached_item_is_reported_without_refreshing() {
    let h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success());
    h.clear_calls();
    h.fail("item-view", LOCKED);

    let out = h.run(&["github", "-p"]);

    assert!(!out.status.success());
    assert!(stderr(&out).contains("pass-cli session unlock"));
    assert!(h.calls_to("vault list").is_empty());
    assert!(h.calls_to("item list").is_empty());
    assert_eq!(h.calls_to("item view").len(), 1);
}

#[test]
fn the_retry_reuses_item_lists_fetched_in_the_same_run() {
    let mut h = personal_vault();
    h.vault("Work", "share-work");
    assert!(h.run(&["github", "-p"]).status.success()); // caches the vault list and login lists
    h.clear_calls();

    // -a needs every item type, so both vaults' lists are fetched fresh; only the
    // vault list comes from the cache. The retry must not fetch the lists again.
    let out = h.run(&["nothing-matches-this", "-a", "-p"]);

    assert!(!out.status.success());
    assert_eq!(h.calls_to("vault list").len(), 1);
    assert_eq!(h.calls_to("item list").len(), 2);
}

#[test]
fn an_empty_cached_vault_list_is_checked_again_before_saying_there_are_no_vaults() {
    let h = personal_vault();
    h.write_cache(
        &serde_json::json!({
            "version": 2,
            "vault_list": { "vaults": { "vaults": [] }, "timestamp": now() },
            "vaults": []
        })
        .to_string(),
    );

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(h.calls_to("vault list").len(), 1);
    assert_eq!(stdout(&out), "Username: octocat\nPassword: github-secret\n");
}
