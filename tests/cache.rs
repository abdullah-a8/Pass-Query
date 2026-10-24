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
    cache_of_github_at(now() - age)
}

/// The same cache, written at `ts`.
fn cache_of_github_at(ts: u64) -> String {
    serde_json::json!({
        "version": 3,
        "vault_list": { "vaults": { "vaults": [{ "name": "Personal", "share_id": "share-personal" }] }, "timestamp": ts },
        "vaults": [{
            "vault_key": "share:share-personal", "login_only": true, "timestamp": ts,
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
fn a_cache_timestamp_in_the_future_is_not_trusted() {
    for future in [now() + 10 * HOUR, u64::MAX] {
        let h = personal_vault();
        h.write_cache(&cache_of_github_at(future));

        let out = h.run(&["github", "-p"]);

        // A future timestamp (a clock moved back, or an edited cache) would
        // otherwise never expire: it is treated as stale and refetched.
        assert!(out.status.success(), "stderr: {}", stderr(&out));
        assert_eq!(h.calls_to("vault list").len(), 1, "{future}");
        assert_eq!(h.calls_to("item list").len(), 1, "{future}");
    }
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
            "version": 3,
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

/// Make the cached vault list (only) look a day old, so the next run
/// fetches it again while the cached item lists stay fresh.
fn expire_cached_vault_list(h: &Harness) {
    let cache = std::fs::read_to_string(h.cache_file()).unwrap();
    let mut cache: serde_json::Value = serde_json::from_str(&cache).unwrap();
    cache["vault_list"]["timestamp"] = (now() - 25 * HOUR).into();
    h.write_cache(&cache.to_string());
}

#[test]
fn a_vault_renamed_since_caching_never_lends_its_items_to_a_new_vault_of_that_name() {
    let mut h = Harness::new();
    h.vault("Personal", "share-old").login(
        "share-old",
        Login {
            id: "item-old",
            password: "old-secret",
            ..GITHUB
        },
    );
    assert!(h.run(&["github", "-p"]).status.success()); // caches share-old's list
    expire_cached_vault_list(&h);
    // "Personal" is now another vault; the old one is called "Old".
    h.rename_vault("share-old", "Old")
        .vault("Personal", "share-new")
        .login(
            "share-new",
            Login {
                id: "item-gitea",
                title: "gitea",
                ..GITHUB
            },
        );
    h.clear_calls();
    h.pick(1);

    let out = h.run(&["git", "-p"]);

    // Both vaults are searched under their current names; the old vault's
    // items are not shown as "Personal".
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let picker = h.fzf_input().expect("two matches");
    assert!(picker.contains("[Old] github"), "{picker}");
    assert!(picker.contains("[Personal] gitea"), "{picker}");
    assert!(!picker.contains("[Personal] github"), "{picker}");
    let lists = h.calls_to("item list");
    assert!(
        lists
            .iter()
            .any(|call| has_arg(call, "--share-id=share-new")),
        "the new vault was never listed: {lists:?}"
    );
}

const BANK_PERSONAL: Login = Login {
    id: "item-bank-personal",
    title: "bank personal",
    username: "me",
    email: "",
    password: "personal-secret",
};

const BANK_WORK: Login = Login {
    id: "item-bank-work",
    title: "bank work",
    username: "worker",
    email: "",
    password: "work-secret",
};

#[test]
fn after_the_picked_item_fails_the_retry_asks_again_even_for_one_match() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", BANK_PERSONAL)
        .login("share-personal", BANK_WORK);
    h.pick(1);
    assert!(h.run(&["bank", "-p"]).status.success()); // caches both
    h.remove("item-bank-personal");
    h.clear_calls();
    // Line 1 of the first picker is "bank personal", now deleted; line 1 of
    // the retry's picker is "bank work".
    h.pick(1);

    let out = h.run(&["bank", "-p"]);

    // The retry found only "bank work": it is shown in a picker, not copied
    // without asking.
    assert_eq!(h.fzf_invocations(), 2, "no picker on the retry");
    let picker = h.fzf_input().unwrap();
    assert!(picker.contains("bank work"), "{picker}");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "Username: worker\nPassword: work-secret\n");
}

#[test]
fn a_cancelled_retry_picker_copies_nothing() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", BANK_PERSONAL)
        .login("share-personal", BANK_WORK);
    h.pick(1);
    assert!(h.run(&["bank", "-p"]).status.success());
    h.remove("item-bank-personal");
    h.clear_calls();
    // First picker: line 1 (deleted item); retry picker: cancelled.
    h.pick_sequence(&["1", "cancel"]);

    let out = h.run(&["bank", "-p"]);

    assert!(!out.status.success());
    assert!(stdout(&out).is_empty(), "credentials copied without a pick");
}

#[test]
fn the_newest_cached_list_wins_over_an_older_broader_one() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal").login(
        "share-personal",
        Login {
            title: "github personal",
            ..BANK_WORK
        },
    );
    assert!(h.run(&["github", "-a", "-p"]).status.success()); // all-items list, old title
    // The item is renamed in Proton Pass; a refresh writes a newer login-only list.
    h.remove("item-bank-work")
        .login("share-personal", BANK_WORK);
    assert!(h.run(&["bank", "-r", "-p"]).status.success());
    h.clear_calls();

    let out = h.run(&["github", "-p"]);

    // The older all-items entry still says "github personal"; the newer
    // login-only one says "bank work" and must win.
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(stdout(&out).is_empty());
}

#[test]
fn the_retry_does_not_read_the_same_accounts_again() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .vault("Work", "share-work")
        .vault("Other", "share-other")
        .login(
            "share-personal",
            Login {
                id: "item-a",
                ..BANK_WORK
            },
        )
        .login(
            "share-work",
            Login {
                id: "item-b",
                ..BANK_WORK
            },
        )
        .login(
            "share-other",
            Login {
                id: "item-c",
                ..BANK_WORK
            },
        );
    h.pick(1);
    assert!(h.run(&["bank", "-p"]).status.success()); // caches all three
    h.remove("item-a");
    h.clear_calls();
    // Sorted by vault: Other (c), Personal (a, now deleted), Work (b). Pick a,
    // then b in the retry's picker.
    h.pick_sequence(&["2", "2"]);

    let out = h.run(&["bank", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("could not be read"),
        "{}",
        stderr(&out)
    );
    for item in ["item-b", "item-c"] {
        let reads = h
            .calls_to("item view")
            .into_iter()
            .filter(|call| has_arg(call, &format!("--item-id={item}")) && has_arg(call, "--field"))
            .count();
        assert_eq!(reads, 1, "{item} account read {reads} times");
    }
}

#[test]
fn a_read_error_that_is_not_about_the_cache_is_reported_without_a_retry() {
    let h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success()); // cached
    h.clear_calls();
    h.fail("item-view", "Error: Error opening item\n");

    let out = h.run(&["github", "-p"]);

    // A fresh search cannot fix this, so there is none.
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("Error opening item"),
        "{}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("searching again"),
        "{}",
        stderr(&out)
    );
    assert!(h.calls_to("vault list").is_empty());
    assert_eq!(h.calls_to("item view").len(), 1);
}
