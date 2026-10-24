//! Trashed items are never offered, and caches from before the trash filter are refetched.

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

fn personal_vault() -> Harness {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", REDDIT)
        .login("share-personal", GITHUB);
    h
}

#[test]
fn trashed_items_are_never_offered() {
    let mut h = personal_vault();
    h.login(
        "share-personal",
        Login {
            id: "item-reddit-old",
            password: "old-secret",
            ..REDDIT
        },
    )
    .trash("item-reddit-old");

    let out = h.run(&["reddit", "-p"]);

    // The trashed duplicate is gone, so the live item is picked without fzf.
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        h.fzf_input().is_none(),
        "picker opened for a trashed duplicate"
    );
    assert_eq!(
        stdout(&out),
        "Username: redditor\nPassword: reddit-secret\n"
    );
    let cache = h.cache_json().to_string();
    assert!(!cache.contains("item-reddit-old"), "trashed item cached");
}

#[test]
fn a_trashed_only_match_is_not_found() {
    let mut h = personal_vault();
    h.trash("item-github");

    let out = h.run(&["github", "-p"]);

    assert!(!out.status.success());
    assert!(stderr(&out).contains("No items found"));
    assert!(h.calls_to("item view").is_empty());
}

#[test]
fn a_cache_from_an_older_pq_is_refetched() {
    let h = personal_vault();
    // Written by pq 0.4.x: no format version, and it may list trashed items.
    h.write_cache(
        r#"{"vault_list":{"vaults":{"vaults":[{"name":"Personal","share_id":"share-personal"}]},"timestamp":1},
            "vaults":[{"vault_name":"Personal","login_only":true,"timestamp":1,
                       "items":{"items":[{"id":"item-ghost","share_id":"share-personal","title":"ghost","item_type":"login"}]}}]}"#,
    );

    let out = h.run(&["ghost", "-p"]);

    assert!(!out.status.success());
    assert!(stderr(&out).contains("No items found"));
    assert_eq!(h.calls_to("vault list").len(), 1);
    assert_eq!(h.calls_to("item list").len(), 1);
}

#[test]
fn an_item_trashed_after_it_was_cached_is_not_copied() {
    let mut h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success()); // cached while active
    h.trash("item-github");
    h.clear_calls();

    let out = h.run(&["github", "-p"]);

    // The fresh read refuses the trashed item, so pq searches once more on
    // fresh data, where the item is filtered out.
    assert!(!out.status.success());
    assert!(
        stdout(&out).is_empty(),
        "credentials of a trashed item printed"
    );
    assert!(stderr(&out).contains("No items found"), "{}", stderr(&out));
    assert_eq!(h.calls_to("item view").len(), 1, "only the refused read");
}

#[test]
fn a_cache_entry_marked_trashed_is_not_offered() {
    let h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success());
    // A cache edited (or written by another tool) to hold a trashed item.
    let cache = std::fs::read_to_string(h.cache_file()).unwrap();
    let mut cache: serde_json::Value = serde_json::from_str(&cache).unwrap();
    for vault in cache["vaults"].as_array_mut().unwrap() {
        for item in vault["items"]["items"].as_array_mut().unwrap() {
            item["state"] = "Trashed".into();
        }
    }
    h.write_cache(&cache.to_string());
    h.clear_calls();

    let out = h.run(&["github", "-p"]);

    // The cached entry is not offered; pq refetches, and Proton Pass says the
    // item is active.
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        h.calls_to("item list").len(),
        1,
        "refetched, not served from the cache"
    );
    assert_eq!(stdout(&out), "Username: octocat\nPassword: github-secret\n");
}
