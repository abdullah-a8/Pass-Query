//! End-to-end tests of pq's search, pick and copy flow against a fake pass-cli.

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
        .login("share-personal", GITHUB)
        .note("share-personal", "item-note", "reddit recovery codes");
    h
}

fn has_arg(call: &[String], arg: &str) -> bool {
    call.iter().any(|a| a == arg)
}

#[test]
fn print_mode_prints_the_credentials_of_a_single_match() {
    let h = personal_vault();

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "Username: octocat\nPassword: github-secret\n");
}

#[test]
fn searches_logins_only_by_default_and_never_asks_for_secrets_in_lists() {
    let h = personal_vault();

    let out = h.run(&["reddit", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // The note "reddit recovery codes" is not a login, so reddit is the only match.
    assert_eq!(
        stdout(&out),
        "Username: redditor\nPassword: reddit-secret\n"
    );

    let lists = h.calls_to("item list");
    assert_eq!(lists.len(), 1);
    assert!(has_arg(&lists[0], "--share-id=share-personal"));
    assert_eq!(
        lists[0].windows(2).find(|w| w[0] == "--filter-type"),
        Some(&["--filter-type".to_string(), "login".to_string()][..])
    );
    assert!(
        h.calls()
            .iter()
            .all(|call| !has_arg(call, "--show-secrets"))
    );

    let views = h.calls_to("item view");
    assert_eq!(views.len(), 1);
    assert!(has_arg(&views[0], "--item-id=item-reddit"));
    assert!(has_arg(&views[0], "--share-id=share-personal"));
}

#[test]
fn all_flag_searches_every_item_type() {
    let h = personal_vault();
    h.pick(1);

    let out = h.run(&["reddit", "-a", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let lists = h.calls_to("item list");
    assert!(!has_arg(&lists[0], "--filter-type"));
    let picker = h.fzf_input().expect("two matches open the picker");
    assert!(picker.contains("reddit recovery codes"));
}

#[test]
fn a_second_search_is_served_from_the_cache() {
    let h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success());
    h.clear_calls();

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(h.calls_to("vault list").is_empty());
    assert!(h.calls_to("item list").is_empty());
    // Credentials are always fetched fresh.
    assert_eq!(h.calls_to("item view").len(), 1);
}

#[test]
fn the_cache_holds_only_search_metadata_and_is_private() {
    let mut h = personal_vault();
    // A second vault with a duplicate title, so the picker also fetched accounts.
    h.vault("Work", "share-work").login(
        "share-work",
        Login {
            id: "item-reddit-work",
            password: "work\\secret\"quoted\u{e9}",
            ..REDDIT
        },
    );
    h.pick(1);
    assert!(h.run(&["reddit", "-p"]).status.success());

    let cache = h.cache_json(); // checks keys and every (unescaped) string

    assert!(cache.to_string().contains("reddit"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(h.cache_file())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[cfg(unix)]
#[test]
fn an_existing_world_readable_cache_is_made_private() {
    use std::os::unix::fs::PermissionsExt;
    let h = personal_vault();
    h.write_cache("{}");
    std::fs::set_permissions(h.cache_file(), std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(h.run(&["github", "-p"]).status.success());

    let mode = std::fs::metadata(h.cache_file())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn refresh_flag_fetches_vaults_and_items_again() {
    let h = personal_vault();
    assert!(h.run(&["github", "-p"]).status.success());
    h.clear_calls();

    let out = h.run(&["github", "-r", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(h.calls_to("vault list").len(), 1);
    assert_eq!(h.calls_to("item list").len(), 1);
}

#[test]
fn several_matches_open_the_picker_and_use_the_chosen_item() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login(
            "share-personal",
            Login {
                id: "item-gmail",
                title: "gmail",
                ..REDDIT
            },
        )
        .login(
            "share-personal",
            Login {
                id: "item-gitlab",
                title: "gitlab",
                username: "tanuki",
                password: "gitlab-secret",
                ..GITHUB
            },
        )
        .login("share-personal", GITHUB);
    h.pick(2);

    let out = h.run(&["g", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // Sorted by title: github, gitlab, gmail; line 2 is gitlab.
    assert_eq!(stdout(&out), "Username: tanuki\nPassword: gitlab-secret\n");
    let picker = h.fzf_input().unwrap();
    let titles: Vec<&str> = picker.lines().collect();
    assert_eq!(titles.len(), 3);
    assert!(titles[0].contains("github"));
    assert!(titles[1].contains("gitlab"));
    assert!(titles[2].contains("gmail"));
}

#[test]
fn duplicate_titles_show_each_account_in_the_picker() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .vault("Work", "share-work")
        .login("share-personal", REDDIT)
        .login(
            "share-work",
            Login {
                id: "item-reddit-work",
                username: "",
                email: "work@example.com",
                password: "work-secret",
                ..REDDIT
            },
        );
    h.pick(2);

    let out = h.run(&["reddit", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let picker = h.fzf_input().unwrap();
    assert!(picker.contains("[Personal] reddit — redditor"), "{picker}");
    // No username on the work item: the picker falls back to its email.
    assert!(
        picker.contains("[Work] reddit — work@example.com"),
        "{picker}"
    );
    assert_eq!(
        stdout(&out),
        "Username: work@example.com\nPassword: work-secret\n"
    );
    // The picker reads only the username or email of each duplicate; the
    // full item, with its password, is read once and only for the choice.
    let views = h.calls_to("item view");
    let (field_reads, full_reads): (Vec<_>, Vec<_>) =
        views.iter().partition(|call| has_arg(call, "--field"));
    for call in &field_reads {
        assert!(
            has_arg(call, "username") || has_arg(call, "email"),
            "{call:?}"
        );
    }
    assert_eq!(full_reads.len(), 1, "{views:?}");
    assert!(has_arg(full_reads[0], "--item-id=item-reddit-work"));
}

#[test]
fn a_cancelled_picker_reads_no_credentials_and_copies_nothing() {
    let mut h = personal_vault();
    // Duplicate titles, so the picker fetched account labels first.
    h.vault("Work", "share-work").login(
        "share-work",
        Login {
            id: "item-reddit-work",
            ..REDDIT
        },
    );
    h.cancel_picker();

    let out = h.run(&["reddit"]);

    assert!(!out.status.success());
    assert!(stderr(&out).contains("Selection cancelled"));
    let views = h.calls_to("item view");
    assert!(!views.is_empty(), "accounts were fetched for the picker");
    assert!(
        views.iter().all(|call| has_arg(call, "--field")),
        "{views:?}"
    );
    assert!(h.copies().is_empty());
}

#[test]
fn no_match_is_reported() {
    let h = personal_vault();

    let out = h.run(&["nothing-matches-this", "-p"]);

    assert!(!out.status.success());
    assert!(stderr(&out).contains("No items found"));
}

#[test]
fn not_logged_in_gives_a_login_hint() {
    let h = personal_vault();
    h.fail(
        "vault-list",
        "Error: This operation requires an authenticated client\n",
    );

    let out = h.run(&["reddit", "-p"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("Not logged in"), "{err}");
    assert!(err.contains("pass-cli login"), "{err}");
}

#[test]
fn a_missing_pass_cli_is_reported_with_an_install_link() {
    let h = personal_vault();
    h.remove_tool("pass-cli");

    let out = h.run(&["reddit", "-p"]);

    assert!(!out.status.success());
    assert!(stderr(&out).contains("pass-cli not found"));
    assert!(stderr(&out).contains("https://protonpass.github.io/pass-cli/"));
}

#[test]
fn a_failing_vault_is_reported_and_the_others_still_searched() {
    let mut h = Harness::new();
    h.vault("Broken", "share-broken")
        .vault("Personal", "share-personal")
        .login("share-personal", GITHUB);
    h.fail_vault(
        "share-broken",
        "Error: Could not perform operation. Reason: NotFound\n",
    );

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("vault search failed"));
    assert_eq!(stdout(&out), "Username: octocat\nPassword: github-secret\n");
}

#[test]
fn print_mode_writes_the_exact_value_to_a_pipe() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal").login(
        "share-personal",
        Login {
            id: "item-odd",
            title: "odd",
            username: "user\u{1b}[31m",
            email: "",
            password: "pass\tword",
        },
    );

    let out = h.run(&["odd", "-p"]);

    // stdout is a pipe here: scripts get the value exactly as stored.
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "Username: user\u{1b}[31m\nPassword: pass\tword\n"
    );
}
