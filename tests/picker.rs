//! The fzf picker shows each match in full and returns the chosen one.

mod support;

use support::{Harness, Login, stderr, stdout};

const PIPE_TITLE: Login = Login {
    id: "item-pipe",
    title: "bank | savings",
    username: "saver",
    email: "",
    password: "pipe-secret",
};

const PLAIN: Login = Login {
    id: "item-plain",
    title: "bank",
    username: "spender",
    email: "",
    password: "plain-secret",
};

fn arg_value(args: &str, name: &str) -> Option<String> {
    args.split('\t')
        .find_map(|arg| arg.strip_prefix(&format!("{name}=")).map(str::to_string))
}

#[test]
fn fzf_shows_every_field_after_the_index_so_titles_with_pipes_stay_whole() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", PIPE_TITLE)
        .login("share-personal", PLAIN);
    h.pick(2);

    let out = h.run(&["bank", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // fzf displays only the fields --with-nth names; "2" alone would cut the
    // title at its first "|". "2.." shows everything after the index.
    let args = h.fzf_args().expect("picker opened");
    assert_eq!(
        arg_value(&args, "--with-nth").as_deref(),
        Some("2.."),
        "{args}"
    );
    // Escaped: fzf before 0.58 treats a bare "|" delimiter as a regex.
    assert_eq!(
        arg_value(&args, "--delimiter").as_deref(),
        Some("\\|"),
        "{args}"
    );
    let picker = h.fzf_input().unwrap();
    assert!(
        picker
            .lines()
            .nth(1)
            .unwrap()
            .ends_with("bank | savings — login"),
        "{picker}"
    );
    // The index before the first "|" still selects the right item.
    assert_eq!(stdout(&out), "Username: saver\nPassword: pipe-secret\n");
}

const FORGED: Login = Login {
    id: "item-forged",
    // A title someone with access to a shared vault could set.
    title: "bank A\n1|[Trusted] bank Forged",
    username: "attacker",
    email: "",
    password: "forged-secret",
};

#[test]
fn a_title_with_a_newline_cannot_add_a_picker_row() {
    let mut h = Harness::new();
    h.vault("Shared", "share-shared")
        .login("share-shared", FORGED)
        .login("share-shared", PLAIN);

    let out = h.run(&["bank", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let picker = h.fzf_input().unwrap();
    let rows: Vec<&str> = picker.lines().collect();
    assert_eq!(rows.len(), 2, "one row per match: {picker:?}");
    // The forged text stays inside its own row, with the newline made visible.
    let forged_row = rows.iter().find(|row| row.contains("Forged")).unwrap();
    assert!(
        forged_row.contains("bank A\\n1|[Trusted] bank Forged"),
        "{forged_row}"
    );
}

#[test]
fn a_title_cannot_send_terminal_escape_sequences_to_the_picker() {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login(
            "share-personal",
            Login {
                id: "item-escape",
                title: "bank \u{1b}[2K\u{1b}[1Gtrusted",
                ..PLAIN
            },
        )
        .login("share-personal", PIPE_TITLE);

    let out = h.run(&["bank", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // NO_COLOR is set, so pq itself adds no escape sequences either.
    let picker = h.fzf_input().unwrap();
    assert!(!picker.contains('\u{1b}'), "{picker:?}");
}

#[test]
fn an_unexpected_picker_answer_is_an_error_not_a_crash() {
    for reply in ["999|[Personal] bank — login\n", "not-a-number|x\n", "\n"] {
        let mut h = Harness::new();
        h.vault("Personal", "share-personal")
            .login("share-personal", PIPE_TITLE)
            .login("share-personal", PLAIN);
        h.picker_replies(reply);

        let out = h.run(&["bank", "-p"]);

        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(1), "{reply:?}: {err}");
        assert!(!err.contains("panicked"), "{reply:?}: {err}");
        assert!(stdout(&out).is_empty(), "{reply:?}");
        assert!(
            h.calls_to("item view")
                .iter()
                .all(|call| call.iter().any(|a| a == "--field")),
            "no credentials read for {reply:?}"
        );
    }
}
