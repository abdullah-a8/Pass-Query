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
    assert_eq!(
        arg_value(&args, "--delimiter").as_deref(),
        Some("|"),
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
