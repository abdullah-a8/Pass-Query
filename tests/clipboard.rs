//! Clipboard mode: the username first, the password after Enter, through the
//! right tool for the display, and the password cleared after a while unless
//! something else has been copied since.

mod support;

use std::time::Duration;
use support::{Harness, Login, eventually, stderr, stdout};

const GITHUB: Login = Login {
    id: "item-github",
    title: "github",
    username: "octocat",
    email: "",
    password: "github-secret",
};

const WIFI: Login = Login {
    id: "item-wifi",
    title: "wifi",
    username: "",
    email: "",
    password: "wifi-secret",
};

fn harness() -> Harness {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", GITHUB)
        .login("share-personal", WIFI);
    h
}

const SECOND: Duration = Duration::from_secs(1);

#[test]
fn the_password_is_copied_only_after_enter() {
    let h = harness();
    let mut pq = h.spawn(&["github", "--clear-after", "0"]);

    assert!(
        eventually(5 * SECOND, || h.copies().len() == 1),
        "username copied"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(pq.is_running(), "pq waits at the prompt");
    assert_eq!(h.copied_texts(), ["octocat"]);

    pq.press_enter();
    let out = pq.finish();

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(h.copied_texts(), ["octocat", "github-secret"]);
    let err = stderr(&out);
    assert!(err.contains("Username copied"), "{err}");
    assert!(err.contains("Press Enter to copy the password"), "{err}");
    assert!(err.contains("Password copied"), "{err}");
    assert!(
        stdout(&out).is_empty(),
        "nothing is printed in clipboard mode"
    );
}

#[test]
fn an_item_without_username_copies_the_password_without_a_prompt() {
    let h = harness();

    let out = h.run(&["wifi", "--clear-after", "0"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(h.copied_texts(), ["wifi-secret"]);
    assert!(!stderr(&out).contains("Press Enter"));
}

#[test]
fn a_failing_clipboard_tool_stops_pq_before_the_password() {
    let h = harness();
    h.fail_clipboard();

    let out = h.run(&["github"]);

    assert!(!out.status.success());
    let err = stderr(&out);
    // wl-copy on Linux, pbcopy on macOS.
    assert!(err.contains(" failed (exit status: 1)"), "{err}");
    assert!(!err.contains("copied"), "{err}");
    assert!(!err.contains("github-secret"), "{err}");
    assert!(stdout(&out).is_empty());
    assert!(h.copied_texts().is_empty());
    assert_eq!(h.clipboard_now(), "");
}

#[test]
fn a_clipboard_tool_left_serving_the_selection_does_not_hold_pq_output_open() {
    let h = harness();
    h.linger_after_copy();

    let started = std::time::Instant::now();
    let out = h.run(&["wifi", "--clear-after", "0"]);

    // run() reads stdout and stderr to the end, as a script capturing them would.
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        started.elapsed() < 3 * SECOND,
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn print_mode_never_touches_the_clipboard() {
    let h = harness();

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(h.copies().is_empty());
}

#[cfg(not(target_os = "macos"))]
mod linux {
    use super::*;
    use crate::support::Display;

    fn copy_tools(h: &Harness) -> Vec<(String, String)> {
        h.copies().into_iter().map(|c| (c.tool, c.args)).collect()
    }

    #[test]
    fn wayland_copies_with_wl_copy() {
        let h = harness();

        let out = h.run(&["wifi", "--clear-after", "0"]);

        assert!(out.status.success(), "stderr: {}", stderr(&out));
        assert_eq!(copy_tools(&h), [("wl-copy".into(), "".into())]);
    }

    #[test]
    fn x11_copies_to_the_clipboard_selection_with_xclip() {
        let mut h = harness();
        h.display(Display::X11);

        let out = h.run(&["wifi", "--clear-after", "0"]);

        assert!(out.status.success(), "stderr: {}", stderr(&out));
        assert_eq!(
            copy_tools(&h),
            [("xclip".into(), "-selection clipboard".into())]
        );
    }

    #[test]
    fn x11_falls_back_to_xsel_without_xclip() {
        let mut h = harness();
        h.display(Display::X11);
        h.remove_tool("xclip");

        let out = h.run(&["wifi", "--clear-after", "0"]);

        assert!(out.status.success(), "stderr: {}", stderr(&out));
        assert_eq!(
            copy_tools(&h),
            [("xsel".into(), "--clipboard --input".into())]
        );
    }

    #[test]
    fn without_a_display_pq_explains_and_suggests_print_mode() {
        let mut h = harness();
        h.display(Display::None);

        let out = h.run(&["wifi"]);

        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(err.contains("No clipboard"), "{err}");
        assert!(err.contains("-p"), "{err}");
        assert!(h.copies().is_empty());
    }

    #[test]
    fn a_missing_clipboard_tool_is_named_with_an_install_hint() {
        let h = harness();
        h.remove_tool("wl-copy");

        let out = h.run(&["wifi"]);

        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(err.contains("wl-copy"), "{err}");
        assert!(err.contains("wl-clipboard"), "{err}");
    }

    #[test]
    fn x11_clears_the_password_with_xsel_too() {
        let mut h = harness();
        h.display(Display::X11);
        h.remove_tool("xclip");

        let out = h.run(&["wifi", "--clear-after", "1"]);

        assert!(out.status.success(), "stderr: {}", stderr(&out));
        assert!(eventually(5 * SECOND, || h.clipboard_now().is_empty()));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_copies_with_pbcopy() {
    let h = harness();

    let out = h.run(&["wifi", "--clear-after", "0"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let tools: Vec<String> = h.copies().into_iter().map(|c| c.tool).collect();
    assert_eq!(tools, ["pbcopy"]);
}

#[test]
fn the_password_is_cleared_after_the_delay() {
    let h = harness();

    let out = h.run(&["wifi", "--clear-after", "1"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("clears in 1s"), "{}", stderr(&out));
    // pq has exited; a detached helper clears the clipboard.
    assert_eq!(h.clipboard_now(), "wifi-secret");
    assert!(
        eventually(5 * SECOND, || h.clipboard_now().is_empty()),
        "clipboard still holds {:?}",
        h.clipboard_now()
    );
}

#[test]
fn something_copied_since_is_not_cleared() {
    let h = harness();

    let out = h.run(&["wifi", "--clear-after", "1"]);
    h.set_clipboard("copied by the user afterwards");

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    std::thread::sleep(3 * SECOND);
    assert_eq!(h.clipboard_now(), "copied by the user afterwards");
}

#[test]
fn clear_after_zero_leaves_the_password() {
    let h = harness();

    let out = h.run(&["wifi", "--clear-after", "0"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    std::thread::sleep(2 * SECOND);
    assert_eq!(h.clipboard_now(), "wifi-secret");
}
