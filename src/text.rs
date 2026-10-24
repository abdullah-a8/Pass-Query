//! Text from Proton Pass or pass-cli made safe to show in the terminal.

/// `text` with every control character, bidi control and line or paragraph
/// separator shown escaped. Titles, vault names and accounts can be set by
/// anyone who shares a vault with the user, and pass-cli's messages can quote
/// them: a newline must not add a picker row (which would map to another
/// item's index), an escape sequence must not redraw or retitle the terminal,
/// and a bidi override must not reorder what the user reads.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if must_escape(c) {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// A credential as print mode writes it, and whether it had to be escaped.
/// Written to a terminal, control characters would drive the terminal, so
/// they are shown escaped; written to a pipe or file, the value is exact,
/// because a script needs the real credential.
pub fn for_stdout(value: &str, to_terminal: bool) -> (String, bool) {
    if to_terminal && value.chars().any(must_escape) {
        (printable(value), true)
    } else {
        (value.to_string(), false)
    }
}

fn must_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Arabic letter mark, left-to-right and right-to-left marks
            '\u{061C}' | '\u{200E}' | '\u{200F}'
            // embeddings, overrides and isolates
            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            // line and paragraph separators
            | '\u{2028}' | '\u{2029}'
        )
}

#[cfg(test)]
mod tests {
    use super::{for_stdout, printable};

    #[test]
    fn credentials_are_exact_when_piped_and_escaped_on_a_terminal() {
        let value = "user\u{1b}]0;pwned\u{7}";
        assert_eq!(for_stdout(value, false), (value.to_string(), false));
        assert_eq!(
            for_stdout(value, true),
            ("user\\u{1b}]0;pwned\\u{7}".to_string(), true)
        );
        assert_eq!(for_stdout("plain", true), ("plain".to_string(), false));
    }

    #[test]
    fn control_characters_are_shown_escaped() {
        assert_eq!(printable("bank | savings"), "bank | savings");
        assert_eq!(printable("a\nb\r\tc"), "a\\nb\\r\\tc");
        assert_eq!(printable("x\u{1b}[2Ky"), "x\\u{1b}[2Ky");
        assert_eq!(printable("café ☕"), "café ☕");
        // Bidi controls reorder what the terminal shows; line and paragraph
        // separators can break a line.
        assert_eq!(printable("bank\u{202e}knab"), "bank\\u{202e}knab");
        assert_eq!(printable("a\u{2066}b\u{2069}"), "a\\u{2066}b\\u{2069}");
        assert_eq!(printable("a\u{2028}b"), "a\\u{2028}b");
        // Zero-width joiners are part of emoji sequences and stay.
        assert_eq!(printable("👩\u{200d}💻"), "👩\u{200d}💻");
    }
}
