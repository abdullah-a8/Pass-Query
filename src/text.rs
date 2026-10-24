//! Text from Proton Pass or pass-cli made safe to show in the terminal.

/// `text` with every control character shown escaped. Titles, vault names
/// and accounts can be set by anyone who shares a vault with the user, and
/// pass-cli's messages can quote them: a newline must not add a picker row
/// (which would map to another item's index), and an escape sequence must not
/// redraw or retitle the terminal.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::printable;

    #[test]
    fn control_characters_are_shown_escaped() {
        assert_eq!(printable("bank | savings"), "bank | savings");
        assert_eq!(printable("a\nb\r\tc"), "a\\nb\\r\\tc");
        assert_eq!(printable("x\u{1b}[2Ky"), "x\\u{1b}[2Ky");
        assert_eq!(printable("café ☕"), "café ☕");
    }
}
