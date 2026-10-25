//! Text that holds secrets: an item's JSON, a template piped to a CLI, a
//! token. It can be read deliberately, never printed by accident.

use serde::de::DeserializeOwned;
use std::fmt;

#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        SecretString(value.into())
    }

    /// The secret itself, for the one place that needs it (a pipe to a CLI).
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        SecretString::new(value)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        SecretString::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

/// Parse JSON that may hold secrets. On failure, say what was being read
/// and where it went wrong, never what was there: serde_json's own messages
/// quote values (`invalid type: string "..."`).
pub fn parse_json<T: DeserializeOwned>(text: &str, what: &str) -> anyhow::Result<T> {
    serde_json::from_str(text).map_err(|e| {
        let problem = match e.classify() {
            serde_json::error::Category::Io => "unreadable",
            serde_json::error::Category::Syntax => "not valid JSON",
            serde_json::error::Category::Data => "not in the expected shape",
            serde_json::error::Category::Eof => "cut short",
        };
        anyhow::anyhow!(
            "{what} is {problem} (line {}, column {})",
            e.line(),
            e.column()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{SecretString, parse_json};

    #[test]
    fn debug_hides_the_value() {
        let secret = SecretString::new("ops_token_value");
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
        assert_eq!(secret.expose(), "ops_token_value");
    }

    #[test]
    fn parse_errors_never_quote_the_input() {
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Shape {
            n: u32,
        }
        for bad in [
            r#"{"n": "s3cret"}"#,
            r#"{"n": 1, "s3cret"#,
            "s3cret",
            r#"["s3cret"]"#,
        ] {
            let err = parse_json::<Shape>(bad, "the input")
                .unwrap_err()
                .to_string();
            assert!(!err.contains("s3cret"), "{err}");
            assert!(err.starts_with("the input is "), "{err}");
        }
        assert_eq!(parse_json::<Shape>(r#"{"n": 2}"#, "x").unwrap().n, 2);
    }
}
