//! Text that holds secrets: an item's JSON, a template piped to a CLI, a
//! token. It can be read deliberately, never printed by accident.

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

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretString;

    #[test]
    fn debug_hides_the_value() {
        let secret = SecretString::new("ops_token_value");
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
        assert_eq!(secret.expose(), "ops_token_value");
    }
}
