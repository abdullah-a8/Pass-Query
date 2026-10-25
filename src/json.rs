//! Parsing JSON that may hold secrets: pass-cli's and op's output, pq's
//! cache, pq-sync's state.

use serde::de::DeserializeOwned;

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
    use super::parse_json;

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
