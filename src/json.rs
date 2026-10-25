//! Reading output that may hold secrets (pass-cli's and op's, fzf's, pq's
//! cache, pq-sync's state) as text and as JSON, with errors that never
//! quote or keep what was read.

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

/// Output that should be UTF-8, as text. On failure, say where the bad
/// bytes start, never keep them: a `FromUtf8Error` holds the whole output,
/// and shows it in its Debug form.
pub fn utf8(bytes: Vec<u8>, what: &str) -> anyhow::Result<String> {
    String::from_utf8(bytes).map_err(|e| {
        anyhow::anyhow!(
            "{what} is not UTF-8 (from byte {})",
            e.utf8_error().valid_up_to()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_json, utf8};

    #[test]
    fn bad_utf8_is_reported_without_the_bytes() {
        let mut bytes = b"{\"password\":\"s3cret\"}".to_vec();
        bytes.push(0xff);
        let err = utf8(bytes, "the output").unwrap_err();
        for shown in [format!("{err:#}"), format!("{err:?}"), format!("{err:#?}")] {
            assert!(!shown.contains("s3cret"), "{shown}");
            assert!(!shown.contains("115, 51"), "no bytes: {shown}");
        }
        assert_eq!(err.to_string(), "the output is not UTF-8 (from byte 21)");
        assert_eq!(utf8(b"ok".to_vec(), "x").unwrap(), "ok");
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
