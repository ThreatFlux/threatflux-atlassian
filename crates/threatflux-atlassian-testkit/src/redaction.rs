//! Secret-leak scanning.
//!
//! `assert!(!log.contains(token))` passes while the base64 `Basic` blob leaks,
//! which is why scanning is a shared type rather than an inline assertion: every
//! needle is checked in all four encodings a secret reaches a log, an error
//! message, a URL or a JSON body in.

use std::fmt;

use base64::prelude::{Engine as _, BASE64_STANDARD};

/// How a secret was rendered into the text being scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// The secret itself.
    Raw,
    /// `base64(value)` — the form the `Authorization: Basic` header carries.
    Base64,
    /// Percent-encoded, as a URL path or query would carry it.
    PercentEncoded,
    /// JSON string escaping, as a serialized request or response body carries it.
    JsonEscaped,
}

impl fmt::Display for Encoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Raw => "raw",
            Self::Base64 => "base64",
            Self::PercentEncoded => "percent-encoded",
            Self::JsonEscaped => "json-escaped",
        };
        formatter.write_str(name)
    }
}

/// One occurrence of a secret in scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The label the secret was registered under.
    pub label: String,
    /// The encoding the secret was found in.
    pub encoding: Encoding,
    /// Byte offset of the first occurrence.
    pub offset: usize,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} leaked at byte {} ({})",
            self.label, self.offset, self.encoding
        )
    }
}

#[derive(Debug, Clone)]
struct Needle {
    label: String,
    encoding: Encoding,
    rendered: String,
}

/// Scans text for registered secrets in every encoding they can appear in.
#[derive(Debug, Clone, Default)]
pub struct SecretScanner {
    needles: Vec<Needle>,
}

impl SecretScanner {
    /// Creates a scanner with no registered secrets.
    pub const fn new() -> Self {
        Self {
            needles: Vec::new(),
        }
    }

    /// Registers a secret under `label`, in all four encodings.
    ///
    /// Encodings that render identically to one already registered for the same
    /// label are dropped, so an alphanumeric token is not reported four times.
    #[must_use]
    pub fn with_secret(mut self, label: &str, value: &str) -> Self {
        self.push(label, Encoding::Raw, value.to_string());
        self.push(label, Encoding::Base64, BASE64_STANDARD.encode(value));
        self.push(label, Encoding::PercentEncoded, percent_encode(value));
        self.push(label, Encoding::JsonEscaped, json_escape(value));
        self
    }

    /// Registers Basic-auth credentials: the token on its own, and the exact
    /// `base64(username:token)` blob the `Authorization` header carries.
    #[must_use]
    pub fn with_basic_credentials(self, label: &str, username: &str, token: &str) -> Self {
        let mut scanner = self.with_secret(label, token);
        let joined = format!("{username}:{token}");
        scanner.push(label, Encoding::Base64, BASE64_STANDARD.encode(&joined));
        scanner.push(label, Encoding::Raw, joined);
        scanner
    }

    fn push(&mut self, label: &str, encoding: Encoding, rendered: String) {
        if rendered.is_empty() {
            return;
        }
        if self
            .needles
            .iter()
            .any(|needle| needle.label == label && needle.rendered == rendered)
        {
            return;
        }
        self.needles.push(Needle {
            label: label.to_string(),
            encoding,
            rendered,
        });
    }

    /// Returns every occurrence of a registered secret in `haystack`.
    pub fn findings(&self, haystack: &str) -> Vec<Finding> {
        self.needles
            .iter()
            .filter_map(|needle| {
                haystack.find(&needle.rendered).map(|offset| Finding {
                    label: needle.label.clone(),
                    encoding: needle.encoding,
                    offset,
                })
            })
            .collect()
    }

    /// Asserts that `haystack` contains no registered secret.
    ///
    /// # Panics
    ///
    /// Panics naming each leaked secret, its encoding and its offset.
    pub fn assert_clean(&self, context: &str, haystack: &str) {
        let findings = self.findings(haystack);
        assert!(
            findings.is_empty(),
            "{context} leaked secrets:\n{}",
            findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

fn hex_digit(nibble: u8) -> char {
    char::from(match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + nibble - 10,
    })
}

fn json_escape(value: &str) -> String {
    let quoted = serde_json::Value::String(value.to_string()).to_string();
    quoted
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(&quoted)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{Encoding, SecretScanner};
    use base64::prelude::{Engine as _, BASE64_STANDARD};

    #[test]
    fn raw_secret_is_found() {
        let scanner = SecretScanner::new().with_secret("token", "s3cr3t-value");
        let findings = scanner.findings("Authorization failed for s3cr3t-value");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].encoding, Encoding::Raw);
        assert_eq!(findings[0].label, "token");
    }

    #[test]
    fn base64_basic_blob_is_found_when_the_raw_token_is_not() {
        let scanner = SecretScanner::new().with_basic_credentials("token", "bot@x.dev", "tok3n");
        let header = format!("Basic {}", BASE64_STANDARD.encode("bot@x.dev:tok3n"));

        assert!(!header.contains("tok3n"));
        let findings = scanner.findings(&header);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].encoding, Encoding::Base64);
    }

    #[test]
    fn percent_encoded_secret_is_found() {
        let scanner = SecretScanner::new().with_secret("token", "a b/c");
        let findings = scanner.findings("GET /search?q=a%20b%2Fc");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].encoding, Encoding::PercentEncoded);
    }

    #[test]
    fn json_escaped_secret_is_found() {
        let scanner = SecretScanner::new().with_secret("token", "line1\nline2");
        let findings = scanner.findings(r#"{"error":"line1\nline2"}"#);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].encoding, Encoding::JsonEscaped);
    }

    #[test]
    fn alphanumeric_secret_is_not_reported_twice_for_identical_encodings() {
        let scanner = SecretScanner::new().with_secret("token", "abc123");
        let findings = scanner.findings("token=abc123");

        assert_eq!(findings.len(), 1, "raw and percent-encoded are identical");
    }

    #[test]
    fn clean_text_has_no_findings() {
        let scanner = SecretScanner::new().with_secret("token", "s3cr3t");
        scanner.assert_clean("redacted log", "token=<redacted>");
    }

    #[test]
    #[should_panic(expected = "redacted log leaked secrets")]
    fn assert_clean_names_the_leak() {
        let scanner = SecretScanner::new().with_secret("token", "s3cr3t");
        scanner.assert_clean("redacted log", "token=s3cr3t");
    }
}
