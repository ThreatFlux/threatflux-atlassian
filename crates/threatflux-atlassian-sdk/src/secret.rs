//! A string that is a credential.
//!
//! [`SecretString`] wraps a credential so that the three ways one usually
//! escapes a process are closed by the type rather than by review:
//!
//! * `Debug` and `Display` both render [`REDACTED`], so a struct that holds one
//!   can keep deriving `Debug` and a `{}`/`{:?}` in a log line, an error message
//!   or a panic payload cannot print it.
//! * There is deliberately **no** [`serde::Serialize`] implementation, and no
//!   lossy one emitting a placeholder either. A lossy `Serialize` corrupts a
//!   round-trip silently; a missing one is a compile error at the call site that
//!   was about to write the credential somewhere. [`serde::Deserialize`] *is*
//!   implemented, because a token arriving from an OAuth token endpoint has to
//!   be readable.
//! * The buffer is zeroed on drop.
//!
//! [`SecretString::expose_secret`] is the only accessor, and it is named so that
//! `rg expose_secret` enumerates every read site in a tree.
//!
//! Zeroization is **best effort**, and the limit is a property of the language
//! rather than of this type: `String` reallocates when it grows, and every
//! reallocation leaves the old bytes wherever the allocator left them. A value
//! that reached this type through a `String` the caller built, or through
//! `serde`'s own scratch buffer, has already been copied at least once, and
//! those copies are not reachable from here. What this type does guarantee is
//! that the copy it owns does not outlive it.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Rendered by [`SecretString`]'s `Display` in place of the credential.
pub const REDACTED: &str = "<redacted>";

/// A credential that does not print, serialize, or outlive itself in memory.
///
/// # Example
///
/// ```rust
/// use threatflux_atlassian_sdk::SecretString;
///
/// let token = SecretString::from("hunter2");
///
/// assert_eq!(token.expose_secret(), "hunter2");
/// assert_eq!(token.to_string(), "<redacted>");
/// assert_eq!(format!("{token:?}"), "SecretString(<redacted>)");
/// ```
///
/// A credential can be read off the wire:
///
/// ```rust
/// use threatflux_atlassian_sdk::SecretString;
///
/// let token: SecretString = serde_json::from_str(r#""hunter2""#).unwrap();
/// assert_eq!(token.expose_secret(), "hunter2");
/// ```
///
/// and cannot be written back onto it. This is the missing `Serialize`
/// implementation, asserted where a unit test cannot reach it:
///
/// ```compile_fail
/// use threatflux_atlassian_sdk::SecretString;
///
/// let token = SecretString::from("hunter2");
/// let _ = serde_json::to_string(&token);
/// ```
#[derive(Clone, Deserialize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps `value` as a credential.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the credential itself.
    ///
    /// Named so that a search for `expose_secret` finds every place a
    /// credential is read. Prefer passing the [`SecretString`] itself and
    /// calling this as late as possible: whatever this returns is borrowed from
    /// a buffer that is zeroed on drop, but anything copied out of it is not.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Reports whether the credential is the empty string.
    ///
    /// Lets a validator reject a missing credential without exposing a present
    /// one.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the credential with leading and trailing whitespace removed.
    ///
    /// A credential read from an environment variable, a file, or a shell
    /// pipeline routinely arrives with a trailing newline, and trimming it
    /// through [`Self::expose_secret`] would put the whole value in an ordinary
    /// `String` at every call site that needs it.
    #[must_use]
    pub fn trimmed(&self) -> Self {
        Self::new(self.0.trim())
    }
}

/// Renders [`REDACTED`], never the credential.
impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretString({REDACTED})")
    }
}

/// Renders [`REDACTED`], never the credential.
///
/// `Display` is redacted as well as `Debug` because a `{}` in a `format!` is at
/// least as easy to reach for as a `{:?}`, and a credential that prints under
/// one of them is not protected by the other.
impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<&String> for SecretString {
    fn from(value: &String) -> Self {
        Self(value.clone())
    }
}

/// Infallible: any string is a credential as far as this type is concerned.
///
/// Present so that an argument parser which resolves a value parser through
/// `FromStr` — `clap` above all — can take a [`SecretString`] directly, rather
/// than parsing a `String` into a struct that then derives `Debug` over it.
impl FromStr for SecretString {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(value))
    }
}

/// Zeroes `value` in place.
///
/// The credential reaches the wire as `base64(username:token)`, so the joined
/// plaintext and its encoding are the same secret in two more encodings and are
/// wiped by their builder rather than left for the allocator.
pub(crate) fn zeroize_string(value: &mut String) {
    value.zeroize();
}

#[cfg(test)]
mod tests {
    use super::{zeroize_string, SecretString, REDACTED};

    #[test]
    fn debug_and_display_render_the_placeholder() {
        let secret = SecretString::from("s3cr3t-token");

        assert_eq!(format!("{secret:?}"), "SecretString(<redacted>)");
        assert_eq!(format!("{secret:#?}"), "SecretString(<redacted>)");
        assert_eq!(secret.to_string(), REDACTED);
        assert_eq!(format!("{secret}"), REDACTED);
    }

    #[test]
    fn a_derived_debug_over_a_holder_is_redacted_too() {
        // The point of redacting `Debug` rather than removing it is that a
        // struct holding a credential keeps its own derive.
        #[derive(Debug)]
        struct Holder {
            username: String,
            token: SecretString,
        }

        let holder = Holder {
            username: "bot@example.com".to_string(),
            token: SecretString::from("s3cr3t-token"),
        };
        let rendered = format!("{holder:?}");

        assert!(!rendered.contains("s3cr3t-token"), "rendered: {rendered}");
        assert!(rendered.contains("bot@example.com"), "rendered: {rendered}");
        assert_eq!(holder.username, "bot@example.com");
        assert_eq!(holder.token.expose_secret(), "s3cr3t-token");
    }

    #[test]
    fn the_only_accessor_returns_the_credential() {
        assert_eq!(SecretString::from("s3cr3t").expose_secret(), "s3cr3t");
        assert_eq!(
            SecretString::new(String::from("s3cr3t")).expose_secret(),
            "s3cr3t"
        );
        assert_eq!(
            SecretString::from(&String::from("s3cr3t")).expose_secret(),
            "s3cr3t"
        );
        assert_eq!(
            "s3cr3t".parse::<SecretString>().unwrap().expose_secret(),
            "s3cr3t"
        );
    }

    #[test]
    fn emptiness_is_reportable_without_exposing_a_present_value() {
        assert!(SecretString::from("").is_empty());
        assert!(!SecretString::from("s3cr3t").is_empty());
    }

    #[test]
    fn trimming_keeps_the_value_inside_the_type() {
        assert_eq!(
            SecretString::from("  s3cr3t\n").trimmed().expose_secret(),
            "s3cr3t"
        );
        assert!(SecretString::from(" \t\n ").trimmed().is_empty());
    }

    #[test]
    fn a_credential_deserializes_from_a_bare_json_string() {
        // An OAuth token endpoint answers with `{"access_token":"..."}`, so the
        // read direction has to work even though the write direction does not.
        #[derive(serde::Deserialize)]
        struct Response {
            access_token: SecretString,
            refresh_token: Option<SecretString>,
        }

        let parsed: Response =
            serde_json::from_str(r#"{"access_token":"at-1","refresh_token":null}"#).unwrap();

        assert_eq!(parsed.access_token.expose_secret(), "at-1");
        assert!(parsed.refresh_token.is_none());

        let parsed: SecretString = serde_json::from_str(r#""bare""#).unwrap();
        assert_eq!(parsed.expose_secret(), "bare");
    }

    #[test]
    fn zeroizing_a_plaintext_buffer_clears_it() {
        let mut joined = String::from("bot@example.com:s3cr3t");
        zeroize_string(&mut joined);

        assert!(joined.is_empty());
    }
}
