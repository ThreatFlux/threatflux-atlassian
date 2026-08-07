//! Issue properties: arbitrary JSON stored against an issue, under a key.
//!
//! This is where source-event identity and reconciliation hashes live. An issue
//! property is a JSON document of the caller's choosing hung off an issue under
//! a name, read and written whole, invisible in the Jira UI and unaffected by
//! screen configuration -- which makes it the right place for bookkeeping that
//! must survive a project administrator rearranging fields.
//!
//! # Properties are storage, not an index
//!
//! Jira Cloud indexes entity properties for JQL only when an *app* declares a
//! `jiraEntityProperties` module. Properties written by a plain API-token
//! integration -- which is what this crate is -- are not indexed and cannot be
//! searched for. So a property confirms identity on an issue whose key is
//! already known; it can never be the thing that finds the issue. Discovery
//! stays label-based.
//!
//! # A missing property is the normal case
//!
//! [`JiraV3::get_property`](super::JiraV3::get_property) answers a 404 with
//! `Ok(None)` rather than an error, because "this issue has no such property
//! yet" is the state every first write starts from. Treating it as a failure
//! would make the ordinary path the error path.
//!
//! # A write says whether it created or updated
//!
//! Jira answers `PUT .../properties/{key}` with **201** when the property did
//! not exist and **200** when it did, and
//! [`JiraV3::set_property`](super::JiraV3::set_property) returns that
//! distinction as [`IssuePropertyWrite`]. It is the only signal available to a
//! caller racing another run for the same key: two concurrent writers both
//! succeed, and exactly one of them is told it created.

use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::error::{AtlassianError, Result};

/// Longest issue property key Jira accepts, in characters.
pub const MAX_PROPERTY_KEY_CHARS: usize = 255;

/// A validated issue property key.
///
/// Validated on construction rather than at the call site, for two independent
/// reasons:
///
/// - Jira caps a property key at [`MAX_PROPERTY_KEY_CHARS`] characters, and a
///   longer one is a 400 that costs a round trip and reads as a server problem.
/// - The key is a URL path segment. The transport percent-encodes each segment
///   on its own, so a key can never introduce a path boundary, but it rejects a
///   segment `Url` would silently *rewrite* rather than encode -- `.`, `..`, and
///   anything holding a control character. Catching those here turns a failure
///   at send time into a failure at construction time, next to the value that
///   caused it.
///
/// ```
/// use threatflux_atlassian_sdk::v3::IssuePropertyKey;
///
/// let key = IssuePropertyKey::new("threatflux.source-event")?;
/// assert_eq!(key.as_str(), "threatflux.source-event");
///
/// assert!(IssuePropertyKey::new("").is_err());
/// assert!(IssuePropertyKey::new("a".repeat(256)).is_err());
/// assert!(IssuePropertyKey::new("..").is_err());
/// # Ok::<(), threatflux_atlassian_sdk::AtlassianError>(())
/// ```
///
/// Deserialization goes through the same check, so a key read out of a stored
/// configuration is validated exactly as one built in code:
///
/// ```
/// use threatflux_atlassian_sdk::v3::IssuePropertyKey;
///
/// let key: IssuePropertyKey = serde_json::from_str(r#""threatflux.reconcile""#)?;
/// assert_eq!(key.as_str(), "threatflux.reconcile");
/// assert!(serde_json::from_str::<IssuePropertyKey>(r#""""#).is_err());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct IssuePropertyKey(String);

impl IssuePropertyKey {
    /// Validates `key` and wraps it.
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if the key is empty, longer than
    /// [`MAX_PROPERTY_KEY_CHARS`] characters, holds a control character, or is
    /// one of the relative path segments `.` and `..`. The message names the
    /// rule and never the key: a key is caller data of unbounded length, and
    /// this error is rendered into logs.
    pub fn new(key: impl Into<String>) -> Result<Self> {
        let key = key.into();

        if key.is_empty() {
            return Err(AtlassianError::validation(
                "an issue property key cannot be empty",
            ));
        }

        // Counted in characters rather than bytes, because that is how Jira
        // counts it and because a byte bound would reject a legal key made of
        // multi-byte characters.
        if key.chars().count() > MAX_PROPERTY_KEY_CHARS {
            return Err(AtlassianError::validation(format!(
                "an issue property key cannot exceed {MAX_PROPERTY_KEY_CHARS} characters"
            )));
        }

        if key.chars().any(char::is_control) {
            return Err(AtlassianError::validation(
                "an issue property key cannot contain control characters",
            ));
        }

        if key == "." || key == ".." {
            return Err(AtlassianError::validation(
                "an issue property key cannot be a relative path segment",
            ));
        }

        Ok(Self(key))
    }

    /// The key as it goes on the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwraps the validated key.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for IssuePropertyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for IssuePropertyKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for IssuePropertyKey {
    type Err = AtlassianError;

    fn from_str(key: &str) -> Result<Self> {
        Self::new(key)
    }
}

impl TryFrom<String> for IssuePropertyKey {
    type Error = AtlassianError;

    fn try_from(key: String) -> Result<Self> {
        Self::new(key)
    }
}

impl TryFrom<&str> for IssuePropertyKey {
    type Error = AtlassianError;

    fn try_from(key: &str) -> Result<Self> {
        Self::new(key)
    }
}

impl<'de> Deserialize<'de> for IssuePropertyKey {
    /// Reads a key through the same validation as [`IssuePropertyKey::new`].
    ///
    /// Hand-written rather than derived so that a key arriving from a
    /// configuration file cannot skip the check a key built in code cannot
    /// skip. The rejection message names the rule, not the key.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        Self::new(key).map_err(serde::de::Error::custom)
    }
}

/// A property as `GET /rest/api/3/issue/{key}/properties/{property}` returns it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct IssueProperty {
    /// The key Jira echoed back.
    ///
    /// A plain `String` rather than an [`IssuePropertyKey`] because a read is
    /// tolerant: a key stored by some other integration is not this crate's to
    /// re-validate, and failing the read over it would withhold a value that is
    /// perfectly readable.
    #[serde(default)]
    pub key: String,
    /// The stored document, whatever shape it has.
    #[serde(default)]
    pub value: Value,
}

/// One entry of `GET /rest/api/3/issue/{key}/properties`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct IssuePropertyRef {
    /// The property key.
    #[serde(default)]
    pub key: String,
    /// API URL of the property.
    #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
    pub self_url: Option<String>,
}

/// What `GET /rest/api/3/issue/{key}/properties` returns.
///
/// Keys only -- listing does not carry values, so discovering that a property
/// exists and reading it are two calls.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct IssuePropertyKeys {
    /// Every property key set on the issue, in the order Jira returned them.
    #[serde(default)]
    pub keys: Vec<IssuePropertyRef>,
}

impl IssuePropertyKeys {
    /// Whether the issue carries a property under this key.
    pub fn contains(&self, key: &str) -> bool {
        self.keys.iter().any(|entry| entry.key == key)
    }

    /// How many properties the issue carries.
    pub const fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the issue carries no properties at all.
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Whether a property write created the property or replaced an existing one.
///
/// Deliberately **not** `#[non_exhaustive]`. The distinction is exactly the two
/// statuses Jira answers a property `PUT` with, and the entire reason a caller
/// asks for it is to branch on both: forcing a wildcard arm onto that `match`
/// would hand back a third case that cannot occur and take away the
/// exhaustiveness check that makes the branch worth writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum IssuePropertyWrite {
    /// HTTP 201: the property did not exist and this call created it.
    ///
    /// Under a race for the same key, exactly one concurrent writer is told
    /// this. It is the closest thing Jira offers to a compare-and-set on an
    /// issue.
    Created,
    /// HTTP 200: the property existed and this call replaced its value.
    Updated,
}

impl IssuePropertyWrite {
    /// Whether this write created the property.
    pub const fn is_created(self) -> bool {
        matches!(self, Self::Created)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IssueProperty, IssuePropertyKey, IssuePropertyKeys, IssuePropertyWrite,
        MAX_PROPERTY_KEY_CHARS,
    };
    use crate::error::AtlassianError;
    use serde_json::json;
    use std::str::FromStr;

    #[test]
    fn a_key_at_the_limit_is_accepted_and_one_past_it_is_not() {
        let at_limit = "k".repeat(MAX_PROPERTY_KEY_CHARS);
        assert_eq!(
            IssuePropertyKey::new(at_limit.clone())
                .expect("255 characters is legal")
                .as_str(),
            at_limit
        );

        let error = IssuePropertyKey::new("k".repeat(MAX_PROPERTY_KEY_CHARS + 1))
            .expect_err("256 characters is not");
        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );
    }

    #[test]
    fn the_limit_counts_characters_not_bytes() {
        // A byte bound would reject this at 255 multi-byte characters, which
        // Jira accepts.
        let multibyte = "\u{1f512}".repeat(MAX_PROPERTY_KEY_CHARS);
        assert!(IssuePropertyKey::new(multibyte).is_ok());
        assert!(IssuePropertyKey::new("\u{1f512}".repeat(MAX_PROPERTY_KEY_CHARS + 1)).is_err());
    }

    #[test]
    fn the_segments_the_url_builder_would_rewrite_are_refused_here_instead() {
        // `path_segments_mut` drops `.` and `..` outright and strips CR, LF and
        // TAB, so any of them would address a different resource than the key
        // named. The transport rejects them too; catching them at construction
        // puts the failure next to the value that caused it.
        for hostile in ["", ".", "..", "with\nnewline", "with\ttab", "with\rreturn"] {
            let error = IssuePropertyKey::new(hostile)
                .expect_err("a key the URL builder would rewrite must be refused");
            assert!(
                matches!(error, AtlassianError::Validation { .. }),
                "{hostile:?} produced {error:?}"
            );
        }
    }

    #[test]
    fn a_slash_is_encoded_rather_than_refused() {
        // Not a traversal risk: the transport percent-encodes each segment on
        // its own, so a slash inside a key becomes `%2F` and cannot open a path
        // boundary. Refusing it would be an invented restriction Jira does not
        // have.
        assert!(IssuePropertyKey::new("a/b").is_ok());
        assert!(IssuePropertyKey::new("../admin").is_ok());
    }

    #[test]
    fn a_rejected_key_never_reaches_the_error_message() {
        // Bounded logging: a key is caller data of unbounded length, and this
        // error is rendered into a workflow log.
        const CANARY: &str = "CANARY-key-material-9f13c7";
        let error =
            IssuePropertyKey::new(format!("{CANARY}{}", "x".repeat(300))).expect_err("too long");

        assert!(
            !error.to_string().contains(CANARY),
            "the rejected key leaked into the message: {error}"
        );
        assert!(
            error.to_string().contains("255"),
            "the message names the rule: {error}"
        );
    }

    #[test]
    fn every_construction_route_runs_the_same_check() {
        assert!(IssuePropertyKey::from_str("threatflux.source-event").is_ok());
        assert!(IssuePropertyKey::try_from("threatflux.source-event").is_ok());
        assert!(IssuePropertyKey::try_from("threatflux.source-event".to_string()).is_ok());

        assert!(IssuePropertyKey::from_str("").is_err());
        assert!(IssuePropertyKey::try_from("").is_err());
        assert!(IssuePropertyKey::try_from(String::new()).is_err());
    }

    #[test]
    fn a_key_serializes_as_a_bare_string_and_deserializes_through_the_check() {
        let key = IssuePropertyKey::new("threatflux.reconcile").expect("legal");
        assert_eq!(
            serde_json::to_value(&key).expect("serializes"),
            json!("threatflux.reconcile"),
            "the newtype must contribute no wrapper of its own"
        );

        let read: IssuePropertyKey =
            serde_json::from_value(json!("threatflux.reconcile")).expect("parses");
        assert_eq!(read, key);

        let rejected = serde_json::from_value::<IssuePropertyKey>(json!("k".repeat(300)))
            .expect_err("deserialization must not be a way around the check");
        assert!(
            rejected.to_string().contains("255"),
            "the rule survives into the serde error: {rejected}"
        );
    }

    #[test]
    fn a_key_renders_as_itself() {
        let key = IssuePropertyKey::new("threatflux.source-event").expect("legal");
        assert_eq!(key.to_string(), "threatflux.source-event");
        assert_eq!(key.as_ref(), "threatflux.source-event");
        assert_eq!(key.into_string(), "threatflux.source-event");
    }

    #[test]
    fn a_property_carries_whatever_shape_was_stored() {
        for stored in [
            json!({"schema": 1, "repository_id": 42}),
            json!("a bare string"),
            json!([1, 2, 3]),
            json!(null),
        ] {
            let property: IssueProperty =
                serde_json::from_value(json!({"key": "threatflux.reconcile", "value": stored}))
                    .expect("parses");
            assert_eq!(property.key, "threatflux.reconcile");
            assert_eq!(property.value, stored);
        }
    }

    #[test]
    fn a_property_list_answers_membership() {
        let keys: IssuePropertyKeys = serde_json::from_value(json!({
            "keys": [
                {"self": "https://example.atlassian.net/rest/api/3/issue/10077/properties/a", "key": "a"},
                {"key": "threatflux.reconcile"}
            ]
        }))
        .expect("parses");

        assert_eq!(keys.len(), 2);
        assert!(!keys.is_empty());
        assert!(keys.contains("threatflux.reconcile"));
        assert!(!keys.contains("threatflux.absent"));
        assert_eq!(
            keys.keys[0].self_url.as_deref(),
            Some("https://example.atlassian.net/rest/api/3/issue/10077/properties/a")
        );
        assert!(keys.keys[1].self_url.is_none());
    }

    #[test]
    fn an_issue_with_no_properties_parses() {
        let empty: IssuePropertyKeys = serde_json::from_value(json!({"keys": []})).expect("parses");
        assert!(empty.is_empty());

        let absent: IssuePropertyKeys = serde_json::from_value(json!({})).expect("parses");
        assert!(absent.is_empty());
    }

    #[test]
    fn a_write_outcome_names_the_race_winner() {
        assert!(IssuePropertyWrite::Created.is_created());
        assert!(!IssuePropertyWrite::Updated.is_created());
    }
}
