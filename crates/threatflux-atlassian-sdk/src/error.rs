//! Error handling for the Atlassian Rust SDK
//!
//! This module provides errors for the implemented Jira and legacy Remote MCP paths,
//! including authentication, configuration, API, and transport failures.
//!
//! ## Response diagnostics
//!
//! A failing Atlassian response is turned into an [`AtlassianError`] by exactly one
//! function, `map_error_response`, and how much of that response survives the trip
//! is decided by [`DiagnosticsPolicy`]. The default is [`DiagnosticsPolicy::MetadataOnly`]:
//! the response head is kept, the body is never even read, and nothing derived from it
//! reaches an error message or a log line. A caller that needs more asks for it.
//!
//! ## Transport failures
//!
//! A failure that never produced a response — a refused connection, a timeout, a body
//! or decode error — becomes an [`AtlassianError`] through `From<reqwest::Error>`
//! instead. That conversion builds its message out of parts rather than copying
//! reqwest's own `Display`, which appends ` for url ({url})` with the URL exactly as
//! sent. The transport hangs query parameters off the request, so copying that string
//! would publish every search's JQL — and, once reconciliation lands, dedupe labels and
//! text lifted from an issue body — into an error the Action prints to a workflow log,
//! undoing in one channel what the log-hygiene work bounds in the other. Only the
//! scheme, host, port and path survive; the query, the fragment and any userinfo never
//! reach the message.
//!
//! The rebuild is also strictly more informative than the string it replaces: reqwest
//! renders a timeout and a refused connection identically as `error sending request`,
//! and both are distinctions the retry classification needs, so
//! [`AtlassianError::from`] names the failure kind explicitly.

use std::collections::BTreeMap;

use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error;
use url::Url;

/// Result type alias for SDK operations
pub type Result<T> = std::result::Result<T, AtlassianError>;

/// How much of a failing Atlassian response may leave the transport.
///
/// A Jira error document echoes the request that produced it — a JQL query built
/// from an event body, a rejected summary, a field value — so the response body is
/// caller data of unknown provenance, and an error carrying it is a value that ends
/// up in a workflow log, an exception report, or a Jira comment. The body is
/// therefore withheld by default and released only per policy.
///
/// # Example
///
/// ```rust
/// use threatflux_atlassian_sdk::error::DiagnosticsPolicy;
///
/// assert_eq!(DiagnosticsPolicy::default(), DiagnosticsPolicy::MetadataOnly);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticsPolicy {
    /// The response head only: status, `Retry-After`, and the declared body length.
    ///
    /// The body is not read at all, so nothing derived from it can be leaked by a
    /// later formatting mistake. This is the default.
    #[default]
    MetadataOnly,
    /// Additionally the `errorMessages` and `errors` members of a Jira error
    /// document, bounded in both count and length. Nothing else from the body.
    JiraErrorFields,
    /// Additionally the response body itself, truncated to
    /// [`ResponseDiagnostics::BODY_LIMIT`] characters.
    ///
    /// The body reaches the returned error and never a log line: what a caller
    /// opted into receiving is not automatically something the SDK publishes.
    IncludeBody,
}

/// What a failing Atlassian response was allowed to say about itself.
///
/// Every field except [`Self::status`] is subject to the [`DiagnosticsPolicy`] that
/// produced the record, which is retained in [`Self::policy`] so a caller can tell
/// an absent field from a suppressed one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ResponseDiagnostics {
    /// HTTP status code of the failing response.
    pub status: Option<u16>,
    /// The `Retry-After` header exactly as sent, bounded and unparsed.
    ///
    /// Captured from the response head before the body is consumed, which is the
    /// only point at which it is still reachable.
    pub retry_after: Option<String>,
    /// Body length: the declared `Content-Length` when the body was not read, the
    /// length actually read when it was.
    pub body_bytes: Option<u64>,
    /// `errorMessages` from a Jira error document. Empty under
    /// [`DiagnosticsPolicy::MetadataOnly`].
    pub error_messages: Vec<String>,
    /// `errors` from a Jira error document, keyed by field name. Empty under
    /// [`DiagnosticsPolicy::MetadataOnly`].
    pub field_errors: BTreeMap<String, String>,
    /// The response body, truncated. `None` unless the policy was
    /// [`DiagnosticsPolicy::IncludeBody`].
    pub body: Option<String>,
    /// The policy that produced this record.
    pub policy: DiagnosticsPolicy,
}

impl ResponseDiagnostics {
    /// Longest response body retained under [`DiagnosticsPolicy::IncludeBody`], in characters.
    pub const BODY_LIMIT: usize = 4096;

    /// Longest `Retry-After` value retained, in characters.
    const RETRY_AFTER_LIMIT: usize = 64;

    /// Longest single server-supplied error message retained, in characters.
    pub(crate) const MESSAGE_LIMIT: usize = 256;

    /// Most Jira error messages, and most field errors, retained.
    const MESSAGE_COUNT_LIMIT: usize = 8;

    /// Renders the Jira-supplied detail as one line, or `None` when there is none.
    ///
    /// This is what an error message is allowed to append once a caller has opted
    /// past [`DiagnosticsPolicy::MetadataOnly`].
    pub fn detail(&self) -> Option<String> {
        let mut parts = self.error_messages.clone();
        parts.extend(
            self.field_errors
                .iter()
                .map(|(field, message)| format!("{field}: {message}")),
        );

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }

    /// Builds the record `policy` allows from a captured head and an optional body.
    fn capture(meta: &ResponseMeta, body: Option<&str>, policy: DiagnosticsPolicy) -> Self {
        let mut diagnostics = Self {
            status: Some(meta.status),
            retry_after: meta
                .retry_after
                .as_deref()
                .map(|value| bounded(value, Self::RETRY_AFTER_LIMIT)),
            body_bytes: body.map_or(meta.content_length, |read| {
                Some(u64::try_from(read.len()).unwrap_or(u64::MAX))
            }),
            policy,
            ..Self::default()
        };

        let Some(body) = body else {
            return diagnostics;
        };

        if policy == DiagnosticsPolicy::MetadataOnly {
            return diagnostics;
        }

        if let Ok(document) = serde_json::from_str::<Value>(body) {
            diagnostics.error_messages = Self::read_error_messages(&document);
            diagnostics.field_errors = Self::read_field_errors(&document);
        }

        if policy == DiagnosticsPolicy::IncludeBody {
            diagnostics.body = Some(bounded(body, Self::BODY_LIMIT));
        }

        diagnostics
    }

    /// Reads the bounded `errorMessages` array out of a Jira error document.
    fn read_error_messages(document: &Value) -> Vec<String> {
        document
            .get("errorMessages")
            .and_then(Value::as_array)
            .map(|messages| {
                messages
                    .iter()
                    .filter_map(Value::as_str)
                    .take(Self::MESSAGE_COUNT_LIMIT)
                    .map(|message| bounded(message, Self::MESSAGE_LIMIT))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Reads the bounded `errors` object out of a Jira error document.
    fn read_field_errors(document: &Value) -> BTreeMap<String, String> {
        document
            .get("errors")
            .and_then(Value::as_object)
            .map(|errors| {
                errors
                    .iter()
                    .filter_map(|(field, message)| {
                        message.as_str().map(|message| {
                            (
                                bounded(field, Self::MESSAGE_LIMIT),
                                bounded(message, Self::MESSAGE_LIMIT),
                            )
                        })
                    })
                    .take(Self::MESSAGE_COUNT_LIMIT)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Truncates `value` to `limit` characters.
///
/// Counted in characters rather than bytes: a byte slice would panic partway
/// through a multi-byte character, and a Jira error message is arbitrary text.
pub(crate) fn bounded(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

/// The head of a failing HTTP response, captured before its body is consumed.
///
/// [`Response::text`] takes the response by value, so everything on the head —
/// `Retry-After` above all — is unreachable once the body has been taken. This type
/// exists so that ordering is a property of the code rather than of the order two
/// statements happen to be written in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseMeta {
    /// HTTP status code.
    status: u16,
    /// The `Retry-After` header exactly as sent, when it is representable as text.
    retry_after: Option<String>,
    /// The declared `Content-Length`, when the response carried one.
    content_length: Option<u64>,
}

impl ResponseMeta {
    /// Reads everything worth keeping off `response` without consuming it.
    pub(crate) fn capture(response: &Response) -> Self {
        Self {
            status: response.status().as_u16(),
            retry_after: response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            content_length: response.content_length(),
        }
    }

    /// The captured status code.
    pub(crate) const fn status(&self) -> u16 {
        self.status
    }
}

/// Which [`AtlassianError`] a given status becomes at a given call site.
///
/// The three shapes are not interchangeable: each one reproduces the mapping its
/// own call site had before [`map_error_response`] became the single seam, so
/// routing every site through one function changed no classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureShape {
    /// Jira REST: 404 is [`AtlassianError::NotFound`], anything unmatched is
    /// [`AtlassianError::JiraApi`].
    JiraRest,
    /// Legacy Remote MCP: there is no 404 rule, and anything unmatched is
    /// [`AtlassianError::Http`].
    RemoteMcp,
    /// OAuth token endpoint: every failure is an [`AtlassianError::Authentication`],
    /// including a 403 or a 429.
    OAuthToken,
}

/// The per-call-site half of [`map_error_response`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailureContext {
    /// Which mapping the status goes through.
    shape: FailureShape,
    /// What the caller was attempting, as the leading clause of the message.
    operation: &'static str,
    /// How much of the response the call site is willing to keep.
    policy: DiagnosticsPolicy,
}

impl FailureContext {
    /// Describes a call site.
    pub(crate) const fn new(
        shape: FailureShape,
        operation: &'static str,
        policy: DiagnosticsPolicy,
    ) -> Self {
        Self {
            shape,
            operation,
            policy,
        }
    }

    /// Maps a captured status and its diagnostics onto this site's error.
    fn build(self, status: u16, diagnostics: ResponseDiagnostics) -> AtlassianError {
        let mut message = format!("{} failed with HTTP {status}", self.operation);
        if let Some(detail) = diagnostics.detail() {
            message.push_str(": ");
            message.push_str(&detail);
        }

        match (self.shape, status) {
            (FailureShape::OAuthToken, _) => AtlassianError::Authentication {
                message,
                diagnostics: Some(Box::new(diagnostics)),
            },
            (FailureShape::JiraRest, 401) => AtlassianError::Authentication {
                message: "Invalid credentials or API token".to_string(),
                diagnostics: Some(Box::new(diagnostics)),
            },
            (FailureShape::RemoteMcp, 401) => AtlassianError::Authentication {
                message: "Authentication failed - token may be expired".to_string(),
                diagnostics: Some(Box::new(diagnostics)),
            },
            (FailureShape::JiraRest, 403) => AtlassianError::PermissionDenied {
                message: "Insufficient permissions for this operation".to_string(),
            },
            (FailureShape::RemoteMcp, 403) => AtlassianError::PermissionDenied {
                message: "Insufficient permissions for Atlassian resources".to_string(),
            },
            (FailureShape::JiraRest, 404) => AtlassianError::NotFound {
                message: "Resource not found".to_string(),
            },
            (_, 429) => AtlassianError::RateLimit {
                message: "Rate limit exceeded".to_string(),
            },
            (FailureShape::JiraRest, _) => AtlassianError::JiraApi {
                message,
                code: Some(i32::from(status)),
                diagnostics: Some(Box::new(diagnostics)),
            },
            (FailureShape::RemoteMcp, _) => AtlassianError::Http {
                message,
                status_code: Some(status),
                diagnostics: Some(Box::new(diagnostics)),
            },
        }
    }
}

/// Turns a failing Atlassian response into an error, and is the only thing that does.
///
/// Every failure path in this crate — the Jira REST transport, the legacy Remote MCP
/// transport, and both OAuth token requests — goes through here, so the response head
/// is captured before the body is read, the body is read only when the policy admits
/// it, and the log line is metadata regardless of policy. A call site cannot get the
/// order wrong because it never sees the two halves separately.
pub(crate) async fn map_error_response(
    response: Response,
    context: FailureContext,
) -> AtlassianError {
    let meta = ResponseMeta::capture(&response);
    let body = if context.policy == DiagnosticsPolicy::MetadataOnly {
        None
    } else {
        response.text().await.ok()
    };
    let diagnostics = ResponseDiagnostics::capture(&meta, body.as_deref(), context.policy);

    error!(
        operation = context.operation,
        status = meta.status(),
        retry_after = ?diagnostics.retry_after,
        body_bytes = ?diagnostics.body_bytes,
        "Atlassian API request failed"
    );

    context.build(meta.status(), diagnostics)
}

/// Error variants returned by SDK operations.
///
/// Non-exhaustive: later milestones add variants for page-token expiry, transport
/// classification, and ambiguous writes, and a downstream `match` should not have to
/// change for each one.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum AtlassianError {
    /// HTTP request errors with optional status codes
    #[error("HTTP error: {message}")]
    Http {
        /// Human-readable error description
        message: String,
        /// HTTP status code returned by Atlassian, when available
        status_code: Option<u16>,
        /// What the failing response was allowed to say about itself.
        ///
        /// Boxed so that the diagnostics do not widen every `Result` in the crate.
        #[serde(default)]
        diagnostics: Option<Box<ResponseDiagnostics>>,
    },

    /// Authentication and authorization errors
    #[error("Authentication error: {message}")]
    Authentication {
        /// Reason the authentication attempt failed
        message: String,
        /// What the failing response was allowed to say about itself.
        ///
        /// Boxed so that the diagnostics do not widen every `Result` in the crate.
        #[serde(default)]
        diagnostics: Option<Box<ResponseDiagnostics>>,
    },

    /// JSON parsing and serialization errors
    #[error("Parse error: {message}")]
    Parse {
        /// Details about the parsing failure
        message: String,
    },

    /// Configuration and setup errors
    #[error("Configuration error: {message}")]
    Configuration {
        /// Context for the configuration failure
        message: String,
    },

    /// File I/O errors
    #[error("I/O error: {message}")]
    Io {
        /// Underlying I/O failure description
        message: String,
    },

    /// Jira API specific errors with optional error codes
    #[error("Jira API error: {message}")]
    JiraApi {
        /// Message returned by Jira
        message: String,
        /// Optional Jira error code
        code: Option<i32>,
        /// What the failing response was allowed to say about itself.
        ///
        /// Boxed so that the diagnostics do not widen every `Result` in the crate.
        #[serde(default)]
        diagnostics: Option<Box<ResponseDiagnostics>>,
    },

    /// Internal SDK errors
    #[error("Internal error: {message}")]
    Internal {
        /// Internal failure description
        message: String,
    },

    /// Request timeout errors
    #[error("Timeout error: {message}")]
    Timeout {
        /// Timeout details
        message: String,
    },

    /// SSL/TLS certificate errors
    #[error("SSL error: {message}")]
    Ssl {
        /// TLS or certificate failure description
        message: String,
    },

    /// Invalid request parameters
    #[error("Invalid request: {message}")]
    InvalidRequest {
        /// Details about the invalid request
        message: String,
    },

    /// Resource not found errors
    #[error("Not found: {message}")]
    NotFound {
        /// Description of the missing resource
        message: String,
    },

    /// Permission denied errors
    #[error("Permission denied: {message}")]
    PermissionDenied {
        /// Explanation for the denied access
        message: String,
    },

    /// Rate limiting errors
    #[error("Rate limited: {message}")]
    RateLimit {
        /// Rate limit error message
        message: String,
    },

    /// Field validation errors for Jira operations
    #[error("Validation error: {message}")]
    Validation {
        /// Reason validation failed
        message: String,
    },

    /// An enhanced-search page token was rejected part-way through an iteration.
    ///
    /// `/search/jql` page tokens are time-limited, so a long walk or a slow
    /// consumer can take a 400 on a page that a healthy iteration had already
    /// been issued a token for. That 400 and a malformed-JQL 400 arrive over the
    /// same wire and call for opposite responses — restart the search, versus fix
    /// the query — which is why this is its own variant rather than a flavour of
    /// [`Validation`](Self::Validation): a caller holding only the `Result` can
    /// still tell them apart.
    ///
    /// # Restart, never resume
    ///
    /// Recovery is to build a fresh cursor and walk the result set again from its
    /// first page, discarding what the abandoned walk delivered. It is **not** to
    /// carry on where the walk stopped, and the SDK does not offer a way to:
    /// between the two halves of such a walk the result set has been changing, so
    /// the pages already delivered and the pages still to come answer the query
    /// as it stood at two different instants. Stitching them together produces a
    /// set that was never the answer at any instant — with issues counted twice
    /// or missed entirely as rows shift between pages — and a caller
    /// reconciling over it acts on it believing it is complete.
    #[error(
        "the enhanced-search page token for page {page_index} was rejected; page tokens are time-limited, so start the search again from its first page rather than resuming this one"
    )]
    PageTokenExpired {
        /// Index of the page the rejected token asked for, counting the first
        /// page of the iteration as zero.
        ///
        /// Never zero: the first request of an iteration carries no
        /// Jira-issued token, so a failure there is a query error rather than an
        /// expiry.
        page_index: usize,
    },
}

impl AtlassianError {
    /// Create a new HTTP error
    pub fn http(message: impl Into<String>, status_code: Option<u16>) -> Self {
        Self::Http {
            message: message.into(),
            status_code,
            diagnostics: None,
        }
    }

    /// Create a new authentication error
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
            diagnostics: None,
        }
    }

    /// Create a new parse error
    pub fn parse(message: impl Into<String>) -> Self {
        Self::Parse {
            message: message.into(),
        }
    }

    /// Create a new configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Create a new Jira API error
    pub fn jira_api(message: impl Into<String>, code: Option<i32>) -> Self {
        Self::JiraApi {
            message: message.into(),
            code,
            diagnostics: None,
        }
    }

    /// Create a new validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Check if this is a temporary/retryable error
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Http { status_code: Some(code), .. } if *code >= 500,
        ) || matches!(self, Self::Timeout { .. })
            || matches!(self, Self::RateLimit { .. })
    }

    /// Get the HTTP status code if available
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Http { status_code, .. } => *status_code,
            _ => None,
        }
    }

    /// What the failing response was allowed to say about itself, if this error
    /// came from one.
    ///
    /// Present on the three variants a response body used to be interpolated into.
    /// The typed 403, 404, and 429 mappings carry a constant message and never
    /// carried response text, so there is nothing to record on them.
    pub fn diagnostics(&self) -> Option<&ResponseDiagnostics> {
        match self {
            Self::Http { diagnostics, .. }
            | Self::Authentication { diagnostics, .. }
            | Self::JiraApi { diagnostics, .. } => diagnostics.as_deref(),
            _ => None,
        }
    }
}

/// Longest sanitized destination retained in a transport error message, in characters.
///
/// A path segment is caller data — an issue key, an attachment id — so the rendered
/// destination is bounded for the same reason a response body is.
const DESTINATION_LIMIT: usize = 256;

/// Names what a [`reqwest::Error`] failed at, in one phrase and without any data.
///
/// This is the half of reqwest's `Display` worth keeping. It is deliberately not
/// flattened: `is_timeout` and `is_connect` are the two signals a retry
/// classification needs most — a refused connection means the request cannot have
/// been applied, a timeout means it may have been — and reqwest renders both as the
/// same `error sending request`, so the distinction has to be recovered here or it
/// is lost for good.
fn transport_failure_kind(err: &reqwest::Error) -> &'static str {
    // `is_timeout` and `is_connect` walk the source chain rather than matching on
    // the error's own kind, so they are asked first: a send failure that is really
    // a timeout must be reported as one.
    if err.is_timeout() {
        "request timed out"
    } else if err.is_connect() {
        "connection failed"
    } else if err.is_status() {
        "server returned an error status"
    } else if err.is_decode() {
        "response body could not be decoded"
    } else if err.is_body() {
        "request or response body failed"
    } else if err.is_redirect() {
        "redirect handling failed"
    } else if err.is_builder() {
        "request could not be built"
    } else {
        "request failed"
    }
}

/// Renders `url` as scheme, host, port and path, and nothing else.
///
/// Built by allowlist rather than by clearing the parts that must not appear: a
/// component this function does not name cannot leak through it, so a URL shape
/// nobody anticipated fails closed. `None` for any URL with no host — a
/// cannot-be-a-base URL has no structure to take apart safely, and naming the
/// destination is worth less than the guarantee.
fn safe_destination(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let scheme = url.scheme();
    let path = url.path();

    // `port` is `None` for the scheme's default port, which is the one case where
    // spelling it out would say nothing.
    let rendered = url.port().map_or_else(
        || format!("{scheme}://{host}{path}"),
        |port| format!("{scheme}://{host}:{port}{path}"),
    );

    Some(bounded(&rendered, DESTINATION_LIMIT))
}

/// Describes a transport failure without quoting the request that caused it.
fn transport_message(err: &reqwest::Error) -> String {
    let kind = transport_failure_kind(err);

    err.url().and_then(safe_destination).map_or_else(
        || kind.to_owned(),
        |destination| format!("{kind} ({destination})"),
    )
}

// Implement conversions from common error types
impl From<reqwest::Error> for AtlassianError {
    /// Converts a transport failure, keeping the failure kind and the destination
    /// host and dropping everything the request carried.
    ///
    /// Notably **not** `err.to_string()`: reqwest appends the request URL with its
    /// query string, which on this crate's search paths is a JQL query built from
    /// caller data. See the module documentation.
    fn from(err: reqwest::Error) -> Self {
        let status_code = err.status().map(|status| status.as_u16());
        Self::Http {
            message: transport_message(&err),
            status_code,
            diagnostics: None,
        }
    }
}

impl From<serde_json::Error> for AtlassianError {
    fn from(err: serde_json::Error) -> Self {
        Self::Parse {
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for AtlassianError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            message: err.to_string(),
        }
    }
}

impl From<url::ParseError> for AtlassianError {
    fn from(err: url::ParseError) -> Self {
        Self::Configuration {
            message: format!("Invalid URL: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let http_err = AtlassianError::http("Request failed", Some(404));
        assert!(matches!(http_err, AtlassianError::Http { .. }));
        assert_eq!(http_err.status_code(), Some(404));

        let auth_err = AtlassianError::auth("Invalid credentials");
        assert!(matches!(auth_err, AtlassianError::Authentication { .. }));

        let parse_err = AtlassianError::parse("JSON parsing failed");
        assert!(matches!(parse_err, AtlassianError::Parse { .. }));
    }

    #[test]
    fn test_retryable_errors() {
        let server_error = AtlassianError::http("Server error", Some(500));
        assert!(server_error.is_retryable());

        let client_error = AtlassianError::http("Client error", Some(400));
        assert!(!client_error.is_retryable());

        let timeout_error = AtlassianError::Timeout {
            message: "Request timed out".to_string(),
        };
        assert!(timeout_error.is_retryable());

        let rate_limit_error = AtlassianError::RateLimit {
            message: "Rate limited".to_string(),
        };
        assert!(rate_limit_error.is_retryable());
    }

    #[test]
    fn test_error_display() {
        let error = AtlassianError::auth("Invalid API token");
        assert_eq!(error.to_string(), "Authentication error: Invalid API token");
    }

    #[test]
    fn test_error_conversions() {
        // Test serde_json error conversion
        let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let atlassian_error: AtlassianError = json_error.into();
        assert!(matches!(atlassian_error, AtlassianError::Parse { .. }));

        // Test URL parse error conversion
        let url_error = url::ParseError::InvalidPort;
        let atlassian_error: AtlassianError = url_error.into();
        assert!(matches!(
            atlassian_error,
            AtlassianError::Configuration { .. }
        ));
    }
}

#[cfg(test)]
mod transport_error_tests {
    use super::{AtlassianError, DESTINATION_LIMIT};
    use serde_json::Value;
    use std::time::Duration;
    use url::Url;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The value that must never appear in an error message.
    ///
    /// A single token with no percent-encodable character in it, so a message that
    /// quoted the URL in either form still trips the assertion.
    const CANARY: &str = "CANARY-dedupe-label-9f13c7";

    /// Starts a mock server that answers every GET with `template`.
    async fn mock(template: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(template)
            .mount(&server)
            .await;
        server
    }

    /// Asserts `rendered` kept nothing of the request it came from.
    ///
    /// `jql=` rather than `jql`: `/rest/api/3/search/jql` is the endpoint's own path
    /// and is allowed to appear, while `jql=` can only be the parameter.
    fn assert_no_request_data(rendered: &str) {
        assert!(!rendered.contains(CANARY), "rendered: {rendered}");
        assert!(!rendered.contains("jql="), "rendered: {rendered}");
        assert!(
            !rendered.contains('?'),
            "a query string survived: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_transport_error_never_renders_the_request_query() {
        // `Transport::send` hangs the query off the reqwest builder, so the URL
        // reqwest attaches to a decode error is the one with the JQL on it. Before
        // this was rebuilt from parts the message read
        // `error decoding response body for url (http://127.0.0.1:PORT/?jql=...)`.
        let server = mock(ResponseTemplate::new(200).set_body_string("not json at all")).await;

        let failure = reqwest::Client::new()
            .get(server.uri())
            .query(&[("jql", format!("labels = {CANARY}"))])
            .send()
            .await
            .expect("the mock server answers")
            .json::<Value>()
            .await
            .expect_err("a non-JSON body fails to decode");

        // The leak is in the source error, which is exactly why it cannot be copied.
        assert!(failure.to_string().contains(CANARY));

        let rendered = AtlassianError::from(failure).to_string();
        assert_no_request_data(&rendered);
        assert!(
            rendered.contains("response body could not be decoded"),
            "the failure kind is still named: {rendered}"
        );
        assert!(
            rendered.contains("127.0.0.1"),
            "the destination host is still named: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_timeout_and_a_refused_connection_stay_distinguishable() {
        // Both render as `error sending request` through reqwest's own `Display`,
        // and they sit in different rows of the retry classification: a refused
        // connection cannot have been applied, a timeout may have been.
        let slow = mock(ResponseTemplate::new(200).set_delay(Duration::from_secs(5))).await;
        let timeout = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .expect("a client with a timeout builds")
            .get(slow.uri())
            .query(&[("jql", format!("labels = {CANARY}"))])
            .send()
            .await
            .expect_err("the delayed response outlives the timeout");
        assert!(timeout.is_timeout());

        let rendered = AtlassianError::from(timeout).to_string();
        assert_no_request_data(&rendered);
        assert!(
            rendered.starts_with("HTTP error: request timed out ("),
            "rendered: {rendered}"
        );

        // Port 1 is reserved and never listening, so this refuses rather than hangs.
        let refused = reqwest::Client::new()
            .get("http://127.0.0.1:1/rest/api/3/search/jql")
            .query(&[("jql", format!("labels = {CANARY}"))])
            .send()
            .await
            .expect_err("nothing listens on port 1");
        assert!(refused.is_connect());

        let rendered = AtlassianError::from(refused).to_string();
        assert_no_request_data(&rendered);
        assert_eq!(
            rendered,
            "HTTP error: connection failed (http://127.0.0.1:1/rest/api/3/search/jql)"
        );
    }

    #[tokio::test]
    async fn a_status_error_keeps_its_code_and_loses_its_query() {
        let server = mock(ResponseTemplate::new(500)).await;

        let failure = reqwest::Client::new()
            .get(server.uri())
            .query(&[("jql", format!("labels = {CANARY}"))])
            .send()
            .await
            .expect("the mock server answers")
            .error_for_status()
            .expect_err("a 500 is an error status");

        let error = AtlassianError::from(failure);
        assert_eq!(
            error.status_code(),
            Some(500),
            "the status mapping is unchanged"
        );
        let rendered = error.to_string();
        assert_no_request_data(&rendered);
        assert!(
            rendered.contains("server returned an error status"),
            "rendered: {rendered}"
        );
    }

    /// A transport failure carrying `url`, for the URL shapes a mock server cannot
    /// produce. `with_url` is reqwest's own public way to attach one, and it is the
    /// same call `Response::json` makes when it attaches the request URL to a decode
    /// failure — so these exercise the real path with a URL of the test's choosing.
    fn error_for(url: &str) -> reqwest::Error {
        reqwest::Client::new()
            .get("http://[not-an-address")
            .build()
            .expect_err("an unparseable URL fails to build")
            .with_url(Url::parse(url).expect("the test URL parses"))
    }

    #[test]
    fn credentials_and_a_fragment_in_a_url_never_reach_the_message() {
        // A base URL carrying userinfo is a configuration mistake rather than this
        // crate's own doing, but it is one that puts a token in every transport
        // error, so the destination is assembled from named parts and cannot
        // reproduce it.
        let rendered = AtlassianError::from(error_for(&format!(
            "https://svc-account:s3cr3t-token@jira.example.com/rest/api/3/search/jql?jql={CANARY}#fragment-{CANARY}"
        )))
        .to_string();

        assert_no_request_data(&rendered);
        assert!(!rendered.contains("s3cr3t-token"), "rendered: {rendered}");
        assert!(!rendered.contains("svc-account"), "rendered: {rendered}");
        assert!(!rendered.contains('#'), "rendered: {rendered}");
        assert_eq!(
            rendered,
            "HTTP error: request could not be built (https://jira.example.com/rest/api/3/search/jql)"
        );
    }

    #[test]
    fn a_default_port_is_dropped_and_a_context_path_is_kept() {
        // Data Center deployments live under a context path, and naming the wrong
        // destination is worse than naming none.
        let rendered = AtlassianError::from(error_for(
            "https://jira.example.com:8443/jira/rest/api/3/issue/ABC-1",
        ))
        .to_string();
        assert_eq!(
            rendered,
            "HTTP error: request could not be built \
             (https://jira.example.com:8443/jira/rest/api/3/issue/ABC-1)"
        );

        let rendered =
            AtlassianError::from(error_for("https://jira.example.com:443/rest/api/3/myself"))
                .to_string();
        assert_eq!(
            rendered,
            "HTTP error: request could not be built (https://jira.example.com/rest/api/3/myself)"
        );
    }

    #[test]
    fn a_hostile_path_is_bounded() {
        let rendered = AtlassianError::from(error_for(&format!(
            "https://jira.example.com/rest/api/3/issue/{}",
            "A".repeat(DESTINATION_LIMIT * 8)
        )))
        .to_string();

        let destination = rendered
            .rsplit_once(" (")
            .and_then(|(_, tail)| tail.strip_suffix(')'))
            .expect("the message ends with a parenthesised destination");
        assert_eq!(destination.chars().count(), DESTINATION_LIMIT);
    }

    #[test]
    fn a_url_with_no_host_yields_no_destination_at_all() {
        // Nothing in this crate dials one, but a `data:` URL has no structure to
        // take apart, so the destination is dropped rather than guessed at.
        let rendered =
            AtlassianError::from(error_for(&format!("data:text/plain,{CANARY}"))).to_string();

        assert_no_request_data(&rendered);
        assert_eq!(rendered, "HTTP error: request could not be built");
    }
}

#[cfg(test)]
mod diagnostics_tests {
    use super::{
        map_error_response, AtlassianError, DiagnosticsPolicy, FailureContext, FailureShape,
        ResponseDiagnostics,
    };
    use serde_json::{json, Value};
    use std::future::Future;
    use threatflux_atlassian_testkit::logs;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A Jira REST call site at `policy`.
    const fn jira_rest(policy: DiagnosticsPolicy) -> FailureContext {
        FailureContext::new(FailureShape::JiraRest, "Jira API request", policy)
    }

    /// Drives a real HTTP response through the seam, returning it and the log.
    ///
    /// Every test that reaches the seam goes through here rather than calling
    /// [`map_error_response`] directly. `tracing` caches per-callsite interest
    /// globally, so a hit taken on a thread with no subscriber installed disables
    /// the seam's one log line for every later hit in the process — running all of
    /// them under a capture is what makes the log assertions deterministic under
    /// `cargo test`'s default parallelism.
    fn mapped(template: ResponseTemplate, context: FailureContext) -> (AtlassianError, String) {
        capture_async(async move {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(template)
                .mount(&server)
                .await;

            let response = reqwest::Client::new()
                .get(server.uri())
                .send()
                .await
                .expect("the mock server should answer");

            map_error_response(response, context).await
        })
    }

    /// Runs `body` on a current-thread runtime with every `tracing` event captured.
    ///
    /// The subscriber `logs::capture` installs is thread-local, so the future has
    /// to be driven on the thread that installed it rather than on a worker pool.
    fn capture_async<T>(body: impl Future<Output = T>) -> (T, String) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime should build");
        logs::capture(|| runtime.block_on(body))
    }

    #[test]
    fn a_response_body_does_not_reach_the_error_or_the_log_by_default() {
        const MARKER: &str = "issue-body-echoed-back-by-jira";

        let (error, log) = mapped(
            ResponseTemplate::new(500).set_body_json(json!({
                "errorMessages": [format!("summary: {MARKER}")],
            })),
            jira_rest(DiagnosticsPolicy::MetadataOnly),
        );

        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "Jira API error: Jira API request failed with HTTP 500"
        );
        assert!(!rendered.contains(MARKER), "rendered: {rendered}");
        assert!(!log.contains(MARKER), "log was: {log}");
        assert!(
            log.contains("Atlassian API request failed"),
            "log was: {log}"
        );
        assert!(log.contains("status=500"), "log was: {log}");

        let diagnostics = error.diagnostics().expect("a response error is diagnosed");
        assert_eq!(diagnostics.status, Some(500));
        assert_eq!(diagnostics.policy, DiagnosticsPolicy::MetadataOnly);
        assert!(diagnostics.error_messages.is_empty());
        assert!(diagnostics.field_errors.is_empty());
        assert!(diagnostics.body.is_none());
        assert!(
            diagnostics.body_bytes.is_some(),
            "the declared length is metadata and survives an unread body"
        );
    }

    #[test]
    fn the_retry_after_header_survives_the_body_read() {
        // The regression this pins: `Response::text` takes the response by value,
        // so a site that reads the body first can no longer see any header.
        for policy in [
            DiagnosticsPolicy::MetadataOnly,
            DiagnosticsPolicy::JiraErrorFields,
            DiagnosticsPolicy::IncludeBody,
        ] {
            let (error, log) = mapped(
                ResponseTemplate::new(503)
                    .insert_header("Retry-After", "120")
                    .set_body_string("service unavailable"),
                jira_rest(policy),
            );

            let diagnostics = error.diagnostics().expect("a response error is diagnosed");
            assert_eq!(
                diagnostics.retry_after.as_deref(),
                Some("120"),
                "policy: {policy:?}"
            );
            assert!(log.contains(r#"retry_after=Some("120")"#), "log was: {log}");
        }
    }

    #[test]
    fn jira_error_fields_are_released_only_on_request() {
        let template = || {
            ResponseTemplate::new(400).set_body_json(json!({
                "errorMessages": ["Field 'summary' is too long"],
                "errors": { "summary": "cannot exceed 255 characters" },
            }))
        };

        let (withheld, _) = mapped(template(), jira_rest(DiagnosticsPolicy::MetadataOnly));
        assert_eq!(
            withheld.to_string(),
            "Jira API error: Jira API request failed with HTTP 400"
        );

        let (released, log) = mapped(template(), jira_rest(DiagnosticsPolicy::JiraErrorFields));
        assert_eq!(
            released.to_string(),
            "Jira API error: Jira API request failed with HTTP 400: \
             Field 'summary' is too long; summary: cannot exceed 255 characters"
        );
        assert!(!log.contains("too long"), "log was: {log}");

        let diagnostics = released
            .diagnostics()
            .expect("a response error is diagnosed");
        assert_eq!(diagnostics.error_messages, ["Field 'summary' is too long"]);
        assert_eq!(
            diagnostics.field_errors.get("summary").map(String::as_str),
            Some("cannot exceed 255 characters")
        );
        assert!(
            diagnostics.body.is_none(),
            "the structured fields are not the whole body"
        );
    }

    #[test]
    fn the_whole_body_is_released_only_under_include_body_and_never_to_a_log() {
        const MARKER: &str = "<html>not json at all</html>";

        let (error, log) = mapped(
            ResponseTemplate::new(502).set_body_string(MARKER),
            jira_rest(DiagnosticsPolicy::IncludeBody),
        );

        let diagnostics = error.diagnostics().expect("a response error is diagnosed");
        assert_eq!(diagnostics.body.as_deref(), Some(MARKER));
        assert!(
            diagnostics.error_messages.is_empty(),
            "a non-JSON body yields no Jira fields"
        );
        assert!(
            !error.to_string().contains(MARKER),
            "the body reaches the record, not the message"
        );
        assert!(!log.contains(MARKER), "log was: {log}");
        assert!(
            log.contains("Atlassian API request failed"),
            "log was: {log}"
        );
    }

    #[test]
    fn a_hostile_body_is_bounded_in_every_direction() {
        let long = "a".repeat(ResponseDiagnostics::BODY_LIMIT * 4);
        let (error, _) = mapped(
            ResponseTemplate::new(400).set_body_json(json!({
                "errorMessages": vec![long.clone(); 64],
                "errors": (0..64)
                    .map(|index| (format!("field{index}"), Value::String(long.clone())))
                    .collect::<serde_json::Map<_, _>>(),
            })),
            jira_rest(DiagnosticsPolicy::IncludeBody),
        );

        let diagnostics = error.diagnostics().expect("a response error is diagnosed");
        assert_eq!(
            diagnostics.body.as_ref().map(|body| body.chars().count()),
            Some(ResponseDiagnostics::BODY_LIMIT)
        );
        assert_eq!(diagnostics.error_messages.len(), 8);
        assert_eq!(diagnostics.field_errors.len(), 8);
        assert!(diagnostics
            .error_messages
            .iter()
            .all(|message| message.chars().count() == 256));
    }

    #[test]
    fn a_multibyte_body_is_truncated_on_a_character_boundary() {
        // The bound counts characters rather than bytes; a byte slice at the limit
        // would panic partway through a 4-byte character.
        let body = "\u{1f512}".repeat(ResponseDiagnostics::BODY_LIMIT * 2);
        let (error, _) = mapped(
            ResponseTemplate::new(400).set_body_string(body),
            jira_rest(DiagnosticsPolicy::IncludeBody),
        );

        let diagnostics = error.diagnostics().expect("a response error is diagnosed");
        let kept = diagnostics.body.as_deref().unwrap_or_default();
        assert_eq!(
            kept.matches('\u{1f512}').count(),
            ResponseDiagnostics::BODY_LIMIT
        );
    }

    #[test]
    fn an_oauth_token_failure_keeps_the_endpoint_body_out_of_the_error() {
        // The body of a token-endpoint rejection echoes the request, and on this
        // path the request carries the PKCE verifier and the authorization code.
        const MARKER: &str = "code_verifier=leaked-pkce-verifier";

        let (error, log) = mapped(
            ResponseTemplate::new(400).set_body_string(format!("invalid_grant: {MARKER}")),
            FailureContext::new(
                FailureShape::OAuthToken,
                "Token exchange",
                DiagnosticsPolicy::default(),
            ),
        );

        assert_eq!(
            error.to_string(),
            "Authentication error: Token exchange failed with HTTP 400"
        );
        assert!(!error.to_string().contains(MARKER));
        assert!(!log.contains(MARKER), "log was: {log}");
    }

    #[test]
    fn each_call_site_keeps_the_mapping_it_had_before_the_seam() {
        let cases = [
            (
                FailureShape::JiraRest,
                401_u16,
                "Authentication error: Invalid credentials or API token",
            ),
            (
                FailureShape::JiraRest,
                403,
                "Permission denied: Insufficient permissions for this operation",
            ),
            (FailureShape::JiraRest, 404, "Not found: Resource not found"),
            (
                FailureShape::JiraRest,
                429,
                "Rate limited: Rate limit exceeded",
            ),
            (
                FailureShape::JiraRest,
                500,
                "Jira API error: Probe failed with HTTP 500",
            ),
            (
                FailureShape::RemoteMcp,
                401,
                "Authentication error: Authentication failed - token may be expired",
            ),
            (
                FailureShape::RemoteMcp,
                403,
                "Permission denied: Insufficient permissions for Atlassian resources",
            ),
            (
                FailureShape::RemoteMcp,
                404,
                "HTTP error: Probe failed with HTTP 404",
            ),
            (
                FailureShape::RemoteMcp,
                429,
                "Rate limited: Rate limit exceeded",
            ),
            (
                FailureShape::RemoteMcp,
                500,
                "HTTP error: Probe failed with HTTP 500",
            ),
            (
                FailureShape::OAuthToken,
                401,
                "Authentication error: Probe failed with HTTP 401",
            ),
            (
                FailureShape::OAuthToken,
                403,
                "Authentication error: Probe failed with HTTP 403",
            ),
            (
                FailureShape::OAuthToken,
                429,
                "Authentication error: Probe failed with HTTP 429",
            ),
            (
                FailureShape::OAuthToken,
                500,
                "Authentication error: Probe failed with HTTP 500",
            ),
        ];

        for (shape, status, expected) in cases {
            let context = FailureContext::new(shape, "Probe", DiagnosticsPolicy::MetadataOnly);
            let error = context.build(status, ResponseDiagnostics::default());

            assert_eq!(error.to_string(), expected, "{shape:?} {status}");
        }
    }

    #[test]
    fn only_the_variants_that_once_carried_response_text_are_diagnosed() {
        let site = FailureContext::new(
            FailureShape::JiraRest,
            "Probe",
            DiagnosticsPolicy::MetadataOnly,
        );

        assert!(site
            .build(500, ResponseDiagnostics::default())
            .diagnostics()
            .is_some());
        assert!(site
            .build(401, ResponseDiagnostics::default())
            .diagnostics()
            .is_some());
        // 403, 404 and 429 map onto a constant message that never carried response
        // text, so there is nothing to record on them. E1 revisits 429 when
        // `RateLimit` gains a parsed `retry_after`.
        assert!(site
            .build(429, ResponseDiagnostics::default())
            .diagnostics()
            .is_none());
        assert!(AtlassianError::parse("bad json").diagnostics().is_none());
        assert!(AtlassianError::http("no response", None)
            .diagnostics()
            .is_none());
    }

    #[test]
    fn a_diagnosed_error_round_trips_through_serde() {
        let site = FailureContext::new(
            FailureShape::JiraRest,
            "Probe",
            DiagnosticsPolicy::IncludeBody,
        );
        let diagnostics = ResponseDiagnostics {
            status: Some(503),
            retry_after: Some("120".to_string()),
            body: Some("upstream down".to_string()),
            policy: DiagnosticsPolicy::IncludeBody,
            ..ResponseDiagnostics::default()
        };
        let error = site.build(503, diagnostics.clone());

        let encoded = serde_json::to_string(&error).expect("an error serializes");
        let decoded: AtlassianError = serde_json::from_str(&encoded).expect("and deserializes");

        assert_eq!(decoded.diagnostics(), Some(&diagnostics));
    }

    #[test]
    fn an_error_encoded_before_diagnostics_existed_still_decodes() {
        let decoded: AtlassianError =
            serde_json::from_str(r#"{"JiraApi":{"message":"boom","code":500}}"#)
                .expect("the added field is defaulted, not required");

        assert!(decoded.diagnostics().is_none());
    }

    #[test]
    fn a_server_error_is_still_classified_as_non_retryable() {
        // Not an endorsement: the transport routes every 5xx into `JiraApi`, which
        // `is_retryable` does not match, so nothing about a 500 is retryable today.
        // E1 owns that fix and flips this assertion; pinning it here keeps the gap
        // visible rather than implied.
        let (error, _) = mapped(
            ResponseTemplate::new(500),
            jira_rest(DiagnosticsPolicy::MetadataOnly),
        );

        assert!(matches!(error, AtlassianError::JiraApi { .. }));
        assert!(!error.is_retryable());
        assert_eq!(
            error.status_code(),
            None,
            "`status_code` only reads the `Http` variant"
        );
    }
}
