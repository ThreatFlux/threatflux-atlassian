//! Error handling for the Atlassian Rust SDK
//!
//! This module provides comprehensive error types for all Atlassian API operations,
//! including Jira authentication, ticket operations, and HTTP communication errors.

use serde::{Deserialize, Serialize};

/// Result type alias for SDK operations
pub type Result<T> = std::result::Result<T, AtlassianError>;

/// Comprehensive error types for Atlassian SDK operations
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum AtlassianError {
    /// HTTP request errors with optional status codes
    #[error("HTTP error: {message}")]
    Http {
        /// Human-readable error description
        message: String,
        /// HTTP status code returned by Atlassian, when available
        status_code: Option<u16>,
    },

    /// Authentication and authorization errors
    #[error("Authentication error: {message}")]
    Authentication {
        /// Reason the authentication attempt failed
        message: String,
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
}

impl AtlassianError {
    /// Create a new HTTP error
    pub fn http(message: impl Into<String>, status_code: Option<u16>) -> Self {
        AtlassianError::Http {
            message: message.into(),
            status_code,
        }
    }

    /// Create a new authentication error
    pub fn auth(message: impl Into<String>) -> Self {
        AtlassianError::Authentication {
            message: message.into(),
        }
    }

    /// Create a new parse error
    pub fn parse(message: impl Into<String>) -> Self {
        AtlassianError::Parse {
            message: message.into(),
        }
    }

    /// Create a new configuration error
    pub fn config(message: impl Into<String>) -> Self {
        AtlassianError::Configuration {
            message: message.into(),
        }
    }

    /// Create a new Jira API error
    pub fn jira_api(message: impl Into<String>, code: Option<i32>) -> Self {
        AtlassianError::JiraApi {
            message: message.into(),
            code,
        }
    }

    /// Create a new validation error
    pub fn validation(message: impl Into<String>) -> Self {
        AtlassianError::Validation {
            message: message.into(),
        }
    }

    /// Check if this is a temporary/retryable error
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AtlassianError::Http { status_code: Some(code), .. } if *code >= 500,
        ) || matches!(self, AtlassianError::Timeout { .. })
            || matches!(self, AtlassianError::RateLimit { .. })
    }

    /// Get the HTTP status code if available
    pub fn status_code(&self) -> Option<u16> {
        match self {
            AtlassianError::Http { status_code, .. } => *status_code,
            _ => None,
        }
    }
}

// Implement conversions from common error types
impl From<reqwest::Error> for AtlassianError {
    fn from(err: reqwest::Error) -> Self {
        let status_code = err.status().map(|s| s.as_u16());
        AtlassianError::Http {
            message: err.to_string(),
            status_code,
        }
    }
}

impl From<serde_json::Error> for AtlassianError {
    fn from(err: serde_json::Error) -> Self {
        AtlassianError::Parse {
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for AtlassianError {
    fn from(err: std::io::Error) -> Self {
        AtlassianError::Io {
            message: err.to_string(),
        }
    }
}

impl From<url::ParseError> for AtlassianError {
    fn from(err: url::ParseError) -> Self {
        AtlassianError::Configuration {
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
        let error = AtlassianError::Authentication {
            message: "Invalid API token".to_string(),
        };
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
