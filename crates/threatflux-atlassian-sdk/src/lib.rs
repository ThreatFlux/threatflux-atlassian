//! # `threatflux-atlassian-sdk`
//!
//! An async Rust client for focused Jira Cloud REST API v2 automation. The supported
//! path is [`AtlassianClient`], which authenticates with an Atlassian account email
//! and API token. It covers common issue, search, comment, assignment, link,
//! attachment, changelog, transition, project, user, and field operations.
//!
//! This independent project is not affiliated with, endorsed by, or sponsored by
//! Atlassian. It is not a complete SDK for Jira, Confluence, Compass, Jira Software,
//! or Jira Service Management.
//!
//! ## Quickstart
//!
//! Set `JIRA_URL`, `JIRA_USERNAME`, and `JIRA_API_TOKEN`, then create a client:
//!
//! ```rust,no_run
//! use threatflux_atlassian_sdk::AtlassianClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = AtlassianClient::from_env()?;
//!     let issue = client.get_issue("KAN-123").await?;
//!     println!("{}: {}", issue.key, issue.fields.summary);
//!     Ok(())
//! }
//! ```
//!
//! The direct client sends Basic authentication to `/rest/api/2` routes below the
//! configured Jira URL. Use an API token, not an account password. See Atlassian's
//! [Basic authentication guidance](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/)
//! before designing a distributable integration.
//!
//! ## Configuration and transport
//!
//! [`AtlassianConfig`] defaults to a 60-second timeout, TLS certificate verification,
//! three stored retry attempts, and a one-second stored retry delay. The retry values
//! are not executed automatically; callers own backoff and write
//! idempotency. A custom PEM or DER root certificate can be added with
//! [`AtlassianConfig::with_cert_path`].
//!
//! The reqwest client uses rustls and disables system proxy discovery. Proxy
//! environment variables are not honored. Disabling certificate verification calls
//! reqwest's dangerous invalid-certificate option and should be limited to controlled
//! local testing.
//!
//! ## Legacy Remote MCP warning
//!
//! [`AtlassianRemoteClient`] is retained for compatibility and migration assessment,
//! but it is not usable with Atlassian's current Rovo MCP service. It hard-codes the
//! retired `https://mcp.atlassian.com/v1/sse` endpoint, does not implement Streamable
//! HTTP, does not host an OAuth callback listener, and keeps tokens only in memory.
//! Atlassian stopped supporting the SSE endpoint after June 30, 2026; consult the
//! [official migration notice](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/configuring-oauth-2-1/).
//!
//! The `direct`, `remote`, and `ssl-verification` Cargo features are compatibility
//! markers and do not gate modules, dependencies, or runtime TLS behavior.

#![allow(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

// Re-export main types for convenience
pub use auth::{AccessToken, AuthManager, AuthorizationResponse, McpAuthHandler, OAuthConfig};
pub use client::AtlassianClient;
pub use config::{AtlassianConfig, AtlassianConfigBuilder};
pub use error::{AtlassianError, Result};
pub use remote_client::AtlassianRemoteClient;
pub use types::*;

// Internal modules
pub mod auth;
pub mod client;
pub mod config;
pub mod error;
pub mod remote_client;
pub mod types;

// Re-export commonly used external types
pub use serde_json::Value as JsonValue;

/// SDK version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default Jira API version
pub const API_VERSION: &str = "2";

/// Get SDK version
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }

    #[test]
    fn test_constants() {
        assert_eq!(API_VERSION, "2");
    }
}
