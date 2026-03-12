//! # Atlassian Rust SDK
//!
//! A comprehensive Rust SDK for Atlassian products with dual architecture support:
//! **Remote MCP Server** (recommended) and **Direct API** access for Jira, Confluence, and Compass.
//!
//! ## Features
//!
//! - **🌐 Remote MCP Server**: OAuth 2.1 authentication via <https://mcp.atlassian.com/v1/sse>
//! - **🔑 OAuth 2.1 + PKCE**: Secure browser-based authentication with MCP auth screen
//! - **📋 Jira Operations**: Complete ticket CRUD, search, custom fields (story points, complexity)
//! - **📖 Confluence**: Content management and documentation operations
//! - **🧭 Compass**: Service landscape and component management
//! - **🔒 Security**: Respects existing Atlassian Cloud permissions and access controls
//! - **⚡ Async Support**: Built on Tokio for high-performance operations
//! - **🏢 Enterprise Ready**: SSL verification and corporate environment support
//!
//! ## Remote MCP Server (Recommended)
//!
//! Use Atlassian's cloud-based Remote MCP Server for secure, permission-respecting operations:
//!
//! ```rust,no_run
//! use threatflux_atlassian_sdk::AtlassianRemoteClient;
//! use std::collections::HashMap;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create Remote MCP client
//!     let client = AtlassianRemoteClient::new(
//!         "your-oauth-client-id".to_string(),
//!         8080  // Local callback port
//!     )?;
//!
//!     // Initialize OAuth 2.1 authentication (shows auth screen)
//!     let auth_response = client.initialize_auth().await?;
//!     println!("Visit auth URL: {}", auth_response["auth_url"]);
//!
//!     // After OAuth completion...
//!     // client.complete_auth(auth_code, state).await?;
//!
//!     // Use Jira operations via Remote MCP Server
//!     let issue = client.get_issue("PROJ-123").await?;
//!     client.update_story_points("PROJ-123", 8.0, "customfield_10100").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Direct API Client (Legacy)
//!
//! For direct Jira API access (requires API tokens):
//!
//! ```rust,no_run
//! use threatflux_atlassian_sdk::{AtlassianClient, AtlassianConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = AtlassianClient::from_env()?;
//!     let issue = client.get_issue("PROJ-123").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## OAuth Configuration
//!
//! For Remote MCP Server (OAuth 2.1):
//!
//! ```bash
//! export ATLASSIAN_CLIENT_ID="your-oauth-client-id"
//! export ATLASSIAN_CALLBACK_PORT="8080"           # Optional: OAuth callback port
//! ```
//!
//! For Direct API (Legacy):
//!
//! ```bash
//! export JIRA_URL="https://company.atlassian.net"
//! export JIRA_USERNAME="user@company.com"
//! export JIRA_API_TOKEN="your-api-token"
//! ```
//!
//! ## Advanced Usage
//!
//! ```rust,no_run
//! use threatflux_atlassian_sdk::{AtlassianConfig, AtlassianClient};
//! use threatflux_atlassian_sdk::{CreateIssueRequest, CreateIssueFields};
//! use threatflux_atlassian_sdk::{ProjectReference, IssueTypeReference, UserReference};
//! use std::time::Duration;
//! use std::collections::HashMap;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create custom configuration
//!     let config = AtlassianConfig::builder()
//!         .base_url("https://company.atlassian.net")
//!         .username("user@company.com")
//!         .api_token("your-api-token")
//!         .timeout(Duration::from_secs(30))
//!         .verify_ssl(true)
//!         .retries(5, Duration::from_millis(500))
//!         .build()?;
//!
//!     let client = AtlassianClient::new(config)?;
//!
//!     // Create a new issue
//!     let mut custom_fields = HashMap::new();
//!     custom_fields.insert("customfield_11024".to_string(),
//!                          serde_json::json!({"value": "Security"}));
//!
//!     let create_request = CreateIssueRequest {
//!         fields: CreateIssueFields {
//!             project: ProjectReference::by_key("TMP"),
//!             summary: "New security task".to_string(),
//!             issue_type: IssueTypeReference::by_name("Task"),
//!             description: Some("Security enhancement task".to_string()),
//!             assignee: Some(UserReference::by_account_id("account123")),
//!             priority: None,
//!             labels: Some(vec!["security".to_string(), "automation".to_string()]),
//!             components: None,
//!             parent: None,
//!             custom_fields,
//!         },
//!     };
//!
//!     let created_issue = client.create_issue(create_request).await?;
//!     println!("Created issue: {}", created_issue.key);
//!
//!     Ok(())
//! }
//! ```

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
