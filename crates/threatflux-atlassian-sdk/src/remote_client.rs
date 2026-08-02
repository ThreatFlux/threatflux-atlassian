//! Legacy Atlassian Remote MCP client implementation.
//!
//! This module is retained for API compatibility and migration assessment. It targets
//! `https://mcp.atlassian.com/v1/sse`, which Atlassian stopped supporting after
//! June 30, 2026. It does not implement the current Streamable HTTP transport and is
//! not usable with today's Atlassian Rovo MCP service.

use crate::auth::{AccessToken, McpAuthHandler};
use crate::error::{AtlassianError, Result};
use crate::types::{IssueSearchResult, JiraIssue, JiraUser, Project};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use url::Url;

/// Legacy Remote MCP client that is incompatible with Atlassian's current service.
///
/// The client does not start an OAuth callback listener or persist tokens. Prefer the
/// direct [`crate::AtlassianClient`] for supported SDK use.
#[derive(Debug)]
pub struct AtlassianRemoteClient {
    /// HTTP client for MCP requests
    client: Client,
    /// MCP server endpoint
    mcp_endpoint: Url,
    /// OAuth authentication handler
    auth_handler: Arc<RwLock<McpAuthHandler>>,
}

/// MCP request wrapper
#[derive(Debug, serde::Serialize)]
struct McpRequest {
    /// JSON-RPC version
    jsonrpc: String,
    /// Request ID
    id: u64,
    /// Method name
    method: String,
    /// Request parameters
    params: Option<Value>,
}

/// MCP response wrapper
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct McpResponse {
    /// JSON-RPC version
    jsonrpc: String,
    /// Request ID
    id: u64,
    /// Response result
    result: Option<Value>,
    /// Error information
    error: Option<McpError>,
}

/// MCP error information
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct McpError {
    /// Error code
    code: i32,
    /// Error message
    message: String,
    /// Additional error data
    data: Option<Value>,
}

impl AtlassianRemoteClient {
    /// Create a client for the legacy, retired Remote MCP endpoint.
    ///
    /// # Arguments
    /// * `client_id` - OAuth client ID for Atlassian
    /// * `callback_port` - Port embedded in the redirect URI; no callback server is started
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianRemoteClient;
    ///
    /// # tokio_test::block_on(async {
    /// let client = AtlassianRemoteClient::new(
    ///     "your-oauth-client-id".to_string(),
    ///     8080
    /// ).unwrap();
    /// # });
    /// ```
    pub fn new(client_id: String, callback_port: u16) -> Result<Self> {
        let client = Client::builder().no_proxy().build().map_err(|err| {
            AtlassianError::config(format!(
                "Failed to create HTTP client for Atlassian Remote MCP: {err}"
            ))
        })?;
        let mcp_endpoint = Url::parse("https://mcp.atlassian.com/v1/sse")?;

        let auth_handler = McpAuthHandler::new(client_id.clone(), callback_port)?;
        let auth_handler = Arc::new(RwLock::new(auth_handler));

        Ok(AtlassianRemoteClient {
            client,
            mcp_endpoint,
            auth_handler,
        })
    }

    /// Generate the legacy authorization response.
    ///
    /// This returns an authorization URL but does not open a browser or start a callback
    /// listener. The flow targets the retired Remote MCP implementation.
    pub async fn initialize_auth(&self) -> Result<Value> {
        info!("Initializing Atlassian OAuth authentication");

        let mut auth_handler = self.auth_handler.write().await;
        auth_handler.generate_auth_response().await
    }

    /// Complete the legacy OAuth flow with a caller-supplied authorization code and state.
    pub async fn complete_auth(&self, code: String, state: Option<String>) -> Result<AccessToken> {
        info!("Completing OAuth authorization flow");

        let mut auth_handler = self.auth_handler.write().await;
        auth_handler.process_callback(code, state).await
    }

    /// Check whether a non-expired in-memory access token is present.
    pub async fn is_authenticated(&self) -> bool {
        let auth_handler = self.auth_handler.read().await;
        !auth_handler.needs_reauth().await
    }

    /// Make authenticated MCP request to Atlassian Remote Server
    async fn make_mcp_request(&self, method: &str, params: Option<Value>) -> Result<Value> {
        // Check authentication
        if !self.is_authenticated().await {
            return Err(AtlassianError::auth(
                "Not authenticated with Atlassian. Call initialize_auth() first.",
            ));
        }

        // Get auth header
        let auth_header = {
            let auth_handler = self.auth_handler.read().await;
            auth_handler
                .get_auth_header()
                .await
                .ok_or_else(|| AtlassianError::auth("No valid access token"))?
        };

        // Create MCP request
        let request_id = rand::random::<u64>();
        let mcp_request = McpRequest {
            jsonrpc: "2.0".to_string(),
            id: request_id,
            method: method.to_string(),
            params,
        };

        debug!("Making MCP request to {}: {}", self.mcp_endpoint, method);

        // Send request to Atlassian Remote MCP Server
        let response = self
            .client
            .post(self.mcp_endpoint.as_str())
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .json(&mcp_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();

            return Err(match status.as_u16() {
                401 => AtlassianError::auth("Authentication failed - token may be expired"),
                403 => AtlassianError::PermissionDenied {
                    message: "Insufficient permissions for Atlassian resources".to_string(),
                },
                429 => AtlassianError::RateLimit {
                    message: "Rate limit exceeded".to_string(),
                },
                _ => AtlassianError::http(
                    format!("MCP request failed: {error_text}"),
                    Some(status.as_u16()),
                ),
            });
        }

        let mcp_response: McpResponse = response.json().await?;

        // Check for MCP-level errors
        if let Some(error) = mcp_response.error {
            return Err(AtlassianError::jira_api(
                format!("MCP error: {} (code: {})", error.message, error.code),
                Some(error.code),
            ));
        }

        mcp_response
            .result
            .ok_or_else(|| AtlassianError::parse("No result in MCP response".to_string()))
    }

    /// Send the legacy, currently unsupported payload for reading a Jira issue.
    ///
    /// # Arguments
    /// * `issue_key` - Issue key (e.g., "PROJ-123")
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianRemoteClient;
    ///
    /// # tokio_test::block_on(async {
    /// let client = AtlassianRemoteClient::new("client-id".to_string(), 8080).unwrap();
    /// // Complete auth flow first...
    /// let issue = client.get_issue("PROJ-123").await.unwrap();
    /// # });
    /// ```
    pub async fn get_issue(&self, issue_key: &str) -> Result<JiraIssue> {
        info!("Getting Jira issue via Remote MCP: {}", issue_key);

        let params = serde_json::json!({
            "resource": "jira_issue",
            "issue_key": issue_key,
            "expand": ["changelog", "renderedFields"]
        });

        let result = self
            .make_mcp_request("resources/read", Some(params))
            .await?;

        // Parse the result as JiraIssue
        serde_json::from_value(result)
            .map_err(|e| AtlassianError::parse(format!("Failed to parse issue response: {e}")))
    }

    /// Send the legacy, currently unsupported payload for updating a Jira issue.
    ///
    /// # Arguments
    /// * `issue_key` - Issue key to update
    /// * `fields` - Fields to update
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianRemoteClient;
    /// use std::collections::HashMap;
    ///
    /// # tokio_test::block_on(async {
    /// let client = AtlassianRemoteClient::new("client-id".to_string(), 8080).unwrap();
    /// // Complete auth flow first...
    ///
    /// let mut fields = HashMap::new();
    /// fields.insert("summary".to_string(), serde_json::Value::String("Updated summary".to_string()));
    /// client.update_issue("PROJ-123", fields).await.unwrap();
    /// # });
    /// ```
    pub async fn update_issue(
        &self,
        issue_key: &str,
        fields: HashMap<String, Value>,
    ) -> Result<()> {
        info!("Updating Jira issue via Remote MCP: {}", issue_key);

        let params = serde_json::json!({
            "resource": "jira_issue",
            "issue_key": issue_key,
            "operation": "update",
            "fields": fields
        });

        self.make_mcp_request("resources/write", Some(params))
            .await?;
        info!("Successfully updated issue: {}", issue_key);
        Ok(())
    }

    /// Send the legacy, currently unsupported payload for searching Jira issues.
    ///
    /// # Arguments
    /// * `jql` - Jira Query Language string
    /// * `max_results` - Maximum results to return
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianRemoteClient;
    ///
    /// # tokio_test::block_on(async {
    /// let client = AtlassianRemoteClient::new("client-id".to_string(), 8080).unwrap();
    /// // Complete auth flow first...
    ///
    /// let results = client.search_issues("project = TEST", 50).await.unwrap();
    /// # });
    /// ```
    pub async fn search_issues(&self, jql: &str, max_results: u32) -> Result<IssueSearchResult> {
        info!("Searching Jira issues via Remote MCP: {}", jql);

        let params = serde_json::json!({
            "resource": "jira_search",
            "jql": jql,
            "maxResults": max_results,
            "expand": ["changelog"]
        });

        let result = self
            .make_mcp_request("resources/search", Some(params))
            .await?;

        serde_json::from_value(result)
            .map_err(|e| AtlassianError::parse(format!("Failed to parse search response: {e}")))
    }

    /// Send the legacy, currently unsupported payload for reading the current user.
    pub async fn get_myself(&self) -> Result<JiraUser> {
        info!("Getting current user via Remote MCP");

        let params = serde_json::json!({
            "resource": "current_user"
        });

        let result = self
            .make_mcp_request("resources/read", Some(params))
            .await?;

        serde_json::from_value(result)
            .map_err(|e| AtlassianError::parse(format!("Failed to parse user response: {e}")))
    }

    /// Send the legacy, currently unsupported payload for listing projects.
    pub async fn get_projects(&self) -> Result<Vec<Project>> {
        info!("Getting accessible projects via Remote MCP");

        let params = serde_json::json!({
            "resource": "jira_projects"
        });

        let result = self
            .make_mcp_request("resources/list", Some(params))
            .await?;

        serde_json::from_value(result)
            .map_err(|e| AtlassianError::parse(format!("Failed to parse projects response: {e}")))
    }

    /// Send the legacy, currently unsupported payload for updating story points.
    pub async fn update_story_points(
        &self,
        issue_key: &str,
        story_points: f64,
        story_points_field_id: &str,
    ) -> Result<()> {
        info!(
            "Updating story points for {} to {} via Remote MCP",
            issue_key, story_points
        );

        let mut fields = HashMap::new();
        fields.insert(
            story_points_field_id.to_string(),
            Value::Number(serde_json::Number::from_f64(story_points).unwrap()),
        );

        self.update_issue(issue_key, fields).await
    }

    /// Send the legacy, currently unsupported payload for updating a custom field.
    pub async fn update_custom_field(
        &self,
        issue_key: &str,
        field_id: &str,
        value: &str,
    ) -> Result<()> {
        info!(
            "Updating custom field {} for {} to {} via Remote MCP",
            field_id, issue_key, value
        );

        let mut fields = HashMap::new();
        fields.insert(field_id.to_string(), serde_json::json!({"value": value}));

        self.update_issue(issue_key, fields).await
    }

    /// Send the legacy, currently unsupported payload for creating a Jira issue.
    pub async fn create_issue(
        &self,
        summary: &str,
        project_key: &str,
        issue_type: &str,
    ) -> Result<JiraIssue> {
        info!("Creating Jira issue via Remote MCP: {}", summary);

        let params = serde_json::json!({
            "resource": "jira_issue",
            "operation": "create",
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "issuetype": {"name": issue_type}
            }
        });

        let result = self
            .make_mcp_request("resources/write", Some(params))
            .await?;

        serde_json::from_value(result).map_err(|e| {
            AtlassianError::parse(format!("Failed to parse created issue response: {e}"))
        })
    }

    /// Attempt a health check against the legacy, retired Remote MCP endpoint.
    pub async fn health_check(&self) -> Result<bool> {
        info!("Performing health check for Atlassian Remote MCP Server");

        if !self.is_authenticated().await {
            warn!("Not authenticated - health check will trigger auth flow");
            return Ok(false);
        }

        // Try to get current user as a simple connectivity test
        match self.get_myself().await {
            Ok(user) => {
                info!(
                    "Health check passed - connected as: {}",
                    user.display_name.unwrap_or_default()
                );
                Ok(true)
            }
            Err(e) => {
                error!("Health check failed: {}", e);
                Err(e)
            }
        }
    }

    /// Send the legacy, currently unsupported payload for listing MCP tools.
    pub async fn list_tools(&self) -> Result<Vec<Value>> {
        info!("Listing available MCP tools from Atlassian Remote Server");

        let result = self.make_mcp_request("tools/list", None).await?;

        if let Value::Object(obj) = result {
            if let Some(Value::Array(tools)) = obj.get("tools") {
                Ok(tools.clone())
            } else {
                Ok(vec![])
            }
        } else {
            Ok(vec![])
        }
    }

    /// Send the legacy, currently unsupported payload for calling an MCP tool.
    pub async fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<Value> {
        info!(
            "Calling MCP tool '{}' on Atlassian Remote Server",
            tool_name
        );

        let params = serde_json::json!({
            "name": tool_name,
            "arguments": arguments
        });

        self.make_mcp_request("tools/call", Some(params)).await
    }

    /// Construct the legacy, unverified Jira tool payload.
    pub async fn jira_operation(
        &self,
        operation: &str,
        issue_key: Option<&str>,
        params: Value,
    ) -> Result<Value> {
        info!("Performing Jira operation '{}' via MCP", operation);

        let mut tool_args = serde_json::Map::new();
        tool_args.insert(
            "operation".to_string(),
            Value::String(operation.to_string()),
        );

        if let Some(key) = issue_key {
            tool_args.insert("issue_key".to_string(), Value::String(key.to_string()));
        }

        // Merge additional parameters
        if let Value::Object(param_map) = params {
            for (key, value) in param_map {
                tool_args.insert(key, value);
            }
        }

        self.call_tool("jira", Value::Object(tool_args)).await
    }

    /// Construct the legacy, unverified Confluence tool payload.
    pub async fn confluence_operation(&self, operation: &str, params: Value) -> Result<Value> {
        info!("Performing Confluence operation '{}' via MCP", operation);

        let mut tool_args = serde_json::Map::new();
        tool_args.insert(
            "operation".to_string(),
            Value::String(operation.to_string()),
        );

        if let Value::Object(param_map) = params {
            for (key, value) in param_map {
                tool_args.insert(key, value);
            }
        }

        self.call_tool("confluence", Value::Object(tool_args)).await
    }

    /// Construct the legacy, unverified Compass tool payload.
    pub async fn compass_operation(&self, operation: &str, params: Value) -> Result<Value> {
        info!("Performing Compass operation '{}' via MCP", operation);

        let mut tool_args = serde_json::Map::new();
        tool_args.insert(
            "operation".to_string(),
            Value::String(operation.to_string()),
        );

        if let Value::Object(param_map) = params {
            for (key, value) in param_map {
                tool_args.insert(key, value);
            }
        }

        self.call_tool("compass", Value::Object(tool_args)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_client_creation() {
        let client = AtlassianRemoteClient::new("test-client-id".to_string(), 8080);
        assert!(client.is_ok());
    }

    #[test]
    fn test_mcp_request_serialization() {
        let request = McpRequest {
            jsonrpc: "2.0".to_string(),
            id: 123,
            method: "tools/list".to_string(),
            params: Some(serde_json::json!({"test": "value"})),
        };

        let serialized = serde_json::to_string(&request);
        assert!(serialized.is_ok());
    }

    #[test]
    fn test_mcp_response_deserialization() {
        let response_json = r#"{
            "jsonrpc": "2.0",
            "id": 123,
            "result": {"tools": []}
        }"#;

        let response: McpResponse = serde_json::from_str(response_json).unwrap();
        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, 123);
        assert!(response.result.is_some());
    }
}
