//! Jira API client implementation
//!
//! This module provides the main AtlassianClient for interacting with Jira APIs,
//! including authentication, ticket operations, and project management.

use crate::config::AtlassianConfig;
use crate::error::{AtlassianError, Result};
use crate::types::{
    CreateIssueRequest, IssueSearchResult, IssueTransition, IssueTransitionsResponse, JiraField,
    JiraIssue, JiraUser, Project, UpdateIssueRequest,
};
use base64::prelude::*;
use reqwest::{Certificate, Client, ClientBuilder, Method, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use tracing::{debug, error, info, warn};

/// Main client for Atlassian/Jira API operations
#[derive(Debug)]
pub struct AtlassianClient {
    /// HTTP client for making requests
    client: Client,
    /// Configuration settings
    config: AtlassianConfig,
}

impl AtlassianClient {
    /// Create a new Atlassian client
    ///
    /// # Arguments
    /// * `config` - Configuration with Jira URL, credentials, and settings
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::{AtlassianClient, AtlassianConfig};
    ///
    /// # tokio_test::block_on(async {
    /// let config = AtlassianConfig::new(
    ///     "https://company.atlassian.net".to_string(),
    ///     "user@company.com".to_string(),
    ///     "api-token".to_string()
    /// ).unwrap();
    /// let client = AtlassianClient::new(config).unwrap();
    /// # });
    /// ```
    pub fn new(config: AtlassianConfig) -> Result<Self> {
        config.validate()?;

        let mut client_builder = ClientBuilder::new()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .no_proxy();

        // Handle SSL certificate configuration
        if !config.verify_ssl {
            warn!("SSL verification is disabled - not recommended for production");
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        // Handle custom certificate if provided
        if let Some(cert_path) = &config.cert_path {
            if cert_path.exists() {
                info!("Loading custom certificate from: {}", cert_path.display());
                let cert_data = fs::read(cert_path).map_err(|e| {
                    AtlassianError::config(format!("Failed to read certificate file: {e}"))
                })?;

                let cert = Certificate::from_pem(&cert_data)
                    .or_else(|_| Certificate::from_der(&cert_data))
                    .map_err(|e| {
                        AtlassianError::config(format!("Failed to parse certificate: {e}"))
                    })?;

                client_builder = client_builder.add_root_certificate(cert);
            }
        }

        let client = client_builder
            .build()
            .map_err(|e| AtlassianError::config(format!("Failed to create HTTP client: {e}")))?;

        Ok(AtlassianClient { client, config })
    }

    /// Create client from environment variables
    pub fn from_env() -> Result<Self> {
        let config = AtlassianConfig::from_env()?;
        Self::new(config)
    }

    /// Make an authenticated HTTP request to the Jira API
    async fn make_request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<&Value>,
        query_params: Option<&HashMap<String, String>>,
    ) -> Result<Response> {
        let url = if endpoint.starts_with('/') {
            format!("{}{}", self.config.base_url, endpoint)
        } else {
            format!("{}/{}", self.config.base_url, endpoint)
        };

        debug!("Making {} request to: {}", method, url);

        // Create basic auth header with username and API token
        let auth = base64::prelude::BASE64_STANDARD.encode(format!(
            "{}:{}",
            self.config.username, self.config.api_token
        ));
        let auth_header = format!("Basic {auth}");

        let mut request = self
            .client
            .request(method, &url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");

        if let Some(params) = query_params {
            request = request.query(params);
        }

        if let Some(json_body) = body {
            request = request.json(json_body);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!(
                "Jira API request failed with status {}: {}",
                status, error_text
            );

            // Handle specific HTTP status codes
            return Err(match status.as_u16() {
                401 => AtlassianError::auth("Invalid credentials or API token"),
                403 => AtlassianError::PermissionDenied {
                    message: "Insufficient permissions for this operation".to_string(),
                },
                404 => AtlassianError::NotFound {
                    message: "Resource not found".to_string(),
                },
                429 => AtlassianError::RateLimit {
                    message: "Rate limit exceeded".to_string(),
                },
                _ => AtlassianError::jira_api(
                    format!("API request failed: {}", error_text),
                    Some(status.as_u16() as i32),
                ),
            });
        }

        Ok(response)
    }

    /// Get issue by key or ID
    ///
    /// # Arguments
    /// * `issue_key` - Issue key (e.g., "PROJ-123") or ID
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let issue = client.get_issue("PROJ-123").await.unwrap();
    /// println!("Issue: {} - {}", issue.key, issue.fields.summary);
    /// # });
    /// ```
    pub async fn get_issue(&self, issue_key: &str) -> Result<JiraIssue> {
        info!("Getting issue: {}", issue_key);

        let endpoint = format!("/rest/api/2/issue/{}", issue_key);
        let response = self
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let issue: JiraIssue = response.json().await?;
        debug!("Retrieved issue: {} - {}", issue.key, issue.fields.summary);

        Ok(issue)
    }

    /// Update issue fields
    ///
    /// # Arguments
    /// * `issue_key` - Issue key or ID to update
    /// * `fields` - Fields to update as key-value pairs
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use std::collections::HashMap;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let mut fields = HashMap::new();
    /// fields.insert("summary".to_string(), serde_json::Value::String("Updated summary".to_string()));
    ///
    /// client.update_issue("PROJ-123", fields).await.unwrap();
    /// # });
    /// ```
    pub async fn update_issue(
        &self,
        issue_key: &str,
        fields: HashMap<String, Value>,
    ) -> Result<()> {
        info!("Updating issue: {} with {} fields", issue_key, fields.len());

        let endpoint = format!("/rest/api/2/issue/{}", issue_key);
        let update_request = UpdateIssueRequest { fields };
        let body = serde_json::to_value(&update_request)?;

        let response = self
            .make_request(Method::PUT, &endpoint, Some(&body), None)
            .await?;

        // Jira returns 204 No Content for successful updates
        if response.status().as_u16() == 204 {
            info!("Successfully updated issue: {}", issue_key);
            Ok(())
        } else {
            Err(AtlassianError::jira_api(
                format!("Unexpected response status: {}", response.status()),
                Some(response.status().as_u16() as i32),
            ))
        }
    }

    /// Create a new issue
    ///
    /// # Arguments
    /// * `request` - Issue creation request with all required fields
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::{AtlassianClient, CreateIssueRequest, CreateIssueFields};
    /// use threatflux_atlassian_sdk::{ProjectReference, IssueTypeReference};
    /// use std::collections::HashMap;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let request = CreateIssueRequest {
    ///     fields: CreateIssueFields {
    ///         project: ProjectReference::by_key("TEST"),
    ///         summary: "New issue".to_string(),
    ///         issue_type: IssueTypeReference::by_name("Task"),
    ///         description: Some("Issue description".to_string()),
    ///         assignee: None,
    ///         priority: None,
    ///         labels: None,
    ///         components: None,
    ///         parent: None,
    ///         custom_fields: HashMap::new(),
    ///     },
    /// };
    ///
    /// let created_issue = client.create_issue(request).await.unwrap();
    /// # });
    /// ```
    pub async fn create_issue(&self, request: CreateIssueRequest) -> Result<JiraIssue> {
        info!("Creating new issue: {}", request.fields.summary);

        let endpoint = "/rest/api/2/issue";
        let body = serde_json::to_value(&request)?;

        let response = self
            .make_request(Method::POST, endpoint, Some(&body), None)
            .await?;

        let created_issue: JiraIssue = response.json().await?;
        info!("Successfully created issue: {}", created_issue.key);

        Ok(created_issue)
    }

    /// Search for issues using JQL
    ///
    /// # Arguments
    /// * `jql` - Jira Query Language string
    /// * `start_at` - Index of first result (for pagination)
    /// * `max_results` - Maximum number of results to return
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let results = client.search_issues(
    ///     "project = TEST AND status = 'To Do'",
    ///     0,
    ///     50
    /// ).await.unwrap();
    ///
    /// for issue in results.issues {
    ///     println!("{}: {}", issue.key, issue.fields.summary);
    /// }
    /// # });
    /// ```
    pub async fn search_issues(
        &self,
        jql: &str,
        start_at: u32,
        max_results: u32,
    ) -> Result<IssueSearchResult> {
        info!("Searching issues with JQL: {}", jql);

        let endpoint = "/rest/api/2/search";
        let mut params = HashMap::new();
        params.insert("jql".to_string(), jql.to_string());
        params.insert("startAt".to_string(), start_at.to_string());
        params.insert("maxResults".to_string(), max_results.to_string());

        let response = self
            .make_request(Method::GET, endpoint, None, Some(&params))
            .await?;

        let search_result: IssueSearchResult = response.json().await?;
        info!(
            "Found {} issues (showing {} from index {})",
            search_result.total,
            search_result.issues.len(),
            search_result.start_at
        );

        Ok(search_result)
    }

    /// Get current user information
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let user = client.get_myself().await.unwrap();
    /// println!("Current user: {}", user.display_name.unwrap_or_default());
    /// # });
    /// ```
    pub async fn get_myself(&self) -> Result<JiraUser> {
        info!("Getting current user information");

        let endpoint = "/rest/api/2/myself";
        let response = self.make_request(Method::GET, endpoint, None, None).await?;

        let user: JiraUser = response.json().await?;
        debug!("Current user: {:?}", user.display_name);

        Ok(user)
    }

    /// Get all projects accessible to the current user
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let projects = client.get_projects().await.unwrap();
    /// for project in projects {
    ///     println!("Project: {} ({})", project.name, project.key);
    /// }
    /// # });
    /// ```
    pub async fn get_projects(&self) -> Result<Vec<Project>> {
        info!("Getting accessible projects");

        let endpoint = "/rest/api/2/project";
        let response = self.make_request(Method::GET, endpoint, None, None).await?;

        let projects: Vec<Project> = response.json().await?;
        info!("Retrieved {} projects", projects.len());

        Ok(projects)
    }

    /// Get project by key or ID
    ///
    /// # Arguments
    /// * `project_key` - Project key (e.g., "PROJ") or ID
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let project = client.get_project("TEST").await.unwrap();
    /// println!("Project: {} - {}", project.key, project.name);
    /// # });
    /// ```
    pub async fn get_project(&self, project_key: &str) -> Result<Project> {
        info!("Getting project: {}", project_key);

        let endpoint = format!("/rest/api/2/project/{}", project_key);
        let response = self
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let project: Project = response.json().await?;
        debug!("Retrieved project: {} - {}", project.key, project.name);

        Ok(project)
    }

    /// Get all fields (including custom fields)
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let fields = client.get_fields().await.unwrap();
    /// for field in fields {
    ///     if field.custom {
    ///         println!("Custom field: {} ({})", field.name, field.id);
    ///     }
    /// }
    /// # });
    /// ```
    pub async fn get_fields(&self) -> Result<Vec<JiraField>> {
        info!("Getting all Jira fields");

        let endpoint = "/rest/api/2/field";
        let response = self.make_request(Method::GET, endpoint, None, None).await?;

        let fields: Vec<JiraField> = response.json().await?;
        info!("Retrieved {} fields", fields.len());

        Ok(fields)
    }

    /// Update issue with story points (common operation from Python examples)
    ///
    /// # Arguments
    /// * `issue_key` - Issue key to update
    /// * `story_points` - Story points value
    /// * `story_points_field_id` - Custom field ID for story points (e.g., "customfield_10100")
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// client.update_story_points("PROJ-123", 5.0, "customfield_10100").await.unwrap();
    /// # });
    /// ```
    pub async fn update_story_points(
        &self,
        issue_key: &str,
        story_points: f64,
        story_points_field_id: &str,
    ) -> Result<()> {
        info!(
            "Updating story points for {} to {}",
            issue_key, story_points
        );

        let mut fields = HashMap::new();
        fields.insert(
            story_points_field_id.to_string(),
            serde_json::Value::Number(serde_json::Number::from_f64(story_points).unwrap()),
        );

        self.update_issue(issue_key, fields).await
    }

    /// Update issue with custom field value (like improvement area from Python examples)
    ///
    /// # Arguments
    /// * `issue_key` - Issue key to update
    /// * `field_id` - Custom field ID (e.g., "customfield_11024")
    /// * `value` - Field value
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// client.update_custom_field("PROJ-123", "customfield_11024", "Security").await.unwrap();
    /// # });
    /// ```
    pub async fn update_custom_field(
        &self,
        issue_key: &str,
        field_id: &str,
        value: &str,
    ) -> Result<()> {
        info!(
            "Updating custom field {} for {} to {}",
            field_id, issue_key, value
        );

        let mut fields = HashMap::new();
        fields.insert(field_id.to_string(), serde_json::json!({ "value": value }));

        self.update_issue(issue_key, fields).await
    }

    /// Retrieve the list of workflow transitions available for an issue
    pub async fn get_issue_transitions(&self, issue_key: &str) -> Result<Vec<IssueTransition>> {
        info!("Fetching transitions for issue: {}", issue_key);

        let endpoint = format!("/rest/api/2/issue/{}/transitions", issue_key);
        let response = self
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let payload: IssueTransitionsResponse = response.json().await.map_err(|err| {
            AtlassianError::parse(format!(
                "Failed to parse transition list for {}: {}",
                issue_key, err
            ))
        })?;

        info!(
            "Issue {} has {} available transitions",
            issue_key,
            payload.transitions.len()
        );

        Ok(payload.transitions)
    }

    /// Execute a workflow transition on an issue using a transition id
    pub async fn transition_issue(
        &self,
        issue_key: &str,
        transition_id: &str,
        comment: Option<&str>,
    ) -> Result<()> {
        info!(
            "Transitioning issue {} using transition id {}",
            issue_key, transition_id
        );

        let endpoint = format!("/rest/api/2/issue/{}/transitions", issue_key);
        let mut payload = json!({
            "transition": { "id": transition_id }
        });

        if let Some(comment_text) = comment.and_then(|c| {
            let trimmed = c.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }) {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "update".to_string(),
                    json!({
                        "comment": [
                            {
                                "add": {
                                    "body": comment_text
                                }
                            }
                        ]
                    }),
                );
            }
        }

        let response = self
            .make_request(Method::POST, &endpoint, Some(&payload), None)
            .await?;

        if response.status().is_success() {
            info!("Successfully transitioned issue {}", issue_key);
            Ok(())
        } else {
            let status = response.status();
            error!(
                "Failed to transition issue {} with status {}",
                issue_key, status
            );
            Err(AtlassianError::jira_api(
                format!(
                    "Failed to transition issue {} (HTTP status {})",
                    issue_key, status
                ),
                Some(status.as_u16() as i32),
            ))
        }
    }

    /// Execute a workflow transition on an issue by transition name (case-insensitive)
    pub async fn transition_issue_by_name(
        &self,
        issue_key: &str,
        transition_name: &str,
        comment: Option<&str>,
    ) -> Result<()> {
        info!(
            "Transitioning issue {} using transition name {}",
            issue_key, transition_name
        );

        let transitions = self.get_issue_transitions(issue_key).await?;
        let transition = transitions
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(transition_name.trim()));

        match transition {
            Some(match_transition) => {
                self.transition_issue(issue_key, &match_transition.id, comment)
                    .await
            }
            None => {
                let available: Vec<String> = transitions.into_iter().map(|t| t.name).collect();
                error!(
                    "Transition {} not available for {}. Available transitions: {:?}",
                    transition_name, issue_key, available
                );
                Err(AtlassianError::validation(format!(
                    "Transition '{}' is not available for issue {}. Available transitions: {}",
                    transition_name,
                    issue_key,
                    available.join(", ")
                )))
            }
        }
    }

    /// Get issues for a specific project
    ///
    /// # Arguments
    /// * `project_key` - Project key (e.g., "PROJ")
    /// * `limit` - Maximum number of results
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let issues = client.get_project_issues("TEST", 50).await.unwrap();
    /// println!("Found {} issues in project TEST", issues.len());
    /// # });
    /// ```
    pub async fn get_project_issues(
        &self,
        project_key: &str,
        limit: u32,
    ) -> Result<Vec<JiraIssue>> {
        let jql = format!("project = {}", project_key);
        let search_result = self.search_issues(&jql, 0, limit).await?;
        Ok(search_result.issues)
    }

    /// Test connectivity and authentication
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let is_healthy = client.health_check().await.unwrap();
    /// println!("Jira connection healthy: {}", is_healthy);
    /// # });
    /// ```
    pub async fn health_check(&self) -> Result<bool> {
        info!("Performing Jira health check");

        match self.get_myself().await {
            Ok(user) => {
                info!(
                    "Health check passed - authenticated as: {}",
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

    /// Find custom field ID by name
    ///
    /// # Arguments
    /// * `field_name` - Name of the custom field to find
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// if let Some(field_id) = client.find_custom_field_id("Story Points").await.unwrap() {
    ///     println!("Story Points field ID: {}", field_id);
    /// }
    /// # });
    /// ```
    pub async fn find_custom_field_id(&self, field_name: &str) -> Result<Option<String>> {
        let fields = self.get_fields().await?;

        for field in fields {
            if field.name.to_lowercase() == field_name.to_lowercase() && field.custom {
                return Ok(Some(field.id));
            }
        }

        Ok(None)
    }
}

// Implement Clone for AtlassianClient to support Arc usage
impl Clone for AtlassianClient {
    fn clone(&self) -> Self {
        AtlassianClient {
            client: self.client.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_config() -> AtlassianConfig {
        AtlassianConfig::new(
            "https://test.atlassian.net".to_string(),
            "test@example.com".to_string(),
            "test-token".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn test_client_creation() {
        let config = create_test_config();
        let client = AtlassianClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_clone() {
        let config = create_test_config();
        let client = AtlassianClient::new(config).unwrap();
        let cloned_client = client.clone();

        assert_eq!(client.config.base_url, cloned_client.config.base_url);
        assert_eq!(client.config.username, cloned_client.config.username);
    }

    #[test]
    fn test_config_with_custom_settings() {
        let config = AtlassianConfig::new(
            "https://test.atlassian.net".to_string(),
            "test@example.com".to_string(),
            "test-token".to_string(),
        )
        .unwrap()
        .with_timeout(Duration::from_secs(30))
        .with_ssl_verification(false);

        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(!config.verify_ssl);
    }
}
