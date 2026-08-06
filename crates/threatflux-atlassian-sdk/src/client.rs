//! Jira API client implementation
//!
//! This module provides the main `AtlassianClient` for interacting with Jira APIs,
//! including authentication, ticket operations, and project management.

use crate::config::AtlassianConfig;
use crate::error::{AtlassianError, Result};
use crate::jql::JqlBuilder;
use crate::types::{
    CreateIssueRequest, IssueSearchResult, IssueTransition, IssueTransitionsResponse, JiraField,
    JiraIssue, JiraUser, Project, UpdateIssueRequest,
};
use base64::prelude::*;
use reqwest::{multipart, Certificate, Client, ClientBuilder, Method, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::fs as tokio_fs;
use tracing::{debug, error, info, warn};

#[derive(Debug, Deserialize)]
struct CreateIssueResponse {
    key: String,
}

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

        Ok(Self { client, config })
    }

    /// Create client from environment variables
    pub fn from_env() -> Result<Self> {
        let config = AtlassianConfig::from_env()?;
        Self::new(config)
    }

    fn authorization_header(&self) -> String {
        let auth = BASE64_STANDARD.encode(format!(
            "{}:{}",
            self.config.username, self.config.api_token
        ));
        format!("Basic {auth}")
    }

    async fn ensure_success(response: Response) -> Result<Response> {
        if response.status().is_success() {
            return Ok(response);
        }

        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        error!(
            "Jira API request failed with status {}: {}",
            status, error_text
        );

        Err(match status.as_u16() {
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
                format!("API request failed: {error_text}"),
                Some(i32::from(status.as_u16())),
            ),
        })
    }

    /// Make an authenticated HTTP request to the Jira API
    async fn make_request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<&Value>,
        query_params: Option<&HashMap<String, String>>,
    ) -> Result<Response> {
        let url = self
            .config
            .base_url
            .join(endpoint.trim_start_matches('/'))?;

        debug!("Making {} request to: {}", method, url);

        let mut request = self
            .client
            .request(method, url)
            .header("Authorization", self.authorization_header())
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");

        if let Some(params) = query_params {
            request = request.query(params);
        }

        if let Some(json_body) = body {
            request = request.json(json_body);
        }

        Self::ensure_success(request.send().await?).await
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

        let endpoint = format!("/rest/api/2/issue/{issue_key}");
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

        let endpoint = format!("/rest/api/2/issue/{issue_key}");
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
                Some(i32::from(response.status().as_u16())),
            ))
        }
    }

    /// Add a standalone comment to an issue without changing workflow state.
    pub async fn add_issue_comment(&self, issue_key: &str, body: &str) -> Result<Value> {
        let body = body.trim();
        if body.is_empty() {
            return Err(AtlassianError::validation("Comment body cannot be empty"));
        }

        info!("Adding comment to issue: {}", issue_key);
        let endpoint = format!("/rest/api/2/issue/{issue_key}/comment");
        let payload = json!({ "body": body });
        let response = self
            .make_request(Method::POST, &endpoint, Some(&payload), None)
            .await?;
        Ok(response.json().await?)
    }

    /// List comments on an issue with Jira pagination.
    pub async fn get_issue_comments(
        &self,
        issue_key: &str,
        start_at: u32,
        max_results: u32,
    ) -> Result<Value> {
        info!("Listing comments for issue: {}", issue_key);
        let endpoint = format!("/rest/api/2/issue/{issue_key}/comment");
        let mut params = HashMap::new();
        params.insert("startAt".to_string(), start_at.to_string());
        params.insert("maxResults".to_string(), max_results.to_string());
        let response = self
            .make_request(Method::GET, &endpoint, None, Some(&params))
            .await?;
        Ok(response.json().await?)
    }

    /// Assign an issue by Atlassian account ID, or unassign it with `None`.
    pub async fn assign_issue(&self, issue_key: &str, account_id: Option<&str>) -> Result<()> {
        let account_id = account_id.map(str::trim).filter(|value| !value.is_empty());
        info!("Updating assignee for issue: {}", issue_key);
        let endpoint = format!("/rest/api/2/issue/{issue_key}/assignee");
        let payload = json!({ "accountId": account_id });
        self.make_request(Method::PUT, &endpoint, Some(&payload), None)
            .await?;
        Ok(())
    }

    /// Search Jira users by display name, email, or other supported query text.
    pub async fn search_users(
        &self,
        query: &str,
        start_at: u32,
        max_results: u32,
    ) -> Result<Vec<JiraUser>> {
        let query = query.trim();
        if query.is_empty() {
            return Err(AtlassianError::validation("User query cannot be empty"));
        }

        info!("Searching Jira users");
        let mut params = HashMap::new();
        params.insert("query".to_string(), query.to_string());
        params.insert("startAt".to_string(), start_at.to_string());
        params.insert("maxResults".to_string(), max_results.to_string());
        let response = self
            .make_request(Method::GET, "/rest/api/2/user/search", None, Some(&params))
            .await?;
        Ok(response.json().await?)
    }

    /// Create an issue link between two Jira issues.
    pub async fn create_issue_link(
        &self,
        link_type: &str,
        inward_issue: &str,
        outward_issue: &str,
    ) -> Result<()> {
        let link_type = link_type.trim();
        if link_type.is_empty() {
            return Err(AtlassianError::validation(
                "Issue link type cannot be empty",
            ));
        }

        info!(
            "Creating {} link from {} to {}",
            link_type, inward_issue, outward_issue
        );
        let payload = json!({
            "type": { "name": link_type },
            "inwardIssue": { "key": inward_issue },
            "outwardIssue": { "key": outward_issue }
        });
        self.make_request(Method::POST, "/rest/api/2/issueLink", Some(&payload), None)
            .await?;
        Ok(())
    }

    /// Delete an issue link by numeric link ID.
    pub async fn delete_issue_link(&self, link_id: &str) -> Result<()> {
        let link_id = link_id.trim();
        if link_id.is_empty() || !link_id.chars().all(|character| character.is_ascii_digit()) {
            return Err(AtlassianError::validation(
                "Issue link ID must contain only digits",
            ));
        }

        info!("Deleting issue link: {}", link_id);
        let endpoint = format!("/rest/api/2/issueLink/{link_id}");
        self.make_request(Method::DELETE, &endpoint, None, None)
            .await?;
        Ok(())
    }

    /// Upload one file as an attachment to an issue.
    pub async fn add_issue_attachment(
        &self,
        issue_key: &str,
        file_path: impl AsRef<Path>,
    ) -> Result<Value> {
        let file_path = file_path.as_ref();
        let file_name = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| AtlassianError::validation("Attachment path has no valid file name"))?;
        let bytes = tokio_fs::read(file_path).await?;
        let part = multipart::Part::bytes(bytes).file_name(file_name.to_string());
        let form = multipart::Form::new().part("file", part);
        let endpoint = format!("/rest/api/2/issue/{issue_key}/attachments");
        let url = self
            .config
            .base_url
            .join(endpoint.trim_start_matches('/'))?;

        info!("Uploading attachment to issue: {}", issue_key);
        let response = self
            .client
            .post(url)
            .header("Authorization", self.authorization_header())
            .header("Accept", "application/json")
            .header("X-Atlassian-Token", "no-check")
            .multipart(form)
            .send()
            .await?;
        let response = Self::ensure_success(response).await?;
        Ok(response.json().await?)
    }

    /// Retrieve an issue's changelog with Jira pagination.
    pub async fn get_issue_changelog(
        &self,
        issue_key: &str,
        start_at: u32,
        max_results: u32,
    ) -> Result<Value> {
        info!("Getting changelog for issue: {}", issue_key);
        let endpoint = format!("/rest/api/2/issue/{issue_key}/changelog");
        let mut params = HashMap::new();
        params.insert("startAt".to_string(), start_at.to_string());
        params.insert("maxResults".to_string(), max_results.to_string());
        let response = self
            .make_request(Method::GET, &endpoint, None, Some(&params))
            .await?;
        Ok(response.json().await?)
    }

    /// Create a new issue and return the key Jira assigned it
    ///
    /// One round trip, and the key comes back in the create response itself, so
    /// nothing that can fail happens between the issue existing and the caller
    /// holding its key. [`create_issue`](Self::create_issue) reads the created
    /// issue back for its fields and can therefore fail *after* the create
    /// succeeded, which leaves an issue live in Jira and returns no key for it;
    /// a caller that only needs the key -- to publish it, link it or log it --
    /// uses this and cannot lose it to a transient 5xx or to a token that may
    /// create but not read.
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
    /// # let request = CreateIssueRequest {
    /// #     fields: CreateIssueFields {
    /// #         project: ProjectReference::by_key("TEST"),
    /// #         summary: "New issue".to_string(),
    /// #         issue_type: IssueTypeReference::by_name("Task"),
    /// #         description: None,
    /// #         assignee: None,
    /// #         priority: None,
    /// #         labels: None,
    /// #         components: None,
    /// #         parent: None,
    /// #         custom_fields: HashMap::new(),
    /// #     },
    /// # };
    /// let issue_key = client.create_issue_key(request).await.unwrap();
    /// println!("created {issue_key}");
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the create request fails or its response cannot be
    /// parsed. An error means no issue was created.
    pub async fn create_issue_key(&self, request: CreateIssueRequest) -> Result<String> {
        info!("Creating new issue: {}", request.fields.summary);

        let endpoint = "/rest/api/2/issue";
        let body = serde_json::to_value(&request)?;

        let response = self
            .make_request(Method::POST, endpoint, Some(&body), None)
            .await?;

        let created_issue: CreateIssueResponse = response.json().await?;
        info!("Successfully created issue: {}", created_issue.key);

        Ok(created_issue.key)
    }

    /// Create a new issue and read it back
    ///
    /// The returned issue is the one Jira stored, with the fields it derived --
    /// id, status, project -- which the create response does not carry. That
    /// second round trip can fail on its own, and then this returns an error for
    /// an issue that exists; the failure names the key so the created issue can
    /// still be found. A caller that needs only the key uses
    /// [`create_issue_key`](Self::create_issue_key), which cannot fail that way.
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
        let issue_key = self.create_issue_key(request).await?;

        self.get_issue(&issue_key).await.inspect_err(|error| {
            error!("Issue {issue_key} was created but could not be read back: {error}");
        })
    }

    /// Search for issues using JQL through Jira's legacy GET search route.
    ///
    /// # Upstream deprecation
    ///
    /// This compatibility helper calls `GET /rest/api/2/search`, which Atlassian
    /// marks as currently being removed. It does not implement enhanced search at
    /// `/rest/api/2/search/jql`; use an implementation of that current endpoint for
    /// new integrations. See Atlassian's
    /// [issue-search reference](https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/).
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

    /// Get projects through Jira's legacy non-paginated project route.
    ///
    /// # Upstream deprecation
    ///
    /// This compatibility helper calls deprecated `GET /rest/api/2/project`.
    /// Atlassian directs new implementations to paginated
    /// `GET /rest/api/2/project/search`, whose response type is not modeled here.
    /// See the
    /// [project endpoint deprecation notice](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-removal-of-get-filters-and-get-all-projects/).
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

        let endpoint = format!("/rest/api/2/project/{project_key}");
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
    /// * `story_points_field_id` - Custom field ID for story points (e.g., "`customfield_10100`")
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
            Self::story_points_json_value(story_points)?,
        );

        self.update_issue(issue_key, fields).await
    }

    fn story_points_json_value(story_points: f64) -> Result<Value> {
        let number = serde_json::Number::from_f64(story_points).ok_or_else(|| {
            AtlassianError::validation(format!(
                "Story points must be a finite number, got {story_points}"
            ))
        })?;

        Ok(Value::Number(number))
    }

    /// Update issue with custom field value (like improvement area from Python examples)
    ///
    /// # Arguments
    /// * `issue_key` - Issue key to update
    /// * `field_id` - Custom field ID (e.g., "`customfield_11024`")
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

        let endpoint = format!("/rest/api/2/issue/{issue_key}/transitions");
        let response = self
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let payload: IssueTransitionsResponse = response.json().await.map_err(|err| {
            AtlassianError::parse(format!(
                "Failed to parse transition list for {issue_key}: {err}"
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

        let endpoint = format!("/rest/api/2/issue/{issue_key}/transitions");
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
                format!("Failed to transition issue {issue_key} (HTTP status {status})"),
                Some(i32::from(status.as_u16())),
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

        if let Some(match_transition) = transition {
            self.transition_issue(issue_key, &match_transition.id, comment)
                .await
        } else {
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

    /// Get issues for a project through Jira's legacy GET search route.
    ///
    /// This compatibility helper delegates to [`Self::search_issues`] and therefore
    /// calls the upstream-deprecated `GET /rest/api/2/search` endpoint. Use an
    /// implementation of enhanced search at `/rest/api/2/search/jql` for new work.
    ///
    /// # Arguments
    /// * `project_key` - Project key (e.g., "PROJ"), quoted and escaped into the
    ///   generated query by [`crate::jql`]
    /// * `limit` - Maximum number of results
    ///
    /// # Errors
    ///
    /// Returns [`AtlassianError::Validation`] when `project_key` contains U+0000,
    /// which JQL cannot represent.
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
        let jql = JqlBuilder::new().eq("project", project_key)?.build()?;
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
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CreateIssueFields, IssueTypeReference, ProjectReference};
    use std::time::Duration;
    use wiremock::matchers::{body_json, body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_config() -> AtlassianConfig {
        AtlassianConfig::new(
            "https://test.atlassian.net".to_string(),
            "test@example.com".to_string(),
            "test-token".to_string(),
        )
        .unwrap()
    }

    fn create_mock_client(server: &MockServer) -> AtlassianClient {
        let config = AtlassianConfig::builder()
            .base_url(server.uri())
            .username("test@example.com")
            .api_token("test-token")
            .verify_ssl(false)
            .build()
            .unwrap();
        AtlassianClient::new(config).unwrap()
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

    #[test]
    fn test_story_points_reject_non_finite_values() {
        for story_points in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let err = AtlassianClient::story_points_json_value(story_points).unwrap_err();

            assert!(matches!(err, AtlassianError::Validation { .. }));
        }
    }

    #[test]
    fn test_story_points_accept_finite_values() {
        let value = AtlassianClient::story_points_json_value(5.0).unwrap();

        assert_eq!(value.as_f64(), Some(5.0));
    }

    #[tokio::test]
    async fn test_create_issue_fetches_issue_after_create_response() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/rest/api/2/issue"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "10001",
                "key": "TEST-123",
                "self": format!("{}/rest/api/2/issue/10001", server.uri()),
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/api/2/issue/TEST-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "10001",
                "key": "TEST-123",
                "self": format!("{}/rest/api/2/issue/10001", server.uri()),
                "fields": {
                    "summary": "Created issue",
                    "description": "Test description",
                    "issuetype": {
                        "id": "10000",
                        "name": "Task",
                        "description": "Task issue",
                        "iconUrl": null,
                        "subtask": false
                    },
                    "status": {
                        "id": "1",
                        "name": "To Do",
                        "description": "Pending work",
                        "category": {
                            "id": 2,
                            "key": "new",
                            "name": "To Do",
                            "colorName": "blue-gray"
                        }
                    },
                    "priority": null,
                    "assignee": null,
                    "reporter": null,
                    "project": {
                        "id": "10000",
                        "key": "TEST",
                        "name": "Test Project",
                        "description": null,
                        "projectTypeKey": "software",
                        "avatarUrls": null
                    },
                    "created": null,
                    "updated": null,
                    "resolutiondate": null,
                    "labels": [],
                    "components": []
                }
            })))
            .mount(&server)
            .await;

        let config = AtlassianConfig::builder()
            .base_url(server.uri())
            .username("test@example.com")
            .api_token("test-token")
            .verify_ssl(false)
            .build()
            .unwrap();
        let client = AtlassianClient::new(config).unwrap();

        let request = CreateIssueRequest {
            fields: CreateIssueFields {
                project: ProjectReference::by_key("TEST"),
                summary: "Created issue".to_string(),
                issue_type: IssueTypeReference::by_name("Task"),
                description: Some("Test description".to_string()),
                assignee: None,
                priority: None,
                labels: None,
                components: None,
                parent: None,
                custom_fields: HashMap::new(),
            },
        };

        let created_issue = client.create_issue(request).await.unwrap();

        assert_eq!(created_issue.key, "TEST-123");
        assert_eq!(created_issue.fields.summary, "Created issue");
    }

    #[tokio::test]
    async fn test_create_issue_key_returns_the_key_without_reading_the_issue_back() {
        // The POST is irreversible and answers with the key, so a caller that
        // wants only the key may not be made to depend on a second round trip:
        // a 503, a 429 or a token that can create but not read would otherwise
        // discard the key of an issue that exists.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/rest/api/2/issue"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "10077",
                "key": "KAN-77",
                "self": format!("{}/rest/api/2/issue/10077", server.uri()),
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/api/2/issue/KAN-77"))
            .respond_with(ResponseTemplate::new(503))
            .expect(0)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let request = CreateIssueRequest {
            fields: CreateIssueFields {
                project: ProjectReference::by_key("KAN"),
                summary: "Created issue".to_string(),
                issue_type: IssueTypeReference::by_name("Bug"),
                description: None,
                assignee: None,
                priority: None,
                labels: None,
                components: None,
                parent: None,
                custom_fields: HashMap::new(),
            },
        };

        let issue_key = client
            .create_issue_key(request)
            .await
            .expect("a created issue must yield its key");

        assert_eq!(issue_key, "KAN-77");
    }

    #[tokio::test]
    async fn test_comment_and_assignment_requests() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/rest/api/2/issue/TEST-123/comment"))
            .and(body_json(json!({ "body": "Review evidence" })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "10001",
                "body": "Review evidence"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/rest/api/2/issue/TEST-123/comment"))
            .and(query_param("startAt", "5"))
            .and(query_param("maxResults", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "startAt": 5,
                "maxResults": 10,
                "total": 0,
                "comments": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/rest/api/2/issue/TEST-123/assignee"))
            .and(body_json(json!({ "accountId": "account-123" })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/rest/api/2/issue/TEST-123/assignee"))
            .and(body_json(json!({ "accountId": null })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/rest/api/2/issue/TEST-123"))
            .and(body_json(json!({
                "fields": {
                    "summary": "Updated summary",
                    "labels": ["reviewed"]
                }
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let comment = client
            .add_issue_comment("TEST-123", "  Review evidence  ")
            .await
            .unwrap();
        let comments = client.get_issue_comments("TEST-123", 5, 10).await.unwrap();
        client
            .assign_issue("TEST-123", Some("account-123"))
            .await
            .unwrap();
        client.assign_issue("TEST-123", None).await.unwrap();
        client
            .update_issue(
                "TEST-123",
                HashMap::from([
                    (
                        "summary".to_string(),
                        Value::String("Updated summary".to_string()),
                    ),
                    ("labels".to_string(), json!(["reviewed"])),
                ]),
            )
            .await
            .unwrap();

        assert_eq!(comment["id"], "10001");
        assert_eq!(comments["startAt"], 5);
    }

    #[tokio::test]
    async fn test_user_search_and_changelog_requests() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/2/user/search"))
            .and(query_param("query", "Allen"))
            .and(query_param("startAt", "0"))
            .and(query_param("maxResults", "25"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
                "accountId": "account-123",
                "displayName": "Allen Example",
                "active": true
            }])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/rest/api/2/issue/TEST-123/changelog"))
            .and(query_param("startAt", "1"))
            .and(query_param("maxResults", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "startAt": 1,
                "maxResults": 2,
                "total": 1,
                "values": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let users = client.search_users(" Allen ", 0, 25).await.unwrap();
        let changelog = client.get_issue_changelog("TEST-123", 1, 2).await.unwrap();

        assert_eq!(users[0].account_id.as_deref(), Some("account-123"));
        assert_eq!(changelog["maxResults"], 2);
    }

    #[tokio::test]
    async fn test_issue_link_requests() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/rest/api/2/issueLink"))
            .and(body_json(json!({
                "type": { "name": "Blocks" },
                "inwardIssue": { "key": "TEST-123" },
                "outwardIssue": { "key": "TEST-456" }
            })))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/rest/api/2/issueLink/10001"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        client
            .create_issue_link("Blocks", "TEST-123", "TEST-456")
            .await
            .unwrap();
        client.delete_issue_link("10001").await.unwrap();
    }

    #[tokio::test]
    async fn test_attachment_upload_request() {
        let server = MockServer::start().await;
        let attachment_path = std::env::temp_dir().join(format!(
            "threatflux-atlassian-attachment-{}.txt",
            std::process::id()
        ));
        fs::write(&attachment_path, b"review evidence").unwrap();

        Mock::given(method("POST"))
            .and(path("/rest/api/2/issue/TEST-123/attachments"))
            .and(header("x-atlassian-token", "no-check"))
            .and(body_string_contains("review evidence"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
                "id": "10001",
                "filename": attachment_path.file_name().unwrap().to_string_lossy()
            }])))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let response = client
            .add_issue_attachment("TEST-123", &attachment_path)
            .await
            .unwrap();
        fs::remove_file(&attachment_path).unwrap();

        assert_eq!(response[0]["id"], "10001");
    }

    #[tokio::test]
    async fn test_operator_input_validation() {
        let client = AtlassianClient::new(create_test_config()).unwrap();

        assert!(matches!(
            client.add_issue_comment("TEST-123", "  ").await,
            Err(AtlassianError::Validation { .. })
        ));
        assert!(matches!(
            client.search_users("", 0, 10).await,
            Err(AtlassianError::Validation { .. })
        ));
        assert!(matches!(
            client.delete_issue_link("not-a-number").await,
            Err(AtlassianError::Validation { .. })
        ));
    }

    async fn mount_empty_search(server: &MockServer, expected_jql: &str) {
        Mock::given(method("GET"))
            .and(path("/rest/api/2/search"))
            .and(query_param("jql", expected_jql))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 0,
                "startAt": 0,
                "maxResults": 50,
                "issues": [],
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn test_get_project_issues_quotes_the_project_key() {
        let server = MockServer::start().await;
        mount_empty_search(&server, r#"project = "TEST""#).await;

        let client = create_mock_client(&server);
        let issues = client.get_project_issues("TEST", 50).await.unwrap();

        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn test_get_project_issues_keeps_a_hostile_project_key_inside_its_literal() {
        let server = MockServer::start().await;
        mount_empty_search(&server, r#"project = "TEST\" OR project = \"EVIL""#).await;

        let client = create_mock_client(&server);
        let issues = client
            .get_project_issues(r#"TEST" OR project = "EVIL"#, 50)
            .await
            .unwrap();

        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn test_get_project_issues_rejects_an_unrepresentable_project_key() {
        let server = MockServer::start().await;
        // No mock is mounted: the query must fail before any request is sent.
        let client = create_mock_client(&server);

        assert!(matches!(
            client.get_project_issues("TE\0ST", 50).await,
            Err(AtlassianError::Validation { .. })
        ));
        assert!(server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty());
    }
}
