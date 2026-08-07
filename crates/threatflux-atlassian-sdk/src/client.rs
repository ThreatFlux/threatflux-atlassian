//! Jira API client implementation
//!
//! This module provides the main `AtlassianClient` for interacting with Jira APIs,
//! including authentication, ticket operations, and project management.

use crate::config::AtlassianConfig;
use crate::error::{
    map_error_response, AtlassianError, DiagnosticsPolicy, FailureContext, FailureShape, Result,
};
use crate::jql::JqlBuilder;
use crate::secret::zeroize_string;
use crate::types::{
    CreateIssueRequest, IssueSearchResult, IssueTransition, IssueTransitionsResponse, JiraField,
    JiraIssue, JiraUser, Project, UpdateIssueRequest,
};
use crate::v3::JiraV3;
use base64::prelude::*;
use reqwest::header::HeaderValue;
use reqwest::{multipart, Certificate, Client, ClientBuilder, Method, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::fs as tokio_fs;
use tracing::{debug, error, info, warn};
use url::Url;

#[derive(Debug, Deserialize)]
struct CreateIssueResponse {
    key: String,
}

/// Longest prefix of a caller-supplied value that may reach a log line.
const PREVIEW_LIMIT: usize = 48;

/// A bounded, escaped preview of a value this crate did not author.
///
/// Two properties, both of which a bare `{}` loses. The bound keeps an
/// unbounded value — a JQL query carrying a rendered issue body, a 32 KiB
/// summary — from being copied wholesale into a log sink that outlives the run
/// and is readable by anyone with the workflow log. The `{:?}` escaping keeps a
/// newline inside that value from ending the log line and forging the next one.
///
/// Visible to the crate rather than to this module so that the v3 endpoints log
/// through the same bound; a second copy of it would be a second policy.
pub(crate) fn preview(value: &str) -> String {
    let truncated: String = value.chars().take(PREVIEW_LIMIT).collect();
    if truncated.len() == value.len() {
        format!("{truncated:?}")
    } else {
        format!("{truncated:?} (truncated)")
    }
}

/// Whether replaying a request can duplicate a server-side effect.
///
/// Every routed call records one of these so the retry work has a per-operation
/// input instead of inferring safety from the HTTP method. Nothing branches on it
/// yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Idempotency {
    /// Reads, and writes that set a value rather than append one: a replay
    /// converges on the same server state.
    Safe,
    /// Writes that append. A replay creates a second issue, comment, link, or
    /// attachment.
    UnsafeWrite,
}

/// The request body, which decides which content type the request carries.
#[derive(Debug)]
enum Payload<'a> {
    /// No body. Kept distinct from an empty JSON body so the request is byte-identical
    /// to what the endpoint expects.
    Empty,
    /// A JSON document.
    Json(&'a Value),
    /// A multipart form, which owns its parts and therefore cannot be borrowed.
    Multipart(Box<multipart::Form>),
}

/// One outbound Jira API call, described independently of how it is sent.
///
/// The path arrives as already-split segments rather than a joined string: each one
/// is percent-encoded on its own, so a caller-supplied identifier can never introduce
/// a path boundary.
#[derive(Debug)]
pub(crate) struct TransportRequest<'a> {
    method: Method,
    segments: &'a [&'a str],
    idempotency: Idempotency,
    query: Option<&'a HashMap<String, String>>,
    payload: Payload<'a>,
}

impl<'a> TransportRequest<'a> {
    /// Describe a request to the API path formed by `segments`.
    pub(crate) const fn new(
        method: Method,
        segments: &'a [&'a str],
        idempotency: Idempotency,
    ) -> Self {
        Self {
            method,
            segments,
            idempotency,
            query: None,
            payload: Payload::Empty,
        }
    }

    /// Attach a JSON request body.
    pub(crate) fn json(mut self, body: &'a Value) -> Self {
        self.payload = Payload::Json(body);
        self
    }

    /// Attach a multipart form body.
    pub(crate) fn multipart(mut self, form: multipart::Form) -> Self {
        self.payload = Payload::Multipart(Box::new(form));
        self
    }

    /// Attach query parameters, which reqwest percent-encodes.
    pub(crate) const fn query(mut self, params: &'a HashMap<String, String>) -> Self {
        self.query = Some(params);
        self
    }

    /// The replay class recorded for this call.
    pub(crate) const fn idempotency(&self) -> Idempotency {
        self.idempotency
    }
}

/// Authenticated HTTP plumbing shared by every Jira endpoint.
///
/// This is the single place that resolves an API path against the configured base
/// URL, applies credentials, and maps a failure response onto [`AtlassianError`].
#[derive(Debug, Clone)]
pub(crate) struct Transport {
    client: Client,
    config: AtlassianConfig,
    diagnostics: DiagnosticsPolicy,
}

impl Transport {
    /// Build the HTTP client described by `config`.
    fn new(config: AtlassianConfig) -> Result<Self> {
        let mut client_builder = ClientBuilder::new()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .no_proxy();

        // Certificate verification is a property of a TLS handshake, so relaxing
        // it is scoped to the scheme that performs one. On an `http://` base URL
        // reqwest never negotiates TLS, and `danger_accept_invalid_certs(true)`
        // was a no-op that read like a downgrade.
        if !config.verify_ssl && config.base_url.scheme() == "https" {
            warn!("TLS certificate verification is disabled - not recommended for production");
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

        Ok(Self {
            client,
            config,
            diagnostics: DiagnosticsPolicy::default(),
        })
    }

    /// Build the `Authorization: Basic` header for the configured credentials.
    ///
    /// The returned value is marked sensitive, which is what keeps reqwest and
    /// hyper from printing it in their own `Debug` output and error text — a
    /// `HeaderMap` renders a sensitive value as `Sensitive` and nothing else.
    /// That covers the `username:token` blob, which is the credential in another
    /// encoding and which no amount of redaction on [`crate::SecretString`]
    /// reaches once base64 has been applied to it.
    fn authorization_header(&self) -> Result<HeaderValue> {
        let mut credentials = format!(
            "{}:{}",
            self.config.username,
            self.config.api_token.expose_secret()
        );
        let mut encoded = BASE64_STANDARD.encode(&credentials);
        zeroize_string(&mut credentials);

        let mut rendered = format!("Basic {encoded}");
        zeroize_string(&mut encoded);

        // Base64 emits only header-safe ASCII, so this cannot fail for any
        // username or token; it is mapped rather than unwrapped so that no
        // credential can reach a panic payload.
        let header = HeaderValue::from_str(&rendered);
        zeroize_string(&mut rendered);

        let mut header = header.map_err(|_| {
            AtlassianError::config("Jira credentials cannot be encoded as an HTTP header")
        })?;
        header.set_sensitive(true);
        Ok(header)
    }

    /// Resolve API path `segments` below the configured base URL.
    ///
    /// Segments are appended, never resolved: a Data Center context path in the base
    /// URL is preserved, and each segment is percent-encoded on its own so a
    /// caller-supplied identifier cannot escape the API path.
    ///
    /// The [`crate::HostPolicy`] is applied to the **joined** URL rather than to the base,
    /// so the destination that is checked is the destination that is dialled. Every
    /// endpoint reaches the wire through here, `add_issue_attachment` — whose
    /// multipart body kept it off the shared path for a while — included.
    pub(crate) fn build_url(&self, segments: &[&str]) -> Result<Url> {
        for segment in segments {
            Self::validate_segment(segment)?;
        }

        let mut url = self.config.base_url.clone();
        {
            let mut path = url.path_segments_mut().map_err(|()| {
                AtlassianError::config(format!(
                    "Jira base URL scheme '{}' cannot carry an API path",
                    self.config.base_url.scheme()
                ))
            })?;
            // A base URL always ends in at least "/", whose empty trailing segment
            // would otherwise become a "//" in the joined path.
            path.pop_if_empty();
            path.extend(segments);
        }

        self.config.host_policy.check_destination(&url)?;

        Ok(url)
    }

    /// Reject the segments `Url` would silently rewrite rather than encode.
    ///
    /// `path_segments_mut` drops `.` and `..` outright and strips CR, LF, and TAB,
    /// so any of them would address a different resource than the caller named.
    fn validate_segment(segment: &str) -> Result<()> {
        if segment.is_empty() {
            return Err(AtlassianError::validation(
                "Jira API path segment cannot be empty",
            ));
        }

        if segment == "." || segment == ".." {
            return Err(AtlassianError::validation(format!(
                "Jira API path segment cannot be the relative segment {segment:?}"
            )));
        }

        if segment.chars().any(char::is_control) {
            return Err(AtlassianError::validation(
                "Jira API path segment cannot contain control characters",
            ));
        }

        Ok(())
    }

    async fn ensure_success(&self, response: Response) -> Result<Response> {
        if response.status().is_success() {
            return Ok(response);
        }

        Err(map_error_response(
            response,
            FailureContext::new(FailureShape::JiraRest, "Jira API request", self.diagnostics),
        )
        .await)
    }

    /// Send an authenticated request and map a failure response onto an error.
    pub(crate) async fn send(&self, request: TransportRequest<'_>) -> Result<Response> {
        let url = self.build_url(request.segments)?;

        debug!(
            "Making {} request to: {} ({:?})",
            request.method,
            url,
            request.idempotency()
        );

        let mut builder = self
            .client
            .request(request.method, url)
            .header("Authorization", self.authorization_header()?)
            .header("Accept", "application/json");

        if let Some(params) = request.query {
            builder = builder.query(params);
        }

        builder = match request.payload {
            Payload::Empty => builder.header("Content-Type", "application/json"),
            Payload::Json(body) => builder
                .header("Content-Type", "application/json")
                .json(body),
            // Jira rejects an attachment upload that does not opt out of its XSRF
            // check, and reqwest owns the multipart content type and its boundary.
            Payload::Multipart(form) => builder
                .header("X-Atlassian-Token", "no-check")
                .multipart(*form),
        };

        self.ensure_success(builder.send().await?).await
    }
}

/// Main client for Atlassian/Jira API operations
#[derive(Debug)]
pub struct AtlassianClient {
    /// Authenticated HTTP plumbing and the configuration it was built from
    transport: Transport,
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

        Ok(Self {
            transport: Transport::new(config)?,
        })
    }

    /// Create client from environment variables
    pub fn from_env() -> Result<Self> {
        let config = AtlassianConfig::from_env()?;
        Self::new(config)
    }

    /// Choose how much of a failing Jira response may reach the errors this client returns.
    ///
    /// The default is [`DiagnosticsPolicy::MetadataOnly`], under which a Jira
    /// response body is never read. Widening the policy is a decision about where
    /// this process's errors end up — a workflow log, a Jira comment, an exception
    /// report — and is deliberately not reachable from the environment.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::error::DiagnosticsPolicy;
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// let client = AtlassianClient::from_env()
    ///     .unwrap()
    ///     .with_diagnostics(DiagnosticsPolicy::JiraErrorFields);
    /// ```
    #[must_use]
    pub const fn with_diagnostics(mut self, policy: DiagnosticsPolicy) -> Self {
        self.transport.diagnostics = policy;
        self
    }

    /// The response-diagnostics policy in force for this client.
    pub const fn diagnostics(&self) -> DiagnosticsPolicy {
        self.transport.diagnostics
    }

    /// The authenticated plumbing every endpoint on this client shares.
    ///
    /// Visible to the crate so an endpoint family implemented outside this
    /// module — the enhanced-search methods in [`crate::search`] — reaches the
    /// wire through this transport rather than building one of its own, and is
    /// therefore subject to the same credentials, host policy, path builder and
    /// diagnostics policy as the methods defined here.
    pub(crate) const fn transport(&self) -> &Transport {
        &self.transport
    }

    /// The Jira Cloud REST API v3 endpoints.
    ///
    /// v2 and v3 are the same REST API with one structural difference: a
    /// rich-text field is a wiki-markup string under v2 and an
    /// [ADF](crate::adf) object under v3. Reaching v3 is therefore additive —
    /// the methods on this type keep talking v2 and keep their types, and
    /// [`crate::v3`] carries a parallel model for the endpoints that speak ADF.
    ///
    /// The returned handle borrows this client's transport, so a v3 call is
    /// subject to the same credentials, host policy and diagnostics policy as a
    /// v2 one.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let issue = client.v3().get_issue("PROJ-123").await.unwrap();
    /// println!("{:?}", issue.fields.summary);
    /// # });
    /// ```
    #[must_use]
    pub const fn v3(&self) -> JiraV3<'_> {
        JiraV3::new(&self.transport)
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

        let response = self
            .transport
            .send(TransportRequest::new(
                Method::GET,
                &["rest", "api", "2", "issue", issue_key],
                Idempotency::Safe,
            ))
            .await?;

        let issue: JiraIssue = response.json().await?;
        debug!(
            "Retrieved issue: {} - {}",
            issue.key,
            preview(&issue.fields.summary)
        );

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

        let update_request = UpdateIssueRequest { fields };
        let body = serde_json::to_value(&update_request)?;

        let response = self
            .transport
            .send(
                TransportRequest::new(
                    Method::PUT,
                    &["rest", "api", "2", "issue", issue_key],
                    Idempotency::Safe,
                )
                .json(&body),
            )
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
        let payload = json!({ "body": body });
        let response = self
            .transport
            .send(
                TransportRequest::new(
                    Method::POST,
                    &["rest", "api", "2", "issue", issue_key, "comment"],
                    Idempotency::UnsafeWrite,
                )
                .json(&payload),
            )
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
        let mut params = HashMap::new();
        params.insert("startAt".to_string(), start_at.to_string());
        params.insert("maxResults".to_string(), max_results.to_string());
        let response = self
            .transport
            .send(
                TransportRequest::new(
                    Method::GET,
                    &["rest", "api", "2", "issue", issue_key, "comment"],
                    Idempotency::Safe,
                )
                .query(&params),
            )
            .await?;
        Ok(response.json().await?)
    }

    /// Assign an issue by Atlassian account ID, or unassign it with `None`.
    pub async fn assign_issue(&self, issue_key: &str, account_id: Option<&str>) -> Result<()> {
        let account_id = account_id.map(str::trim).filter(|value| !value.is_empty());
        info!("Updating assignee for issue: {}", issue_key);
        let payload = json!({ "accountId": account_id });
        self.transport
            .send(
                TransportRequest::new(
                    Method::PUT,
                    &["rest", "api", "2", "issue", issue_key, "assignee"],
                    Idempotency::Safe,
                )
                .json(&payload),
            )
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
            .transport
            .send(
                TransportRequest::new(
                    Method::GET,
                    &["rest", "api", "2", "user", "search"],
                    Idempotency::Safe,
                )
                .query(&params),
            )
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
        self.transport
            .send(
                TransportRequest::new(
                    Method::POST,
                    &["rest", "api", "2", "issueLink"],
                    Idempotency::UnsafeWrite,
                )
                .json(&payload),
            )
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
        self.transport
            .send(TransportRequest::new(
                Method::DELETE,
                &["rest", "api", "2", "issueLink", link_id],
                Idempotency::Safe,
            ))
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

        info!("Uploading attachment to issue: {}", issue_key);
        let response = self
            .transport
            .send(
                TransportRequest::new(
                    Method::POST,
                    &["rest", "api", "2", "issue", issue_key, "attachments"],
                    Idempotency::UnsafeWrite,
                )
                .multipart(form),
            )
            .await?;
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
        let mut params = HashMap::new();
        params.insert("startAt".to_string(), start_at.to_string());
        params.insert("maxResults".to_string(), max_results.to_string());
        let response = self
            .transport
            .send(
                TransportRequest::new(
                    Method::GET,
                    &["rest", "api", "2", "issue", issue_key, "changelog"],
                    Idempotency::Safe,
                )
                .query(&params),
            )
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
    /// Returns an error if Jira rejects the create, or if Jira accepts it and
    /// its response cannot be read. Only the first means no issue was made: an
    /// unreadable response leaves an issue whose key nothing learned, which a
    /// retry would duplicate, so that case is logged.
    pub async fn create_issue_key(&self, request: CreateIssueRequest) -> Result<String> {
        info!("Creating new issue");
        debug!("New issue summary: {}", preview(&request.fields.summary));

        let body = serde_json::to_value(&request)?;

        let response = self
            .transport
            .send(
                TransportRequest::new(
                    Method::POST,
                    &["rest", "api", "2", "issue"],
                    Idempotency::UnsafeWrite,
                )
                .json(&body),
            )
            .await?;

        let created_issue: CreateIssueResponse =
            response.json().await.inspect_err(|error| {
                error!("Jira accepted the create but its response could not be read, so the created issue has no key here: {error}");
            })?;
        info!("Successfully created issue: {}", created_issue.key);

        Ok(created_issue.key)
    }

    /// Create a new issue and read it back
    ///
    /// The returned issue is the one Jira stored, with the fields it derived --
    /// id, status, project -- which the create response does not carry. That
    /// second round trip can fail on its own, and then this returns an error for
    /// an issue that exists. The returned error does not carry the key; the key
    /// is logged at `ERROR` level, which is enough to find the issue by hand but
    /// not to act on. A caller that needs the key in code uses
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
        // The query is not this crate's text. A dedupe query carries the caller's
        // label scheme, and a `summary ~` term carries whatever the event that
        // produced it did, so the whole of it is exactly what must not land in an
        // `info` log that a workflow publishes.
        info!("Searching issues with a {}-character JQL query", jql.len());
        debug!("JQL query: {}", preview(jql));

        let mut params = HashMap::new();
        params.insert("jql".to_string(), jql.to_string());
        params.insert("startAt".to_string(), start_at.to_string());
        params.insert("maxResults".to_string(), max_results.to_string());

        let response = self
            .transport
            .send(
                TransportRequest::new(
                    Method::GET,
                    &["rest", "api", "2", "search"],
                    Idempotency::Safe,
                )
                .query(&params),
            )
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

        let response = self
            .transport
            .send(TransportRequest::new(
                Method::GET,
                &["rest", "api", "2", "myself"],
                Idempotency::Safe,
            ))
            .await?;

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
    /// `GET /rest/api/2/project/search`, which
    /// [`crate::search::ProjectSearchPage`] models.
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

        let response = self
            .transport
            .send(TransportRequest::new(
                Method::GET,
                &["rest", "api", "2", "project"],
                Idempotency::Safe,
            ))
            .await?;

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

        let response = self
            .transport
            .send(TransportRequest::new(
                Method::GET,
                &["rest", "api", "2", "project", project_key],
                Idempotency::Safe,
            ))
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

        let response = self
            .transport
            .send(TransportRequest::new(
                Method::GET,
                &["rest", "api", "2", "field"],
                Idempotency::Safe,
            ))
            .await?;

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
        // The value is whatever the caller is writing into a Jira field, which is
        // the one argument here that can be a credential.
        info!("Updating custom field {} for {}", field_id, issue_key);
        debug!("Custom field {} value: {}", field_id, preview(value));

        let mut fields = HashMap::new();
        fields.insert(field_id.to_string(), serde_json::json!({ "value": value }));

        self.update_issue(issue_key, fields).await
    }

    /// Retrieve the list of workflow transitions available for an issue
    pub async fn get_issue_transitions(&self, issue_key: &str) -> Result<Vec<IssueTransition>> {
        info!("Fetching transitions for issue: {}", issue_key);

        let response = self
            .transport
            .send(TransportRequest::new(
                Method::GET,
                &["rest", "api", "2", "issue", issue_key, "transitions"],
                Idempotency::Safe,
            ))
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
            .transport
            .send(
                TransportRequest::new(
                    Method::POST,
                    &["rest", "api", "2", "issue", issue_key, "transitions"],
                    Idempotency::UnsafeWrite,
                )
                .json(&payload),
            )
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
            transport: self.transport.clone(),
        }
    }
}

/// Unit tests for the parts of this module that are not reachable from outside
/// the crate: `Transport`, `build_url`, `preview`, the authorization header, and
/// the endpoint behaviours whose assertions need a private item.
///
/// The end-to-end coverage of the endpoints themselves lives in
/// `tests/jira_endpoint_journal.rs`. Those cases start a server and send real
/// requests, so they belong in a binary compiled against the published surface —
/// and they assert on the mock's request journal rather than on a
/// `Mock::…expect(1)` mount, which counts only the requests a matcher already
/// accepted and so cannot report a request that was built wrong.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HostPolicy;
    use crate::types::{CreateIssueFields, IssueTypeReference, ProjectReference};
    use std::future::Future;
    use std::time::Duration;
    use threatflux_atlassian_testkit::logs;
    use threatflux_atlassian_testkit::redaction::SecretScanner;
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
        create_mock_client_at(&server.uri())
    }

    /// A client pointed at a `http://127.0.0.1:PORT` mock.
    ///
    /// `HostPolicy::Loopback` is the whole reason the scheme is admitted. The
    /// `verify_ssl(false)` this replaced never did anything here — reqwest
    /// negotiates no TLS on an `http://` URL — it only bought past a scheme check
    /// that was wrongly conditioned on it.
    fn create_mock_client_at(base_url: &str) -> AtlassianClient {
        let config = AtlassianConfig::builder()
            .base_url(base_url)
            .username("test@example.com")
            .api_token("test-token")
            .host_policy(HostPolicy::Loopback)
            .build()
            .unwrap();
        AtlassianClient::new(config).unwrap()
    }

    /// A transport at an arbitrary base, for the tests that only exercise path
    /// joining and so must not be constrained by the default host policy.
    fn transport_at(base_url: &str) -> Transport {
        let host = Url::parse(base_url)
            .expect("test base URL parses")
            .host_str()
            .expect("test base URL names a host")
            .to_string();
        let config = AtlassianConfig::builder()
            .base_url(base_url)
            .username("test@example.com")
            .api_token("test-token")
            .host_policy(HostPolicy::Allowlist(vec![host]))
            .build()
            .unwrap();
        Transport::new(config).unwrap()
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

        assert_eq!(
            client.transport.config.base_url,
            cloned_client.transport.config.base_url
        );
        assert_eq!(
            client.transport.config.username,
            cloned_client.transport.config.username
        );
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
    async fn test_create_issue_key_reports_a_create_response_it_cannot_read() {
        // The one error this method can return *after* Jira made the issue, and
        // the reason its documented boundary is "a rejected create made no
        // issue" rather than "an error means no issue": a 2xx whose body does
        // not carry a key leaves an issue behind that a retry would duplicate.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/rest/api/2/issue"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": "10077" })))
            .expect(1)
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

        let error = client
            .create_issue_key(request)
            .await
            .expect_err("a create response without a key cannot yield one");

        assert!(matches!(error, AtlassianError::Http { .. }), "{error:?}");
    }

    /// Read this before "fixing" the inline comment body in `transition_issue`
    /// into ADF.
    ///
    /// `transition_issue` posts to `/rest/api/2/issue/{key}/transitions`, and v2
    /// carries a comment body as a **wiki-markup string**. ADF is the v3 wire
    /// form; sending an ADF object to a v2 route is a 400, and quietly changing
    /// the request shape of a published v2 method is a breaking change to
    /// callers who asked for none. The ADF migration is deliberately additive
    /// and lives entirely behind `client.v3()` — the ADF equivalent of this
    /// comment is `client.v3().add_comment`, which posts to
    /// `/rest/api/3/issue/{key}/comment`.
    ///
    /// The assertion is on the exact body because the failure this pins is
    /// silent: an ADF body would still be a well-formed request to a route that
    /// exists, and only Jira would object.
    #[tokio::test]
    async fn test_transition_issue_comment_body_stays_a_v2_plain_string() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/rest/api/2/issue/TEST-123/transitions"))
            .and(body_json(json!({
                "transition": {"id": "31"},
                "update": {"comment": [{"add": {"body": "shipped in 3.5.4"}}]}
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        // The padding also pins the trimming: the body is the trimmed text, and
        // it is a bare JSON string rather than a `{"type":"doc",...}` object.
        create_mock_client(&server)
            .transition_issue("TEST-123", "31", Some("  shipped in 3.5.4  "))
            .await
            .expect("the transition succeeds");
    }

    #[tokio::test]
    async fn test_transition_issue_omits_the_comment_when_there_is_none() {
        // The other half of the same pin: no comment, and no `update` member at
        // all. A migration that reached for `RichText` here would have to invent
        // an empty document for this case, which is how an empty comment starts
        // appearing on every transition.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/rest/api/2/issue/TEST-123/transitions"))
            .and(body_json(json!({"transition": {"id": "31"}})))
            .respond_with(ResponseTemplate::new(204))
            .expect(2)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        client
            .transition_issue("TEST-123", "31", None)
            .await
            .expect("the transition succeeds");
        client
            .transition_issue("TEST-123", "31", Some("   "))
            .await
            .expect("a whitespace-only comment is no comment");
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

    #[test]
    fn test_build_url_keeps_a_data_center_context_path() {
        // `Url::join`, which this replaced, resolves the API path against the base and
        // drops the context path entirely.
        for base in [
            "https://jira.example.com/jira",
            "https://jira.example.com/jira/",
        ] {
            let url = transport_at(base)
                .build_url(&["rest", "api", "2", "issue", "KAN-1"])
                .unwrap();

            assert_eq!(
                url.as_str(),
                "https://jira.example.com/jira/rest/api/2/issue/KAN-1",
                "context path dropped for base {base}"
            );
        }
    }

    #[test]
    fn test_build_url_keeps_a_multi_element_context_path() {
        let url = transport_at("https://jira.example.com/apps/jira/")
            .build_url(&["rest", "api", "2", "myself"])
            .unwrap();

        assert_eq!(
            url.as_str(),
            "https://jira.example.com/apps/jira/rest/api/2/myself"
        );
    }

    #[test]
    fn test_build_url_leaves_a_bare_host_base_unchanged() {
        for base in ["https://test.atlassian.net", "https://test.atlassian.net/"] {
            let url = transport_at(base)
                .build_url(&["rest", "api", "2", "issue", "KAN-1"])
                .unwrap();

            assert_eq!(
                url.as_str(),
                "https://test.atlassian.net/rest/api/2/issue/KAN-1",
                "unexpected path for base {base}"
            );
        }
    }

    #[test]
    fn test_build_url_percent_encodes_a_traversal_attempt_into_one_segment() {
        let url = transport_at("https://test.atlassian.net")
            .build_url(&["rest", "api", "2", "issue", "KAN-1/../../../admin"])
            .unwrap();

        assert_eq!(url.path(), "/rest/api/2/issue/KAN-1%2F..%2F..%2F..%2Fadmin");
        assert_eq!(
            url.path_segments().unwrap().count(),
            5,
            "a caller-supplied identifier introduced a path boundary"
        );
    }

    #[test]
    fn test_build_url_percent_encodes_query_and_fragment_delimiters() {
        let url = transport_at("https://test.atlassian.net")
            .build_url(&["rest", "api", "2", "issue", "KAN-1?expand=all#frag"])
            .unwrap();

        assert_eq!(url.path(), "/rest/api/2/issue/KAN-1%3Fexpand=all%23frag");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_build_url_rejects_segments_url_would_rewrite_rather_than_encode() {
        let transport = transport_at("https://test.atlassian.net");

        for segment in ["", ".", "..", "KAN\r\n-1", "KAN\t-1"] {
            let err = transport
                .build_url(&["rest", "api", "2", "issue", segment])
                .unwrap_err();

            assert!(
                matches!(err, AtlassianError::Validation { .. }),
                "segment {segment:?} produced {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_requests_reach_a_data_center_context_path() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/jira/rest/api/2/issue/TEST-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "10001",
                "key": "TEST-123",
                "self": format!("{}/jira/rest/api/2/issue/10001", server.uri()),
                "fields": {
                    "summary": "Context path issue",
                    "issuetype": {
                        "id": "10000",
                        "name": "Task",
                        "description": null,
                        "iconUrl": null,
                        "subtask": false
                    },
                    "status": {
                        "id": "1",
                        "name": "To Do",
                        "description": null,
                        "category": {
                            "id": 2,
                            "key": "new",
                            "name": "To Do",
                            "colorName": "blue-gray"
                        }
                    },
                    "project": {
                        "id": "10000",
                        "key": "TEST",
                        "name": "Test Project",
                        "description": null,
                        "projectTypeKey": "software",
                        "avatarUrls": null
                    },
                    "labels": [],
                    "components": []
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client_at(&format!("{}/jira", server.uri()));
        let issue = client.get_issue("TEST-123").await.unwrap();

        assert_eq!(issue.key, "TEST-123");
    }

    #[tokio::test]
    async fn test_attachment_upload_reaches_a_data_center_context_path() {
        let server = MockServer::start().await;
        let attachment_path = std::env::temp_dir().join(format!(
            "threatflux-atlassian-context-attachment-{}.txt",
            std::process::id()
        ));
        fs::write(&attachment_path, b"context evidence").unwrap();

        Mock::given(method("POST"))
            .and(path("/jira/rest/api/2/issue/TEST-123/attachments"))
            .and(header("x-atlassian-token", "no-check"))
            .and(body_string_contains("context evidence"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "id": "10001" }])))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client_at(&format!("{}/jira", server.uri()));
        let response = client
            .add_issue_attachment("TEST-123", &attachment_path)
            .await
            .unwrap();
        fs::remove_file(&attachment_path).unwrap();

        assert_eq!(response[0]["id"], "10001");
    }

    #[tokio::test]
    async fn test_a_hostile_issue_key_cannot_escape_the_api_path() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result = client.get_issue("TEST-123/../../../../admin").await;

        assert!(matches!(result, Err(AtlassianError::NotFound { .. })));

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url.path(),
            "/rest/api/2/issue/TEST-123%2F..%2F..%2F..%2F..%2Fadmin"
        );
    }

    #[tokio::test]
    async fn test_a_rejected_path_segment_sends_no_request() {
        let server = MockServer::start().await;
        // No mock is mounted: the segment must be rejected before any request is sent.
        let client = create_mock_client(&server);

        assert!(matches!(
            client.get_issue("..").await,
            Err(AtlassianError::Validation { .. })
        ));
        assert!(server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty());
    }

    /// A transport whose base URL was replaced after the configuration was
    /// validated.
    ///
    /// `AtlassianConfig.base_url` is a public field and `AtlassianConfig::new`
    /// does not validate, so a destination check anchored only to
    /// `AtlassianClient::new` is a check on a value that can still change. This
    /// is what the check on the joined URL is for.
    fn transport_with_unvalidated_base(base_url: &str, policy: HostPolicy) -> Transport {
        let config = AtlassianConfig::new(
            base_url.to_string(),
            "test@example.com".to_string(),
            "test-token",
        )
        .unwrap()
        .with_host_policy(policy);
        Transport::new(config).unwrap()
    }

    #[test]
    fn test_the_joined_url_is_checked_against_the_host_policy() {
        for (base_url, policy) in [
            ("http://attacker.example", HostPolicy::Loopback),
            ("https://attacker.example", HostPolicy::AtlassianCloud),
            ("http://127.0.0.1:9999", HostPolicy::AtlassianCloud),
        ] {
            let transport = transport_with_unvalidated_base(base_url, policy.clone());

            let error = transport
                .build_url(&["rest", "api", "2", "issue", "TEST-1"])
                .unwrap_err();

            assert!(
                matches!(error, AtlassianError::Configuration { .. }),
                "{base_url} under {policy} produced {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_refused_destination_sends_no_request_on_any_endpoint() {
        // Every endpoint reaches the wire through the same builder, so one
        // refusal covers all of them -- including the attachment upload, whose
        // multipart body used to bypass the shared request path entirely.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let attachment_path = std::env::temp_dir().join(format!(
            "threatflux-atlassian-refused-attachment-{}.txt",
            std::process::id()
        ));
        fs::write(&attachment_path, b"must not be uploaded").unwrap();

        // Built against the mock, then re-pointed at a host the policy refuses.
        let mut client = create_mock_client(&server);
        client.transport.config.base_url = Url::parse("http://attacker.example/").unwrap();

        let read = client.get_issue("TEST-123").await.unwrap_err();
        let comment = client
            .add_issue_comment("TEST-123", "body")
            .await
            .unwrap_err();
        let attachment = client
            .add_issue_attachment("TEST-123", &attachment_path)
            .await
            .unwrap_err();
        fs::remove_file(&attachment_path).unwrap();

        for error in [read, comment, attachment] {
            assert!(
                matches!(error, AtlassianError::Configuration { .. }),
                "expected a configuration refusal, got {error:?}"
            );
        }
        assert!(server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty());
    }

    #[test]
    fn test_certificate_verification_is_only_relaxed_where_tls_happens() {
        // `danger_accept_invalid_certs` is not readable back off a built
        // `reqwest::Client`, so the warning the branch emits stands in for it.
        const WARNING: &str = "TLS certificate verification is disabled";

        let ((), cleartext_log) = logs::capture(|| {
            let config = AtlassianConfig::new(
                "http://127.0.0.1:9999".to_string(),
                "test@example.com".to_string(),
                "test-token",
            )
            .unwrap()
            .with_host_policy(HostPolicy::Loopback)
            .with_ssl_verification(false);
            Transport::new(config).unwrap();
        });
        assert!(
            !cleartext_log.contains(WARNING),
            "an http base URL negotiates no TLS to relax; log was: {cleartext_log}"
        );

        let ((), tls_log) = logs::capture(|| {
            let config = AtlassianConfig::new(
                "https://jira.example.com".to_string(),
                "test@example.com".to_string(),
                "test-token",
            )
            .unwrap()
            .with_ssl_verification(false);
            Transport::new(config).unwrap();
        });
        assert!(tls_log.contains(WARNING), "log was: {tls_log}");
    }

    #[test]
    fn test_transport_request_carries_its_idempotency_tag() {
        let body = json!({ "body": "evidence" });
        let params = HashMap::from([("startAt".to_string(), "0".to_string())]);

        assert_eq!(
            TransportRequest::new(Method::GET, &["rest"], Idempotency::Safe)
                .query(&params)
                .idempotency(),
            Idempotency::Safe
        );
        assert_eq!(
            TransportRequest::new(Method::POST, &["rest"], Idempotency::UnsafeWrite)
                .json(&body)
                .idempotency(),
            Idempotency::UnsafeWrite
        );
        assert_eq!(
            TransportRequest::new(Method::POST, &["rest"], Idempotency::UnsafeWrite)
                .multipart(multipart::Form::new())
                .idempotency(),
            Idempotency::UnsafeWrite
        );
    }

    #[test]
    fn test_the_basic_header_carries_the_credential_itself() {
        // `SecretString` renders `<redacted>` under `Display` as well as `Debug`,
        // so the header builder interpolating it with `{}` would authenticate as
        // `test@example.com:<redacted>` and every request would 401 -- which the
        // mock tests, matching on no header at all, would not have caught.
        let header = transport_at("https://test.atlassian.net")
            .authorization_header()
            .unwrap();
        let encoded = header
            .to_str()
            .expect("a base64 header is ASCII")
            .strip_prefix("Basic ")
            .expect("the header is Basic auth")
            .to_string();

        assert_eq!(
            String::from_utf8(BASE64_STANDARD.decode(encoded).unwrap()).unwrap(),
            "test@example.com:test-token"
        );
    }

    #[test]
    fn test_the_basic_header_is_marked_sensitive() {
        // reqwest and hyper print a `HeaderMap` in their own `Debug` output and
        // in some error text; a sensitive value renders as `Sensitive` there.
        let header = transport_at("https://test.atlassian.net")
            .authorization_header()
            .unwrap();

        assert!(header.is_sensitive());

        let rendered = format!("{header:?}");
        assert_eq!(rendered, "Sensitive");
        SecretScanner::new()
            .with_basic_credentials("api token", "test@example.com", "test-token")
            .assert_clean("the debug rendering of the Basic header", &rendered);
    }

    #[tokio::test]
    async fn test_the_credential_reaches_the_wire_unredacted() {
        let server = MockServer::start().await;
        let expected = format!(
            "Basic {}",
            BASE64_STANDARD.encode("test@example.com:test-token")
        );

        Mock::given(method("GET"))
            .and(path("/rest/api/2/myself"))
            .and(header("authorization", expected.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accountId": "account-123",
                "displayName": "Allen Example",
                "active": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let user = client.get_myself().await.unwrap();

        assert_eq!(user.account_id.as_deref(), Some("account-123"));
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
    fn test_a_search_does_not_log_the_query_it_sends() {
        // A dedupe query carries the caller's label scheme, and a reconciliation
        // query can carry summary text taken from an event body. Neither belongs
        // in a log that a workflow publishes.
        const TAIL: &str = "trailing-term-that-must-not-reach-a-log";
        let jql = format!(r#"project = "TEST" AND labels = "prefix-{TAIL}""#);
        assert!(jql.len() > PREVIEW_LIMIT, "the tail must be past the bound");

        let (result, log) = capture_async(async {
            let server = MockServer::start().await;
            mount_empty_search(&server, &jql).await;
            create_mock_client(&server).search_issues(&jql, 0, 50).await
        });

        assert_eq!(result.unwrap().total, 0);
        assert!(!log.contains(TAIL), "log was: {log}");
        assert!(!log.contains(&jql), "log was: {log}");
        assert!(
            log.contains(&format!("{}-character JQL query", jql.len())),
            "log was: {log}"
        );
        assert!(log.contains("(truncated)"), "log was: {log}");
    }

    #[test]
    fn test_creating_an_issue_does_not_log_the_whole_summary() {
        // The summary is rendered from a template over event fields, so its tail
        // is attacker-controlled text of unbounded length. The line is emitted
        // before the request, so a rejected create still exercises it.
        const TAIL: &str = "trailing-summary-text-that-must-not-reach-a-log";
        let summary = format!("[Dependabot][High] a very long advisory title {TAIL}");

        let (result, log) = capture_async(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/api/2/issue"))
                .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                    "errorMessages": ["summary: Field cannot exceed 255 characters"]
                })))
                .mount(&server)
                .await;

            create_mock_client(&server)
                .create_issue(CreateIssueRequest {
                    fields: CreateIssueFields {
                        project: ProjectReference::by_key("TEST"),
                        summary: summary.clone(),
                        issue_type: IssueTypeReference::by_name("Task"),
                        description: None,
                        assignee: None,
                        priority: None,
                        labels: None,
                        components: None,
                        parent: None,
                        custom_fields: HashMap::new(),
                    },
                })
                .await
        });

        assert!(result.is_err());
        // The property this test exists for: whatever reached the log, the
        // attacker-controlled tail is not in it. It holds however much of the
        // create path ran, including not at all.
        assert!(!log.contains(TAIL), "log was: {log}");

        // What the line itself renders is asserted on `preview` directly rather
        // than by matching the emitted text. Asserting a line is *present* tests
        // `tracing`'s global emission state, which every other test in this
        // binary shares and can settle before this one runs; that made this
        // assertion fail in CI while passing everywhere it was reproduced.
        let rendered = preview(&summary);
        assert!(!rendered.contains(TAIL), "preview was: {rendered}");
        assert!(rendered.contains("(truncated)"), "preview was: {rendered}");
        assert!(
            rendered.len() < summary.len(),
            "preview was: {rendered}, summary was {} bytes",
            summary.len()
        );
    }

    #[test]
    fn test_updating_a_custom_field_does_not_log_the_value() {
        // The value is the one argument here that a caller can point at a
        // credential -- an integration writing a rotated token into a field.
        const VALUE: &str = "s3cr3t-value-written-into-a-jira-field-and-never-into-a-log";

        let (result, log) = capture_async(async {
            let server = MockServer::start().await;
            Mock::given(method("PUT"))
                .and(path("/rest/api/2/issue/TEST-123"))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(&server)
                .await;

            create_mock_client(&server)
                .update_custom_field("TEST-123", "customfield_11024", VALUE)
                .await
        });

        result.unwrap();
        assert!(!log.contains(VALUE), "log was: {log}");
        assert!(
            log.contains("Updating custom field customfield_11024 for TEST-123"),
            "log was: {log}"
        );
    }

    #[test]
    fn test_the_logged_request_url_carries_no_query_string() {
        // `Transport::send` logs the URL `build_url` returned, and query
        // parameters are attached to the reqwest builder afterwards -- so the
        // JQL, the user-search term and the pagination cursor are not in it.
        // Asserted rather than assumed, because the log line reads as though it
        // renders the URL that was sent.
        let params = HashMap::from([("jql".to_string(), r#"labels = "secret""#.to_string())]);
        let request = TransportRequest::new(
            Method::GET,
            &["rest", "api", "2", "search"],
            Idempotency::Safe,
        )
        .query(&params);
        let url = transport_at("https://test.atlassian.net")
            .build_url(request.segments)
            .unwrap();

        assert_eq!(url.query(), None);
        assert_eq!(
            url.as_str(),
            "https://test.atlassian.net/rest/api/2/search",
            "the logged URL is built before query parameters are attached"
        );
    }

    #[test]
    fn test_a_preview_is_bounded_and_escaped() {
        // Bounded, so an unbounded value cannot be copied wholesale into a log
        // sink; escaped, so a newline inside it cannot end the log line and forge
        // the next one.
        let long = "s".repeat(4096);
        let rendered = preview(&long);

        assert!(rendered.len() < 200, "preview: {rendered}");
        assert!(!rendered.contains(&long));
        assert!(rendered.contains("(truncated)"));

        assert_eq!(preview("high"), r#""high""#);
        assert_eq!(
            preview("one\ntwo"),
            r#""one\ntwo""#,
            "a newline must not survive as a line break"
        );
    }

    #[test]
    fn test_the_diagnostics_policy_defaults_to_metadata_only_and_survives_a_clone() {
        let client = AtlassianClient::new(create_test_config()).unwrap();
        assert_eq!(client.diagnostics(), DiagnosticsPolicy::MetadataOnly);

        let widened = client.with_diagnostics(DiagnosticsPolicy::IncludeBody);
        let cloned = widened.clone();
        assert_eq!(widened.diagnostics(), DiagnosticsPolicy::IncludeBody);
        assert_eq!(
            cloned.diagnostics(),
            DiagnosticsPolicy::IncludeBody,
            "an `Arc`-shared client must not silently narrow the policy"
        );
    }

    #[test]
    fn test_a_failing_response_keeps_its_body_out_of_the_error_and_the_log() {
        // A Jira error document echoes the request that produced it, and the
        // workflow log this process writes into is world-readable on a public
        // repository.
        const MARKER: &str = "jira-response-text-that-must-not-escape";

        let (result, log) = capture_async(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/api/2/issue/TEST-123"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                    "errorMessages": [MARKER],
                })))
                .mount(&server)
                .await;

            create_mock_client(&server).get_issue("TEST-123").await
        });

        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Jira API error: Jira API request failed with HTTP 500"
        );
        assert!(!log.contains(MARKER), "log was: {log}");
        assert_eq!(
            error.diagnostics().map(|diagnostics| diagnostics.policy),
            Some(DiagnosticsPolicy::MetadataOnly)
        );
        assert!(error
            .diagnostics()
            .is_some_and(|diagnostics| diagnostics.body.is_none()));
    }

    #[test]
    fn test_a_client_can_opt_into_the_jira_error_fields() {
        const DETAIL: &str = "Field 'summary' is required";

        let (result, log) = capture_async(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/api/2/issue/TEST-123"))
                .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                    "errorMessages": [DETAIL],
                })))
                .mount(&server)
                .await;

            create_mock_client(&server)
                .with_diagnostics(DiagnosticsPolicy::JiraErrorFields)
                .get_issue("TEST-123")
                .await
        });

        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("Jira API error: Jira API request failed with HTTP 400: {DETAIL}")
        );
        assert!(
            !log.contains(DETAIL),
            "the opt-in widens the error, not the log: {log}"
        );
    }

    #[test]
    fn test_a_preview_never_splits_a_character() {
        // The bound counts characters rather than bytes; a byte slice at 48 would
        // panic partway through a 4-byte emoji.
        let emoji = "\u{1f512}".repeat(PREVIEW_LIMIT * 2);
        let rendered = preview(&emoji);

        assert!(rendered.contains("(truncated)"));
        assert_eq!(
            rendered.matches('\u{1f512}').count(),
            PREVIEW_LIMIT,
            "preview: {rendered}"
        );
    }
}
