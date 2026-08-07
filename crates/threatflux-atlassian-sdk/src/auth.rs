//! Legacy OAuth helpers for the retired Atlassian Remote MCP implementation.
//!
//! These helpers generate a PKCE authorization URL and exchange caller-supplied
//! callback values, but they do not host a callback server or persist tokens. The
//! associated client targets an endpoint Atlassian stopped supporting after June 30,
//! 2026 and is not compatible with the current Rovo MCP service.

use crate::error::{
    map_error_response, AtlassianError, DiagnosticsPolicy, FailureContext, FailureShape, Result,
};
use crate::secret::{zeroize_string, SecretString};
use base64::Engine;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use url::Url;

/// OAuth configuration used by the legacy Remote MCP flow.
///
/// Not `Serialize`: `code_verifier` is the PKCE secret that binds an
/// authorization code to this client, so a serialized configuration is a
/// serialized credential. `Deserialize` is kept, and a deserialized
/// configuration simply carries no verifier until one is generated.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    /// Client ID for OAuth application
    pub client_id: String,
    /// Authorization endpoint URL
    pub authorization_endpoint: Url,
    /// Token endpoint URL
    pub token_endpoint: Url,
    /// Redirect URI for OAuth callback
    pub redirect_uri: Url,
    /// OAuth scopes requested
    pub scopes: Vec<String>,
    /// PKCE code verifier for enhanced security
    pub code_verifier: Option<SecretString>,
    /// State parameter for CSRF protection
    pub state: Option<String>,
}

/// OAuth access token information
///
/// Not `Serialize`: the access and refresh tokens are bearer credentials, and a
/// token that can be written to a cache file or a log line is a token that will
/// be. `Deserialize` is kept because a stored token has to be readable.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessToken {
    /// The access token string
    pub access_token: SecretString,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Token expiration timestamp
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Refresh token for renewals
    pub refresh_token: Option<SecretString>,
    /// Granted scopes
    pub scope: Option<String>,
}

/// Authorization server response
#[derive(Debug, Deserialize)]
pub struct AuthorizationResponse {
    /// Authorization code from OAuth flow
    pub code: SecretString,
    /// State parameter for validation
    pub state: Option<String>,
}

/// Token endpoint response
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: SecretString,
    /// Token type
    pub token_type: String,
    /// Expires in seconds
    pub expires_in: Option<u64>,
    /// Refresh token
    pub refresh_token: Option<SecretString>,
    /// Granted scope
    pub scope: Option<String>,
}

/// Authorization manager for OAuth 2.1 flow
#[derive(Debug)]
pub struct AuthManager {
    /// OAuth configuration
    config: OAuthConfig,
    /// HTTP client for token requests
    client: reqwest::Client,
    /// Current access token
    token: Arc<RwLock<Option<AccessToken>>>,
    /// How much of a failing token-endpoint response may reach an error
    diagnostics: DiagnosticsPolicy,
}

impl AuthManager {
    /// Create new authorization manager
    pub fn new(config: OAuthConfig) -> Self {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap_or_else(|err| {
                warn!(
                    ?err,
                    "failed to build HTTP client without system proxy discovery; falling back"
                );
                reqwest::Client::new()
            });
        let token = Arc::new(RwLock::new(None));

        Self {
            config,
            client,
            token,
            diagnostics: DiagnosticsPolicy::default(),
        }
    }

    /// Choose how much of a failing token-endpoint response may reach an error.
    ///
    /// A token endpoint's error body echoes the request that produced it, which on
    /// this path is a PKCE verifier and an authorization code, so the default is
    /// [`DiagnosticsPolicy::MetadataOnly`] and the body is not read at all.
    ///
    /// The setting is per-manager. [`AuthorizationProxy`] and [`McpAuthHandler`]
    /// build their own managers for the retired Remote MCP flow and leave them at
    /// the default.
    #[must_use]
    pub const fn with_diagnostics(mut self, policy: DiagnosticsPolicy) -> Self {
        self.diagnostics = policy;
        self
    }

    /// Create the hard-coded OAuth configuration used by the legacy Remote MCP flow.
    pub fn create_atlassian_oauth_config(
        client_id: String,
        redirect_uri: &str,
    ) -> Result<OAuthConfig> {
        let authorization_endpoint = Url::parse("https://auth.atlassian.com/authorize")?;
        let token_endpoint = Url::parse("https://auth.atlassian.com/oauth/token")?;
        let redirect_uri = Url::parse(redirect_uri)?;

        // Legacy hard-coded scope set; it is not verified against the current service.
        let scopes = vec![
            "read:jira-work".to_string(),
            "write:jira-work".to_string(),
            "read:jira-user".to_string(),
            "read:confluence-content.summary".to_string(),
            "write:confluence-content".to_string(),
            "read:compass".to_string(),
            "write:compass".to_string(),
        ];

        Ok(OAuthConfig {
            client_id,
            authorization_endpoint,
            token_endpoint,
            redirect_uri,
            scopes,
            code_verifier: None,
            state: None,
        })
    }

    /// Refuses a token endpoint that would carry the credential in cleartext.
    ///
    /// The requests guarded by this send the authorization code, the PKCE
    /// verifier, and the refresh token. `OAuthConfig` has public fields and
    /// derives `Deserialize`, so a checked constructor is not enough on its own
    /// -- this runs on the value actually about to be posted to, which is the
    /// same reason [`HostPolicy::check_destination`] re-runs per request.
    ///
    /// There is no loopback escape here, unlike the Jira transport: nothing in
    /// this crate posts to a mock token endpoint, so adding one would only widen
    /// the surface.
    ///
    /// [`HostPolicy::check_destination`]: crate::config::HostPolicy::check_destination
    fn check_token_endpoint(endpoint: &Url) -> Result<()> {
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            return Err(AtlassianError::config(
                "OAuth token endpoint must not carry credentials in its authority",
            ));
        }

        if endpoint.scheme() != "https" {
            return Err(AtlassianError::config(format!(
                "OAuth token endpoint must be https, but {} was addressed over '{}'",
                endpoint.host_str().unwrap_or("a host-less URL"),
                endpoint.scheme()
            )));
        }

        Ok(())
    }

    /// Generate authorization URL with PKCE
    pub fn generate_authorization_url(&mut self) -> Result<String> {
        info!("Generating OAuth 2.1 authorization URL with PKCE");

        // Generate PKCE code verifier and challenge
        let code_verifier = Self::generate_code_verifier();
        let code_challenge = Self::generate_code_challenge(code_verifier.expose_secret());

        // Generate state parameter for CSRF protection
        let state = uuid::Uuid::new_v4().to_string();

        self.config.code_verifier = Some(code_verifier);
        self.config.state = Some(state.clone());

        let mut auth_url = self.config.authorization_endpoint.clone();

        // Add OAuth 2.1 parameters
        let mut query_pairs = auth_url.query_pairs_mut();
        query_pairs.append_pair("client_id", &self.config.client_id);
        query_pairs.append_pair("response_type", "code");
        query_pairs.append_pair("redirect_uri", self.config.redirect_uri.as_str());
        query_pairs.append_pair("scope", &self.config.scopes.join(" "));
        query_pairs.append_pair("state", &state);
        query_pairs.append_pair("code_challenge", &code_challenge);
        query_pairs.append_pair("code_challenge_method", "S256");
        query_pairs.append_pair("audience", "api.atlassian.com");
        drop(query_pairs);

        debug!("Generated authorization URL: {}", auth_url);
        Ok(auth_url.to_string())
    }

    /// Exchange authorization code for access token
    pub async fn exchange_code_for_token(
        &self,
        auth_response: AuthorizationResponse,
    ) -> Result<AccessToken> {
        info!("Exchanging authorization code for access token");

        // Validate state parameter
        if let Some(expected_state) = &self.config.state {
            if auth_response.state.as_ref() != Some(expected_state) {
                return Err(AtlassianError::auth(
                    "Invalid state parameter - possible CSRF attack",
                ));
            }
        }

        let code_verifier = self
            .config
            .code_verifier
            .as_ref()
            .ok_or_else(|| AtlassianError::auth("Code verifier not found"))?;

        // Prepare token request
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", auth_response.code.expose_secret());
        params.insert("redirect_uri", self.config.redirect_uri.as_str());
        params.insert("client_id", &self.config.client_id);
        params.insert("code_verifier", code_verifier.expose_secret());

        Self::check_token_endpoint(&self.config.token_endpoint)?;

        let response = self
            .client
            .post(self.config.token_endpoint.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(map_error_response(
                response,
                FailureContext::new(FailureShape::OAuthToken, "Token exchange", self.diagnostics),
            )
            .await);
        }

        let token_response: TokenResponse = response.json().await?;

        let expires_at = token_response.expires_in.map(|expires_in| {
            let expires_in = i64::try_from(expires_in).unwrap_or(i64::MAX);
            chrono::Utc::now() + chrono::Duration::seconds(expires_in)
        });

        let access_token = AccessToken {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_at,
            refresh_token: token_response.refresh_token,
            scope: token_response.scope,
        };

        // Store the token
        {
            let mut token_guard = self.token.write().await;
            *token_guard = Some(access_token.clone());
        }

        info!("Successfully obtained access token");
        Ok(access_token)
    }

    /// Get current access token
    pub async fn get_access_token(&self) -> Option<AccessToken> {
        let token_guard = self.token.read().await;
        token_guard.clone()
    }

    /// Check if current token is valid and not expired
    pub async fn is_token_valid(&self) -> bool {
        self.get_access_token().await.is_some_and(|token| {
            token
                .expires_at
                .is_none_or(|expires_at| chrono::Utc::now() < expires_at)
        })
    }

    /// Refresh access token using refresh token
    pub async fn refresh_token(&self) -> Result<AccessToken> {
        info!("Refreshing access token");

        let current_token = self
            .get_access_token()
            .await
            .ok_or_else(|| AtlassianError::auth("No current token to refresh"))?;

        let refresh_token = current_token
            .refresh_token
            .ok_or_else(|| AtlassianError::auth("No refresh token available"))?;

        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token.expose_secret());
        params.insert("client_id", &self.config.client_id);

        Self::check_token_endpoint(&self.config.token_endpoint)?;

        let response = self
            .client
            .post(self.config.token_endpoint.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(map_error_response(
                response,
                FailureContext::new(FailureShape::OAuthToken, "Token refresh", self.diagnostics),
            )
            .await);
        }

        let token_response: TokenResponse = response.json().await?;

        let expires_at = token_response.expires_in.map(|expires_in| {
            let expires_in = i64::try_from(expires_in).unwrap_or(i64::MAX);
            chrono::Utc::now() + chrono::Duration::seconds(expires_in)
        });

        let access_token = AccessToken {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_at,
            refresh_token: token_response.refresh_token.or(Some(refresh_token)),
            scope: token_response.scope,
        };

        // Update stored token
        {
            let mut token_guard = self.token.write().await;
            *token_guard = Some(access_token.clone());
        }

        info!("Successfully refreshed access token");
        Ok(access_token)
    }

    /// Generate PKCE code verifier
    fn generate_code_verifier() -> SecretString {
        use rand::RngExt;
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let mut rng = rand::rng();
        let verifier: String = (0..128)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        SecretString::from(verifier)
    }

    /// Generate PKCE code challenge from verifier
    fn generate_code_challenge(code_verifier: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(code_verifier.as_bytes());
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(digest)
    }

    /// Clear stored token
    pub async fn clear_token(&self) {
        *self.token.write().await = None;
        info!("Cleared stored access token");
    }
}

/// Legacy authorization-flow coordinator; it does not run a proxy or callback server.
#[derive(Debug)]
pub struct AuthorizationProxy {
    /// OAuth configuration
    oauth_config: OAuthConfig,
    /// Authorization manager
    auth_manager: Arc<AuthManager>,
    /// Port embedded in the callback URL
    callback_port: u16,
}

impl AuthorizationProxy {
    /// Create a new legacy authorization-flow coordinator.
    pub fn new(oauth_config: OAuthConfig, callback_port: u16) -> Self {
        let auth_manager = Arc::new(AuthManager::new(oauth_config.clone()));

        Self {
            oauth_config,
            auth_manager,
            callback_port,
        }
    }

    /// Start the legacy authorization flow and return an auth URL for the caller.
    // Awaits nothing today, but it is the first half of a published async pair with
    // `handle_oauth_callback`; dropping `async` would break every caller.
    #[allow(
        clippy::unused_async,
        reason = "published async OAuth flow entry point"
    )]
    pub async fn start_authorization_flow(&mut self) -> Result<String> {
        info!("Starting OAuth 2.1 authorization flow");

        // Update the redirect URI. The caller is responsible for hosting this callback.
        self.oauth_config.redirect_uri = Url::parse(&format!(
            "http://localhost:{}/oauth/callback",
            self.callback_port
        ))?;

        // Generate authorization URL
        let mut auth_manager = AuthManager::new(self.oauth_config.clone());
        let auth_url = auth_manager.generate_authorization_url()?;

        // Store the auth manager for later use
        self.auth_manager = Arc::new(auth_manager);

        Ok(auth_url)
    }

    /// Handle OAuth callback and exchange code for token
    pub async fn handle_oauth_callback(
        &self,
        auth_response: AuthorizationResponse,
    ) -> Result<AccessToken> {
        info!("Handling OAuth callback");

        self.auth_manager
            .exchange_code_for_token(auth_response)
            .await
    }

    /// Get current access token
    pub async fn get_access_token(&self) -> Option<AccessToken> {
        self.auth_manager.get_access_token().await
    }

    /// Check if authenticated
    pub async fn is_authenticated(&self) -> bool {
        self.auth_manager.is_token_valid().await
    }
}

/// Authorization state holder for the legacy Remote MCP flow.
#[derive(Debug)]
pub struct McpAuthHandler {
    /// Authorization proxy
    proxy: AuthorizationProxy,
    /// Whether auth flow is active
    auth_flow_active: bool,
}

impl McpAuthHandler {
    /// Create a new legacy authorization handler.
    pub fn new(client_id: String, callback_port: u16) -> Result<Self> {
        let oauth_config = AuthManager::create_atlassian_oauth_config(
            client_id,
            &format!("http://localhost:{callback_port}/oauth/callback"),
        )?;

        let proxy = AuthorizationProxy::new(oauth_config, callback_port);

        Ok(Self {
            proxy,
            auth_flow_active: false,
        })
    }

    /// Generate a legacy authorization response for the caller to present.
    pub async fn generate_auth_response(&mut self) -> Result<serde_json::Value> {
        if self.proxy.is_authenticated().await {
            info!("User already authenticated");
            Ok(serde_json::json!({
                "type": "already_authenticated",
                "message": "Already authenticated with Atlassian",
                "status": "ready"
            }))
        } else {
            info!("User not authenticated, generating auth screen");

            let auth_url = self.proxy.start_authorization_flow().await?;
            self.auth_flow_active = true;

            // Return the retained runtime response; module docs describe legacy limitations.
            Ok(serde_json::json!({
                "type": "authorization_required",
                "message": "Atlassian OAuth 2.1 authorization required",
                "auth_url": auth_url,
                "instructions": [
                    "1. Click the authorization URL above",
                    "2. Sign in to your Atlassian account",
                    "3. Grant permissions for Jira, Confluence, and Compass access",
                    "4. Complete the OAuth flow to continue"
                ],
                "scopes": self.proxy.oauth_config.scopes,
                "provider": "Atlassian Cloud",
                "security_note": "This uses OAuth 2.1 with PKCE for enhanced security"
            }))
        }
    }

    /// Process callback values received and supplied by the caller.
    pub async fn process_callback(
        &mut self,
        code: impl Into<SecretString>,
        state: Option<String>,
    ) -> Result<AccessToken> {
        if !self.auth_flow_active {
            return Err(AtlassianError::auth("No active authorization flow"));
        }

        let auth_response = AuthorizationResponse {
            code: code.into(),
            state,
        };
        let token = self.proxy.handle_oauth_callback(auth_response).await?;

        self.auth_flow_active = false;
        info!("OAuth flow completed successfully");

        Ok(token)
    }

    /// Get authorization header value for authenticated requests
    ///
    /// Returns a header already marked sensitive, so reqwest and hyper render it
    /// as `Sensitive` in their own `Debug` output and error text rather than
    /// printing the bearer token. The plaintext never leaves this function: the
    /// rendered value is zeroized once the header owns a copy.
    ///
    /// Returns `None` when there is no token, and when the token cannot be
    /// rendered into a header value at all.
    pub async fn get_auth_header(&self) -> Option<HeaderValue> {
        let token = self.proxy.get_access_token().await?;

        let mut rendered = format!(
            "{} {}",
            token.token_type,
            token.access_token.expose_secret()
        );
        let header = HeaderValue::from_str(&rendered).ok().map(|mut header| {
            header.set_sensitive(true);
            header
        });
        zeroize_string(&mut rendered);

        header
    }

    /// Check if needs re-authorization
    pub async fn needs_reauth(&self) -> bool {
        !self.proxy.is_authenticated().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_endpoint_body_is_withheld_unless_the_caller_asks_for_it() {
        // A token endpoint's error body echoes the request, and on this path the
        // request carries the PKCE verifier and the authorization code.
        let config = AuthManager::create_atlassian_oauth_config(
            "test-client-id".to_string(),
            "http://localhost:8080/callback",
        )
        .unwrap();
        let manager = AuthManager::new(config);

        assert_eq!(manager.diagnostics, DiagnosticsPolicy::MetadataOnly);
        assert_eq!(
            manager
                .with_diagnostics(DiagnosticsPolicy::IncludeBody)
                .diagnostics,
            DiagnosticsPolicy::IncludeBody
        );
    }

    #[test]
    fn a_cleartext_token_endpoint_is_refused_before_the_verifier_is_sent() {
        // This request carries the authorization code and the PKCE verifier, so
        // the refusal has to happen before the POST, not at construction: the
        // fields are public and the type deserializes.
        for endpoint in [
            "http://auth.atlassian.com/oauth/token",
            "http://127.0.0.1:8080/oauth/token",
        ] {
            let error = AuthManager::check_token_endpoint(&Url::parse(endpoint).unwrap())
                .expect_err("a cleartext token endpoint must be refused");
            let rendered = error.to_string();
            assert!(rendered.contains("must be https"), "error was: {rendered}");
        }

        AuthManager::check_token_endpoint(
            &Url::parse("https://auth.atlassian.com/oauth/token").unwrap(),
        )
        .expect("the real token endpoint must still be accepted");
    }

    #[test]
    fn a_token_endpoint_carrying_credentials_is_refused() {
        let error = AuthManager::check_token_endpoint(
            &Url::parse("https://user:p4ssw0rd-CANARY@auth.atlassian.com/oauth/token").unwrap(),
        )
        .expect_err("userinfo in the token endpoint must be refused");

        let rendered = error.to_string();
        assert!(
            !rendered.contains("p4ssw0rd-CANARY"),
            "error echoed the credential: {rendered}"
        );
    }

    #[tokio::test]
    async fn the_mcp_bearer_header_is_marked_sensitive() {
        // reqwest and hyper print a HeaderMap in their own Debug output, so an
        // unmarked bearer header reaches those channels in full. The Jira
        // transport marks its Basic header the same way.
        let mut header = HeaderValue::from_str("Bearer token-CANARY").unwrap();
        header.set_sensitive(true);

        assert!(header.is_sensitive());
        let rendered = format!("{header:?}");
        assert!(
            !rendered.contains("token-CANARY"),
            "a sensitive header still rendered its value: {rendered}"
        );
    }

    #[test]
    fn test_oauth_config_creation() {
        let config = AuthManager::create_atlassian_oauth_config(
            "test-client-id".to_string(),
            "http://localhost:8080/callback",
        )
        .unwrap();

        assert_eq!(config.client_id, "test-client-id");
        assert!(config.scopes.contains(&"read:jira-work".to_string()));
        assert!(config
            .authorization_endpoint
            .as_str()
            .contains("auth.atlassian.com"));
    }

    #[test]
    fn test_access_token_deserialization() {
        // This test used to round-trip an `AccessToken` through
        // `serde_json::to_string`, which made "a bearer token can be serialized"
        // a de-facto contract of this crate. The contract is withdrawn: the read
        // direction is what a token endpoint response and a stored token need,
        // and it is asserted here; the write direction no longer compiles, which
        // `SecretString`'s own `compile_fail` doctest pins.
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
        let deserialized: AccessToken = serde_json::from_value(serde_json::json!({
            "access_token": "test-token",
            "token_type": "Bearer",
            "expires_at": expires_at,
            "refresh_token": "refresh-token",
            "scope": "read:jira-work",
        }))
        .unwrap();

        assert_eq!(deserialized.access_token.expose_secret(), "test-token");
        assert_eq!(deserialized.token_type, "Bearer");
        assert_eq!(
            deserialized.refresh_token.as_ref().unwrap().expose_secret(),
            "refresh-token"
        );
        assert_eq!(deserialized.scope.as_deref(), Some("read:jira-work"));
        assert_eq!(deserialized.expires_at, Some(expires_at));
    }

    #[test]
    fn test_access_token_debug_does_not_print_the_credentials() {
        let token: AccessToken = serde_json::from_value(serde_json::json!({
            "access_token": "at-s3cr3t",
            "token_type": "Bearer",
            "refresh_token": "rt-s3cr3t",
        }))
        .unwrap();

        let rendered = format!("{token:?}");

        assert!(!rendered.contains("at-s3cr3t"), "rendered: {rendered}");
        assert!(!rendered.contains("rt-s3cr3t"), "rendered: {rendered}");
        assert!(rendered.contains("Bearer"), "rendered: {rendered}");
    }

    #[test]
    fn test_an_oauth_config_debug_does_not_print_the_code_verifier() {
        // The verifier is what binds an authorization code to this client, so a
        // config dumped into a log is a config whose PKCE protection is gone.
        let mut manager = AuthManager::new(
            AuthManager::create_atlassian_oauth_config(
                "test-client-id".to_string(),
                "http://localhost:8080/callback",
            )
            .unwrap(),
        );
        manager.generate_authorization_url().unwrap();

        let verifier = manager
            .config
            .code_verifier
            .as_ref()
            .expect("the flow stores a verifier")
            .expose_secret()
            .to_string();
        let rendered = format!("{:?}", manager.config);

        assert!(!rendered.contains(&verifier), "rendered: {rendered}");
        assert!(rendered.contains("test-client-id"), "rendered: {rendered}");
    }

    #[test]
    fn test_an_authorization_code_is_not_printed_either() {
        let response: AuthorizationResponse = serde_json::from_value(serde_json::json!({
            "code": "authcode-s3cr3t",
            "state": "csrf-state",
        }))
        .unwrap();

        let rendered = format!("{response:?}");

        assert_eq!(response.code.expose_secret(), "authcode-s3cr3t");
        assert!(
            !rendered.contains("authcode-s3cr3t"),
            "rendered: {rendered}"
        );
        assert!(rendered.contains("csrf-state"), "rendered: {rendered}");
    }

    #[test]
    fn test_a_token_endpoint_response_parses_into_the_secret_type() {
        let response: TokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt-1",
            "scope": "read:jira-work",
        }))
        .unwrap();

        assert_eq!(response.access_token.expose_secret(), "at-1");
        assert_eq!(
            response.refresh_token.as_ref().unwrap().expose_secret(),
            "rt-1"
        );
        assert!(
            !format!("{response:?}").contains("at-1"),
            "the response prints its own token"
        );
    }

    #[test]
    fn test_pkce_generation() {
        let _auth_manager = AuthManager::new(
            AuthManager::create_atlassian_oauth_config(
                "test".to_string(),
                "http://localhost:8080/callback",
            )
            .unwrap(),
        );

        let code_verifier = AuthManager::generate_code_verifier();
        let exposed = code_verifier.expose_secret();
        assert!(exposed.len() >= 43 && exposed.len() <= 128);
        assert!(
            !format!("{code_verifier:?}").contains(exposed),
            "the verifier prints itself"
        );

        let code_challenge = AuthManager::generate_code_challenge(exposed);
        assert_eq!(code_challenge.len(), 43); // Base64 URL-safe encoded SHA256 hash
    }
}
