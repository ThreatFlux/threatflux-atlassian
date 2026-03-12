//! OAuth 2.1 authentication for Atlassian Remote MCP Server
//!
//! This module implements OAuth 2.1 authentication flow for connecting to
//! Atlassian's Remote MCP Server at <https://mcp.atlassian.com/v1/sse>

use crate::error::{AtlassianError, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use url::Url;

/// OAuth 2.1 configuration for Atlassian Remote MCP Server
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub code_verifier: Option<String>,
    /// State parameter for CSRF protection
    pub state: Option<String>,
}

/// OAuth access token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The access token string
    pub access_token: String,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Token expiration timestamp
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Refresh token for renewals
    pub refresh_token: Option<String>,
    /// Granted scopes
    pub scope: Option<String>,
}

/// Authorization server response
#[derive(Debug, Deserialize)]
pub struct AuthorizationResponse {
    /// Authorization code from OAuth flow
    pub code: String,
    /// State parameter for validation
    pub state: Option<String>,
}

/// Token endpoint response
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,
    /// Token type
    pub token_type: String,
    /// Expires in seconds
    pub expires_in: Option<u64>,
    /// Refresh token
    pub refresh_token: Option<String>,
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
        }
    }

    /// Create OAuth configuration for Atlassian Remote MCP Server
    pub fn create_atlassian_oauth_config(
        client_id: String,
        redirect_uri: &str,
    ) -> Result<OAuthConfig> {
        let authorization_endpoint = Url::parse("https://auth.atlassian.com/authorize")?;
        let token_endpoint = Url::parse("https://auth.atlassian.com/oauth/token")?;
        let redirect_uri = Url::parse(redirect_uri)?;

        // Standard Atlassian OAuth scopes for MCP operations
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

    /// Generate authorization URL with PKCE
    pub fn generate_authorization_url(&mut self) -> Result<String> {
        info!("Generating OAuth 2.1 authorization URL with PKCE");

        // Generate PKCE code verifier and challenge
        let code_verifier = Self::generate_code_verifier();
        let code_challenge = Self::generate_code_challenge(&code_verifier);

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
        params.insert("code", &auth_response.code);
        params.insert("redirect_uri", self.config.redirect_uri.as_str());
        params.insert("client_id", &self.config.client_id);
        params.insert("code_verifier", code_verifier);

        let response = self
            .client
            .post(self.config.token_endpoint.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AtlassianError::auth(format!(
                "Token exchange failed: {error_text}"
            )));
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
        self.get_access_token().await.map_or(false, |token| {
            token
                .expires_at
                .map_or(true, |expires_at| chrono::Utc::now() < expires_at)
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
        params.insert("refresh_token", &refresh_token);
        params.insert("client_id", &self.config.client_id);

        let response = self
            .client
            .post(self.config.token_endpoint.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AtlassianError::auth(format!(
                "Token refresh failed: {error_text}"
            )));
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
    fn generate_code_verifier() -> String {
        use rand::RngExt;
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let mut rng = rand::rng();
        (0..128)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
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

/// Authorization proxy server for handling OAuth flow within MCP
#[derive(Debug)]
pub struct AuthorizationProxy {
    /// OAuth configuration
    oauth_config: OAuthConfig,
    /// Authorization manager
    auth_manager: Arc<AuthManager>,
    /// Server port for OAuth callbacks
    callback_port: u16,
}

impl AuthorizationProxy {
    /// Create new authorization proxy
    pub fn new(oauth_config: OAuthConfig, callback_port: u16) -> Self {
        let auth_manager = Arc::new(AuthManager::new(oauth_config.clone()));

        AuthorizationProxy {
            oauth_config,
            auth_manager,
            callback_port,
        }
    }

    /// Start authorization flow and return auth URL for user
    pub async fn start_authorization_flow(&mut self) -> Result<String> {
        info!("Starting OAuth 2.1 authorization flow");

        // Update redirect URI to use local callback server
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

/// MCP authorization handler for embedding auth flow in MCP responses
#[derive(Debug)]
pub struct McpAuthHandler {
    /// Authorization proxy
    proxy: AuthorizationProxy,
    /// Whether auth flow is active
    auth_flow_active: bool,
}

impl McpAuthHandler {
    /// Create new MCP auth handler
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

    /// Generate MCP authorization response with embedded auth screen
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

            // Return MCP response with auth screen
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

    /// Process OAuth callback from authorization flow
    pub async fn process_callback(
        &mut self,
        code: String,
        state: Option<String>,
    ) -> Result<AccessToken> {
        if !self.auth_flow_active {
            return Err(AtlassianError::auth("No active authorization flow"));
        }

        let auth_response = AuthorizationResponse { code, state };
        let token = self.proxy.handle_oauth_callback(auth_response).await?;

        self.auth_flow_active = false;
        info!("OAuth flow completed successfully");

        Ok(token)
    }

    /// Get authorization header value for authenticated requests
    pub async fn get_auth_header(&self) -> Option<String> {
        if let Some(token) = self.proxy.get_access_token().await {
            Some(format!("{} {}", token.token_type, token.access_token))
        } else {
            None
        }
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
    fn test_access_token_serialization() {
        let token = AccessToken {
            access_token: "test-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            refresh_token: Some("refresh-token".to_string()),
            scope: Some("read:jira-work".to_string()),
        };

        let serialized = serde_json::to_string(&token);
        assert!(serialized.is_ok());

        let deserialized: AccessToken = serde_json::from_str(&serialized.unwrap()).unwrap();
        assert_eq!(deserialized.access_token, token.access_token);
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
        assert!(code_verifier.len() >= 43 && code_verifier.len() <= 128);

        let code_challenge = AuthManager::generate_code_challenge(&code_verifier);
        assert_eq!(code_challenge.len(), 43); // Base64 URL-safe encoded SHA256 hash
    }
}
