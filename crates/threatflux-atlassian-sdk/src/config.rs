//! Configuration management for the Atlassian Rust SDK
//!
//! This module handles Jira authentication, SSL settings, and client configuration
//! based on environment variables and explicit configuration options.

use crate::error::{AtlassianError, Result};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use fluxencrypt::env::secrets::{EnvSecret, SecretFormat};
use fluxencrypt::error::FluxError;
use fluxencrypt::keys::parsing;
use fluxencrypt::{Config as FluxConfig, HybridCipher};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

/// Configuration for Atlassian/Jira API client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlassianConfig {
    /// Jira base URL (e.g., `https://company.atlassian.net`)
    pub base_url: Url,
    /// Jira username (email for cloud instances)
    pub username: String,
    /// API token (used as password for authentication)
    pub api_token: String,
    /// Request timeout duration
    pub timeout: Duration,
    /// Path to custom SSL certificate bundle
    pub cert_path: Option<PathBuf>,
    /// Whether to verify SSL certificates
    pub verify_ssl: bool,
    /// Maximum number of retry attempts for failed requests
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff)
    pub retry_delay: Duration,
    /// User agent string for requests
    pub user_agent: String,
}

impl AtlassianConfig {
    /// Create a new configuration with required parameters
    ///
    /// # Arguments
    /// * `base_url` - Jira instance URL
    /// * `username` - Jira username (usually email)
    /// * `api_token` - Jira API token
    ///
    /// # Example
    /// ```rust
    /// use threatflux_atlassian_sdk::AtlassianConfig;
    ///
    /// let config = AtlassianConfig::new(
    ///     "https://company.atlassian.net".to_string(),
    ///     "user@company.com".to_string(),
    ///     "your-api-token".to_string()
    /// ).unwrap();
    /// ```
    pub fn new(base_url: String, username: String, api_token: String) -> Result<Self> {
        let parsed_url = Url::parse(&base_url)
            .map_err(|e| AtlassianError::config(format!("Invalid base URL: {e}")))?;

        Ok(AtlassianConfig {
            base_url: parsed_url,
            username,
            api_token,
            timeout: Duration::from_secs(60),
            cert_path: None,
            verify_ssl: true,
            max_retries: 3,
            retry_delay: Duration::from_millis(1000),
            user_agent: format!("atlassian-rust-sdk/{}", env!("CARGO_PKG_VERSION")),
        })
    }

    /// Create configuration from environment variables
    ///
    /// Expected environment variables:
    /// * `JIRA_URL` - Jira instance URL (required)
    /// * `JIRA_USERNAME` - Jira username/email (required)
    /// * `JIRA_API_TOKEN` - Jira API token (required)
    ///   * You can instead supply `JIRA_USERNAME_ENCRYPTED` / `JIRA_API_TOKEN_ENCRYPTED` along with
    ///     `JIRA_USERNAME_PRIVATE_KEY` / `JIRA_API_TOKEN_PRIVATE_KEY` (and optional
    ///     `<VAR>_PRIVATE_KEY_PASSWORD`) containing FluxEncrypt-compatible private keys.
    /// * `JIRA_TIMEOUT` - Request timeout in seconds (optional, default: 60)
    /// * `JIRA_CERT_PATH` - Path to custom certificate file (optional)
    /// * `JIRA_VERIFY_SSL` - Enable/disable SSL verification (optional, default: true)
    /// * `JIRA_MAX_RETRIES` - Maximum retry attempts (optional, default: 3)
    ///
    /// Encrypted environment variables must contain base64 ciphertext generated via
    /// `fluxencrypt::HybridCipher::encrypt`.
    ///
    /// # Example
    /// ```rust
    /// use threatflux_atlassian_sdk::AtlassianConfig;
    ///
    /// // Set environment variables first
    /// std::env::set_var("JIRA_URL", "https://company.atlassian.net");
    /// std::env::set_var("JIRA_USERNAME", "user@company.com");
    /// std::env::set_var("JIRA_API_TOKEN", "your-api-token");
    ///
    /// let config = AtlassianConfig::from_env().unwrap();
    /// ```
    pub fn from_env() -> Result<Self> {
        load_encrypted_env_file_if_present()?;

        let base_url = env::var("JIRA_URL")
            .map_err(|_| AtlassianError::config("JIRA_URL environment variable not set"))?;

        let username = load_required_secret("JIRA_USERNAME")?;
        let api_token = load_required_secret("JIRA_API_TOKEN")?;

        let mut config = Self::new(base_url, username, api_token)?;

        // Optional timeout configuration
        if let Ok(timeout_str) = env::var("JIRA_TIMEOUT") {
            if let Ok(timeout_secs) = timeout_str.parse::<u64>() {
                config.timeout = Duration::from_secs(timeout_secs);
            } else {
                return Err(AtlassianError::config("Invalid JIRA_TIMEOUT value"));
            }
        }

        // Optional SSL certificate path
        if let Ok(cert_path) = env::var("JIRA_CERT_PATH") {
            config.cert_path = Some(PathBuf::from(cert_path));
        }

        // SSL verification setting
        if let Ok(verify_ssl_str) = env::var("JIRA_VERIFY_SSL") {
            config.verify_ssl = verify_ssl_str.to_lowercase() != "false";
        }

        // Optional max retries
        if let Ok(retries_str) = env::var("JIRA_MAX_RETRIES") {
            if let Ok(retries) = retries_str.parse::<u32>() {
                config.max_retries = retries;
            }
        }

        Ok(config)
    }

    /// Builder pattern for configuration
    pub fn builder() -> AtlassianConfigBuilder {
        AtlassianConfigBuilder::new()
    }

    /// Set custom timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set custom certificate path
    pub fn with_cert_path(mut self, cert_path: PathBuf) -> Self {
        self.cert_path = Some(cert_path);
        self
    }

    /// Disable SSL verification (not recommended for production)
    pub fn with_ssl_verification(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    /// Set retry configuration
    pub fn with_retries(mut self, max_retries: u32, delay: Duration) -> Self {
        self.max_retries = max_retries;
        self.retry_delay = delay;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.username.is_empty() {
            return Err(AtlassianError::config("Username cannot be empty"));
        }

        if self.api_token.is_empty() {
            return Err(AtlassianError::config("API token cannot be empty"));
        }

        if self.base_url.scheme() != "https" && self.verify_ssl {
            return Err(AtlassianError::config(
                "SSL verification enabled but URL is not HTTPS",
            ));
        }

        if let Some(cert_path) = &self.cert_path {
            if !cert_path.exists() {
                return Err(AtlassianError::config(format!(
                    "Certificate file does not exist: {}",
                    cert_path.display()
                )));
            }
        }

        Ok(())
    }
}

/// Builder for AtlassianConfig
#[derive(Debug)]
pub struct AtlassianConfigBuilder {
    base_url: Option<String>,
    username: Option<String>,
    api_token: Option<String>,
    timeout: Duration,
    cert_path: Option<PathBuf>,
    verify_ssl: bool,
    max_retries: u32,
    retry_delay: Duration,
}

impl AtlassianConfigBuilder {
    /// Create a new configuration builder
    pub fn new() -> Self {
        AtlassianConfigBuilder {
            base_url: None,
            username: None,
            api_token: None,
            timeout: Duration::from_secs(60),
            cert_path: None,
            verify_ssl: true,
            max_retries: 3,
            retry_delay: Duration::from_millis(1000),
        }
    }

    /// Set the Jira base URL
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Set the username
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the API token
    pub fn api_token(mut self, token: impl Into<String>) -> Self {
        self.api_token = Some(token.into());
        self
    }

    /// Set the request timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the SSL certificate path
    pub fn cert_path(mut self, path: PathBuf) -> Self {
        self.cert_path = Some(path);
        self
    }

    /// Set SSL verification
    pub fn verify_ssl(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    /// Set retry configuration
    pub fn retries(mut self, max_retries: u32, delay: Duration) -> Self {
        self.max_retries = max_retries;
        self.retry_delay = delay;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<AtlassianConfig> {
        let base_url = self
            .base_url
            .ok_or_else(|| AtlassianError::config("Base URL is required"))?;
        let username = self
            .username
            .ok_or_else(|| AtlassianError::config("Username is required"))?;
        let api_token = self
            .api_token
            .ok_or_else(|| AtlassianError::config("API token is required"))?;

        let parsed_url = Url::parse(&base_url)
            .map_err(|e| AtlassianError::config(format!("Invalid base URL: {e}")))?;

        let config = AtlassianConfig {
            base_url: parsed_url,
            username,
            api_token,
            timeout: self.timeout,
            cert_path: self.cert_path,
            verify_ssl: self.verify_ssl,
            max_retries: self.max_retries,
            retry_delay: self.retry_delay,
            user_agent: format!("atlassian-rust-sdk/{}", env!("CARGO_PKG_VERSION")),
        };

        config.validate()?;
        Ok(config)
    }
}

impl Default for AtlassianConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn load_encrypted_env_file_if_present() -> Result<()> {
    use std::env::VarError;

    let (ciphertext, source) = match env::var("ENV_FILE_ENCRYPTED_PATH") {
        Ok(path) => {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                return Err(AtlassianError::config(
                    "ENV_FILE_ENCRYPTED_PATH is set but empty",
                ));
            }

            let path_buf = PathBuf::from(trimmed);
            let contents = fs::read_to_string(&path_buf).map_err(|err| {
                AtlassianError::config(format!(
                    "Failed to read encrypted env file at {}: {err}",
                    path_buf.display()
                ))
            })?;

            (
                contents,
                format!("ENV_FILE_ENCRYPTED_PATH ({})", path_buf.display()),
            )
        }
        Err(VarError::NotPresent) => match env::var("ENV_FILE_ENCRYPTED") {
            Ok(value) => {
                if value.trim().is_empty() {
                    return Err(AtlassianError::config(
                        "ENV_FILE_ENCRYPTED is set but empty",
                    ));
                }
                (value, "ENV_FILE_ENCRYPTED".to_string())
            }
            Err(VarError::NotPresent) => return Ok(()),
            Err(err) => {
                return Err(AtlassianError::config(format!(
                    "Failed to read ENV_FILE_ENCRYPTED: {err}"
                )));
            }
        },
        Err(err) => {
            return Err(AtlassianError::config(format!(
                "Failed to read ENV_FILE_ENCRYPTED_PATH: {err}"
            )));
        }
    };

    let decrypted = decrypt_secret_for_base("ENV_FILE", ciphertext)?;
    dotenvy::from_read_override(decrypted.as_bytes()).map_err(|err| {
        AtlassianError::config(format!(
            "Failed to load decrypted environment file from {source}: {err}"
        ))
    })?;

    Ok(())
}

fn load_required_secret(base: &str) -> Result<String> {
    match load_secret(base)? {
        Some(value) => Ok(value),
        None => Err(AtlassianError::config(format!(
            "{base} environment variable not set"
        ))),
    }
}

fn load_secret(base: &str) -> Result<Option<String>> {
    match env::var(base) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(AtlassianError::config(format!("{base} is set but empty")));
            }
            return Ok(Some(trimmed.to_string()));
        }
        Err(env::VarError::NotPresent) => {}
        Err(err) => {
            return Err(AtlassianError::config(format!(
                "Failed to read {base}: {err}"
            )));
        }
    }

    let encrypted_var = format!("{base}_ENCRYPTED");
    let ciphertext = match env::var(&encrypted_var) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(err) => {
            return Err(AtlassianError::config(format!(
                "Failed to read {encrypted_var}: {err}",
            )));
        }
    };

    let decrypted = decrypt_secret_for_base(base, ciphertext)?;
    Ok(Some(decrypted))
}

fn decrypt_secret_for_base(base: &str, ciphertext: String) -> Result<String> {
    let encrypted_var = format!("{base}_ENCRYPTED");
    let private_key_var = format!("{base}_PRIVATE_KEY");
    let password_var = format!("{base}_PRIVATE_KEY_PASSWORD");

    let encoded: String = ciphertext.split_whitespace().collect();
    if encoded.is_empty() {
        return Err(AtlassianError::config(format!(
            "{encrypted_var} is set but empty"
        )));
    }

    let encrypted_bytes = BASE64_ENGINE.decode(encoded.as_bytes()).map_err(|err| {
        AtlassianError::config(format!("Failed to decode {encrypted_var}: {err}"))
    })?;

    let private_key_value = env::var(&private_key_var).map_err(|err| {
        AtlassianError::config(format!(
            "{private_key_var} must be set when {encrypted_var} is provided ({err})",
        ))
    })?;

    if private_key_value.trim().is_empty() {
        return Err(AtlassianError::config(format!(
            "{private_key_var} is set but empty"
        )));
    }

    let secret = parse_private_key_secret(private_key_value)
        .map_err(|err| flux_error_to_config("Failed to parse private key", err))?;

    if secret.is_empty() {
        return Err(AtlassianError::config("Private key secret is empty"));
    }

    let password = match env::var(&password_var) {
        Ok(value) => {
            if value.is_empty() {
                return Err(AtlassianError::config(format!(
                    "{password_var} is set but empty"
                )));
            }
            Some(value)
        }
        Err(env::VarError::NotPresent) => None,
        Err(err) => {
            return Err(AtlassianError::config(format!(
                "Failed to read {password_var}: {err}"
            )));
        }
    };

    let private_key = if let Some(password) = password {
        let pem = secret
            .as_string()
            .map_err(|err| flux_error_to_config("Failed to decode private key bytes", err))?;
        parsing::parse_encrypted_private_key_from_str(&pem, &password)
            .map_err(|err| flux_error_to_config("Failed to parse encrypted private key", err))?
    } else {
        secret
            .as_private_key()
            .map_err(|err| flux_error_to_config("Failed to parse private key", err))?
    };

    let cipher = HybridCipher::new(FluxConfig::default());
    let decrypted = cipher
        .decrypt(&private_key, &encrypted_bytes)
        .map_err(|err| flux_error_to_config("Failed to decrypt secret", err))?;

    if decrypted.is_empty() {
        return Err(AtlassianError::config("Decrypted secret is empty"));
    }

    let secret_string = String::from_utf8(decrypted).map_err(|err| {
        AtlassianError::config(format!("Decrypted secret is not valid UTF-8: {err}"))
    })?;
    let trimmed = secret_string.trim();
    if trimmed.is_empty() {
        return Err(AtlassianError::config(
            "Decrypted secret contains only whitespace",
        ));
    }

    Ok(trimmed.to_string())
}

fn flux_error_to_config(context: &str, err: FluxError) -> AtlassianError {
    AtlassianError::config(format!("{context}: {err}"))
}

fn parse_private_key_secret(value: String) -> std::result::Result<EnvSecret, FluxError> {
    let mut secret = EnvSecret::from_string(value.clone())?;

    if secret.format() != SecretFormat::Raw {
        return Ok(secret);
    }

    if let Some(decoded_pem) = decode_private_key_from_base64(&value) {
        secret = EnvSecret::from_string(decoded_pem)?;
    }

    Ok(secret)
}

fn decode_private_key_from_base64(value: &str) -> Option<String> {
    let candidate: String = value.chars().filter(|c| !c.is_whitespace()).collect();

    if candidate.len() < 16 {
        return None;
    }

    if candidate
        .chars()
        .any(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '='))
    {
        return None;
    }

    if candidate.len() % 4 == 1 {
        return None;
    }

    let mut padded = candidate;
    let pad = padded.len() % 4;
    if pad != 0 {
        padded.extend(std::iter::repeat_n('=', 4 - pad));
    }

    let decoded = BASE64_ENGINE.decode(padded.as_bytes()).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;

    if decoded_str.starts_with("-----BEGIN") && decoded_str.contains("-----END") {
        Some(decoded_str)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxencrypt::keys::KeyPair;
    use serial_test::serial;
    use std::env;
    use std::time::Duration;

    #[test]
    fn test_config_creation() {
        let config = AtlassianConfig::new(
            "https://test.atlassian.net".to_string(),
            "test@example.com".to_string(),
            "test-token".to_string(),
        )
        .unwrap();

        assert_eq!(config.base_url.as_str(), "https://test.atlassian.net/");
        assert_eq!(config.username, "test@example.com");
        assert_eq!(config.api_token, "test-token");
        assert!(config.verify_ssl);
    }

    #[test]
    fn test_config_builder() {
        let config = AtlassianConfig::builder()
            .base_url("https://test.atlassian.net")
            .username("test@example.com")
            .api_token("test-token")
            .timeout(Duration::from_secs(30))
            .verify_ssl(false)
            .retries(5, Duration::from_millis(500))
            .build()
            .unwrap();

        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(!config.verify_ssl);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_delay, Duration::from_millis(500));
    }

    struct EnvGuard {
        key: String,
        original: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let original = env::var(key).ok();
            unsafe {
                env::set_var(key, value);
            }
            Self {
                key: key.to_string(),
                original,
            }
        }

        fn unset(key: &str) -> Self {
            let original = env::var(key).ok();
            unsafe {
                env::remove_var(key);
            }
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(value) => unsafe {
                    env::set_var(&self.key, value);
                },
                None => unsafe {
                    env::remove_var(&self.key);
                },
            }
        }
    }

    fn generate_ciphertext(plaintext: &str) -> (String, String) {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::new(FluxConfig::default());
        let ciphertext = cipher
            .encrypt(keypair.public_key(), plaintext.as_bytes())
            .unwrap();
        let encoded = BASE64_ENGINE.encode(ciphertext);
        let private_pem = keypair.private_key().to_pem().unwrap();
        (encoded, private_pem)
    }

    #[test]
    fn test_invalid_url() {
        let result = AtlassianConfig::new(
            "not-a-url".to_string(),
            "test@example.com".to_string(),
            "test-token".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validation() {
        let config = AtlassianConfig::new(
            "https://test.atlassian.net".to_string(),
            "".to_string(), // Empty username
            "test-token".to_string(),
        )
        .unwrap();

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_retryable_error_detection() {
        let server_error = AtlassianError::http("Server error", Some(500));
        assert!(server_error.is_retryable());

        let auth_error = AtlassianError::auth("Unauthorized");
        assert!(!auth_error.is_retryable());
    }

    #[test]
    #[serial]
    fn from_env_supports_encrypted_username_and_token() {
        let (user_cipher, user_private) = generate_ciphertext("jira-user@example.com");
        let (token_cipher, token_private) = generate_ciphertext("jira-secret-token");

        let _guard_url = EnvGuard::set("JIRA_URL", "https://example.atlassian.net");

        let _guard_user_plain = EnvGuard::unset("JIRA_USERNAME");
        let _guard_user_cipher = EnvGuard::set("JIRA_USERNAME_ENCRYPTED", &user_cipher);
        let _guard_user_key = EnvGuard::set("JIRA_USERNAME_PRIVATE_KEY", &user_private);

        let _guard_token_plain = EnvGuard::unset("JIRA_API_TOKEN");
        let _guard_token_cipher = EnvGuard::set("JIRA_API_TOKEN_ENCRYPTED", &token_cipher);
        let _guard_token_key = EnvGuard::set("JIRA_API_TOKEN_PRIVATE_KEY", &token_private);

        let config = AtlassianConfig::from_env().unwrap();
        assert_eq!(config.username, "jira-user@example.com");
        assert_eq!(config.api_token, "jira-secret-token");
    }

    #[test]
    #[serial]
    fn from_env_accepts_private_key_without_base64_padding() {
        let (user_cipher, user_private) = generate_ciphertext("jira-user@example.com");
        let base64_private = BASE64_ENGINE.encode(user_private.as_bytes());
        let base64_without_padding = base64_private.trim_end_matches('=').to_string();

        let _guard_url = EnvGuard::set("JIRA_URL", "https://example.atlassian.net");
        let _guard_user_plain = EnvGuard::unset("JIRA_USERNAME");
        let _guard_user_cipher = EnvGuard::set("JIRA_USERNAME_ENCRYPTED", &user_cipher);
        let _guard_user_key = EnvGuard::set("JIRA_USERNAME_PRIVATE_KEY", &base64_without_padding);
        let _guard_token_plain = EnvGuard::set("JIRA_API_TOKEN", "plain-token");

        let config = AtlassianConfig::from_env().unwrap();
        assert_eq!(config.username, "jira-user@example.com");
        assert_eq!(config.api_token, "plain-token");
    }

    #[test]
    #[serial]
    fn from_env_loads_encrypted_env_file() {
        let keypair = KeyPair::generate(2048).expect("key generation succeeds");
        let cipher = HybridCipher::new(FluxConfig::default());
        let env_body = "export JIRA_URL=https://env.atlassian.net\nexport JIRA_USERNAME=env-user@example.com\nexport JIRA_API_TOKEN=env-token\n";
        let ciphertext = cipher
            .encrypt(keypair.public_key(), env_body.as_bytes())
            .expect("encrypt env file");
        let encoded = BASE64_ENGINE.encode(ciphertext);
        let private_pem = keypair.private_key().to_pem().expect("private key to pem");

        let _guard_url = EnvGuard::unset("JIRA_URL");
        let _guard_user = EnvGuard::unset("JIRA_USERNAME");
        let _guard_token = EnvGuard::unset("JIRA_API_TOKEN");
        let _guard_cipher = EnvGuard::set("ENV_FILE_ENCRYPTED", &encoded);
        let _guard_cipher_path = EnvGuard::unset("ENV_FILE_ENCRYPTED_PATH");
        let _guard_private = EnvGuard::set("ENV_FILE_PRIVATE_KEY", &private_pem);
        let _guard_password = EnvGuard::unset("ENV_FILE_PRIVATE_KEY_PASSWORD");

        let config = AtlassianConfig::from_env().unwrap();

        assert_eq!(config.base_url.as_str(), "https://env.atlassian.net/");
        assert_eq!(config.username, "env-user@example.com");
        assert_eq!(config.api_token, "env-token");
    }
}
