//! Configuration management for the Atlassian Rust SDK
//!
//! This module handles Jira authentication, SSL settings, and client configuration
//! based on environment variables and explicit configuration options.
//!
//! Resolving `JIRA_USERNAME_ENCRYPTED`, `JIRA_API_TOKEN_ENCRYPTED`,
//! `ENV_FILE_ENCRYPTED` and `ENV_FILE_ENCRYPTED_PATH` needs the `encrypted-env`
//! feature, which is in `full` and therefore on by default. Without it the
//! decrypt path is not compiled and any of those variables being *set* is a hard
//! configuration error naming the feature -- never a silent fall-through to the
//! cleartext variable, which would downgrade a deployment that believed its
//! credentials were encrypted at rest.
//!
//! # What the environment may relax
//!
//! Neither the transport scheme requirement nor certificate verification may be
//! relaxed from the environment. Both are relaxable only by an explicit code
//! call. Three things follow, and all three are enforced here rather than
//! documented and hoped for:
//!
//! * `JIRA_VERIFY_SSL` is read only so that a value meaning *disabled* is a hard
//!   error; [`AtlassianConfigBuilder::verify_ssl`] is the only way to turn
//!   certificate verification off.
//! * `JIRA_HOST_POLICY` refuses the `loopback` token, so no environment can
//!   admit an `http://` destination.
//! * There is **no** `JIRA_CERT_PATH`. Adding a trust anchor is relaxing
//!   certificate verification for the chosen destination -- an extra root can
//!   sign a certificate the system roots would have rejected -- so it is a code
//!   call, [`AtlassianConfig::with_cert_path`], on the same footing as
//!   [`HostPolicy::Loopback`].
//!
//! The residual the host policy does **not** cover is stated on [`HostPolicy`].

use crate::error::{AtlassianError, Result};
use crate::secret::zeroize_string;
use crate::secret::SecretString;
#[cfg(feature = "encrypted-env")]
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
#[cfg(feature = "encrypted-env")]
use base64::Engine;
#[cfg(feature = "encrypted-env")]
use fluxencrypt::env::secrets::{EnvSecret, SecretFormat};
#[cfg(feature = "encrypted-env")]
use fluxencrypt::error::FluxError;
#[cfg(feature = "encrypted-env")]
use fluxencrypt::keys::parsing;
#[cfg(feature = "encrypted-env")]
use fluxencrypt::{Config as FluxConfig, HybridCipher};
use std::env;
use std::fmt;
#[cfg(feature = "encrypted-env")]
use std::fs;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use url::{Host, Url};

/// Where the SDK is allowed to send Jira credentials.
///
/// The destination of an `Authorization: Basic` header is a security decision, so
/// it is made once by policy rather than per call site, and it covers the
/// **scheme** as well as the host: the two are one rule. HTTPS is required unless
/// the host is a literal loopback address *and* the policy is [`Self::Loopback`].
///
/// [`Self::Loopback`] is the only relaxation of that requirement, and it is
/// deliberately unreachable from the environment — `JIRA_HOST_POLICY` refuses the
/// token outright — so no workflow env, and no `ENV_FILE_ENCRYPTED` re-injection,
/// can talk a process into sending its credentials over cleartext. Test and
/// harness code, being code, calls
/// [`AtlassianConfigBuilder::host_policy`] for it.
///
/// # The residual this policy does not cover
///
/// This type bounds the **scheme**, not the set of hosts an environment can
/// name. `JIRA_HOST_POLICY` refuses only the literal `loopback` token;
/// `allowlist:<any-host>` is accepted from the environment. So a process whose
/// environment an attacker can set twice — `JIRA_HOST_POLICY=allowlist:evil.example`
/// and `JIRA_URL=https://evil.example` — will send `Authorization: Basic` to
/// `evil.example` over ordinary TLS, and this type will permit it, because the
/// operator's own Data Center deployment is indistinguishable from it.
///
/// That is deliberate: an SDK cannot tell an operator's private Jira from an
/// attacker's, and a policy that could not be widened from configuration would
/// make Data Center unusable. What the policy *does* guarantee is that the
/// credential never crosses the wire in cleartext, that the default admits only
/// Atlassian Cloud tenants, and that widening requires the environment to be
/// writable in the first place. An environment an attacker can write is a
/// compromise the SDK cannot contain; keep `JIRA_HOST_POLICY` out of
/// workflow-settable inputs, and pin it next to the credential it guards.
///
/// # Example
///
/// ```rust
/// use threatflux_atlassian_sdk::HostPolicy;
///
/// assert_eq!(HostPolicy::default(), HostPolicy::AtlassianCloud);
/// assert_eq!(
///     "allowlist:jira.example.com".parse::<HostPolicy>().unwrap(),
///     HostPolicy::Allowlist(vec!["jira.example.com".to_string()]),
/// );
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HostPolicy {
    /// Atlassian Cloud tenants only, and only over HTTPS. The default.
    #[default]
    AtlassianCloud,
    /// An explicit set of hosts, for Jira Data Center and Server deployments.
    ///
    /// Entries are bare hosts — no scheme, port, path, or credentials — matched
    /// case-insensitively against the whole host. There is no wildcard: a policy
    /// that can be widened by a pattern is a policy whose blast radius is a typo.
    Allowlist(Vec<String>),
    /// Literal loopback addresses (`127.0.0.0/8`, `::1`), which may also be
    /// reached over `http://`.
    ///
    /// No name is resolved and no name is accepted, so a `localtest.me`-style
    /// host that resolves to loopback is still refused. Settable only by a code
    /// call.
    Loopback,
}

impl HostPolicy {
    /// Host suffixes [`Self::AtlassianCloud`] admits, as the host itself or as a
    /// parent of it.
    pub const ATLASSIAN_CLOUD_SUFFIXES: [&'static str; 3] =
        ["atlassian.com", "atlassian.net", "jira.com"];

    /// Refuse a URL this policy does not admit as a credential destination.
    ///
    /// Scheme and host are decided together. Splitting them is what let
    /// `JIRA_VERIFY_SSL=false` turn off the HTTPS requirement: a host check alone
    /// cannot notice that the credential is about to cross the wire in cleartext,
    /// and a scheme check alone has no way to admit the loopback mock the
    /// end-to-end tests need.
    pub fn check_destination(&self, url: &Url) -> Result<()> {
        // Userinfo is judged before the host, because it *is* a credential and
        // this predicate would otherwise be blind to it: everything below reads
        // `url.host()`, which excludes the authority's `user:pass@` half.
        // [`parse_base_url`] already refuses one, so reaching this arm means the
        // URL was assigned straight to the public `base_url` field.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(AtlassianError::config(BASE_URL_USERINFO_REFUSAL));
        }

        // The same reasoning one component over. `Transport::build_url` joins by
        // pushing path segments onto a clone of the base, which leaves a query
        // and a fragment on it untouched, so either one rides every request and
        // reaches the `debug!` that logs the joined URL. [`parse_base_url`]
        // refuses both, so reaching this arm means the URL was assigned straight
        // to the public `base_url` field.
        if url.query().is_some() || url.fragment().is_some() {
            return Err(AtlassianError::config(BASE_URL_QUERY_REFUSAL));
        }

        let Some(host) = url.host() else {
            return Err(AtlassianError::config(
                "Jira URL must name a host to be a credential destination",
            ));
        };

        let loopback = is_literal_loopback(&host);
        let scheme = url.scheme();

        if scheme != "https" && !(scheme == "http" && loopback && *self == Self::Loopback) {
            return Err(AtlassianError::config(format!(
                "Jira URL must use https, but host {host} was addressed over '{scheme}'; \
                 http is admitted only for a literal loopback address under \
                 HostPolicy::Loopback, which no environment variable can select"
            )));
        }

        if !self.permits_host(&host, loopback) {
            return Err(AtlassianError::config(format!(
                "Jira host {host} is not permitted by the '{}' host policy",
                self.token()
            )));
        }

        Ok(())
    }

    /// Whether this policy admits `host`, ignoring the scheme.
    fn permits_host(&self, host: &Host<&str>, loopback: bool) -> bool {
        match self {
            Self::AtlassianCloud => match host {
                Host::Domain(domain) => Self::ATLASSIAN_CLOUD_SUFFIXES
                    .iter()
                    .any(|suffix| is_host_at_or_below(domain, suffix)),
                Host::Ipv4(_) | Host::Ipv6(_) => false,
            },
            Self::Allowlist(hosts) => {
                // Both sides are normalized rather than only the candidate: the
                // variant is public, so an entry can arrive from a struct literal
                // that never passed through the parser.
                let candidate = normalize_host(&host.to_string());
                hosts.iter().any(|entry| normalize_host(entry) == candidate)
            }
            Self::Loopback => loopback,
        }
    }

    /// The policy's own name, without the operator-supplied part of it.
    ///
    /// An error message names the policy but never its allowlist: under the
    /// threat model the variable that carries the allowlist is itself
    /// attacker-settable, and an error is a value that reaches a workflow log.
    const fn token(&self) -> &'static str {
        match self {
            Self::AtlassianCloud => "atlassian-cloud",
            Self::Allowlist(_) => "allowlist",
            Self::Loopback => "loopback",
        }
    }
}

impl FromStr for HostPolicy {
    type Err = AtlassianError;

    fn from_str(value: &str) -> Result<Self> {
        let lowered = value.trim().to_ascii_lowercase();

        if lowered == "atlassian-cloud" {
            return Ok(Self::AtlassianCloud);
        }
        if lowered == "loopback" {
            return Ok(Self::Loopback);
        }
        if let Some(entries) = lowered.strip_prefix("allowlist:") {
            return parse_allowlist(entries).map(Self::Allowlist);
        }

        // The value is not echoed: `JIRA_HOST_POLICY` is attacker-settable under
        // the threat model this type exists for, and the message is log-bound.
        Err(AtlassianError::config(
            "Unsupported host policy; expected 'atlassian-cloud', \
             'allowlist:<host>[,<host>]', or 'loopback'",
        ))
    }
}

impl fmt::Display for HostPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtlassianCloud | Self::Loopback => formatter.write_str(self.token()),
            Self::Allowlist(hosts) => write!(formatter, "allowlist:{}", hosts.join(",")),
        }
    }
}

/// Whether `host` is a literal loopback address, with no name resolution.
const fn is_literal_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
        Host::Domain(_) => false,
    }
}

/// Whether `host` is `suffix` or a subdomain of it.
///
/// The dot boundary is the whole point: a plain `ends_with` would admit
/// `evil-atlassian.net`, and a plain `contains` would admit
/// `atlassian.net.evil.example`.
fn is_host_at_or_below(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.');

    if host.eq_ignore_ascii_case(suffix) {
        return true;
    }

    // `get` rather than an index: a URL host for a special scheme is always
    // ASCII punycode, but a predicate that decides whether a credential may be
    // sent must not be one refactor away from panicking on a byte boundary.
    host.len() > suffix.len()
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        && host
            .get(host.len() - suffix.len()..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

/// The comparable form of a host: lowercased, without the brackets `Url` wraps
/// an IPv6 literal in, and with an IPv6 literal re-rendered from the address it
/// denotes rather than from the text it was spelled as.
///
/// That last step is not cosmetic. [`HostPolicy::permits_host`] compares this
/// against `Url::host()`, which prints an IPv6 address in exactly one canonical
/// compressed form, while an operator may write any of the many spellings that
/// name the same address -- `2001:0db8:0000:0000:0000:0000:0000:0001`, `::0001`.
/// Comparing the text makes such an entry parse and then match nothing, which is
/// the failure mode the port rejection in [`parse_allowlist`] exists to prevent,
/// one component over: every request is refused by a message naming the host the
/// operator just allowlisted, and [`HostPolicy::token`] deliberately will not
/// echo the allowlist that would explain why.
///
/// Both sides pass through here, so the canonical form only has to be
/// self-consistent -- it does not have to be the spelling `url` itself prints.
fn normalize_host(value: &str) -> String {
    let unbracketed = value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();

    unbracketed
        .parse::<Ipv6Addr>()
        .map_or(unbracketed, |address| address.to_string())
}

fn parse_allowlist(raw: &str) -> Result<Vec<String>> {
    let hosts: Vec<String> = raw
        .split(',')
        .map(normalize_host)
        .filter(|host| !host.is_empty())
        .collect();

    if hosts.is_empty() {
        return Err(AtlassianError::config(
            "Host policy 'allowlist:' requires at least one host",
        ));
    }

    if hosts.iter().any(|host| {
        host.contains('/') || host.contains('@') || host.chars().any(char::is_whitespace)
    }) {
        return Err(AtlassianError::config(
            "Host policy allowlist entries must be bare hosts, without a scheme, path, port, or credentials",
        ));
    }

    // `:` cannot simply be rejected -- an IPv6 literal is nothing but colons --
    // so an entry that carries one has to prove it is an address. Anything else
    // is a port, and a port-bearing entry is worse than a rejected one: it
    // parses, and then `permits_host` compares it against `Url::host()`, which
    // excludes the port, so every request is refused by a message naming the
    // host the operator just allowlisted.
    if hosts
        .iter()
        .any(|host| host.contains(':') && host.parse::<Ipv6Addr>().is_err())
    {
        return Err(AtlassianError::config(
            "Host policy allowlist entries must not carry a port: the policy is matched \
             against the URL host, which excludes the port, so a ':'-bearing entry could \
             never match. The only ':' an entry may contain is an IPv6 literal's, as \
             '[::1]' or '::1'",
        ));
    }

    Ok(hosts)
}

/// Configuration for Atlassian/Jira API client
///
/// Deliberately neither `Serialize` nor `Deserialize`. A configuration that can
/// be serialized is a configuration whose token can be written to a log line, a
/// cache file, or a diagnostic dump by a caller who never intended to; the
/// credential itself is a [`SecretString`], which has no `Serialize` at all, and
/// removing the derive here is what keeps the surrounding struct from being the
/// way around that.
///
/// The absence is asserted where a unit test cannot reach it:
///
/// ```compile_fail
/// use threatflux_atlassian_sdk::AtlassianConfig;
///
/// let config = AtlassianConfig::new(
///     "https://company.atlassian.net".to_string(),
///     "user@company.com".to_string(),
///     "your-api-token",
/// )
/// .unwrap();
/// let _ = serde_json::to_string(&config);
/// ```
#[derive(Debug, Clone)]
pub struct AtlassianConfig {
    /// Jira base URL (e.g., `https://company.atlassian.net`)
    pub base_url: Url,
    /// Jira username (email for cloud instances)
    pub username: String,
    /// API token (used as password for authentication)
    pub api_token: SecretString,
    /// Request timeout duration
    pub timeout: Duration,
    /// Path to custom SSL certificate bundle
    pub cert_path: Option<PathBuf>,
    /// Which hosts this configuration may send its credentials to
    pub host_policy: HostPolicy,
    /// Whether to verify TLS certificates
    ///
    /// This is certificate verification and nothing else. It has no bearing on
    /// the transport scheme: an `http://` base URL is refused by
    /// [`HostPolicy::check_destination`] whatever this is set to, and reqwest
    /// performs no TLS at all on such a URL, so relaxing it there never did
    /// anything.
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
    // `base_url` is parsed rather than stored, but narrowing it to `&str` would
    // split the signature of a documented public constructor whose other two
    // arguments really are consumed.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniform by-value signature on a public constructor"
    )]
    pub fn new(
        base_url: String,
        username: String,
        api_token: impl Into<SecretString>,
    ) -> Result<Self> {
        Ok(Self {
            base_url: parse_base_url(&base_url)?,
            username,
            api_token: api_token.into(),
            timeout: Duration::from_mins(1),
            cert_path: None,
            host_policy: HostPolicy::default(),
            verify_ssl: true,
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
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
    /// * `JIRA_HOST_POLICY` - `atlassian-cloud` (default) or
    ///   `allowlist:<host>[,<host>]`. The token `loopback` is refused: see
    ///   [`HostPolicy::Loopback`].
    /// * `JIRA_VERIFY_SSL` - Accepted only with a value meaning *enabled*. A value
    ///   meaning disabled is a hard error, because neither the transport scheme
    ///   requirement nor certificate verification may be relaxed from the
    ///   environment.
    /// * `JIRA_MAX_RETRIES` - Maximum retry attempts (optional, default: 3)
    ///
    /// There is deliberately **no** `JIRA_CERT_PATH`. An extra trust anchor can
    /// sign a certificate the system roots would have rejected, so installing
    /// one relaxes certificate verification for the chosen destination — which
    /// this constructor is not allowed to do. A Data Center deployment with a
    /// private CA calls [`AtlassianConfig::with_cert_path`] or
    /// [`AtlassianConfigBuilder::cert_path`], exactly as
    /// [`HostPolicy::Loopback`] is reached by a code call.
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
        Self::from_env_with_overrides(None, None, None::<SecretString>)
    }

    /// Create configuration from environment variables with optional overrides for the required
    /// Jira credentials.
    ///
    /// The token override is generic over [`SecretString`] so that a caller
    /// holding one — a CLI argument parsed straight into the type, say — never
    /// has to unwrap it into a `String` to get here. Passing a literal `None`
    /// needs a type, for which [`SecretString`] itself is the obvious one.
    pub fn from_env_with_overrides(
        base_url_override: Option<String>,
        username_override: Option<String>,
        api_token_override: Option<impl Into<SecretString>>,
    ) -> Result<Self> {
        load_encrypted_env_file_if_present()?;

        let base_url = match normalize_override("JIRA_URL", base_url_override)? {
            Some(value) => value,
            None => env::var("JIRA_URL")
                .map_err(|_| AtlassianError::config("JIRA_URL environment variable not set"))?,
        };
        let username = match normalize_override("JIRA_USERNAME", username_override)? {
            Some(value) => value,
            None => load_required_secret("JIRA_USERNAME")?,
        };
        let api_token = match normalize_secret_override(
            "JIRA_API_TOKEN",
            api_token_override.map(Into::into),
        )? {
            Some(value) => value,
            None => load_required_credential("JIRA_API_TOKEN")?,
        };

        let mut config = Self::new(base_url, username, api_token)?;
        apply_optional_env_settings(&mut config)?;

        Ok(config)
    }

    /// Builder pattern for configuration
    pub const fn builder() -> AtlassianConfigBuilder {
        AtlassianConfigBuilder::new()
    }

    /// Set custom timeout
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set custom certificate path
    #[must_use]
    pub fn with_cert_path(mut self, cert_path: PathBuf) -> Self {
        self.cert_path = Some(cert_path);
        self
    }

    /// Disable TLS certificate verification (not recommended for production)
    ///
    /// Only certificate verification: an `http://` base URL stays refused, so
    /// this cannot be used to reach a cleartext destination. Its remaining use is
    /// a self-signed certificate on an `https://` Data Center instance.
    #[must_use]
    pub const fn with_ssl_verification(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    /// Set the policy deciding which hosts may receive these credentials
    ///
    /// This is the code call [`HostPolicy::Loopback`] requires; no `JIRA_*`
    /// variable can reach it.
    #[must_use]
    pub fn with_host_policy(mut self, policy: HostPolicy) -> Self {
        self.host_policy = policy;
        self
    }

    /// Set retry configuration
    #[must_use]
    pub const fn with_retries(mut self, max_retries: u32, delay: Duration) -> Self {
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

        self.host_policy.check_destination(&self.base_url)?;

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

/// The refusal a base URL carrying credentials in its authority produces.
///
/// It names the variables to use instead and never echoes what it refused: the
/// value it was handed is a password, and this message reaches a workflow log.
const BASE_URL_USERINFO_REFUSAL: &str =
    "Jira base URL must not carry credentials in its authority: supply them as \
     JIRA_USERNAME and JIRA_API_TOKEN (or AtlassianConfigBuilder::username and \
     ::api_token), which keeps the token inside SecretString instead of inside a \
     URL that is printed by Debug and logged on every request";

/// The refusal a base URL carrying a query string or a fragment produces.
///
/// Shared by [`parse_base_url`] and [`HostPolicy::check_destination`] rather than
/// written twice: the second is the belt to the first's braces, and a caller who
/// reached it through the public `base_url` field deserves the same sentence as
/// one who went through the parser.
///
/// Neither part is echoed: a query string an operator pasted out of a browser can
/// carry a session parameter, and this message is log-bound.
const BASE_URL_QUERY_REFUSAL: &str =
    "Jira base URL must not carry a query string or fragment: every API path is \
     resolved below the base, so a query would be attached to every request, \
     including the paginated ones that pass their own";

/// Parse a configured base URL into the shape the API path builder expects.
///
/// Four normalizations, all of them here rather than spread across the path
/// builder, because a base URL is parsed exactly once and every request resolves
/// below whatever this returns:
///
/// * **Userinfo is refused.** `https://user:pass@host` puts a second
///   credential-bearing value into [`AtlassianConfig`], whose derived `Debug`
///   prints it in full and whose transport logs the joined URL on every request,
///   while [`HostPolicy::check_destination`] reads only `url.host()` and cannot
///   see it. Refusing it closes all three at the only point that has the raw
///   string to complain about.
/// * **A query or fragment is refused.** Both survive `Url::join`, so
///   `https://co.atlassian.net/?maxResults=1000` — a plausible browser
///   copy-paste — would silently prepend a parameter to every call, including
///   the paginated ones that pass their own.
/// * **Repeated slashes collapse.** A base ending in `//` otherwise keeps an
///   empty interior segment, and the joined path addresses a resource nobody
///   named.
/// * **A trailing slash is added.** A path that does not end in `/` loses its
///   last segment under any relative resolution, and on a Data Center deployment
///   that segment is the context path.
fn parse_base_url(raw: &str) -> Result<Url> {
    let mut url =
        Url::parse(raw).map_err(|e| AtlassianError::config(format!("Invalid base URL: {e}")))?;

    if url.cannot_be_a_base() {
        return Err(AtlassianError::config(format!(
            "Jira base URL scheme '{}' cannot carry an API path",
            url.scheme()
        )));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(AtlassianError::config(BASE_URL_USERINFO_REFUSAL));
    }

    if url.query().is_some() || url.fragment().is_some() {
        return Err(AtlassianError::config(BASE_URL_QUERY_REFUSAL));
    }

    // One pass covers the collapse and the trailing slash, which is the whole
    // reason they live together: rebuilding the path from its non-empty segments
    // cannot leave an interior `//`, and closing it with `/` cannot forget the
    // trailing one.
    let mut normalized = String::with_capacity(url.path().len() + 1);
    normalized.push('/');
    for segment in url.path().split('/').filter(|segment| !segment.is_empty()) {
        normalized.push_str(segment);
        normalized.push('/');
    }
    url.set_path(&normalized);

    Ok(url)
}

fn normalize_override(name: &str, value: Option<String>) -> Result<Option<String>> {
    match value {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(AtlassianError::config(format!("{name} override is empty")));
            }
            Ok(Some(trimmed.to_string()))
        }
        None => Ok(None),
    }
}

/// [`normalize_override`] for a value that must stay inside [`SecretString`].
fn normalize_secret_override(
    name: &str,
    value: Option<SecretString>,
) -> Result<Option<SecretString>> {
    match value {
        Some(raw) => {
            let trimmed = raw.trimmed();
            if trimmed.is_empty() {
                return Err(AtlassianError::config(format!("{name} override is empty")));
            }
            Ok(Some(trimmed))
        }
        None => Ok(None),
    }
}

fn apply_optional_env_settings(config: &mut AtlassianConfig) -> Result<()> {
    // Optional timeout configuration
    if let Ok(timeout_str) = env::var("JIRA_TIMEOUT") {
        if let Ok(timeout_secs) = timeout_str.parse::<u64>() {
            config.timeout = Duration::from_secs(timeout_secs);
        } else {
            return Err(AtlassianError::config("Invalid JIRA_TIMEOUT value"));
        }
    }

    // A custom trust anchor is deliberately *not* settable here, and the
    // variable is deliberately not read either. `JIRA_CERT_PATH` used to be, and
    // it contradicted this module's own guarantee: `add_root_certificate` makes
    // the named CA able to vouch for the destination, so an environment that
    // could set it could relax certificate verification for exactly the host it
    // also chose with `JIRA_URL`. `with_cert_path` is the code call that
    // survives, on the same footing as `HostPolicy::Loopback`.
    //
    // Unlike `JIRA_VERIFY_SSL` this is not read in order to refuse it. Refusing
    // would turn every Data Center deployment that still exports the variable
    // into a hard failure with no configuration that satisfies both halves --
    // the operator would have to unset an environment variable to be allowed to
    // pass the same path in code. Ignoring it downgrades nothing: the client
    // falls back to the system roots, which is stricter than what the variable
    // asked for, so the failure mode is a refused handshake rather than a
    // silently widened one.

    // Certificate verification is deliberately *not* settable here. The variable
    // is still read so that an environment trying to turn it off fails loudly
    // instead of being silently ignored -- and so that the values the old parse
    // mistook for "enabled" (" false", "0", "no") are refused rather than
    // honoured backwards.
    if let Ok(raw) = env::var("JIRA_VERIFY_SSL") {
        if !parse_bool_env("JIRA_VERIFY_SSL", &raw)? {
            return Err(AtlassianError::config(
                "JIRA_VERIFY_SSL cannot disable certificate verification: it is relaxable only \
                 by AtlassianConfigBuilder::verify_ssl(false) in code, and only for an https URL",
            ));
        }
    }

    if let Ok(raw) = env::var("JIRA_HOST_POLICY") {
        config.host_policy = parse_host_policy_env(&raw)?;
    }

    // Optional max retries
    if let Ok(retries_str) = env::var("JIRA_MAX_RETRIES") {
        if let Ok(retries) = retries_str.parse::<u32>() {
            config.max_retries = retries;
        }
    }

    Ok(())
}

/// Read a boolean environment variable strictly.
///
/// The old parse was `value.to_lowercase() != "false"`, under which every
/// spelling it did not recognise — `" false"`, `"0"`, `"no"` — meant the
/// opposite of what the operator wrote. A security switch cannot fail towards
/// the permissive answer on a typo, so an unrecognised value is an error.
fn parse_bool_env(name: &str, raw: &str) -> Result<bool> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AtlassianError::config(format!("{name} is set but empty")));
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(AtlassianError::config(format!(
            "Invalid {name} value: expected one of true, false, 1, 0, yes, no, on, off"
        ))),
    }
}

/// Parse `JIRA_HOST_POLICY`, which is the same grammar as [`HostPolicy`]'s own
/// minus the loopback escape hatch.
///
/// This refusal is what makes criteria "production cannot disable TLS
/// verification" and "the end-to-end suite drives a real client against a mock"
/// simultaneously satisfiable: the hatch exists, and the environment cannot
/// reach it, so `AtlassianConfig::from_env*` can never yield a configuration
/// that talks cleartext.
fn parse_host_policy_env(raw: &str) -> Result<HostPolicy> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Err(AtlassianError::config("JIRA_HOST_POLICY is set but empty"));
    }

    if trimmed.eq_ignore_ascii_case("loopback") {
        return Err(AtlassianError::config(
            "JIRA_HOST_POLICY cannot select the loopback policy: it is settable only by \
             AtlassianConfigBuilder::host_policy(HostPolicy::Loopback) in code",
        ));
    }

    trimmed.parse()
}

/// Builder for `AtlassianConfig`
#[derive(Debug)]
pub struct AtlassianConfigBuilder {
    base_url: Option<String>,
    username: Option<String>,
    api_token: Option<SecretString>,
    timeout: Duration,
    cert_path: Option<PathBuf>,
    host_policy: HostPolicy,
    verify_ssl: bool,
    max_retries: u32,
    retry_delay: Duration,
}

impl AtlassianConfigBuilder {
    /// Create a new configuration builder
    pub const fn new() -> Self {
        Self {
            base_url: None,
            username: None,
            api_token: None,
            timeout: Duration::from_mins(1),
            cert_path: None,
            host_policy: HostPolicy::AtlassianCloud,
            verify_ssl: true,
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
    }

    /// Set the Jira base URL
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Set the username
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the API token
    #[must_use]
    pub fn api_token(mut self, token: impl Into<SecretString>) -> Self {
        self.api_token = Some(token.into());
        self
    }

    /// Set the request timeout
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the SSL certificate path
    #[must_use]
    pub fn cert_path(mut self, path: PathBuf) -> Self {
        self.cert_path = Some(path);
        self
    }

    /// Set TLS certificate verification
    ///
    /// Certificate verification only. Passing `false` does not admit an `http://`
    /// base URL — that is [`HostPolicy::Loopback`]'s job, and only for a literal
    /// loopback address.
    #[must_use]
    pub const fn verify_ssl(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    /// Set the policy deciding which hosts may receive these credentials
    ///
    /// # Example
    /// ```rust
    /// use threatflux_atlassian_sdk::{AtlassianConfig, HostPolicy};
    ///
    /// let config = AtlassianConfig::builder()
    ///     .base_url("https://jira.example.com/jira")
    ///     .username("bot@example.com")
    ///     .api_token("api-token")
    ///     .host_policy(HostPolicy::Allowlist(vec!["jira.example.com".to_string()]))
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(config.base_url.as_str(), "https://jira.example.com/jira/");
    /// ```
    #[must_use]
    pub fn host_policy(mut self, policy: HostPolicy) -> Self {
        self.host_policy = policy;
        self
    }

    /// Set retry configuration
    #[must_use]
    pub const fn retries(mut self, max_retries: u32, delay: Duration) -> Self {
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

        let config = AtlassianConfig {
            base_url: parse_base_url(&base_url)?,
            username,
            api_token,
            timeout: self.timeout,
            cert_path: self.cert_path,
            host_policy: self.host_policy,
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

/// The environment variables that only the `encrypted-env` feature can resolve.
///
/// `ENV_FILE_ENCRYPTED_PATH` is first because it wins over `ENV_FILE_ENCRYPTED`
/// when both are set, so the refusal names the one that would have been used.
#[cfg(not(feature = "encrypted-env"))]
const ENCRYPTED_ENV_FILE_VARS: [&str; 2] = ["ENV_FILE_ENCRYPTED_PATH", "ENV_FILE_ENCRYPTED"];

/// The error every encrypted-credential path returns when the feature is off.
///
/// It names the variable that was set, the feature that would resolve it, and
/// the two ways out, because the alternative -- ignoring the variable and
/// falling back to the cleartext one -- would let a build silently stop
/// honouring encryption a deployment is relying on.
#[cfg(not(feature = "encrypted-env"))]
fn encrypted_env_unavailable(variable: &str) -> AtlassianError {
    AtlassianError::config(format!(
        "{variable} is set, but this build of threatflux-atlassian-sdk was compiled \
         without the `encrypted-env` cargo feature, so it cannot decrypt the value. \
         Rebuild the SDK with `--features encrypted-env` (it is part of the default \
         `full` set), or supply the credential in cleartext through the \
         corresponding unencrypted variable."
    ))
}

/// Refuse an encrypted env file rather than ignoring it.
///
/// The file is not read: without the feature there is nothing that could decrypt
/// it, and reading a path only to discard it is a filesystem access with no
/// purpose.
#[cfg(not(feature = "encrypted-env"))]
fn load_encrypted_env_file_if_present() -> Result<()> {
    for variable in ENCRYPTED_ENV_FILE_VARS {
        if env::var_os(variable).is_some() {
            return Err(encrypted_env_unavailable(variable));
        }
    }

    Ok(())
}

#[cfg(feature = "encrypted-env")]
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

    let mut decrypted = decrypt_secret_for_base("ENV_FILE", &ciphertext)?;
    let loaded = dotenvy::from_read_override(decrypted.as_bytes()).map_err(|err| {
        AtlassianError::config(format!(
            "Failed to load decrypted environment file from {source}: {err}"
        ))
    });
    // The decrypted body is every credential the file carries, in plaintext.
    zeroize_string(&mut decrypted);
    loaded?;

    Ok(())
}

fn load_required_secret(base: &str) -> Result<String> {
    load_secret(base)?
        .ok_or_else(|| AtlassianError::config(format!("{base} environment variable not set")))
}

/// [`load_required_secret`] for a value that is a credential.
///
/// The `String` is moved rather than copied into the [`SecretString`], so the
/// buffer the loader produced is the one that gets zeroed — and the buffer the
/// loader trimmed *out of* is zeroed by [`take_trimmed`] before it is dropped,
/// so no un-zeroized copy survives either step.
fn load_required_credential(base: &str) -> Result<SecretString> {
    load_required_secret(base).map(SecretString::from)
}

/// Copy the trimmed contents out of `value` and zero what is left behind.
///
/// `trim` borrows, so taking an owned trimmed value always means a second
/// buffer; this returns that buffer and wipes the first one, which is the same
/// two-buffer shape [`decrypt_secret_for_base`] already handles this way.
///
/// The bound is exactly the heap allocation this process made. The value also
/// exists in the process's own environment block, which `env::var` copied from
/// and which nothing here owns, so this narrows the window rather than closing
/// it.
fn take_trimmed(value: &mut String) -> String {
    let trimmed = value.trim().to_string();
    zeroize_string(value);
    trimmed
}

fn load_secret(base: &str) -> Result<Option<String>> {
    match env::var(base) {
        Ok(mut value) => {
            let trimmed = take_trimmed(&mut value);
            if trimmed.is_empty() {
                return Err(AtlassianError::config(format!("{base} is set but empty")));
            }
            return Ok(Some(trimmed));
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

    let decrypted = decrypt_secret_for_base(base, &ciphertext)?;
    Ok(Some(decrypted))
}

/// The single seam every `{base}_ENCRYPTED` value passes through.
///
/// Gating here rather than at each caller keeps `load_secret` identical in both
/// configurations, so the feature cannot change *which* variables are consulted
/// -- only whether the ciphertext they hold can be turned back into a secret.
#[cfg(not(feature = "encrypted-env"))]
fn decrypt_secret_for_base(base: &str, _ciphertext: &str) -> Result<String> {
    Err(encrypted_env_unavailable(&format!("{base}_ENCRYPTED")))
}

#[cfg(feature = "encrypted-env")]
fn decrypt_secret_for_base(base: &str, ciphertext: &str) -> Result<String> {
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

    let secret = parse_private_key_secret(&private_key_value)
        .map_err(|err| flux_error_to_config("Failed to parse private key", &err))?;

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
            .map_err(|err| flux_error_to_config("Failed to decode private key bytes", &err))?;
        parsing::parse_encrypted_private_key_from_str(&pem, &password)
            .map_err(|err| flux_error_to_config("Failed to parse encrypted private key", &err))?
    } else {
        secret
            .as_private_key()
            .map_err(|err| flux_error_to_config("Failed to parse private key", &err))?
    };

    let cipher = HybridCipher::new(FluxConfig::default());
    let decrypted = cipher
        .decrypt(&private_key, &encrypted_bytes)
        .map_err(|err| flux_error_to_config("Failed to decrypt secret", &err))?;

    if decrypted.is_empty() {
        return Err(AtlassianError::config("Decrypted secret is empty"));
    }

    let mut secret_string = String::from_utf8(decrypted).map_err(|err| {
        AtlassianError::config(format!("Decrypted secret is not valid UTF-8: {err}"))
    })?;
    // `trim` copies the plaintext into a second buffer; `take_trimmed` wipes the
    // first one, on the whitespace-only path as well as the success path.
    let trimmed = take_trimmed(&mut secret_string);
    if trimmed.is_empty() {
        return Err(AtlassianError::config(
            "Decrypted secret contains only whitespace",
        ));
    }

    Ok(trimmed)
}

#[cfg(feature = "encrypted-env")]
fn flux_error_to_config(context: &str, err: &FluxError) -> AtlassianError {
    AtlassianError::config(format!("{context}: {err}"))
}

#[cfg(feature = "encrypted-env")]
fn parse_private_key_secret(value: &str) -> std::result::Result<EnvSecret, FluxError> {
    let mut secret = EnvSecret::from_string(value.to_string())?;

    if secret.format() != SecretFormat::Raw {
        return Ok(secret);
    }

    if let Some(decoded_pem) = decode_private_key_from_base64(value) {
        secret = EnvSecret::from_string(decoded_pem)?;
    }

    Ok(secret)
}

#[cfg(feature = "encrypted-env")]
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
    #[cfg(feature = "encrypted-env")]
    use fluxencrypt::keys::KeyPair;
    use serial_test::serial;
    use std::env;
    use std::time::Duration;
    use threatflux_atlassian_testkit::redaction::SecretScanner;

    // Spelled out rather than written as base64. The refusal path under test
    // never decodes it, and a base64-shaped literal is what a secret scanner
    // reports as a leak.
    #[cfg(not(feature = "encrypted-env"))]
    const NOT_A_REAL_CIPHERTEXT: &str = "not-a-real-ciphertext";

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
        assert_eq!(config.api_token.expose_secret(), "test-token");
        assert!(config.verify_ssl);
    }

    #[test]
    fn default_timeout_and_retry_delay_are_unit_independent() {
        // `Duration::from_mins(1)` and `Duration::from_secs(1)` replaced
        // `from_secs(60)` and `from_millis(1000)`; the documented values are 60
        // seconds and 1 second, and the units they are spelled in must not matter.
        let config = AtlassianConfig::new(
            "https://test.atlassian.net".to_string(),
            "test@example.com".to_string(),
            "test-token".to_string(),
        )
        .unwrap();

        assert_eq!(config.timeout.as_secs(), 60);
        assert_eq!(config.retry_delay.as_millis(), 1000);
        assert_eq!(config.max_retries, 3);

        let built = AtlassianConfig::builder()
            .base_url("https://test.atlassian.net")
            .username("test@example.com")
            .api_token("test-token")
            .build()
            .unwrap();

        assert_eq!(built.timeout, config.timeout);
        assert_eq!(built.retry_delay, config.retry_delay);
        assert_eq!(built.max_retries, config.max_retries);
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

    #[cfg(feature = "encrypted-env")]
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
            String::new(), // Empty username
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
    fn a_config_debug_does_not_print_the_token() {
        // The struct keeps its derive; the field is what is redacted, so a
        // `{:?}` of a config in a log line or a panic payload stays useful
        // without carrying the credential.
        let config = AtlassianConfig::new(
            "https://test.atlassian.net".to_string(),
            "test@example.com".to_string(),
            "s3cr3t-api-token",
        )
        .unwrap();

        for rendered in [format!("{config:?}"), format!("{config:#?}")] {
            SecretScanner::new()
                .with_basic_credentials("api token", "test@example.com", "s3cr3t-api-token")
                .assert_clean("the debug rendering of AtlassianConfig", &rendered);
            assert!(
                rendered.contains("test.atlassian.net"),
                "rendered: {rendered}"
            );
        }
    }

    #[test]
    fn a_builder_debug_does_not_print_the_token_either() {
        // The builder holds the credential between `api_token` and `build`, and
        // it derives `Debug` too.
        let builder = AtlassianConfig::builder()
            .base_url("https://test.atlassian.net")
            .username("test@example.com")
            .api_token("s3cr3t-api-token");

        let rendered = format!("{builder:?}");

        assert!(
            !rendered.contains("s3cr3t-api-token"),
            "rendered: {rendered}"
        );
        assert_eq!(
            builder.build().unwrap().api_token.expose_secret(),
            "s3cr3t-api-token"
        );
    }

    #[test]
    fn an_empty_token_is_rejected_without_exposing_a_present_one() {
        let config = AtlassianConfig::new(
            "https://test.atlassian.net".to_string(),
            "test@example.com".to_string(),
            "",
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("API token cannot be empty"));
    }

    #[test]
    fn a_blank_token_override_is_refused_without_echoing_it() {
        // The message a caller sees names the variable, never the value.
        let error = normalize_secret_override("JIRA_API_TOKEN", Some(SecretString::from(" \t\n ")))
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Configuration error: JIRA_API_TOKEN override is empty"
        );
    }

    #[test]
    fn a_token_override_is_trimmed_inside_the_secret_type() {
        let normalized =
            normalize_secret_override("JIRA_API_TOKEN", Some(SecretString::from("  tok\n")))
                .unwrap()
                .unwrap();

        assert_eq!(normalized.expose_secret(), "tok");
    }

    fn config_at(base_url: &str, policy: HostPolicy) -> AtlassianConfig {
        AtlassianConfig::new(
            base_url.to_string(),
            "test@example.com".to_string(),
            "test-token",
        )
        .unwrap()
        .with_host_policy(policy)
    }

    /// The environment a `from_env` test starts from: credentials present, and
    /// every variable this module also reads explicitly cleared, so a leaked
    /// value from another test cannot decide the outcome.
    fn baseline_env() -> Vec<EnvGuard> {
        vec![
            EnvGuard::set("JIRA_URL", "https://example.atlassian.net"),
            EnvGuard::set("JIRA_USERNAME", "test@example.com"),
            EnvGuard::set("JIRA_API_TOKEN", "test-token"),
            EnvGuard::unset("JIRA_USERNAME_ENCRYPTED"),
            EnvGuard::unset("JIRA_API_TOKEN_ENCRYPTED"),
            EnvGuard::unset("ENV_FILE_ENCRYPTED"),
            EnvGuard::unset("ENV_FILE_ENCRYPTED_PATH"),
            EnvGuard::unset("JIRA_VERIFY_SSL"),
            EnvGuard::unset("JIRA_HOST_POLICY"),
        ]
    }

    #[test]
    fn a_cleartext_destination_is_refused_even_with_certificate_verification_disabled() {
        // The old predicate was `scheme != "https" && verify_ssl`, so turning
        // verification off also turned the HTTPS requirement off, and
        // `Authorization: Basic <base64(user:token)>` went to an attacker-named
        // host in cleartext.
        let config = config_at("http://attacker.example", HostPolicy::AtlassianCloud)
            .with_ssl_verification(false);

        let error = config.validate().unwrap_err();
        assert!(
            error.to_string().contains("must use https"),
            "error was: {error}"
        );

        let built = AtlassianConfig::builder()
            .base_url("http://attacker.example")
            .username("test@example.com")
            .api_token("test-token")
            .verify_ssl(false)
            .build();
        assert!(built.is_err(), "the builder admitted a cleartext base URL");
    }

    #[test]
    fn the_scheme_and_host_predicate_decides_them_together() {
        let cloud = HostPolicy::AtlassianCloud;
        let loopback = HostPolicy::Loopback;
        let allowlist = HostPolicy::Allowlist(vec!["jira.example.com".to_string()]);

        let cases: [(&str, &HostPolicy, bool); 12] = [
            // https + permitted host
            ("https://company.atlassian.net", &cloud, true),
            ("https://jira.example.com/jira", &allowlist, true),
            ("https://127.0.0.1:8443", &loopback, true),
            // https + host the policy does not permit
            ("https://jira.example.com", &cloud, false),
            ("https://company.atlassian.net", &allowlist, false),
            ("https://company.atlassian.net", &loopback, false),
            // http + literal loopback, under the policy that admits it
            ("http://127.0.0.1:8080", &loopback, true),
            ("http://[::1]:8080", &loopback, true),
            // http + literal loopback, under a policy that does not
            ("http://127.0.0.1:8080", &cloud, false),
            ("http://127.0.0.1:8080", &allowlist, false),
            // http + anything else
            ("http://localhost:8080", &loopback, false),
            ("http://company.atlassian.net", &cloud, false),
        ];

        for (base_url, policy, accepted) in cases {
            let outcome = config_at(base_url, policy.clone()).validate();
            assert_eq!(
                outcome.is_ok(),
                accepted,
                "{base_url} under {policy} produced {outcome:?}"
            );
        }
    }

    #[test]
    fn a_refusal_names_whichever_half_of_the_predicate_failed() {
        let scheme = config_at("http://company.atlassian.net", HostPolicy::AtlassianCloud)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(scheme.contains("must use https"), "error was: {scheme}");

        let host = config_at("https://jira.example.com", HostPolicy::AtlassianCloud)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            host.contains("not permitted by the 'atlassian-cloud' host policy"),
            "error was: {host}"
        );
    }

    #[test]
    fn a_refusal_does_not_echo_the_allowlist_it_was_configured_with() {
        // `JIRA_HOST_POLICY` is settable by the environment this type defends
        // against, and an error message ends up in a workflow log.
        const ENTRY: &str = "allowlist-entry-that-must-not-reach-a-log.example";
        let error = config_at(
            "https://company.atlassian.net",
            HostPolicy::Allowlist(vec![ENTRY.to_string()]),
        )
        .validate()
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("'allowlist' host policy"),
            "error was: {error}"
        );
        assert!(!error.contains(ENTRY), "error was: {error}");
    }

    #[test]
    fn only_a_literal_loopback_address_reaches_the_http_escape_hatch() {
        for admitted in [
            "http://127.0.0.1:8080",
            "http://127.0.0.2:8080",
            "http://127.255.255.254",
            "http://[::1]:8080",
        ] {
            assert!(
                config_at(admitted, HostPolicy::Loopback).validate().is_ok(),
                "{admitted} was refused"
            );
        }

        // No name is resolved and no name is accepted, so a host that resolves to
        // loopback -- which an attacker can arrange in DNS -- is still refused.
        for refused in [
            "http://localhost:8080",
            "http://localtest.me:8080",
            "http://127.0.0.1.evil.example",
            "http://[::2]:8080",
            "http://10.0.0.1:8080",
        ] {
            assert!(
                config_at(refused, HostPolicy::Loopback).validate().is_err(),
                "{refused} was admitted"
            );
        }
    }

    #[test]
    fn the_default_policy_admits_atlassian_cloud_and_refuses_what_only_looks_like_it() {
        assert_eq!(HostPolicy::default(), HostPolicy::AtlassianCloud);

        for admitted in [
            "https://company.atlassian.net",
            "https://atlassian.net",
            "https://api.atlassian.com",
            "https://company.jira.com",
            "https://company.atlassian.net.",
        ] {
            assert!(
                config_at(admitted, HostPolicy::AtlassianCloud)
                    .validate()
                    .is_ok(),
                "{admitted} was refused"
            );
        }

        for refused in [
            "https://evil-atlassian.net",
            "https://atlassian.net.evil.example",
            "https://notatlassian.com",
            "https://jira.example.com",
            "https://192.0.2.1",
        ] {
            assert!(
                config_at(refused, HostPolicy::AtlassianCloud)
                    .validate()
                    .is_err(),
                "{refused} was admitted"
            );
        }
    }

    #[test]
    fn an_internationalized_host_is_judged_on_the_form_it_is_dialled_as() {
        // `Url` normalizes a host to ASCII punycode, so the suffix comparison
        // never sees the Unicode spelling and cannot be talked past by one.
        let config = config_at("https://cömpany.atlassian.net", HostPolicy::AtlassianCloud);
        assert_eq!(
            config.base_url.host_str(),
            Some("xn--cmpany-wxa.atlassian.net")
        );
        assert!(config.validate().is_ok());

        assert!(config_at(
            "https://atlassian.net.évil.example",
            HostPolicy::AtlassianCloud
        )
        .validate()
        .is_err());
    }

    #[test]
    fn an_allowlist_admits_exactly_its_entries() {
        let policy =
            HostPolicy::Allowlist(vec!["JIRA.example.com".to_string(), "[::1]".to_string()]);

        for admitted in ["https://jira.example.com", "https://[::1]:8443"] {
            assert!(
                config_at(admitted, policy.clone()).validate().is_ok(),
                "{admitted} was refused"
            );
        }

        for refused in [
            "https://other.example.com",
            "https://sub.jira.example.com",
            "https://company.atlassian.net",
        ] {
            assert!(
                config_at(refused, policy.clone()).validate().is_err(),
                "{refused} was admitted"
            );
        }
    }

    #[test]
    fn certificate_verification_stays_relaxable_in_code_for_an_https_url() {
        // The knob keeps its one real use -- a self-signed certificate on a Data
        // Center instance -- and loses the scheme relaxation it never should have
        // carried.
        let config = AtlassianConfig::builder()
            .base_url("https://jira.example.com")
            .username("test@example.com")
            .api_token("test-token")
            .host_policy(HostPolicy::Allowlist(vec!["jira.example.com".to_string()]))
            .verify_ssl(false)
            .build()
            .unwrap();

        assert!(!config.verify_ssl);
    }

    #[test]
    fn a_base_url_normalizes_to_a_trailing_slash() {
        // Without it the last segment is a file, not a directory, and a Data
        // Center context path is exactly that segment.
        for (raw, expected) in [
            (
                "https://jira.example.com/jira",
                "https://jira.example.com/jira/",
            ),
            (
                "https://jira.example.com/jira/",
                "https://jira.example.com/jira/",
            ),
            (
                "https://jira.example.com/apps/jira",
                "https://jira.example.com/apps/jira/",
            ),
            (
                "https://company.atlassian.net",
                "https://company.atlassian.net/",
            ),
        ] {
            let config = AtlassianConfig::new(
                raw.to_string(),
                "test@example.com".to_string(),
                "test-token",
            )
            .unwrap();
            assert_eq!(config.base_url.as_str(), expected, "from {raw}");

            let built = AtlassianConfig::builder()
                .base_url(raw)
                .username("test@example.com")
                .api_token("test-token")
                .host_policy(HostPolicy::Allowlist(vec![config
                    .base_url
                    .host_str()
                    .unwrap()
                    .to_string()]))
                .build()
                .unwrap();
            assert_eq!(built.base_url.as_str(), expected, "from {raw} via builder");
        }
    }

    #[test]
    fn a_base_url_carrying_credentials_in_its_authority_is_refused_by_every_door() {
        // `https://user:pass@host` puts a second credential-bearing value into a
        // struct that derives `Debug`, and the transport logs the joined URL on
        // every request. Refusing the URL closes both, plus the blind spot in
        // `check_destination`, which reads only `url.host()`.
        const PASSWORD: &str = "p4ssw0rd-that-must-not-reach-a-log";

        for raw in [
            format!("https://user:{PASSWORD}@test.atlassian.net"),
            "https://user@test.atlassian.net".to_string(),
            // The userinfo half spelling a permitted tenant, dialled at whatever
            // follows the `@`.
            "https://test.atlassian.net@evil.example".to_string(),
        ] {
            let error =
                AtlassianConfig::new(raw.clone(), "test@example.com".to_string(), "test-token")
                    .expect_err(&format!("{raw} was accepted"))
                    .to_string();

            assert!(
                error.contains("must not carry credentials in its authority"),
                "{raw} produced: {error}"
            );
            assert!(!error.contains(PASSWORD), "{raw} echoed the password");

            assert!(
                AtlassianConfig::builder()
                    .base_url(raw.clone())
                    .username("test@example.com")
                    .api_token("test-token")
                    .build()
                    .is_err(),
                "{raw} was accepted by the builder"
            );
        }
    }

    #[test]
    fn the_destination_check_sees_userinfo_the_parser_never_got_to_refuse() {
        // `base_url` is a public field, so a caller can install a URL that never
        // passed `parse_base_url`. `check_destination` is the predicate every
        // request goes through, and it judged only `url.host()`.
        let mut config = config_at("https://test.atlassian.net", HostPolicy::AtlassianCloud);
        config.base_url = Url::parse("https://user:p4ssw0rd@test.atlassian.net/")
            .expect("the hostile URL parses");

        let error = config
            .validate()
            .expect_err("a userinfo destination was admitted")
            .to_string();
        assert!(
            error.contains("must not carry credentials in its authority"),
            "error was: {error}"
        );
        assert!(!error.contains("p4ssw0rd"), "error was: {error}");
    }

    #[test]
    fn the_destination_check_sees_a_query_the_parser_never_got_to_refuse() {
        // The same public-field bypass as the userinfo case above, and it needs
        // the same second gate: `build_url` joins by pushing segments onto a
        // clone of the base, which leaves a query or fragment on it untouched,
        // so it rides every request and reaches the `debug!` of the joined URL.
        for raw in [
            "https://test.atlassian.net/?smuggled=CANARY",
            "https://test.atlassian.net/#smuggled=CANARY",
        ] {
            let mut config = config_at("https://test.atlassian.net", HostPolicy::AtlassianCloud);
            config.base_url = Url::parse(raw).expect("the hostile URL parses");

            // Anti-vacuity: the join really does carry it onto the wire URL,
            // which is why refusing it in the parser alone is not enough.
            let mut joined = config.base_url.clone();
            joined
                .path_segments_mut()
                .expect("an https URL can carry a path")
                .pop_if_empty()
                .extend(["rest", "api", "2", "myself"]);
            assert!(
                joined.as_str().contains("CANARY"),
                "the join dropped it, so this test proves nothing: {joined}"
            );

            let error = config
                .validate()
                .expect_err(&format!("{raw} was admitted by validate"))
                .to_string();
            assert!(
                error.contains("must not carry a query string or fragment"),
                "{raw} produced: {error}"
            );
            assert!(!error.contains("CANARY"), "{raw} echoed the query: {error}");

            // The per-request gate, which is the one `build_url` runs.
            assert!(
                config.host_policy.check_destination(&joined).is_err(),
                "{raw} was admitted on the joined URL"
            );
        }
    }

    #[test]
    fn a_base_url_query_string_or_fragment_is_refused() {
        // A query survives every join, so it would be attached to every request
        // -- including the paginated ones that pass their own `maxResults`.
        for raw in [
            "https://test.atlassian.net/?maxResults=1000",
            "https://test.atlassian.net/jira?maxResults=1000",
            "https://test.atlassian.net/#/browse/KAN-1",
            "https://test.atlassian.net/jira?a=1#b",
        ] {
            let error = AtlassianConfig::new(
                raw.to_string(),
                "test@example.com".to_string(),
                "test-token",
            )
            .expect_err(&format!("{raw} was accepted"))
            .to_string();

            assert!(
                error.contains("must not carry a query string or fragment"),
                "{raw} produced: {error}"
            );
            assert!(!error.contains("maxResults"), "{raw} echoed the query");
        }
    }

    #[test]
    fn a_base_url_collapses_repeated_slashes_where_it_adds_the_trailing_one() {
        // An empty interior segment survives every join, and the joined path
        // then addresses a resource nobody named.
        for (raw, expected) in [
            (
                "https://test.atlassian.net//",
                "https://test.atlassian.net/",
            ),
            (
                "https://test.atlassian.net//jira",
                "https://test.atlassian.net/jira/",
            ),
            (
                "https://test.atlassian.net/jira//",
                "https://test.atlassian.net/jira/",
            ),
            (
                "https://test.atlassian.net//apps//jira//",
                "https://test.atlassian.net/apps/jira/",
            ),
            // The collapse rebuilds the path from its segments, so it must not
            // decode one on the way through: `%2F` is a literal slash *inside* a
            // segment, and turning it back into a separator would move the
            // context path.
            (
                "https://test.atlassian.net//a%2Fb//c",
                "https://test.atlassian.net/a%2Fb/c/",
            ),
            (
                "https://test.atlassian.net/my%20jira",
                "https://test.atlassian.net/my%20jira/",
            ),
        ] {
            let config = AtlassianConfig::new(
                raw.to_string(),
                "test@example.com".to_string(),
                "test-token",
            )
            .unwrap_or_else(|error| panic!("{raw} was refused: {error}"));

            assert_eq!(config.base_url.as_str(), expected, "from {raw}");
        }
    }

    #[test]
    fn an_allowlist_entry_carrying_a_port_is_refused_and_says_so() {
        // The entry used to parse and then match nothing, because `permits_host`
        // compares against `Url::host()`, which excludes the port -- so every
        // request was refused by a message naming the host just allowlisted.
        for raw in [
            "allowlist:jira.example.com:8443",
            "allowlist:jira.example.com,other.example.com:443",
            "allowlist:[::1]:8443",
            "allowlist:127.0.0.1:8080",
        ] {
            let error = raw
                .parse::<HostPolicy>()
                .expect_err(&format!("{raw} was accepted"))
                .to_string();

            assert!(
                error.contains("must not carry a port"),
                "{raw} produced: {error}"
            );
        }
    }

    #[test]
    fn an_allowlist_entry_may_still_be_an_ipv6_literal() {
        // The only `:` an entry is allowed to carry, in both spellings, and it
        // has to keep matching the bracketed form a URL host arrives as.
        let policy: HostPolicy = "allowlist:[::1],2001:db8::1".parse().expect("both parse");
        assert_eq!(
            policy,
            HostPolicy::Allowlist(vec!["::1".to_string(), "2001:db8::1".to_string()])
        );

        assert!(config_at("https://[::1]:8443", policy.clone())
            .validate()
            .is_ok());
        assert!(config_at("https://[2001:db8::1]", policy)
            .validate()
            .is_ok());
    }

    #[test]
    fn an_allowlist_entry_matches_every_spelling_of_the_address_it_names() {
        // One address, many valid spellings, and `Url::host()` prints exactly
        // one of them -- so an entry compared as text parsed and then matched
        // nothing. That is the port bug one component over: the request is
        // refused by a message naming the host just allowlisted, and `token()`
        // deliberately never echoes the allowlist that would explain why.
        for (entry, dialled) in [
            (
                "2001:0db8:0000:0000:0000:0000:0000:0001",
                "https://[2001:db8::1]",
            ),
            ("2001:DB8:0:0:0:0:0:1", "https://[2001:db8::1]"),
            ("[2001:0db8::0:1]", "https://[2001:db8::1]"),
            ("::0001", "https://[::1]:8443"),
            ("0:0:0:0:0:0:0:1", "https://[::1]:8443"),
        ] {
            let policy: HostPolicy = format!("allowlist:{entry}")
                .parse()
                .unwrap_or_else(|error| panic!("{entry} was refused at parse: {error}"));

            assert!(
                config_at(dialled, policy).validate().is_ok(),
                "{entry} parsed and then refused {dialled}"
            );

            // The variant is public, so an entry can also arrive from a struct
            // literal that never passed the parser; both sides are normalized
            // for exactly that reason.
            assert!(
                config_at(dialled, HostPolicy::Allowlist(vec![entry.to_string()]))
                    .validate()
                    .is_ok(),
                "{entry} refused {dialled} when set directly on the variant"
            );
        }

        // Anti-vacuity: canonicalizing a spelling must not widen the set to a
        // different address, however that one is spelled.
        for refused in ["https://[2001:db8::2]", "https://[::1]"] {
            assert!(
                config_at(
                    refused,
                    "allowlist:2001:0db8:0000:0000:0000:0000:0000:0001"
                        .parse()
                        .expect("the long spelling parses")
                )
                .validate()
                .is_err(),
                "{refused} was admitted by an allowlist naming another address"
            );
        }
    }

    #[test]
    #[serial]
    fn a_trust_anchor_is_not_installable_from_the_environment() {
        // `JIRA_CERT_PATH` used to reach `add_root_certificate`, which makes the
        // named CA able to vouch for the host the same environment picked with
        // `JIRA_URL` -- certificate verification relaxed from the environment,
        // which is exactly what this module promises cannot happen.
        let _guards = baseline_env();
        let _cert = EnvGuard::set("JIRA_CERT_PATH", "/attacker/controlled/ca.pem");

        let config = AtlassianConfig::from_env().expect("an inert variable is not a refusal");
        assert_eq!(config.cert_path, None);

        // Anti-vacuity: the code call it was demoted to still reaches the field.
        assert_eq!(
            config
                .with_cert_path(PathBuf::from("/operator/chosen/ca.pem"))
                .cert_path
                .as_deref(),
            Some(std::path::Path::new("/operator/chosen/ca.pem"))
        );
    }

    #[test]
    fn a_trimmed_secret_leaves_no_un_zeroized_copy_behind() {
        // `trim` borrows, so an owned trimmed value is always a second buffer.
        // The decrypt path already wiped the first one; the cleartext loader
        // dropped it, and `load_required_credential`'s doc claimed otherwise.
        let mut loaded = format!("  {}  ", "s3cr3t-api-token");
        let trimmed = take_trimmed(&mut loaded);

        assert_eq!(trimmed, "s3cr3t-api-token");
        assert!(
            loaded.is_empty(),
            "the buffer the value was trimmed out of survived: {loaded:?}"
        );
    }

    #[test]
    fn a_host_policy_round_trips_through_its_string_form() {
        for policy in [
            HostPolicy::AtlassianCloud,
            HostPolicy::Loopback,
            HostPolicy::Allowlist(vec!["jira.example.com".to_string(), "::1".to_string()]),
        ] {
            let rendered = policy.to_string();
            assert_eq!(rendered.parse::<HostPolicy>().unwrap(), policy);
        }

        assert_eq!(
            "  ATLASSIAN-CLOUD  ".parse::<HostPolicy>().unwrap(),
            HostPolicy::AtlassianCloud
        );
        assert_eq!(
            "allowlist: JIRA.example.com , second.example.com "
                .parse::<HostPolicy>()
                .unwrap(),
            HostPolicy::Allowlist(vec![
                "jira.example.com".to_string(),
                "second.example.com".to_string()
            ])
        );
    }

    #[test]
    fn an_unparseable_host_policy_is_refused_without_echoing_itself() {
        const HOSTILE: &str = "not-a-policy-and-must-not-reach-a-log";

        for raw in [
            HOSTILE,
            "allowlist:",
            "allowlist:https://jira.example.com/x",
        ] {
            let error = raw.parse::<HostPolicy>().unwrap_err().to_string();
            assert!(!error.contains(HOSTILE), "error was: {error}");
        }
    }

    #[test]
    #[serial]
    fn jira_verify_ssl_refuses_every_spelling_of_disabled() {
        // The old parse was `to_lowercase() != "false"`, so each of these except
        // the first silently meant *enabled* -- the opposite of what was written.
        for raw in ["false", " false ", "FALSE", "0", "no", "off"] {
            let _guards = baseline_env();
            let _verify = EnvGuard::set("JIRA_VERIFY_SSL", raw);

            let error = AtlassianConfig::from_env().unwrap_err().to_string();
            assert!(
                error.contains("cannot disable certificate verification"),
                "{raw:?} produced: {error}"
            );
        }
    }

    #[test]
    #[serial]
    fn jira_verify_ssl_accepts_the_spellings_that_mean_enabled() {
        for raw in ["true", " TRUE ", "1", "yes", "on"] {
            let _guards = baseline_env();
            let _verify = EnvGuard::set("JIRA_VERIFY_SSL", raw);

            let config = AtlassianConfig::from_env()
                .unwrap_or_else(|error| panic!("{raw:?} was refused: {error}"));
            assert!(config.verify_ssl);
        }
    }

    #[test]
    #[serial]
    fn jira_verify_ssl_refuses_a_value_it_cannot_interpret() {
        for raw in ["maybe", "", "  "] {
            let _guards = baseline_env();
            let _verify = EnvGuard::set("JIRA_VERIFY_SSL", raw);

            assert!(
                AtlassianConfig::from_env().is_err(),
                "{raw:?} was interpreted rather than refused"
            );
        }
    }

    #[test]
    #[serial]
    fn jira_host_policy_refuses_the_loopback_token() {
        for raw in ["loopback", " Loopback ", "LOOPBACK"] {
            let _guards = baseline_env();
            let _policy = EnvGuard::set("JIRA_HOST_POLICY", raw);

            let error = AtlassianConfig::from_env().unwrap_err().to_string();
            assert!(
                error.contains("settable only by"),
                "{raw:?} produced: {error}"
            );
        }
    }

    #[test]
    #[serial]
    #[cfg(feature = "encrypted-env")]
    fn an_encrypted_env_file_cannot_re_inject_the_relaxations_either() {
        // `load_encrypted_env_file_if_present` runs `dotenvy::from_read_override`
        // before the optional settings are read, so a decrypted file is a second
        // way into the same variables. It reaches the same parser, which is why
        // there is only one refusal to get right.
        let keypair = KeyPair::generate(2048).expect("key generation succeeds");
        let cipher = HybridCipher::new(FluxConfig::default());

        for line in ["JIRA_HOST_POLICY=loopback", "JIRA_VERIFY_SSL=false"] {
            let body = format!(
                "export JIRA_URL=http://127.0.0.1:9999\n\
                 export JIRA_USERNAME=env-user@example.com\n\
                 export JIRA_API_TOKEN=env-token\n\
                 export {line}\n"
            );
            let encoded = BASE64_ENGINE.encode(
                cipher
                    .encrypt(keypair.public_key(), body.as_bytes())
                    .expect("encrypt env file"),
            );

            let _guards = baseline_env();
            let _cipher = EnvGuard::set("ENV_FILE_ENCRYPTED", &encoded);
            let _private = EnvGuard::set(
                "ENV_FILE_PRIVATE_KEY",
                &keypair.private_key().to_pem().expect("private key to pem"),
            );
            let _password = EnvGuard::unset("ENV_FILE_PRIVATE_KEY_PASSWORD");

            assert!(
                AtlassianConfig::from_env().is_err(),
                "{line} survived re-injection through the encrypted env file"
            );
        }
    }

    #[test]
    #[serial]
    fn jira_host_policy_parses_the_policies_it_admits() {
        let _guards = baseline_env();

        {
            let _policy = EnvGuard::set("JIRA_HOST_POLICY", "atlassian-cloud");
            assert_eq!(
                AtlassianConfig::from_env().unwrap().host_policy,
                HostPolicy::AtlassianCloud
            );
        }

        {
            let _policy = EnvGuard::set("JIRA_HOST_POLICY", "allowlist:jira.example.com");
            assert_eq!(
                AtlassianConfig::from_env().unwrap().host_policy,
                HostPolicy::Allowlist(vec!["jira.example.com".to_string()])
            );
        }

        {
            let _policy = EnvGuard::set("JIRA_HOST_POLICY", "nonsense");
            assert!(AtlassianConfig::from_env().is_err());
        }
    }

    #[test]
    #[serial]
    fn no_environment_yields_a_configuration_that_can_talk_cleartext() {
        // This is the property that lets "production cannot disable TLS
        // verification" and "the end-to-end suite drives a real client against a
        // loopback mock" both hold: the hatch is code-only.
        for policy in ["loopback", "atlassian-cloud", "allowlist:127.0.0.1"] {
            for verify in ["false", "true"] {
                let _guards = baseline_env();
                let _url = EnvGuard::set("JIRA_URL", "http://127.0.0.1:9999");
                let _policy = EnvGuard::set("JIRA_HOST_POLICY", policy);
                let _verify = EnvGuard::set("JIRA_VERIFY_SSL", verify);

                let outcome = AtlassianConfig::from_env().and_then(|config| {
                    config.validate()?;
                    Ok(config)
                });
                assert!(
                    outcome.is_err(),
                    "JIRA_HOST_POLICY={policy} JIRA_VERIFY_SSL={verify} reached a cleartext destination"
                );
            }
        }
    }

    #[test]
    #[serial]
    fn an_env_built_configuration_defaults_to_the_atlassian_cloud_policy() {
        let _guards = baseline_env();

        let config = AtlassianConfig::from_env().unwrap();

        assert_eq!(config.host_policy, HostPolicy::AtlassianCloud);
        assert!(config.verify_ssl);
        assert!(config.validate().is_ok());
    }

    #[test]
    #[serial]
    #[cfg(feature = "encrypted-env")]
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
        assert_eq!(config.api_token.expose_secret(), "jira-secret-token");
    }

    #[test]
    #[serial]
    #[cfg(feature = "encrypted-env")]
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
        assert_eq!(config.api_token.expose_secret(), "plain-token");
    }

    #[test]
    #[serial]
    #[cfg(feature = "encrypted-env")]
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
        assert_eq!(config.api_token.expose_secret(), "env-token");
    }

    #[test]
    #[serial]
    fn from_env_with_overrides_uses_cli_value_for_missing_secret() {
        let _guard_url = EnvGuard::set("JIRA_URL", "https://example.atlassian.net");
        let _guard_user = EnvGuard::set("JIRA_USERNAME", "env-user@example.com");
        let _guard_token = EnvGuard::unset("JIRA_API_TOKEN");

        let config =
            AtlassianConfig::from_env_with_overrides(None, None, Some("cli-token".to_string()))
                .unwrap();

        assert_eq!(config.base_url.as_str(), "https://example.atlassian.net/");
        assert_eq!(config.username, "env-user@example.com");
        assert_eq!(config.api_token.expose_secret(), "cli-token");
    }

    /// A refusal has to name the variable, the feature, and a way forward.
    ///
    /// Asserting on the message rather than only on `is_err()` is what stops the
    /// gate degrading into a generic "not set" error, which reads as a
    /// misconfiguration and sends the operator to fix the wrong thing.
    #[cfg(not(feature = "encrypted-env"))]
    fn assert_names_the_missing_feature(variable: &str, error: &AtlassianError) {
        let rendered = error.to_string();
        for expected in [variable, "encrypted-env", "cargo feature"] {
            assert!(
                rendered.contains(expected),
                "refusal must mention {expected}: {rendered}"
            );
        }
    }

    #[test]
    #[serial]
    #[cfg(not(feature = "encrypted-env"))]
    fn an_encrypted_credential_is_refused_rather_than_ignored() {
        let _guards = baseline_env();
        let _plain = EnvGuard::unset("JIRA_API_TOKEN");
        let _cipher = EnvGuard::set("JIRA_API_TOKEN_ENCRYPTED", "Y2lwaGVydGV4dA==");
        let _key = EnvGuard::set("JIRA_API_TOKEN_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----");

        let error = AtlassianConfig::from_env()
            .expect_err("an encrypted token must not resolve without the feature");
        assert_names_the_missing_feature("JIRA_API_TOKEN_ENCRYPTED", &error);
    }

    /// The refusal must not echo the ciphertext or the private key it was handed.
    #[test]
    #[serial]
    #[cfg(not(feature = "encrypted-env"))]
    fn the_refusal_does_not_echo_what_it_refused_to_decrypt() {
        let _guards = baseline_env();
        let _plain = EnvGuard::unset("JIRA_API_TOKEN");
        let _cipher = EnvGuard::set("JIRA_API_TOKEN_ENCRYPTED", NOT_A_REAL_CIPHERTEXT);
        let _key = EnvGuard::set("JIRA_API_TOKEN_PRIVATE_KEY", "super-secret-private-key");

        let rendered = AtlassianConfig::from_env()
            .expect_err("an encrypted token must not resolve without the feature")
            .to_string();

        SecretScanner::new()
            .with_secret("ciphertext", NOT_A_REAL_CIPHERTEXT)
            .with_secret("private key", "super-secret-private-key")
            .assert_clean("the missing-feature refusal", &rendered);
    }

    /// Both spellings of the encrypted env file are refused, and neither is read.
    ///
    /// The `ENV_FILE_ENCRYPTED_PATH` case points at a path that does not exist:
    /// a refusal that reported an I/O error would prove the checker had touched
    /// the filesystem for a file it can never decrypt.
    #[test]
    #[serial]
    #[cfg(not(feature = "encrypted-env"))]
    fn an_encrypted_env_file_is_refused_without_being_read() {
        for variable in ENCRYPTED_ENV_FILE_VARS {
            let _guards = baseline_env();
            let _file = EnvGuard::set(variable, "no/such/path/env.enc");

            let error = AtlassianConfig::from_env()
                .expect_err("an encrypted env file must not be accepted without the feature");
            assert_names_the_missing_feature(variable, &error);
        }
    }

    /// `ENV_FILE_ENCRYPTED_PATH` wins over `ENV_FILE_ENCRYPTED` when both are
    /// set, so the refusal names the one that would have been used.
    #[test]
    #[serial]
    #[cfg(not(feature = "encrypted-env"))]
    fn the_refusal_names_the_env_file_variable_that_would_have_won() {
        let _guards = baseline_env();
        let _path = EnvGuard::set("ENV_FILE_ENCRYPTED_PATH", "no/such/path/env.enc");
        let _inline = EnvGuard::set("ENV_FILE_ENCRYPTED", "Y2lwaGVydGV4dA==");

        let error = AtlassianConfig::from_env().expect_err("both spellings must be refused");
        assert_names_the_missing_feature("ENV_FILE_ENCRYPTED_PATH", &error);
    }

    /// The gate must not fire on a deployment that never asked for encryption.
    #[test]
    #[serial]
    #[cfg(not(feature = "encrypted-env"))]
    fn a_cleartext_environment_is_unaffected_by_the_gate() {
        let _guards = baseline_env();

        let config = AtlassianConfig::from_env().expect("cleartext credentials still resolve");
        assert_eq!(config.username, "test@example.com");
        assert_eq!(config.api_token.expose_secret(), "test-token");
    }
}
