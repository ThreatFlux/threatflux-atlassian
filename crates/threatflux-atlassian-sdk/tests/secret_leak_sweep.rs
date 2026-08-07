//! Secret-leak sweep over the SDK's observable channels.
//!
//! Five channels can carry a credential out of this process: `Debug`, `Display`,
//! `serde`, `tracing`, and an error value a caller prints. Each case below plants
//! a canary, drives the channel, and asserts the canary's **absence** from what
//! came out — in every encoding the canary reaches a log, a URL or a JSON body
//! in, which is what [`SecretScanner`] is for. Asserting that a redaction marker
//! is present is not the same assertion: a marker can be printed for one field
//! while another field of the same struct prints the credential.
//!
//! The marker is asserted too, but only as a second condition, so a type that
//! stopped rendering its credential *field at all* cannot pass by omission.

use std::fmt::Debug;
use std::marker::PhantomData;

use serial_test::serial;
use threatflux_atlassian_sdk::auth::TokenResponse;
use threatflux_atlassian_sdk::error::{AtlassianError, DiagnosticsPolicy, ResponseDiagnostics};
use threatflux_atlassian_sdk::secret::REDACTED;
use threatflux_atlassian_sdk::{
    AccessToken, AtlassianClient, AtlassianConfig, AtlassianConfigBuilder, AuthManager,
    AuthorizationResponse, CreateIssueRequest, HostPolicy, OAuthConfig, SecretString,
};
use threatflux_atlassian_testkit::env::EnvGuard;
use threatflux_atlassian_testkit::jira_mock::{JiraMock, Step};
use threatflux_atlassian_testkit::redaction::SecretScanner;
use threatflux_atlassian_testkit::{fixtures, logs};
use url::Url;

/// The credential every case in this file plants.
///
/// The `/` and `+` are load-bearing: a token of only alphanumerics and hyphens
/// percent-encodes to itself, and the scanner would then be checking one
/// encoding while reporting four.
const TOKEN: &str = "CANARY-tok3n/4f21c7a9+must-not-escape";

/// The account the credential belongs to, which is half of the `Basic` blob.
const USERNAME: &str = "canary-bot@example.com";

/// The credential planted in a base URL's *authority* rather than in a token slot.
///
/// Spelled without `/`, `+` or `@` so that `Url` stores it verbatim: a value the
/// URL parser re-encoded would be scanned for in one encoding and rendered in
/// another, and the sweep would pass by accident rather than by redaction. The
/// case below asserts the verbatim storage before it asserts anything else.
const URL_USERNAME: &str = "CANARY-url-bot";
const URL_PASSWORD: &str = "CANARY-url-p4ssw0rd-must-not-escape";

/// A canary planted in a Jira response body rather than in a credential slot.
///
/// It carries a quote so its JSON-escaped form differs from its raw one, which
/// is the encoding a response body actually travels in.
const RESPONSE_CANARY: &str = "CANARY-body \"9c71f2\" must-not-escape";

/// Scans for the credential in every encoding, including the `Basic` blob.
fn scanner() -> SecretScanner {
    SecretScanner::new().with_basic_credentials("jira api token", USERNAME, TOKEN)
}

/// Scans for a Jira-supplied response body.
fn response_scanner() -> SecretScanner {
    SecretScanner::new().with_secret("jira response body", RESPONSE_CANARY)
}

/// Scans for a credential carried in a base URL's authority.
fn url_scanner() -> SecretScanner {
    SecretScanner::new().with_basic_credentials("jira url authority", URL_USERNAME, URL_PASSWORD)
}

fn config() -> AtlassianConfig {
    AtlassianConfig::new(
        "https://canary.atlassian.net".to_string(),
        USERNAME.to_string(),
        TOKEN,
    )
    .expect("the canary base URL parses")
}

fn builder() -> AtlassianConfigBuilder {
    AtlassianConfig::builder()
        .base_url("https://canary.atlassian.net")
        .username(USERNAME)
        .api_token(TOKEN)
}

/// A client pointed at a loopback mock.
///
/// `HostPolicy::Loopback` is the code-only hatch that admits the `http://` mock
/// URL; no environment variable can reach it, which is why this is a function in
/// a test and not a configuration a deployment could arrive at.
fn loopback_client(base_url: &str) -> AtlassianClient {
    let config = AtlassianConfig::builder()
        .base_url(base_url)
        .username(USERNAME)
        .api_token(TOKEN)
        .host_policy(HostPolicy::Loopback)
        .build()
        .expect("a loopback client builds");
    AtlassianClient::new(config).expect("a loopback client validates")
}

fn oauth_config() -> OAuthConfig {
    OAuthConfig {
        client_id: "canary-client".to_string(),
        authorization_endpoint: Url::parse("https://auth.atlassian.com/authorize")
            .expect("endpoint parses"),
        token_endpoint: Url::parse("https://auth.atlassian.com/oauth/token")
            .expect("endpoint parses"),
        redirect_uri: Url::parse("http://localhost:8080/callback").expect("redirect parses"),
        scopes: vec!["read:jira-work".to_string()],
        code_verifier: Some(SecretString::from(TOKEN)),
        state: Some("canary-state".to_string()),
    }
}

fn access_token() -> AccessToken {
    AccessToken {
        access_token: SecretString::from(TOKEN),
        token_type: "Bearer".to_string(),
        expires_at: None,
        refresh_token: Some(SecretString::from(TOKEN)),
        scope: Some("read:jira-work".to_string()),
    }
}

fn authorization_response() -> AuthorizationResponse {
    AuthorizationResponse {
        code: SecretString::from(TOKEN),
        state: Some("canary-state".to_string()),
    }
}

fn token_response() -> TokenResponse {
    TokenResponse {
        access_token: SecretString::from(TOKEN),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        refresh_token: Some(SecretString::from(TOKEN)),
        scope: Some("read:jira-work".to_string()),
    }
}

/// Renders `value` both ways a `Debug` reaches a log line or a panic payload.
fn debug_renderings<T: Debug>(value: &T) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

/// Runs an async body with every `tracing` event captured.
fn capture_async<T>(body: impl std::future::Future<Output = T>) -> (T, String) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime should build");
    logs::capture(|| runtime.block_on(body))
}

/// Compile-time probes for the *absence* of a trait implementation.
///
/// A test can call `serde_json::to_string` to prove a type serializes; nothing
/// it can call proves a type does not, because the missing impl is a compile
/// error rather than a value. Autoref specialization recovers the answer: the
/// affirmative impl is on `&Probe<T>` and the fallback on `Probe<T>`, so a
/// `&&Probe<T>` receiver reaches the affirmative one first and falls through to
/// the fallback only when the bound does not hold.
///
/// This is what makes "`SecretString` has no `Serialize`" an assertion rather
/// than a comment. The design decision it pins is F1's: a lossy `Serialize`
/// emitting a placeholder would corrupt round-trips silently, so there is none
/// at all.
mod probe {
    use std::marker::PhantomData;

    pub struct Probe<T>(pub PhantomData<T>);

    pub trait SerializeAbsent {
        fn serializes(&self) -> bool {
            false
        }
    }
    impl<T> SerializeAbsent for Probe<T> {}

    pub trait SerializePresent {
        fn serializes(&self) -> bool {
            true
        }
    }
    impl<T: serde::Serialize> SerializePresent for &Probe<T> {}

    pub trait DisplayAbsent {
        fn displays(&self) -> bool {
            false
        }
    }
    impl<T> DisplayAbsent for Probe<T> {}

    pub trait DisplayPresent {
        fn displays(&self) -> bool {
            true
        }
    }
    impl<T: std::fmt::Display> DisplayPresent for &Probe<T> {}
}

/// Reports whether `$t` implements [`serde::Serialize`].
macro_rules! serializes {
    ($t:ty) => {{
        #[allow(
            unused_imports,
            reason = "exactly one of the two probe traits resolves per type"
        )]
        use crate::probe::{SerializeAbsent as _, SerializePresent as _};
        (&&crate::probe::Probe::<$t>(PhantomData)).serializes()
    }};
}

/// Reports whether `$t` implements [`std::fmt::Display`].
macro_rules! displays {
    ($t:ty) => {{
        #[allow(
            unused_imports,
            reason = "exactly one of the two probe traits resolves per type"
        )]
        use crate::probe::{DisplayAbsent as _, DisplayPresent as _};
        (&&crate::probe::Probe::<$t>(PhantomData)).displays()
    }};
}

/// Calibration type for the probes: it implements neither trait.
struct Opaque;

#[test]
fn the_probe_can_answer_both_ways() {
    // A probe that always answered "absent" would pass every assertion below
    // while proving nothing, so it is calibrated against types whose impls are
    // not in question.
    assert!(serializes!(String));
    assert!(serializes!(AtlassianError));
    assert!(serializes!(ResponseDiagnostics));
    assert!(serializes!(CreateIssueRequest));
    assert!(!serializes!(Opaque));

    assert!(displays!(String));
    assert!(displays!(AtlassianError));
    assert!(!displays!(Opaque));
}

#[test]
fn no_credential_bearing_type_can_be_serialized() {
    // Every type F1 wrapped. `AtlassianConfig` is here because the credential
    // being a `SecretString` is only half the guarantee: a `Serialize` on the
    // surrounding struct would have been the way around it.
    assert!(!serializes!(SecretString));
    assert!(!serializes!(AtlassianConfig));
    assert!(!serializes!(AtlassianConfigBuilder));
    assert!(!serializes!(OAuthConfig));
    assert!(!serializes!(AccessToken));
    assert!(!serializes!(AuthorizationResponse));
    assert!(!serializes!(TokenResponse));
}

#[test]
fn every_credential_bearing_type_either_redacts_display_or_has_none() {
    // `SecretString` is the one that renders, and it renders the marker. The
    // holders have no `Display` at all, so a `{}` on one is a compile error
    // rather than a leak -- which is a stronger guarantee than a redacted
    // rendering and is asserted here so that adding a `Display` later cannot
    // pass unnoticed.
    assert!(displays!(SecretString));
    assert_eq!(SecretString::from(TOKEN).to_string(), REDACTED);
    assert_eq!(format!("{}", SecretString::from(TOKEN)), REDACTED);

    assert!(!displays!(AtlassianConfig));
    assert!(!displays!(AtlassianConfigBuilder));
    assert!(!displays!(OAuthConfig));
    assert!(!displays!(AccessToken));
    assert!(!displays!(AuthorizationResponse));
    assert!(!displays!(TokenResponse));
}

#[test]
fn every_credential_bearing_type_redacts_its_debug_rendering() {
    // Every type F1 wrapped, plus the two that hold one transitively: a client
    // owns its configuration and an `AuthManager` owns its OAuth config, so a
    // `{:?}` of either is a `{:?}` of the credential's holder.
    let cases: [(&str, [String; 2]); 9] = [
        ("SecretString", debug_renderings(&SecretString::from(TOKEN))),
        ("AtlassianConfig", debug_renderings(&config())),
        ("AtlassianConfigBuilder", debug_renderings(&builder())),
        (
            "AtlassianClient",
            debug_renderings(&AtlassianClient::new(config()).expect("the canary config validates")),
        ),
        ("OAuthConfig", debug_renderings(&oauth_config())),
        (
            "AuthManager",
            debug_renderings(&AuthManager::new(oauth_config())),
        ),
        ("AccessToken", debug_renderings(&access_token())),
        (
            "AuthorizationResponse",
            debug_renderings(&authorization_response()),
        ),
        ("TokenResponse", debug_renderings(&token_response())),
    ];

    for (label, renderings) in cases {
        for rendered in renderings {
            scanner().assert_clean(&format!("the Debug rendering of {label}"), &rendered);
            assert!(
                rendered.contains(REDACTED),
                "{label} printed no redaction marker, so the field may have gone missing \
                 rather than being redacted: {rendered}"
            );
        }
    }
}

#[test]
fn a_credential_bearing_struct_keeps_its_other_fields_readable() {
    // The point of redacting the field rather than removing the derive is that a
    // `{:?}` of the holder stays useful. A sweep that only asserted absence
    // would pass on a `Debug` that printed nothing at all.
    let rendered = format!("{:?}", config());

    assert!(rendered.contains("canary.atlassian.net"), "{rendered}");
    assert!(rendered.contains(USERNAME), "{rendered}");
}

#[test]
fn a_successful_request_cycle_puts_no_credential_in_the_trace_log() {
    // The subscriber the capture installs is pinned to TRACE, so this is the
    // most verbose output the transport can produce, not the default filter's
    // subset. The `Basic` header is the encoding that matters here: it is the
    // credential joined to the username and base64'd, which no amount of
    // redaction on `SecretString` reaches.
    let ((), log) = capture_async(async {
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            "/rest/api/2/search",
            Step::json_str(200, fixtures::jira_body("search-empty")),
        )
        .await;

        let client = loopback_client(&mock.uri());
        client
            .search_issues(r#"project = "KAN""#, 0, 50)
            .await
            .expect("the mocked search succeeds");

        let journal = mock.journal().await;
        let authorization = journal
            .first()
            .and_then(|request| request.headers.get("authorization").cloned())
            .expect("the request carried an Authorization header");
        // The credential really did go out on the wire in its base64 form, so
        // the log assertion below is about a value that exists rather than about
        // a request that never authenticated.
        assert!(
            !scanner().findings(&authorization).is_empty(),
            "the request did not authenticate, so the log sweep proves nothing"
        );
    });

    // A capture that recorded nothing would satisfy every absence assertion in
    // this file, so the sweep asserts it has something to sweep.
    assert!(
        log.contains("Making GET request"),
        "the transport logged nothing, so the sweep is vacuous: {log}"
    );
    scanner().assert_clean("the trace log of a successful request cycle", &log);
}

#[test]
fn a_jira_error_body_reaches_neither_the_error_nor_the_log_by_default() {
    // A Jira error document echoes the request that produced it -- a JQL query
    // built from an event body, a rejected summary -- so the body is caller data
    // of unknown provenance and the default policy never reads it. `serde` is
    // swept alongside `Display` and `Debug` because `AtlassianError` *is*
    // `Serialize`, which makes it the one error channel that can carry a
    // structured field a message never would.
    let (result, log) = capture_async(async {
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            "/rest/api/2/search",
            Step::json(
                500,
                &serde_json::json!({
                    "errorMessages": [RESPONSE_CANARY],
                    "errors": { "summary": RESPONSE_CANARY },
                    "unmodelled": RESPONSE_CANARY,
                }),
            ),
        )
        .await;

        loopback_client(&mock.uri())
            .search_issues(r#"project = "KAN""#, 0, 50)
            .await
    });

    let error = result.expect_err("a 500 is an error");
    let serialized = serde_json::to_string(&error).expect("AtlassianError serializes");
    assert!(
        log.contains("Atlassian API request failed"),
        "the failure was not logged at all, so the log sweep is vacuous: {log}"
    );

    for (channel, rendered) in [
        ("the error message", error.to_string()),
        ("the error Debug rendering", format!("{error:?}")),
        ("the serialized error", serialized),
        ("the trace log", log),
    ] {
        response_scanner().assert_clean(channel, &rendered);
        scanner().assert_clean(channel, &rendered);
    }

    assert_eq!(
        error.diagnostics().map(|diagnostics| diagnostics.policy),
        Some(DiagnosticsPolicy::MetadataOnly),
        "the default policy is what this case is about"
    );
    assert!(
        error
            .diagnostics()
            .is_some_and(|diagnostics| diagnostics.body.is_none()),
        "the body was not merely withheld from the message, it was never read"
    );
}

#[test]
fn opting_into_the_body_widens_the_error_and_never_the_log() {
    // The contrast case. A caller that asks for the body gets it in the value it
    // is holding; the log this process writes into is not that caller's, and
    // stays metadata whatever the policy says.
    let (result, log) = capture_async(async {
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            "/rest/api/2/search",
            Step::json(
                400,
                &serde_json::json!({ "errorMessages": [RESPONSE_CANARY] }),
            ),
        )
        .await;

        loopback_client(&mock.uri())
            .with_diagnostics(DiagnosticsPolicy::IncludeBody)
            .search_issues(r#"project = "KAN""#, 0, 50)
            .await
    });

    let error = result.expect_err("a 400 is an error");
    let body = error
        .diagnostics()
        .and_then(|diagnostics| diagnostics.body.clone())
        .expect("IncludeBody delivers the body");
    // Matched through the scanner rather than with `contains`: the body is the
    // raw response text, so the canary is in it JSON-escaped, and a plain
    // `contains` of the unescaped form would report the opt-in as broken.
    assert!(
        !response_scanner().findings(&body).is_empty(),
        "the opt-in must actually deliver the body, or the log assertion is vacuous: {body}"
    );

    response_scanner().assert_clean("the trace log under IncludeBody", &log);
    scanner().assert_clean("the trace log under IncludeBody", &log);
}

#[test]
fn a_base_url_authority_is_a_second_credential_slot_and_never_reaches_a_channel() {
    // Every other case in this file plants the credential in the token slot, and
    // that is exactly why this one exists: `base_url` is a *second*
    // credential-bearing field of the same struct, and it is not a `SecretString`.
    // Before the fix, `https://user:pass@host` reached two channels at once --
    // `AtlassianConfig`'s derived `Debug` printed `password: Some("...")`, and the
    // transport logged the whole `user:pass@host` authority on every request --
    // while the destination check, reading only `Url::host()`, saw neither.
    //
    // The URL is refused at the parse, so no configuration and no client can be
    // built to render. What is swept here is the refusal itself, which is the one
    // value that still has the hostile string in hand.
    let hostile = format!("https://{URL_USERNAME}:{URL_PASSWORD}@canary.atlassian.net/jira");

    // Anti-vacuity: `Url` really does store both halves verbatim, so the scanner
    // is looking for the bytes the leaking channels would have printed.
    let parsed = Url::parse(&hostile).expect("the hostile URL parses");
    assert_eq!(parsed.username(), URL_USERNAME);
    assert_eq!(parsed.password(), Some(URL_PASSWORD));
    assert!(
        !url_scanner().findings(parsed.as_str()).is_empty(),
        "the canary is not in the URL, so the sweep proves nothing: {parsed}"
    );

    // Each door is driven *inside* the capture, so the log really is the log of
    // the refusal rather than an empty string collected after the fact.
    let doors: [(&str, &dyn Fn() -> Result<(), AtlassianError>); 2] = [
        ("AtlassianConfig::new", &|| {
            AtlassianConfig::new(hostile.clone(), USERNAME.to_string(), TOKEN).map(|_| ())
        }),
        ("the builder", &|| {
            AtlassianConfig::builder()
                .base_url(hostile.clone())
                .username(USERNAME)
                .api_token(TOKEN)
                .build()
                .map(|_| ())
        }),
    ];

    for (channel, door) in doors {
        let (result, log) = logs::capture(door);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{channel} accepted a credential-bearing authority"));

        for (rendered_channel, rendered) in [
            (format!("{channel}: the error message"), error.to_string()),
            (format!("{channel}: the error Debug"), format!("{error:?}")),
            (
                format!("{channel}: the serialized error"),
                serde_json::to_string(&error).expect("AtlassianError serializes"),
            ),
            (format!("{channel}: the log"), log),
        ] {
            url_scanner().assert_clean(&rendered_channel, &rendered);
            scanner().assert_clean(&rendered_channel, &rendered);
        }
    }

    // And the predicate every request goes through, reached with a URL assigned
    // straight to the public field. This is the door the parse cannot guard.
    let mut config = AtlassianConfig::new(
        "https://canary.atlassian.net".to_string(),
        USERNAME.to_string(),
        TOKEN,
    )
    .expect("the canary base URL parses");
    config.base_url = parsed;

    let (result, log) = logs::capture(|| AtlassianClient::new(config));
    let error = result.expect_err("the client accepted a credential-bearing authority");

    url_scanner().assert_clean("the destination refusal", &error.to_string());
    url_scanner().assert_clean("the log of a destination refusal", &log);

    // Nothing is asserted about the `Debug` of *that* configuration, and the
    // omission is the point: `base_url` is a public field, so a derived `Debug`
    // prints back whatever a caller assigned to it, and no redaction inside this
    // crate can change that. The containment is one layer earlier — such a value
    // cannot be constructed, and cannot be dialled — which is what the two
    // refusals above are. A `Debug` assertion here would be asserting that
    // `#[derive(Debug)]` lies.
    let clean = AtlassianConfig::new(
        "https://canary.atlassian.net".to_string(),
        USERNAME.to_string(),
        TOKEN,
    )
    .expect("the canary base URL parses");
    url_scanner().assert_clean(
        "the Debug rendering of a configuration built through the parser",
        &format!("{clean:?}"),
    );
}

#[test]
fn a_refused_destination_names_the_host_without_naming_the_credential() {
    // The error a host-policy refusal produces is the one an operator pastes
    // into an issue, and it is produced while the configuration is holding the
    // credential.
    let (result, log) = logs::capture(|| {
        AtlassianConfig::builder()
            .base_url("http://attacker.example")
            .username(USERNAME)
            .api_token(TOKEN)
            .build()
            .and_then(AtlassianClient::new)
    });

    let error = result.expect_err("a cleartext destination is refused");
    let rendered = error.to_string();

    assert!(rendered.contains("attacker.example"), "{rendered}");
    scanner().assert_clean("the host-policy refusal", &rendered);
    scanner().assert_clean("the log of a refused destination", &log);
}

/// The decrypted env file is every credential the deployment holds, in cleartext.
///
/// `load_encrypted_env_file_if_present` hands that plaintext to
/// `dotenvy::from_read_override`, which re-injects it into the process
/// environment before the optional settings are parsed. That makes the file a
/// second way into `JIRA_VERIFY_SSL` and `JIRA_HOST_POLICY`, and the refusal it
/// meets is produced with the file's own token already in the environment.
#[cfg(feature = "encrypted-env")]
mod encrypted_env_file {
    use super::{scanner, EnvGuard, TOKEN, USERNAME};
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use fluxencrypt::keys::KeyPair;
    use fluxencrypt::{Config as FluxConfig, HybridCipher};
    use serial_test::serial;
    use threatflux_atlassian_sdk::{AtlassianConfig, HostPolicy};
    use threatflux_atlassian_testkit::logs;

    /// Encrypts `body` and returns the base64 ciphertext with its private key.
    fn sealed_env_file(body: &str) -> (String, String) {
        let keypair = KeyPair::generate(2048).expect("key generation succeeds");
        let cipher = HybridCipher::new(FluxConfig::default());
        let ciphertext = cipher
            .encrypt(keypair.public_key(), body.as_bytes())
            .expect("the env file encrypts");

        (
            BASE64_STANDARD.encode(ciphertext),
            keypair.private_key().to_pem().expect("private key to pem"),
        )
    }

    /// Clears every variable the file below writes, and restores them on drop.
    fn guarded(ciphertext: &str, private_key: &str) -> EnvGuard {
        let mut guard = EnvGuard::new();
        guard
            .set("ENV_FILE_ENCRYPTED", ciphertext)
            .set("ENV_FILE_PRIVATE_KEY", private_key)
            .remove("ENV_FILE_ENCRYPTED_PATH")
            .remove("ENV_FILE_PRIVATE_KEY_PASSWORD")
            .remove("JIRA_URL")
            .remove("JIRA_USERNAME")
            .remove("JIRA_API_TOKEN")
            .remove("JIRA_VERIFY_SSL")
            .remove("JIRA_HOST_POLICY")
            .remove("JIRA_CERT_PATH")
            .remove("JIRA_TIMEOUT")
            .remove("JIRA_MAX_RETRIES");
        guard
    }

    #[test]
    #[serial]
    fn a_re_injected_transport_relaxation_is_refused_without_echoing_the_file() {
        for (line, expected) in [
            (
                "JIRA_VERIFY_SSL=false",
                "cannot disable certificate verification",
            ),
            ("JIRA_HOST_POLICY=loopback", "cannot select the loopback"),
        ] {
            let body = format!(
                "export JIRA_URL=http://127.0.0.1:9\n\
                 export JIRA_USERNAME={USERNAME}\n\
                 export JIRA_API_TOKEN={TOKEN}\n\
                 export {line}\n"
            );
            let (ciphertext, private_key) = sealed_env_file(&body);
            let _guard = guarded(&ciphertext, &private_key);

            let (result, log) = logs::capture(AtlassianConfig::from_env);
            let error = result
                .err()
                .unwrap_or_else(|| panic!("{line} survived re-injection through the env file"));
            let rendered = error.to_string();

            assert!(
                rendered.contains(expected),
                "{line} was refused for the wrong reason: {rendered}"
            );
            // The file really was decrypted and re-injected, so the refusal came
            // from the parser rather than from the file never being read.
            assert_eq!(
                std::env::var("JIRA_API_TOKEN").as_deref(),
                Ok(TOKEN),
                "{line}: the env file was never re-injected, so nothing was proven"
            );

            scanner().assert_clean("the re-injected relaxation refusal", &rendered);
            scanner().assert_clean("the log of a re-injected relaxation", &log);
        }
    }

    #[test]
    #[serial]
    fn a_decrypted_env_file_never_reaches_a_log() {
        // The success path. The decrypted body is a credential in plaintext for
        // as long as it takes to parse, and nothing on that path may report what
        // it read.
        let body = format!(
            "export JIRA_URL=https://canary.atlassian.net\n\
             export JIRA_USERNAME={USERNAME}\n\
             export JIRA_API_TOKEN={TOKEN}\n"
        );
        let (ciphertext, private_key) = sealed_env_file(&body);
        let _guard = guarded(&ciphertext, &private_key);

        let (result, log) = logs::capture(AtlassianConfig::from_env);
        let config = result.expect("a file carrying only credentials loads");

        assert_eq!(config.api_token.expose_secret(), TOKEN);
        assert_eq!(config.host_policy, HostPolicy::AtlassianCloud);
        assert!(config.verify_ssl);

        scanner().assert_clean("the log of a decrypted env file", &log);
        scanner().assert_clean(
            "the Debug rendering of an env-file configuration",
            &format!("{config:?}"),
        );
    }
}

#[test]
#[serial]
fn an_environment_that_tries_to_flip_the_transport_is_refused_quietly() {
    // The same refusal reached the ordinary way, without the encrypted-env
    // feature: `from_read_override` writes into exactly this environment, so
    // this is the case that holds when the file path is compiled out.
    for (variable, value, expected) in [
        (
            "JIRA_VERIFY_SSL",
            "false",
            "cannot disable certificate verification",
        ),
        ("JIRA_HOST_POLICY", "loopback", "cannot select the loopback"),
    ] {
        let mut guard = EnvGuard::new();
        guard
            .set("JIRA_URL", "http://127.0.0.1:9")
            .set("JIRA_USERNAME", USERNAME)
            .set("JIRA_API_TOKEN", TOKEN)
            .set(variable, value)
            .remove("ENV_FILE_ENCRYPTED")
            .remove("ENV_FILE_ENCRYPTED_PATH");
        if variable == "JIRA_VERIFY_SSL" {
            guard.remove("JIRA_HOST_POLICY");
        } else {
            guard.remove("JIRA_VERIFY_SSL");
        }

        let (result, log) = logs::capture(AtlassianConfig::from_env);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{variable}={value} was accepted"));
        let rendered = error.to_string();

        assert!(
            rendered.contains(expected),
            "{variable}={value} was refused for the wrong reason: {rendered}"
        );
        scanner().assert_clean("the environment refusal", &rendered);
        scanner().assert_clean("the log of an environment refusal", &log);
    }
}
