//! What the process environment can and cannot talk this SDK into.
//!
//! The hardening rests on one property: `HostPolicy::Loopback` and
//! `verify_ssl == false` are reachable by a code call and by nothing else. That
//! is what lets "production cannot disable TLS verification" and "the end-to-end
//! suite drives a real client against a loopback mock" both hold at once, and it
//! is the reason the end-to-end suite does not exercise the environment path at
//! all -- these tests are that path's coverage.
//!
//! A hand-written list of `JIRA_*` names would go stale the first time the
//! configuration layer learned a new variable, and the test would keep passing
//! while covering less. So the surface is **scanned out of the SDK's own
//! source**: every `env::var`/`env::var_os` argument, every credential base a
//! `{base}_ENCRYPTED` family is derived from, and every suffix in that family.
//! Adding a variable to `config.rs` fails
//! [`the_environment_surface_this_suite_fuzzes_is_the_one_the_source_reads`]
//! until it is declared here, and declaring it enrolls it in every property
//! below automatically.

use serial_test::serial;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use threatflux_atlassian_sdk::{AtlassianClient, AtlassianConfig, HostPolicy};
use threatflux_atlassian_testkit::env::EnvGuard;

/// A tenant the default policy admits, used as the baseline destination.
const HTTPS_TENANT: &str = "https://example.atlassian.net";

/// Variables the configuration layer reads by literal name.
///
/// `JIRA_CERT_PATH` is deliberately absent: an extra trust anchor can vouch for
/// the destination the same environment chose with `JIRA_URL`, so installing one
/// relaxes certificate verification, and the configuration layer no longer reads
/// the variable at all. See
/// [`a_trust_anchor_is_not_installable_from_the_environment`].
const LITERAL_ENV_VARS: [&str; 7] = [
    "ENV_FILE_ENCRYPTED",
    "ENV_FILE_ENCRYPTED_PATH",
    "JIRA_HOST_POLICY",
    "JIRA_MAX_RETRIES",
    "JIRA_TIMEOUT",
    "JIRA_URL",
    "JIRA_VERIFY_SSL",
];

/// Names a `{base}_…` family of credential variables is derived from.
const CREDENTIAL_BASES: [&str; 3] = ["ENV_FILE", "JIRA_API_TOKEN", "JIRA_USERNAME"];

/// The suffixes that family is spelled with.
const DERIVED_SUFFIXES: [&str; 3] = ["ENCRYPTED", "PRIVATE_KEY", "PRIVATE_KEY_PASSWORD"];

/// `env::var` arguments that are a binding rather than a name.
///
/// Each one is resolved by the scan of [`CREDENTIAL_BASES`] and
/// [`DERIVED_SUFFIXES`] instead: `base` is the credential base, the three
/// `_var` bindings are that base plus a suffix, and `variable` iterates the
/// encrypted-env-file names, which appear as literals elsewhere in the file.
const DYNAMIC_ENV_ARGUMENTS: [&str; 5] = [
    "&encrypted_var",
    "&password_var",
    "&private_key_var",
    "base",
    "variable",
];

/// Values that mean "relax something", in every spelling the parsers see.
///
/// The two userinfo URLs are here because a base URL's authority is a second
/// credential-bearing field: it is printed by the derived `Debug`, logged whole
/// on every request, and invisible to a destination check that reads only
/// `Url::host()`. No variable may carry one into a configuration.
const HOSTILE_VALUES: [&str; 17] = [
    "loopback",
    "LOOPBACK",
    " Loopback ",
    "allowlist:127.0.0.1",
    "allowlist:jira.example.com:8443",
    "false",
    " false",
    "FALSE",
    "0",
    "no",
    "off",
    "http://127.0.0.1:9999",
    "http://evil.example",
    "https://smuggled-user:smuggled-p4ssw0rd@example.atlassian.net",
    "https://example.atlassian.net@evil.example",
    "127.0.0.1",
    "",
];

/// Spellings of `JIRA_VERIFY_SSL` that must be refused outright.
///
/// The parse this replaced was `value.to_lowercase() != "false"`, under which
/// every entry but the first meant *enabled* -- the opposite of what the
/// operator wrote, and a security switch failing towards the permissive answer.
const DISABLED_SPELLINGS: [&str; 10] = [
    "false",
    " false",
    "false ",
    "\tfalse\n",
    "FALSE",
    "FaLsE",
    "0",
    " 0 ",
    "no",
    "off",
];

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

/// What the SDK's source says it reads out of the environment.
#[derive(Debug, Default)]
struct ScannedSurface {
    literals: BTreeSet<String>,
    dynamic: BTreeSet<String>,
    bases: BTreeSet<String>,
    derived_suffixes: BTreeSet<String>,
}

/// The library half of every SDK source file, with test modules removed.
///
/// Test code reads the environment too, and its variable names are not part of
/// the shipped surface.
fn sdk_sources() -> Vec<String> {
    let mut sources = Vec::new();
    collect_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    assert!(
        sources.len() > 5,
        "the SDK source tree was not found; the scan below would be vacuous"
    );
    sources
}

fn collect_sources(directory: &Path, sources: &mut Vec<String>) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} is not readable: {error}", directory.display()));

    for entry in entries {
        let path = entry.expect("a directory entry should be readable").path();
        if path.is_dir() {
            collect_sources(&path, sources);
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{} is not readable: {error}", path.display()));
            sources.push(library_half(&text));
        }
    }
}

/// Everything before the first `#[cfg(test)]`, which is where every test module
/// in this crate starts.
fn library_half(text: &str) -> String {
    let normalized = text.replace("\r\n", "\n");
    normalized
        .split("\n#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .to_string()
}

/// The argument text of every `callee(` occurrence, up to the first `)`.
///
/// Every call this is pointed at passes plain bindings or string literals, with
/// no nested call and no parenthesis inside an argument. A future call that
/// breaks that shape yields text that parses as neither a literal nor a declared
/// binding, which fails the surface assertion rather than passing silently.
fn call_arguments<'a>(text: &'a str, callee: &str) -> Vec<&'a str> {
    let mut arguments = Vec::new();
    let mut rest = text;

    while let Some(index) = rest.find(callee) {
        let after = &rest[index + callee.len()..];
        let end = after.find(')').unwrap_or(after.len());
        arguments.push(after[..end].trim());
        rest = after;
    }

    arguments
}

fn first_argument(arguments: &str) -> &str {
    arguments
        .split_once(',')
        .map_or(arguments, |(first, _)| first)
        .trim()
}

/// The contents of `text` when it is a plain string literal.
fn string_literal(text: &str) -> Option<&str> {
    text.strip_prefix('"')?.strip_suffix('"')
}

fn scan_sdk_sources() -> ScannedSurface {
    let mut scanned = ScannedSurface::default();

    for source in sdk_sources() {
        for callee in ["env::var(", "env::var_os("] {
            for argument in call_arguments(&source, callee) {
                match string_literal(argument) {
                    Some(name) => scanned.literals.insert(name.to_string()),
                    None => scanned.dynamic.insert(argument.to_string()),
                };
            }
        }

        for callee in [
            "load_required_secret(",
            "load_required_credential(",
            "decrypt_secret_for_base(",
        ] {
            for argument in call_arguments(&source, callee) {
                if let Some(base) = string_literal(first_argument(argument)) {
                    scanned.bases.insert(base.to_string());
                }
            }
        }

        for argument in call_arguments(&source, "format!(") {
            if let Some(suffix) =
                string_literal(argument).and_then(|literal| literal.strip_prefix("{base}_"))
            {
                scanned.derived_suffixes.insert(suffix.to_string());
            }
        }
    }

    scanned
}

fn declared(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

/// Every environment variable name the scan accounts for.
fn env_surface() -> BTreeSet<String> {
    let scanned = scan_sdk_sources();
    let mut surface = scanned.literals;

    for base in &scanned.bases {
        surface.insert(base.clone());
        for suffix in &scanned.derived_suffixes {
            surface.insert(format!("{base}_{suffix}"));
        }
    }

    surface
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Credentials present, and every scanned variable cleared.
///
/// Clearing from the scan rather than from a list is what stops a variable
/// leaked by another test -- or by the developer's shell -- from deciding an
/// outcome here.
fn baseline_env(surface: &BTreeSet<String>) -> EnvGuard {
    let mut guard = EnvGuard::new();
    for name in surface {
        guard.remove(name);
    }
    guard.set("JIRA_URL", HTTPS_TENANT);
    guard.set("JIRA_USERNAME", "bot@example.com");
    guard.set("JIRA_API_TOKEN", "api-token");
    guard
}

/// The invariant every environment must satisfy: a refusal, or a configuration
/// that is neither loopback-policied nor certificate-relaxed, carries no trust
/// anchor and no credential in its base URL, and can only have an `https`
/// destination if it validates at all.
fn assert_no_relaxation(context: &str) {
    let Ok(config) = AtlassianConfig::from_env() else {
        return;
    };

    assert_ne!(
        config.host_policy,
        HostPolicy::Loopback,
        "{context} selected the loopback host policy"
    );
    assert!(
        config.verify_ssl,
        "{context} disabled certificate verification"
    );
    assert_eq!(
        config.cert_path, None,
        "{context} installed a trust anchor, which relaxes certificate \
         verification for whatever host the same environment chose"
    );
    // The authority is checked separately from the scheme: a `user:pass@` half
    // reaches the derived `Debug` and the per-request transport log without ever
    // touching the host the destination check judges.
    assert!(
        config.base_url.username().is_empty() && config.base_url.password().is_none(),
        "{context} produced a base URL carrying credentials in its authority"
    );
    assert!(
        config.validate().is_err() || config.base_url.scheme() == "https",
        "{context} produced a valid cleartext destination"
    );
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn the_environment_surface_this_suite_fuzzes_is_the_one_the_source_reads() {
    let scanned = scan_sdk_sources();

    assert_eq!(
        scanned.literals,
        declared(&LITERAL_ENV_VARS),
        "the SDK reads a variable by name that this suite does not fuzz; add it to LITERAL_ENV_VARS"
    );
    assert_eq!(
        scanned.dynamic,
        declared(&DYNAMIC_ENV_ARGUMENTS),
        "the SDK reads the environment through a binding this suite has not accounted for; \
         resolve it to the names it can produce and add it to DYNAMIC_ENV_ARGUMENTS"
    );
    assert_eq!(
        scanned.bases,
        declared(&CREDENTIAL_BASES),
        "a credential base changed; add it to CREDENTIAL_BASES"
    );
    assert_eq!(
        scanned.derived_suffixes,
        declared(&DERIVED_SUFFIXES),
        "a `{{base}}_…` variable family changed; add the suffix to DERIVED_SUFFIXES"
    );

    // The names the properties below turn on must actually be in the surface,
    // or every one of them is vacuous.
    let surface = env_surface();
    for required in [
        "JIRA_URL",
        "JIRA_HOST_POLICY",
        "JIRA_VERIFY_SSL",
        "JIRA_API_TOKEN_ENCRYPTED",
        "ENV_FILE_ENCRYPTED",
    ] {
        assert!(
            surface.contains(required),
            "{required} is not in the surface"
        );
    }
}

#[test]
#[serial]
fn no_single_environment_variable_can_relax_the_transport() {
    let surface = env_surface();
    let mut cases = 0_usize;

    for name in &surface {
        for value in HOSTILE_VALUES {
            let mut guard = baseline_env(&surface);
            guard.set(name, value);

            assert_no_relaxation(&format!("{name}={value:?}"));
            cases += 1;
        }
    }

    // Standing on its own rather than on the surface assertion in the test
    // above: a scan that found nothing would make this loop pass silently.
    assert!(
        cases >= LITERAL_ENV_VARS.len() * HOSTILE_VALUES.len(),
        "only {cases} environments were tried; the scan found too little"
    );
}

#[test]
#[serial]
fn no_combination_of_url_policy_and_verification_reaches_a_cleartext_destination() {
    let surface = env_surface();
    let urls = [
        "http://127.0.0.1:9999",
        "http://localhost:9999",
        "http://evil.example",
        "https://jira.example.com",
        "https://evil-atlassian.net",
        HTTPS_TENANT,
    ];
    let policies = [
        None,
        Some("loopback"),
        Some("LOOPBACK"),
        Some(" loopback "),
        Some("atlassian-cloud"),
        Some("allowlist:127.0.0.1"),
        Some("allowlist:localhost"),
        Some("allowlist:jira.example.com"),
    ];
    let verifications = [None, Some("false"), Some(" false"), Some("0"), Some("true")];

    let mut accepted = 0_u32;

    for url in urls {
        for policy in policies {
            for verification in verifications {
                let mut guard = baseline_env(&surface);
                guard.set("JIRA_URL", url);
                if let Some(policy) = policy {
                    guard.set("JIRA_HOST_POLICY", policy);
                }
                if let Some(verification) = verification {
                    guard.set("JIRA_VERIFY_SSL", verification);
                }

                let context = format!(
                    "JIRA_URL={url} JIRA_HOST_POLICY={policy:?} JIRA_VERIFY_SSL={verification:?}"
                );
                assert_no_relaxation(&context);

                let admitted = AtlassianConfig::from_env()
                    .and_then(|config| config.validate().map(|()| config));
                if url.starts_with("http://") {
                    assert!(
                        admitted.is_err(),
                        "{context} admitted a cleartext destination"
                    );
                } else if let Ok(config) = admitted {
                    assert_eq!(config.base_url.scheme(), "https", "{context}");
                    accepted += 1;
                }
            }
        }
    }

    // Anti-vacuity: the environment can still configure a working client.
    assert!(
        accepted > 0,
        "no environment at all was admitted, so the refusals prove nothing"
    );
}

#[test]
#[serial]
fn jira_verify_ssl_refuses_every_loose_spelling_of_disabled() {
    let surface = env_surface();

    for value in DISABLED_SPELLINGS {
        let mut guard = baseline_env(&surface);
        guard.set("JIRA_VERIFY_SSL", value);

        let error = AtlassianConfig::from_env()
            .err()
            .unwrap_or_else(|| panic!("JIRA_VERIFY_SSL={value:?} was not refused"))
            .to_string();
        assert!(
            error.contains("cannot disable certificate verification"),
            "JIRA_VERIFY_SSL={value:?} produced: {error}"
        );
    }
}

#[test]
#[serial]
fn jira_verify_ssl_admits_only_the_spellings_that_mean_enabled() {
    let surface = env_surface();

    for value in ["true", " TRUE ", "True", "1", "yes", "on"] {
        let mut guard = baseline_env(&surface);
        guard.set("JIRA_VERIFY_SSL", value);

        let config = AtlassianConfig::from_env()
            .unwrap_or_else(|error| panic!("JIRA_VERIFY_SSL={value:?} was refused: {error}"));
        assert!(config.verify_ssl);
    }

    for value in ["maybe", "2", "true false", "", "   ", "enabled"] {
        let mut guard = baseline_env(&surface);
        guard.set("JIRA_VERIFY_SSL", value);

        assert!(
            AtlassianConfig::from_env().is_err(),
            "JIRA_VERIFY_SSL={value:?} was interpreted rather than refused"
        );
    }
}

#[test]
#[serial]
fn the_loopback_policy_parses_in_code_and_is_refused_from_the_environment() {
    // The same token, through the two doors. `FromStr` is the code call the
    // harnesses use; the environment parser is a strictly narrower grammar
    // wrapped around it.
    assert_eq!(
        "loopback"
            .parse::<HostPolicy>()
            .expect("code may select it"),
        HostPolicy::Loopback
    );

    let surface = env_surface();
    for value in ["loopback", "LOOPBACK", " Loopback ", "\tloopback\n"] {
        let mut guard = baseline_env(&surface);
        guard.set("JIRA_HOST_POLICY", value);

        let error = AtlassianConfig::from_env()
            .err()
            .unwrap_or_else(|| panic!("JIRA_HOST_POLICY={value:?} was not refused"))
            .to_string();
        assert!(
            error.contains("settable only by"),
            "JIRA_HOST_POLICY={value:?} produced: {error}"
        );
    }
}

#[test]
#[serial]
fn an_env_built_configuration_refuses_a_non_atlassian_host_by_default() {
    let surface = env_surface();

    for url in [
        "https://jira.example.com",
        "https://evil-atlassian.net",
        "https://atlassian.net.evil.example",
        "https://192.0.2.1",
    ] {
        let mut guard = baseline_env(&surface);
        guard.set("JIRA_URL", url);

        let config = AtlassianConfig::from_env().expect("the URL itself parses");
        assert_eq!(config.host_policy, HostPolicy::AtlassianCloud);
        let error = config
            .validate()
            .expect_err(&format!("{url} was admitted by the default policy"))
            .to_string();
        assert!(
            error.contains("not permitted by the 'atlassian-cloud' host policy"),
            "{url} produced: {error}"
        );
    }
}

#[test]
#[serial]
fn an_env_allowlist_widens_the_host_set_and_never_the_scheme() {
    // A Data Center deployment is the case the allowlist exists for, and it is
    // the widest thing the environment can ask for.
    let surface = env_surface();

    let mut guard = baseline_env(&surface);
    guard.set("JIRA_HOST_POLICY", "allowlist:jira.example.com");
    guard.set("JIRA_URL", "https://jira.example.com/jira");

    let config = AtlassianConfig::from_env().expect("an allowlisted https host is admitted");
    assert_eq!(
        config.host_policy,
        HostPolicy::Allowlist(vec!["jira.example.com".to_string()])
    );
    assert!(config.validate().is_ok());
    assert!(config.verify_ssl);

    guard.set("JIRA_URL", "http://jira.example.com/jira");
    let error = AtlassianConfig::from_env()
        .expect("the URL itself parses")
        .validate()
        .expect_err("the allowlist admitted a cleartext destination")
        .to_string();
    assert!(error.contains("must use https"), "error was: {error}");
}

#[test]
#[serial]
fn the_client_constructor_refuses_what_the_environment_can_build() {
    // `AtlassianClient::new` is the one line the end-to-end suite cannot reach
    // through the environment, because the environment can never produce the
    // loopback policy its mock client needs.
    let surface = env_surface();

    {
        let _guard = baseline_env(&surface);
        assert!(
            AtlassianClient::from_env().is_ok(),
            "a permitted https tenant must still build a client"
        );
    }

    for url in [
        "http://127.0.0.1:9999",
        "http://evil.example",
        "https://jira.example.com",
    ] {
        let mut guard = baseline_env(&surface);
        guard.set("JIRA_URL", url);

        assert!(
            AtlassianClient::from_env().is_err(),
            "{url} reached a constructed client"
        );
    }
}

#[test]
#[serial]
fn an_override_supplied_base_url_is_held_to_the_same_predicate() {
    // The Action and the CLI both build their configuration this way -- the
    // base URL arrives as an override, from `JIRA_BASE_URL` or `--base-url` --
    // so the override path is a second door into the same check.
    let surface = env_surface();
    let _guard = baseline_env(&surface);

    for url in ["http://127.0.0.1:9999", "https://jira.example.com"] {
        let config = AtlassianConfig::from_env_with_overrides(
            Some(url.to_string()),
            Some("bot@example.com".to_string()),
            Some("api-token".to_string()),
        )
        .expect("the URL itself parses");

        assert_eq!(config.host_policy, HostPolicy::AtlassianCloud);
        assert!(config.verify_ssl);
        assert!(config.validate().is_err(), "{url} was admitted");
        assert!(
            AtlassianClient::new(config).is_err(),
            "{url} built a client"
        );
    }
}

#[test]
#[serial]
fn the_residual_the_host_policy_does_not_cover_is_pinned_where_it_is_documented() {
    // `HostPolicy`'s rustdoc and the SDK README both state this in as many words:
    // the policy bounds the **scheme**, not the set of hosts an environment can
    // name. `JIRA_HOST_POLICY` refuses only the literal `loopback` token, so an
    // environment that can set two variables sends `Authorization: Basic` to a
    // host of its choosing over ordinary TLS -- an operator's own Data Center
    // being indistinguishable from an attacker's is the reason it cannot be
    // closed here.
    //
    // This is a pin on documented behaviour, not an endorsement of it. A later
    // change that narrows the residual fails this test, which is what forces the
    // rustdoc and the README to be corrected in the same commit rather than
    // drifting into claiming a containment the type never had.
    let surface = env_surface();
    let mut guard = baseline_env(&surface);
    guard.set("JIRA_HOST_POLICY", "allowlist:jira.attacker.example");
    guard.set("JIRA_URL", "https://jira.attacker.example");

    let config = AtlassianConfig::from_env().expect("the environment may name its own host");
    assert_eq!(
        config.host_policy,
        HostPolicy::Allowlist(vec!["jira.attacker.example".to_string()])
    );
    assert!(
        config.validate().is_ok(),
        "the documented residual is no longer reachable; update the HostPolicy \
         rustdoc and the SDK README with it"
    );
    assert!(AtlassianClient::new(config).is_ok());

    // And the half the policy does bound, in the very same environment.
    guard.set("JIRA_URL", "http://jira.attacker.example");
    let error = AtlassianConfig::from_env()
        .expect("the URL itself parses")
        .validate()
        .expect_err("the environment reached a cleartext destination")
        .to_string();
    assert!(error.contains("must use https"), "error was: {error}");
}

#[test]
#[serial]
fn a_trust_anchor_is_not_installable_from_the_environment() {
    // `JIRA_CERT_PATH` used to reach the TLS configuration: the file it named was
    // handed to `add_root_certificate`, which makes that CA able to vouch for the
    // destination the same environment picked with `JIRA_URL`. That is
    // certificate verification relaxed from the environment, so the variable is
    // gone and the builder is the only door left -- the same demotion
    // `HostPolicy::Loopback` took.
    //
    // The old test here asserted only that the variable changed neither the host
    // policy nor `verify_ssl`, and its comment concluded it "cannot disable
    // certificate verification". Both were true and neither was the question.
    let surface = env_surface();
    assert!(
        !surface.contains("JIRA_CERT_PATH"),
        "the configuration layer reads JIRA_CERT_PATH again"
    );

    let certificate = unique_temp_path("threatflux-atlassian-cert");
    fs::write(&certificate, b"-----BEGIN CERTIFICATE-----\n").expect("temp file should be written");

    let mut guard = baseline_env(&surface);
    guard.set("JIRA_CERT_PATH", &certificate);

    let config = AtlassianConfig::from_env().expect("an inert variable is not a refusal");

    assert_eq!(
        config.cert_path, None,
        "the environment installed a trust anchor"
    );
    assert_eq!(config.host_policy, HostPolicy::AtlassianCloud);
    assert!(config.verify_ssl);
    assert_eq!(config.base_url.scheme(), "https");

    // Anti-vacuity: the code call the variable was demoted to still works, so
    // this is a relocation of the capability and not its removal. A Data Center
    // deployment with a private CA passes the same path through the builder.
    let by_code = AtlassianConfig::builder()
        .base_url(HTTPS_TENANT)
        .username("bot@example.com")
        .api_token("api-token")
        .cert_path(certificate.clone())
        .build()
        .expect("a code-supplied trust anchor builds");
    assert_eq!(by_code.cert_path.as_deref(), Some(certificate.as_path()));

    fs::remove_file(&certificate).expect("temp file should be removable");
}

#[test]
#[serial]
fn no_environment_can_put_a_credential_in_the_base_url_authority() {
    // A base URL's `user:pass@` half is a credential in a field the derived
    // `Debug` prints in full and the transport logs on every request, and the
    // destination check reads only `Url::host()`, so it never saw one. The URL is
    // refused instead, through both doors the environment has.
    let surface = env_surface();

    for url in [
        "https://smuggled-user:smuggled-p4ssw0rd@example.atlassian.net",
        "https://smuggled-user@example.atlassian.net",
        "https://example.atlassian.net@evil.example",
    ] {
        let mut guard = baseline_env(&surface);
        guard.set("JIRA_URL", url);

        let error = AtlassianConfig::from_env()
            .err()
            .unwrap_or_else(|| panic!("JIRA_URL={url} was accepted"))
            .to_string();
        assert!(
            error.contains("must not carry credentials in its authority"),
            "JIRA_URL={url} produced: {error}"
        );
        assert!(
            !error.contains("smuggled-p4ssw0rd"),
            "the refusal echoed the password: {error}"
        );

        // The override door the Action and the CLI use.
        let error = AtlassianConfig::from_env_with_overrides(
            Some(url.to_string()),
            Some("bot@example.com".to_string()),
            Some("api-token".to_string()),
        )
        .err()
        .unwrap_or_else(|| panic!("the {url} override was accepted"))
        .to_string();
        assert!(
            error.contains("must not carry credentials in its authority"),
            "the {url} override produced: {error}"
        );
    }
}
