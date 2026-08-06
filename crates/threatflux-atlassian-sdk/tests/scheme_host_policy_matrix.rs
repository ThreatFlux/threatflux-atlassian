//! One case per row of the predicate that decides where `Authorization: Basic`
//! may be sent.
//!
//! Scheme and host are one rule, so every row states three things -- the URL,
//! the policy, and *which half* refused it. Asserting only `is_err()` would let
//! a host refusal stand in for a scheme refusal, and the whole point of the
//! combined predicate is that `http://` is admitted for exactly one host shape
//! under exactly one policy. The expected messages are the observable form of
//! that distinction.
//!
//! Every row is driven through the published surface -- `AtlassianConfig`,
//! `HostPolicy`, `AtlassianClient::new` -- rather than through the private
//! predicate, because a downstream crate can only reach the former, and the
//! constructor is the line the end-to-end suite cannot cover (its client is
//! built by code call, not from the environment).
//!
//! No row performs I/O. `AtlassianClient::new` builds a reqwest client and
//! dials nothing, and the policy never resolves a name -- which is itself
//! asserted below, from both sides.

use std::net::ToSocketAddrs;
use threatflux_atlassian_sdk::{AtlassianClient, AtlassianConfig, AtlassianError, HostPolicy};
use url::Url;

/// A policy in a form a `const` table can carry.
///
/// `HostPolicy::Allowlist` owns a `Vec`, which no const can build, so the rows
/// name their entries as a slice and mint the policy per case.
#[derive(Debug, Clone, Copy)]
enum Policy {
    Cloud,
    Allow(&'static [&'static str]),
    Loopback,
}

impl Policy {
    fn build(self) -> HostPolicy {
        match self {
            Self::Cloud => HostPolicy::AtlassianCloud,
            Self::Allow(entries) => HostPolicy::Allowlist(
                entries
                    .iter()
                    .map(|entry| (*entry).to_string())
                    .collect::<Vec<_>>(),
            ),
            Self::Loopback => HostPolicy::Loopback,
        }
    }
}

/// Which half of the predicate a row expects to decide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// A permitted credential destination.
    Accept,
    /// Refused on the transport scheme.
    Scheme,
    /// Refused on the host.
    Host,
    /// Refused because the URL names no host to judge.
    Hostless,
}

impl Verdict {
    /// The substring that identifies the refusing half.
    const fn marker(self) -> &'static str {
        match self {
            Self::Accept => "",
            Self::Scheme => "must use https",
            Self::Host => "is not permitted by the",
            Self::Hostless => "must name a host",
        }
    }
}

fn config_at(base_url: &str, policy: Policy) -> AtlassianConfig {
    AtlassianConfig::new(
        base_url.to_string(),
        "bot@example.com".to_string(),
        "api-token",
    )
    .unwrap_or_else(|error| panic!("{base_url} is not a parseable base URL: {error}"))
    .with_host_policy(policy.build())
}

/// Assert one row, on `validate()` and on the constructor that calls it.
///
/// Both are checked because `AtlassianConfig::new` does not validate and
/// `base_url` is a public field: a caller can reach `AtlassianClient::new` with
/// a configuration `validate()` never saw.
fn assert_row(base_url: &str, policy: Policy, verdict: Verdict) {
    let outcome = config_at(base_url, policy).validate();
    let constructed = AtlassianClient::new(config_at(base_url, policy));

    if verdict == Verdict::Accept {
        assert!(
            outcome.is_ok(),
            "{base_url} under {policy:?} was refused: {outcome:?}"
        );
        assert!(
            constructed.is_ok(),
            "{base_url} under {policy:?} validated but the client refused it"
        );
        return;
    }

    let error = outcome.expect_err(&format!("{base_url} under {policy:?} was admitted"));
    assert!(
        matches!(error, AtlassianError::Configuration { .. }),
        "{base_url} under {policy:?} produced {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains(verdict.marker()),
        "{base_url} under {policy:?} expected {verdict:?}, got: {rendered}"
    );
    assert!(
        constructed.is_err(),
        "{base_url} under {policy:?} failed validation but the client accepted it"
    );
}

fn assert_rows(rows: &[(&str, Policy, Verdict)]) {
    for (base_url, policy, verdict) in rows {
        assert_row(base_url, *policy, *verdict);
    }
}

const DATA_CENTER: Policy = Policy::Allow(&["jira.example.com"]);
/// An allowlist that names the loopback literal without being the loopback policy.
const ALLOWED_LOOPBACK: Policy = Policy::Allow(&["127.0.0.1"]);

#[test]
fn https_is_admitted_under_every_policy_that_permits_the_host() {
    assert_rows(&[
        (
            "https://company.atlassian.net",
            Policy::Cloud,
            Verdict::Accept,
        ),
        (
            "https://jira.example.com/jira",
            DATA_CENTER,
            Verdict::Accept,
        ),
        ("https://127.0.0.1:8443", Policy::Loopback, Verdict::Accept),
        ("https://[::1]:8443", Policy::Loopback, Verdict::Accept),
        ("https://127.0.0.1:8443", ALLOWED_LOOPBACK, Verdict::Accept),
    ]);
}

#[test]
fn https_to_a_host_the_policy_does_not_permit_is_refused_on_the_host() {
    assert_rows(&[
        ("https://jira.example.com", Policy::Cloud, Verdict::Host),
        ("https://company.atlassian.net", DATA_CENTER, Verdict::Host),
        (
            "https://company.atlassian.net",
            Policy::Loopback,
            Verdict::Host,
        ),
        ("https://jira.example.com", Policy::Loopback, Verdict::Host),
        // An IP literal is a host like any other, and the cloud policy has no
        // suffix that an address can sit below.
        ("https://127.0.0.1", Policy::Cloud, Verdict::Host),
        ("https://[::1]", Policy::Cloud, Verdict::Host),
    ]);
}

#[test]
fn a_base_url_carrying_credentials_in_its_authority_is_refused_under_every_policy() {
    // Userinfo is not the host, and that used to be the whole answer: a URL whose
    // credential half spelled a permitted tenant was dialled at whatever followed
    // the `@`, and the host refusal caught it. It is not the whole answer, because
    // the authority is itself a credential — the derived `Debug` on
    // `AtlassianConfig` prints `password: Some(..)`, the transport logs the joined
    // URL on every request, and this predicate reads only `Url::host()`, so it
    // sees none of it. The URL is refused before any of that can happen.
    const PASSWORD: &str = "p4ssw0rd-that-must-not-reach-a-log";
    let hostile = [
        format!("https://user:{PASSWORD}@company.atlassian.net"),
        "https://user@company.atlassian.net".to_string(),
        // The two shapes the host refusal used to catch, and one it did not:
        // userinfo on a destination the policy would otherwise accept.
        "https://company.atlassian.net@evil.example".to_string(),
        format!("http://user:{PASSWORD}@127.0.0.1:8080"),
        format!("https://user:{PASSWORD}@jira.example.com"),
    ];

    for raw in &hostile {
        for policy in [Policy::Cloud, DATA_CENTER, Policy::Loopback] {
            let error =
                AtlassianConfig::new(raw.clone(), "bot@example.com".to_string(), "api-token")
                    .expect_err(&format!("{raw} under {policy:?} became a configuration"));

            assert!(
                matches!(error, AtlassianError::Configuration { .. }),
                "{raw} produced {error:?}"
            );
            let rendered = error.to_string();
            assert!(
                rendered.contains("must not carry credentials in its authority"),
                "{raw} under {policy:?} was refused for the wrong reason: {rendered}"
            );
            assert!(
                !rendered.contains(PASSWORD),
                "the refusal echoed the password: {rendered}"
            );
        }
    }

    // `base_url` is a public field and `AtlassianConfig::new` is not the only way
    // to fill it, so the predicate itself has to refuse one too — this is the row
    // that covers a configuration the parser never saw.
    let mut config = config_at("https://company.atlassian.net", Policy::Cloud);
    config.base_url =
        Url::parse("https://user:p4ssw0rd@company.atlassian.net/").expect("the hostile URL parses");

    let error = config
        .validate()
        .expect_err("the predicate admitted a userinfo destination")
        .to_string();
    assert!(
        error.contains("must not carry credentials in its authority"),
        "error was: {error}"
    );
    assert!(
        AtlassianClient::new(config).is_err(),
        "the constructor accepted a userinfo destination"
    );
}

#[test]
fn http_is_refused_under_every_policy_except_a_literal_loopback_under_loopback() {
    assert_rows(&[
        // The one admitted combination, and the only reason the escape hatch exists.
        ("http://127.0.0.1:8080", Policy::Loopback, Verdict::Accept),
        ("http://[::1]:8080", Policy::Loopback, Verdict::Accept),
        // The same literal loopback host under every other policy.
        ("http://127.0.0.1:8080", Policy::Cloud, Verdict::Scheme),
        ("http://127.0.0.1:8080", DATA_CENTER, Verdict::Scheme),
        // Naming the loopback literal in an allowlist widens the *host* set and
        // buys nothing on the scheme: the hatch is keyed to the policy variant,
        // not to the address.
        ("http://127.0.0.1:8080", ALLOWED_LOOPBACK, Verdict::Scheme),
        // Anything that is not a literal loopback address, under every policy.
        (
            "http://company.atlassian.net",
            Policy::Cloud,
            Verdict::Scheme,
        ),
        ("http://jira.example.com", DATA_CENTER, Verdict::Scheme),
        ("http://localhost:8080", Policy::Loopback, Verdict::Scheme),
        ("http://10.0.0.1:8080", Policy::Loopback, Verdict::Scheme),
        ("http://[::2]:8080", Policy::Loopback, Verdict::Scheme),
    ]);
}

#[test]
fn a_scheme_that_is_neither_http_nor_https_is_refused_under_every_policy() {
    // The hatch is spelled `http`, so no other cleartext transport inherits it.
    assert_rows(&[
        (
            "ftp://company.atlassian.net",
            Policy::Cloud,
            Verdict::Scheme,
        ),
        ("ftp://jira.example.com", DATA_CENTER, Verdict::Scheme),
        ("ws://127.0.0.1:8080", Policy::Loopback, Verdict::Scheme),
        ("wss://127.0.0.1:8080", Policy::Loopback, Verdict::Scheme),
    ]);
}

#[test]
fn a_url_that_names_no_host_is_refused_before_any_policy_is_consulted() {
    assert_rows(&[
        ("file:///srv/jira", Policy::Cloud, Verdict::Hostless),
        ("file:///srv/jira", Policy::Loopback, Verdict::Hostless),
        ("file:///srv/jira", DATA_CENTER, Verdict::Hostless),
    ]);
}

#[test]
fn the_loopback_hatch_covers_the_whole_literal_range_and_nothing_beside_it() {
    let admitted = [
        "http://127.0.0.1:8080",
        "http://127.0.0.2:8080",
        "http://127.255.255.254",
        "http://[::1]:8080",
        // The uncompressed spelling of ::1, which `Url` normalizes before the
        // predicate ever sees it.
        "http://[0:0:0:0:0:0:0:1]:8080",
    ];
    for base_url in admitted {
        assert_row(base_url, Policy::Loopback, Verdict::Accept);
    }

    let refused = [
        // Loopback-adjacent addresses that are not in 127.0.0.0/8 or ::1.
        "http://10.0.0.1",
        "http://169.254.169.254",
        "http://[::2]",
        // An IPv4-mapped loopback address routes to loopback on most stacks but
        // is not `::1`, and the hatch stays as narrow as it is written.
        "http://[::ffff:127.0.0.1]",
    ];
    for base_url in refused {
        assert_row(base_url, Policy::Loopback, Verdict::Scheme);
    }
}

#[test]
fn the_atlassian_cloud_suffixes_are_matched_on_a_label_boundary() {
    assert_rows(&[
        (
            "https://company.atlassian.net",
            Policy::Cloud,
            Verdict::Accept,
        ),
        ("https://atlassian.net", Policy::Cloud, Verdict::Accept),
        ("https://api.atlassian.com", Policy::Cloud, Verdict::Accept),
        ("https://company.jira.com", Policy::Cloud, Verdict::Accept),
        // `Url` lowercases a special-scheme host, and the fully qualified form
        // with a root dot is the same host.
        (
            "https://COMPANY.Atlassian.NET",
            Policy::Cloud,
            Verdict::Accept,
        ),
        (
            "https://company.atlassian.net.",
            Policy::Cloud,
            Verdict::Accept,
        ),
        // A suffix glued to a longer label, and a suffix in the middle.
        ("https://evil-atlassian.net", Policy::Cloud, Verdict::Host),
        (
            "https://atlassian.net.evil.example",
            Policy::Cloud,
            Verdict::Host,
        ),
        ("https://notatlassian.com", Policy::Cloud, Verdict::Host),
        ("https://atlassian.net.", Policy::Cloud, Verdict::Accept),
    ]);
}

#[test]
fn an_internationalized_host_is_judged_as_the_ascii_form_it_is_dialled_as() {
    // `Url` punycodes the host, so the suffix comparison never sees a Unicode
    // spelling that could be confused with an ASCII one.
    let config = config_at("https://cömpany.atlassian.net", Policy::Cloud);
    assert_eq!(
        config.base_url.host_str(),
        Some("xn--cmpany-wxa.atlassian.net")
    );
    assert_row(
        "https://cömpany.atlassian.net",
        Policy::Cloud,
        Verdict::Accept,
    );
    assert_row(
        "https://atlassian.net.évil.example",
        Policy::Cloud,
        Verdict::Host,
    );
}

#[test]
fn an_allowlist_matches_whole_hosts_with_both_sides_normalized() {
    const MIXED: Policy = Policy::Allow(&["JIRA.example.com", " [::1] ", "127.0.0.1"]);

    assert_rows(&[
        // Case on either side, and the brackets `Url` wraps an IPv6 literal in.
        ("https://jira.example.com", MIXED, Verdict::Accept),
        ("https://JIRA.example.com", MIXED, Verdict::Accept),
        ("https://[::1]:8443", MIXED, Verdict::Accept),
        ("https://127.0.0.1:8443", MIXED, Verdict::Accept),
        // No wildcard, in either direction.
        ("https://sub.jira.example.com", MIXED, Verdict::Host),
        ("https://example.com", MIXED, Verdict::Host),
        ("https://company.atlassian.net", MIXED, Verdict::Host),
    ]);
}

#[test]
fn the_policy_decides_on_the_literal_host_and_never_on_what_it_would_resolve_to() {
    // Bracketed from both sides, because either half alone has an innocent
    // explanation:
    //
    // * a name that really does resolve to loopback here is still refused, so
    //   the refusal is not an artifact of the name being unroutable;
    // * a name that can never resolve anywhere is still accepted when a policy
    //   names it, which no resolver-consulting predicate could do.
    //
    // Together they say the decision is made on the literal host text.

    // Premise, verified rather than assumed.
    if let Ok(addresses) = ("localhost", 8080_u16).to_socket_addrs() {
        let addresses: Vec<_> = addresses.collect();
        assert!(
            !addresses.is_empty() && addresses.iter().all(|address| address.ip().is_loopback()),
            "premise failed: localhost resolved to {addresses:?}"
        );
    }

    for host in ["localhost", "localtest.me", "127.0.0.1.nip.io"] {
        assert_row(
            &format!("http://{host}:8080"),
            Policy::Loopback,
            Verdict::Scheme,
        );
        assert_row(
            &format!("https://{host}:8443"),
            Policy::Loopback,
            Verdict::Host,
        );
    }

    // `.invalid` is reserved by RFC 2606 and resolves nowhere, and a tenant that
    // was never provisioned resolves nowhere either.
    assert_row(
        "https://jira.invalid",
        Policy::Allow(&["jira.invalid"]),
        Verdict::Accept,
    );
    assert_row(
        "https://this-tenant-was-never-provisioned.atlassian.net",
        Policy::Cloud,
        Verdict::Accept,
    );
}

#[test]
fn certificate_verification_is_orthogonal_to_the_predicate() {
    // `verify_ssl(false)` used to be the way past the scheme check. It now
    // decides certificate verification and nothing else, so it neither admits a
    // cleartext destination nor withdraws a permitted one.
    let refused = config_at("http://attacker.example", Policy::Cloud).with_ssl_verification(false);
    let error = refused
        .validate()
        .expect_err("a cleartext destination was admitted");
    assert!(
        error.to_string().contains("must use https"),
        "error was: {error}"
    );

    let permitted = config_at("https://jira.example.com", DATA_CENTER).with_ssl_verification(false);
    assert!(permitted.validate().is_ok());
    assert!(!permitted.verify_ssl);

    // And it cannot buy the loopback hatch either: the hatch is the policy.
    let cleartext_loopback =
        config_at("http://127.0.0.1:8080", Policy::Cloud).with_ssl_verification(false);
    assert!(cleartext_loopback.validate().is_err());
}
