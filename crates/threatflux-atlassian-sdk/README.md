# threatflux-atlassian-sdk

[![crates.io](https://img.shields.io/crates/v/threatflux-atlassian-sdk.svg)](https://crates.io/crates/threatflux-atlassian-sdk)
[![docs.rs](https://docs.rs/threatflux-atlassian-sdk/badge.svg)](https://docs.rs/threatflux-atlassian-sdk)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ThreatFlux/threatflux-atlassian/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.96.0-orange.svg)](https://www.rust-lang.org)
[![CI](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/ci.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/ci.yml)
[![Security](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/security.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/security.yml)

An async Rust client for focused Jira Cloud REST API v2 automation. The crate provides typed issue models,
environment-driven configuration, and helpers used by the ThreatFlux Atlassian CLI and GitHub Action.

> [!IMPORTANT]
> This independent project is not affiliated with, endorsed by, or sponsored by Atlassian.

> [!WARNING]
> Do not use `AtlassianRemoteClient` for a new integration. It hard-codes Atlassian's retired
> `https://mcp.atlassian.com/v1/sse` endpoint; Atlassian stopped supporting that endpoint after June 30, 2026. The
> module also does not implement the current Streamable HTTP transport or host an OAuth callback server. Read
> [Legacy Remote MCP](#legacy-remote-mcp) and [Atlassian's migration notice](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/configuring-oauth-2-1/).

## Features

- Focused Jira issue create, read, and field-update operations
- Legacy JQL search and pagination inputs through an upstream-deprecated route
- Comments, assignees, issue links, attachments, and changelogs
- Individual project lookup, a legacy non-paginated project list, users, fields, custom fields, and workflow transitions
- API-token Basic authentication for Jira Cloud scripts and automation
- rustls transport with certificate verification by default and an optional custom trust root
- Plain environment inputs, and FluxEncrypt-compatible encrypted ones behind the `encrypted-env` feature
- Typed `AtlassianError` variants for configuration, transport, API, permission, rate-limit, and validation failures

This is not a complete Atlassian product SDK. It does not provide verified coverage for Jira Software, Jira Service
Management, Confluence, Compass, or the current Atlassian Rovo MCP protocol.

## Installation

```bash
cargo add threatflux-atlassian-sdk
cargo add tokio --features macros,rt-multi-thread
```

This resolves the latest published [SDK crate](https://crates.io/crates/threatflux-atlassian-sdk). The current repository
source declares Rust 1.96.0 as its minimum supported Rust version (MSRV).

## Quickstart

Set the Jira Cloud site, account email, and API token:

```bash
export JIRA_URL="https://your-domain.atlassian.net"
export JIRA_USERNAME="you@example.com"
export JIRA_API_TOKEN="your-api-token"
```

<!-- BEGIN QUICKSTART -->
```rust
use threatflux_atlassian_sdk::AtlassianClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AtlassianClient::from_env()?;
    let issue = client.get_issue("KAN-123").await?;
    println!("{}: {}", issue.key, issue.fields.summary);
    Ok(())
}
```
<!-- END QUICKSTART -->

This exact source is compiled in CI as [`examples/quickstart.rs`](examples/quickstart.rs). From the workspace root:

```bash
cargo run -p threatflux-atlassian-sdk --example quickstart
```

The direct client sends `Authorization: Basic base64(email:api_token)` to Jira REST API v2 routes beneath `JIRA_URL`.
Use an API token, never an Atlassian account password. Atlassian positions Basic auth for personal scripts, bots, and
ad-hoc REST calls; consult [Atlassian's authentication guidance](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/)
when designing a distributable integration.

## Direct API Coverage

| Area | Methods |
| --- | --- |
| Issues | `get_issue`, `create_issue_key`, `create_issue` (creates, then reads the issue back), `update_issue`; `get_project_issues` uses the legacy issue-search route |
| Search | `search_issues` uses an upstream-deprecated route; `search_users` |
| Comments and history | `add_issue_comment`, `get_issue_comments`, `get_issue_changelog` |
| Assignment and links | `assign_issue`, `create_issue_link`, `delete_issue_link` |
| Attachments | `add_issue_attachment` (one file per call) |
| Workflow | `get_issue_transitions`, `transition_issue`, `transition_issue_by_name` |
| Projects and identity | `get_project`, `get_myself`; `get_projects` uses the legacy non-paginated route |
| Fields | `get_fields`, `find_custom_field_id`, `update_custom_field`, `update_story_points` |
| Connectivity | `health_check` (calls the current-user endpoint) |

The methods use `/rest/api/2`. Operation availability and returned fields still depend on the Jira tenant, project
configuration, issue type, field schema, and authenticated account permissions. Consult the
[Jira Cloud REST API v2 reference](https://developer.atlassian.com/cloud/jira/platform/rest/v2/intro/) for server-side
behavior.

### Legacy endpoint compatibility

> [!WARNING]
> `search_issues` and `get_project_issues` call `GET /rest/api/2/search`, which Atlassian marks as currently being
> removed. `get_projects` calls deprecated `GET /rest/api/2/project` rather than paginated project search. The methods
> remain public for compatibility, but new integrations should not depend on them.

Atlassian documents enhanced issue search at `GET` or `POST /rest/api/2/search/jql` and paginated project search at
`GET /rest/api/2/project/search`. This crate does not yet model the replacements' current pagination and response types.
Use an implementation of the current endpoints for new work and track equivalent SDK implementation before migration.
See Atlassian's [issue-search reference](https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/)
and [project endpoint deprecation notice](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-removal-of-get-filters-and-get-all-projects/).
The other direct operations in the table remain the supported SDK path.

## Configuration

The simplest path is `AtlassianClient::from_env()`. `AtlassianConfig::new` and `AtlassianConfig::builder` support
explicit configuration.

| Environment variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `JIRA_URL` | Yes | — | Site URL. HTTPS is required unconditionally; `verify_ssl` never gates the scheme. |
| `JIRA_USERNAME` | Yes | — | Account email; plaintext takes precedence over its encrypted form. |
| `JIRA_API_TOKEN` | Yes | — | API token; plaintext takes precedence over its encrypted form. |
| `JIRA_TIMEOUT` | No | `60` | Seconds; an invalid integer is an error. |
| `JIRA_HOST_POLICY` | No | `atlassian-cloud` | `atlassian-cloud` or `allowlist:<host>[,<host>]`. The `loopback` token is refused. |
| `JIRA_VERIFY_SSL` | No | `true` | Read only so that a value meaning *disabled* is a hard error. |
| `JIRA_MAX_RETRIES` | No | `3` | Stored but not executed automatically; invalid values are ignored. |

Neither the transport scheme requirement nor certificate verification may be relaxed from the environment; both are
relaxable only by an explicit code call. That is why there is no `JIRA_CERT_PATH` and no way to spell
`JIRA_VERIFY_SSL=false` — see [TLS and Proxy Behavior](#tls-and-proxy-behavior) for the code calls that replace them.

The default retry delay is one second and can be changed only through the builder or `with_retries`; it is also stored
but not executed by the request path. The client disables system proxy discovery, so proxy environment variables are
not honored. See the [full configuration reference](https://github.com/ThreatFlux/threatflux-atlassian/blob/main/docs/SDK_CONFIGURATION.md)
for encrypted inputs, precedence, TLS, error, retry, and logging behavior.

`JIRA_URL` must not carry credentials in its authority. A base URL of the form `https://user:token@host` is refused,
because it would put a second credential-bearing value into `AtlassianConfig` — one that the derived `Debug` prints in
full, that the transport logs on every request, and that the host policy cannot see, since the policy is matched against
the URL host and the host excludes the userinfo. Supply the credentials as `JIRA_USERNAME` and `JIRA_API_TOKEN`, where
the token stays inside `SecretString`. A base URL carrying a query string or a fragment is refused for a different
reason: both survive path resolution, so `https://site.atlassian.net/?maxResults=1000` would attach that parameter to
every request the SDK makes.

## Feature Flags

`encrypted-env` is the only flag that gates code and dependencies. The rest preserve package compatibility:
`default-features = false` does not remove the direct or Remote MCP modules, and `ssl-verification` does not switch TLS
behavior. Certificate verification is controlled at runtime by `AtlassianConfig`.

<!-- BEGIN FEATURES -->
| Feature | Enabled by | Behavior |
| --- | --- | --- |
| `default` | Cargo default | Enables `full`. |
| `full` | `default` | Enables the `direct`, `remote`, and `encrypted-env` features. |
| `direct` | `full` | Compatibility marker; direct code and dependencies are always compiled. |
| `remote` | `full` | Compatibility marker; legacy Remote MCP code and dependencies are always compiled. |
| `ssl-verification` | Explicit only | Compatibility marker; runtime configuration controls verification. |
| `encrypted-env` | `full` | Compiles the FluxEncrypt decrypt path and the `dotenvy` env-file loader. |
<!-- END FEATURES -->

Turning `encrypted-env` off drops the `fluxencrypt` and `dotenvy` dependencies, and with them `rsa` 0.9.x
([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071), which has no patched release). The
`*_ENCRYPTED`, `ENV_FILE_ENCRYPTED`, and `ENV_FILE_ENCRYPTED_PATH` variables are then unresolvable: a ciphertext that
would otherwise have to be decrypted is a hard `AtlassianError::Configuration` naming the feature, rather than a silent
downgrade that would remove encryption-at-rest from a deployment that still believed it had it. Plaintext precedence
still applies, so a cleartext `JIRA_API_TOKEN` alongside a `*_ENCRYPTED` value wins as it always does; and a bare
`*_PRIVATE_KEY` with no ciphertext to decrypt is inert in either build.

```toml
[dependencies]
threatflux-atlassian-sdk = { version = "0.5", default-features = false, features = ["direct", "remote"] }
```

## Errors, Retries, and Rate Limits

All public operations return `threatflux_atlassian_sdk::Result<T>` with `AtlassianError`:

- `401`, `403`, `404`, and `429` become authentication, permission, not-found, and rate-limit variants;
- other Jira non-success responses become `JiraApi`, carrying status and `Retry-After` but **not** the response body:
  releasing the body requires opting into `DiagnosticsPolicy::JiraErrorFields` or `IncludeBody` via
  `AtlassianClient::with_diagnostics`, and no policy ever writes it to a log;
- reqwest failures become `Http`; JSON decoding and local validation use separate variants;
- `is_retryable()` recognizes `RateLimit`, `Timeout`, and `Http` errors with status 500 or greater. A Jira 5xx response
  mapped to `JiraApi` is not classified as retryable by that helper.

No SDK method automatically retries, sleeps, or honors `Retry-After`. Apply bounded exponential backoff with jitter in
the calling application, and only retry operations whose idempotency you understand.

## TLS and Proxy Behavior

- reqwest is compiled without default features and with its rustls transport.
- Certificate verification is enabled by default, and HTTPS is required.
- `AtlassianConfig::with_cert_path` / `AtlassianConfigBuilder::cert_path` add one custom PEM or DER root certificate; it
  does not replace the built-in roots. This is a **code call only**. An extra trust anchor can sign a certificate the
  system roots would have rejected, so installing one relaxes certificate verification for the chosen destination —
  which the environment is not permitted to do.
- `AtlassianConfigBuilder::verify_ssl(false)` calls `danger_accept_invalid_certs(true)` on an `https://` URL and should
  be limited to controlled local testing. It is certificate verification only: it does not admit an `http://` base URL.
- `HostPolicy::Loopback` is the only way to reach an `http://` destination, only for a literal loopback address, and it
  too is a code call.
- The direct client calls `no_proxy()`, so standard proxy environment variables are intentionally bypassed.

### What the host policy does not cover

`HostPolicy` bounds the **scheme**, not the set of hosts an environment can name. `JIRA_HOST_POLICY` refuses only the
literal `loopback` token; `allowlist:<any-host>` is accepted from the environment. A process whose environment an
attacker can set twice — `JIRA_HOST_POLICY=allowlist:evil.example` together with `JIRA_URL=https://evil.example` — will
send `Authorization: Basic` to `evil.example` over ordinary TLS, and the policy will permit it, because an operator's
own Data Center deployment is indistinguishable from it.

That residual is deliberate and cannot be closed here: a policy that could not be widened from configuration would make
Data Center unusable. What the policy guarantees is that the credential never crosses the wire in cleartext, that the
default admits only Atlassian Cloud tenants, and that widening it requires the environment to be writable in the first
place. Treat `JIRA_HOST_POLICY` as part of the credential: pin it wherever the token is pinned, and keep it out of
workflow-settable inputs.

## Breaking Changes

- **`JIRA_CERT_PATH` is no longer read.** It reached `add_root_certificate`, which let an environment install a trust
  anchor for whatever host the same environment chose with `JIRA_URL` — certificate verification relaxed from the
  environment, which is precisely what this crate now guarantees cannot happen. Setting the variable is ignored rather
  than refused, so a deployment that still exports it keeps working against the system roots; the failure mode is a
  refused handshake, never a silently widened one. A Data Center deployment with a private CA passes the same path
  through `AtlassianConfig::with_cert_path`, `AtlassianConfigBuilder::cert_path`, or the CLI's `--cert-path` flag.
- **`JIRA_VERIFY_SSL` no longer disables certificate verification.** A value meaning *disabled* is a hard error rather
  than a silent downgrade. `AtlassianConfigBuilder::verify_ssl(false)` is the code call that survives.
- **A base URL carrying credentials, a query string, or a fragment is refused.** See
  [Configuration](#configuration).

## Legacy Remote MCP

`AtlassianRemoteClient` remains public for compatibility and migration assessment, but it is not a working client for
Atlassian's current Rovo MCP service. Its exact limitations are:

- hard-coded retired endpoint: `https://mcp.atlassian.com/v1/sse`;
- JSON-RPC requests are sent as ordinary `POST` requests without Streamable HTTP session handling;
- `initialize_auth()` creates an auth URL but does not launch a browser or listen on the callback port;
- the caller must receive the callback, retain the returned `state`, and pass the code and state to `complete_auth()`;
- access and refresh tokens exist only in memory; refresh support is exposed on `AuthManager` but is not automatic;
- convenience methods for Jira, Confluence, and Compass produce assumed payloads that are not verified against the
  current service.

Use Atlassian's [current Rovo MCP setup guide](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/)
with a supported MCP client. The [`remote_mcp_example`](examples/remote_mcp_example.rs) only demonstrates the retained
legacy API shape and stops before making an MCP request.

## Examples

| Example | Purpose | Makes remote changes? |
| --- | --- | --- |
| [`quickstart.rs`](examples/quickstart.rs) | Fetch one Jira issue from environment config | No |
| [`jira_example.rs`](examples/jira_example.rs) | Explore direct reads, including retained legacy list/search helpers, and construct a create request | Reads Jira; does not create the sample issue |
| [`ticket_management.rs`](examples/ticket_management.rs) | Demonstrate ticket/custom-field workflows and retained legacy JQL search | Performs reads; review before adapting |
| [`remote_mcp_example.rs`](examples/remote_mcp_example.rs) | Show the retained legacy OAuth API shape and migration warning | No MCP request |

## Security

`AtlassianConfig`, `AccessToken`, and the OAuth token types implement `Debug` but deliberately not `Serialize`, and
their credential fields are `SecretString`, so `Debug` is redacted and serializing one is a compile error. Jira error
response bodies are **not** included in errors and are never logged: releasing one requires opting into
`DiagnosticsPolicy::JiraErrorFields` or `IncludeBody` via `AtlassianClient::with_diagnostics`, and even then only into
the returned error. Prefer least-privilege service accounts, rotate API tokens, keep certificate verification on,
and avoid committing plaintext or encrypted secrets alongside their private keys. Report vulnerabilities through the
repository's [security policy](https://github.com/ThreatFlux/threatflux-atlassian/security/policy).

## License

Licensed under the [MIT License](https://github.com/ThreatFlux/threatflux-atlassian/blob/main/LICENSE).
