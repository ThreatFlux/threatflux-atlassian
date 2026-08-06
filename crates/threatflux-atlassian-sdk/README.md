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
- Plain or FluxEncrypt-compatible encrypted environment inputs
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
| `JIRA_URL` | Yes | — | HTTPS site URL while verification is enabled. |
| `JIRA_USERNAME` | Yes | — | Account email; plaintext takes precedence over its encrypted form. |
| `JIRA_API_TOKEN` | Yes | — | API token; plaintext takes precedence over its encrypted form. |
| `JIRA_TIMEOUT` | No | `60` | Seconds; an invalid integer is an error. |
| `JIRA_CERT_PATH` | No | — | One PEM or DER certificate added as a root. |
| `JIRA_VERIFY_SSL` | No | `true` | Only case-insensitive `false` disables verification. |
| `JIRA_MAX_RETRIES` | No | `3` | Stored but not executed automatically; invalid values are ignored. |

The default retry delay is one second and can be changed only through the builder or `with_retries`; it is also stored
but not executed by the request path. The client disables system proxy discovery, so proxy environment variables are
not honored. See the [full configuration reference](https://github.com/ThreatFlux/threatflux-atlassian/blob/main/docs/SDK_CONFIGURATION.md)
for encrypted inputs, precedence, TLS, error, retry, and logging behavior.

## Feature Flags

The current flags preserve package compatibility but do not gate code or dependencies. In particular,
`default-features = false` does not remove the direct or Remote MCP modules, and `ssl-verification` does not switch TLS
behavior. Certificate verification is controlled at runtime by `AtlassianConfig`.

<!-- BEGIN FEATURES -->
| Feature | Enabled by | Behavior |
| --- | --- | --- |
| `default` | Cargo default | Enables `full`. |
| `full` | `default` | Enables the `direct` and `remote` marker features. |
| `direct` | `full` | Compatibility marker; direct code and dependencies are always compiled. |
| `remote` | `full` | Compatibility marker; legacy Remote MCP code and dependencies are always compiled. |
| `ssl-verification` | Explicit only | Compatibility marker; runtime configuration controls verification. |
<!-- END FEATURES -->

## Errors, Retries, and Rate Limits

All public operations return `threatflux_atlassian_sdk::Result<T>` with `AtlassianError`:

- `401`, `403`, `404`, and `429` become authentication, permission, not-found, and rate-limit variants;
- other Jira non-success responses become `JiraApi` and include the response body in the error message;
- reqwest failures become `Http`; JSON decoding and local validation use separate variants;
- `is_retryable()` recognizes `RateLimit`, `Timeout`, and `Http` errors with status 500 or greater. A Jira 5xx response
  mapped to `JiraApi` is not classified as retryable by that helper.

No SDK method automatically retries, sleeps, or honors `Retry-After`. Apply bounded exponential backoff with jitter in
the calling application, and only retry operations whose idempotency you understand.

## TLS and Proxy Behavior

- reqwest is compiled without default features and with its rustls transport.
- Certificate verification is enabled by default.
- `JIRA_CERT_PATH` adds one custom PEM or DER root certificate; it does not replace the built-in roots.
- `JIRA_VERIFY_SSL=false` calls `danger_accept_invalid_certs(true)` and should be limited to controlled local testing.
- The direct client calls `no_proxy()`, so standard proxy environment variables are intentionally bypassed.

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

`AtlassianConfig`, `AccessToken`, and related types implement `Debug` and/or `Serialize`; do not log or serialize values
that contain credentials. Jira error response bodies are included in errors and logged at error level, so configure log
collection accordingly. Prefer least-privilege service accounts, rotate API tokens, keep certificate verification on,
and avoid committing plaintext or encrypted secrets alongside their private keys. Report vulnerabilities through the
repository's [security policy](https://github.com/ThreatFlux/threatflux-atlassian/security/policy).

## License

Licensed under the [MIT License](https://github.com/ThreatFlux/threatflux-atlassian/blob/main/LICENSE).
