# ThreatFlux Atlassian

[![crates.io](https://img.shields.io/crates/v/threatflux-atlassian-sdk.svg)](https://crates.io/crates/threatflux-atlassian-sdk)
[![docs.rs](https://docs.rs/threatflux-atlassian-sdk/badge.svg)](https://docs.rs/threatflux-atlassian-sdk)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.96.0-orange.svg)](https://www.rust-lang.org)
[![CI](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/ci.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/ci.yml)
[![Security](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/security.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/security.yml)
[![Docs contract](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/docs.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/docs.yml)

A Rust workspace for Jira Cloud automation: a reusable REST SDK, an operator CLI, and a config-driven GitHub Action.
The SDK is the primary library surface; the CLI and Action build on it.

> [!IMPORTANT]
> This independent, community-maintained project is not affiliated with, endorsed by, or sponsored by Atlassian.

> [!WARNING]
> The `remote` API is **not usable with Atlassian's current Rovo MCP service**. It targets
> `https://mcp.atlassian.com/v1/sse`, which Atlassian stopped supporting after June 30, 2026. Atlassian now documents
> a Streamable HTTP endpoint and a different authorization flow. See [Remote MCP status](#remote-mcp-status) and
> [Atlassian's migration notice](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/configuring-oauth-2-1/).

## Choose a Surface

| Surface | Package | Use it for | Status |
| --- | --- | --- | --- |
| Rust SDK | [`threatflux-atlassian-sdk`](crates/threatflux-atlassian-sdk/) | Direct Jira Cloud REST API v2 integrations | Supported path |
| CLI | [`threatflux-atlassian-cli`](crates/threatflux-atlassian-cli/) | Operator-driven Jira workflows | Built on the direct SDK |
| GitHub Action | [`threatflux-atlassian-action`](crates/threatflux-atlassian-action/) | Event-to-Jira automation from committed rules | Built on the direct SDK |
| Legacy Remote MCP module | `AtlassianRemoteClient` | API evaluation and migration work only | Incompatible with the current Atlassian endpoint |

The direct SDK currently covers issue retrieval, creation and field updates; JQL search; comments; assignments; issue
links; attachments; changelogs; workflow transitions; projects; users; and field discovery. It does not claim complete
coverage of Jira, Confluence, Compass, Jira Software, or Jira Service Management.

## Installation

Install the latest published [SDK crate](https://crates.io/crates/threatflux-atlassian-sdk):

```bash
cargo add threatflux-atlassian-sdk
cargo add tokio --features macros,rt-multi-thread
```

Current `main` declares Rust 1.96.0 as its minimum supported Rust version (MSRV). See
[Version and release channels](#version-and-release-channels) before using a Git tag as a package version.

## Quickstart

Create an Atlassian API token for an account that has only the Jira permissions your integration needs, then export:

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

The same source is compiled as [`quickstart.rs`](crates/threatflux-atlassian-sdk/examples/quickstart.rs):

```bash
cargo run -p threatflux-atlassian-sdk --example quickstart
```

`AtlassianClient` sends Basic authentication using the account email and API token to Jira REST API v2 under
`JIRA_URL`. Atlassian recommends this form of authentication for personal scripts, bots, and other ad-hoc calls; review
their [Basic auth guidance](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/) before
shipping a distributable integration.

## Configuration and Operational Behavior

| Setting | Default | Behavior |
| --- | --- | --- |
| `JIRA_URL` | Required | Jira Cloud site URL; HTTPS is required while certificate verification is enabled. |
| `JIRA_USERNAME` | Required | Atlassian account email used in the Basic auth header. |
| `JIRA_API_TOKEN` | Required | Atlassian API token; never use the account password. |
| `JIRA_TIMEOUT` | `60` seconds | Whole-request timeout. Invalid values return a configuration error. |
| `JIRA_CERT_PATH` | System roots | Adds one PEM- or DER-encoded trust root. |
| `JIRA_VERIFY_SSL` | `true` | Only the case-insensitive value `false` disables certificate verification. |
| `JIRA_MAX_RETRIES` | `3` | Stored in configuration, but the client does **not** automatically retry requests. |

The direct client uses rustls and intentionally disables system proxy discovery with `reqwest::ClientBuilder::no_proxy`;
`HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` are therefore not used. Encrypted credential and env-file inputs are also
supported. See the [SDK configuration reference](docs/SDK_CONFIGURATION.md) for precedence, encrypted variable names,
TLS details, retry semantics, and logging caveats.

## Remote MCP Status

`AtlassianRemoteClient` is retained as an experimental legacy surface so existing users can assess migration work. Do
not select the `remote` feature expecting a working connection to today's Atlassian Rovo MCP service:

- it hard-codes the retired `/v1/sse` endpoint and sends a single JSON-RPC `POST` rather than implementing the current
  Streamable HTTP transport;
- it generates an authorization URL, but does not start a local callback server or open a browser;
- callers must capture the authorization `code` and `state`, then call `complete_auth` themselves;
- access and refresh tokens are held only in memory, are not persisted, and refresh is not automatic;
- Jira, Confluence, and Compass convenience methods construct proposed JSON-RPC payloads but are not verified against
  the current Atlassian service.

Follow Atlassian's [current Rovo MCP setup documentation](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/)
for a supported MCP client. The direct Jira REST client is the supported path in this crate.

## CLI

Install the latest published [CLI crate](https://crates.io/crates/threatflux-atlassian-cli):

```bash
cargo install --locked threatflux-atlassian-cli
tflux-atlassian --help
```

Prebuilt binaries are available separately from [GitHub Releases](https://github.com/ThreatFlux/threatflux-atlassian/releases).

Common commands include:

```bash
tflux-atlassian profile
tflux-atlassian issue-get KAN-123
tflux-atlassian issue-search --jql "project = KAN ORDER BY created DESC" --limit 10
tflux-atlassian issue-comment-add KAN-123 --body-file ./review.md
tflux-atlassian issue-transition KAN-123 --status "In Progress"
```

See the [CLI README](crates/threatflux-atlassian-cli/README.md) and [usage guide](docs/USAGE.md) for all operator
commands and secret-handling options.

## GitHub Action

The Docker action evaluates a committed rules file against the GitHub issue event, deduplicates matching work, and can
create a Jira issue through the direct SDK. Keep credentials in repository or organization secrets and pin the action
to a reviewed full commit SHA in production:

```yaml
- uses: ThreatFlux/threatflux-atlassian@<full-commit-sha>
  with:
    config-path: .github/threatflux/jira-automation.yml
  env:
    JIRA_BASE_URL: ${{ vars.JIRA_BASE_URL }}
    JIRA_EMAIL: ${{ vars.JIRA_EMAIL }}
    JIRA_API_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
```

Start with the [example rules](examples/github-automation/dependabot-high.yml), the
[consumer workflow](examples/workflows/dependabot-jira-issues.yml), and the
[Action crate README](crates/threatflux-atlassian-action/README.md).

## Features

The SDK declares `default`, `full`, `direct`, `remote`, and `ssl-verification`. These are compatibility markers: they do
not gate modules or dependencies, and `ssl-verification` does not control runtime certificate verification.
See the [SDK feature table](crates/threatflux-atlassian-sdk/README.md#feature-flags) before using
`default-features = false` to optimize a build.

## Documentation

- [SDK README](crates/threatflux-atlassian-sdk/README.md) — SDK-first onboarding and API boundaries
- [SDK configuration reference](docs/SDK_CONFIGURATION.md) — auth, environment precedence, TLS, retries, and secrets
- [Usage guide](docs/USAGE.md) — SDK examples, CLI commands, and GitHub Action configuration
- [API documentation](https://docs.rs/threatflux-atlassian-sdk) — public Rust types and methods
- [README standards](docs/README_STANDARDS.md) — repository documentation conventions
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)

## Version and Release Channels

[Crates.io](https://crates.io/crates/threatflux-atlassian-sdk) is the Rust package channel; let `cargo add` and
`cargo install` resolve the latest compatible published packages. [GitHub Releases](https://github.com/ThreatFlux/threatflux-atlassian/releases)
is a separate source and binary-artifact channel. A release tag can differ from the Cargo package versions embedded in
that source, so inspect the tagged `Cargo.toml` or `cargo metadata` output before treating a tag as a crate version.

For source dependencies, pin a reviewed full commit SHA. For release binaries, verify the adjacent SHA-256 file before
use.

## Development

Install `just` 1.45.0 or newer, then run:

```bash
just dev-setup
just docs-check
just ci
```

The workspace pins Rust 1.97.1 for development and CI while checking the 1.96.0 MSRV separately. See
[`justfile`](justfile) for focused formatting, lint, test, feature, rustdoc, security, and packaging recipes.

## Security

Do not log `AtlassianConfig`, OAuth token values, Jira error bodies, or decrypted environment files. Keep TLS verification
enabled, use least-privilege accounts and revocable API tokens, and implement application-level backoff for rate limits
and transient failures. Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE).
