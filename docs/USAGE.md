# Usage Guide

This guide covers the direct Jira Cloud SDK, the operator CLI, and the config-driven GitHub Action. The project is not
affiliated with, endorsed by, or sponsored by Atlassian.

## Install the SDK

Install the latest published [SDK crate](https://crates.io/crates/threatflux-atlassian-sdk):

```bash
cargo add threatflux-atlassian-sdk
cargo add tokio --features macros,rt-multi-thread
```

For unreleased source, pin a reviewed full commit rather than a moving branch or assuming a GitHub release tag equals
the Cargo package version:

```toml
[dependencies]
threatflux-atlassian-sdk = { git = "https://github.com/ThreatFlux/threatflux-atlassian.git", rev = "<full-commit-sha>" }
```

Current source declares Rust 1.96.0 as its MSRV. Crates.io packages and
[GitHub source or binary releases](https://github.com/ThreatFlux/threatflux-atlassian/releases) are separate channels.
A release tag can differ from the Cargo package versions embedded in its source, so inspect the tagged manifest when
exact package provenance matters.

## Direct Jira REST Usage

Required environment variables:

- `JIRA_URL`
- `JIRA_USERNAME`
- `JIRA_API_TOKEN`

Optional environment variables:

- `JIRA_TIMEOUT` (60 seconds by default)
- `JIRA_VERIFY_SSL` (`true` by default)
- `JIRA_CERT_PATH` (one PEM or DER trust root)
- `JIRA_MAX_RETRIES` (stored as `3` by default, but no automatic retries occur)

The direct client targets Jira Cloud REST API v2, uses Basic auth with the account email and API token, and disables
system proxy discovery. See the [configuration reference](SDK_CONFIGURATION.md) for exact precedence, encrypted inputs,
TLS, retry, and logging behavior.

Example:

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

### Legacy search and project-list helpers

`search_issues` and `get_project_issues` call `GET /rest/api/2/search`, which Atlassian marks as currently being
removed. `get_projects` calls deprecated, non-paginated `GET /rest/api/2/project`. They are retained for compatibility,
not recommended for new integrations. Atlassian's replacements are enhanced `/rest/api/2/search/jql` and paginated
`/rest/api/2/project/search`; this SDK does not yet model their current response and pagination types. See the official
[issue-search reference](https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/) and
[project deprecation notice](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-removal-of-get-filters-and-get-all-projects/).

## Legacy Remote MCP API

> [!WARNING]
> `AtlassianRemoteClient` is not compatible with Atlassian's current Rovo MCP service. It targets the retired
> `/v1/sse` endpoint, does not implement Streamable HTTP, does not start its advertised callback server, and keeps
> tokens only in memory. Atlassian stopped supporting the SSE endpoint after June 30, 2026; see the
> [official migration notice](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/configuring-oauth-2-1/).

The legacy example is retained only to compile-check the public API shape. Use Atlassian's
[current setup guide](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/)
with a supported MCP client for new integrations.

## CLI Usage

Build locally:

```bash
cargo build -p threatflux-atlassian-cli --release
./target/release/tflux-atlassian --help
```

Install the latest published [CLI crate](https://crates.io/crates/threatflux-atlassian-cli):

```bash
cargo install --locked threatflux-atlassian-cli
```

[GitHub Releases](https://github.com/ThreatFlux/threatflux-atlassian/releases) also provides platform binaries. Verify
the adjacent SHA-256 file when using a release asset. For an unreleased source install, use `--git` with a reviewed
`--rev <full-commit-sha>`.

Typical commands:

```bash
tflux-atlassian profile
tflux-atlassian issue-get KAN-123
tflux-atlassian issue-search --jql "project = KAN ORDER BY created DESC" --limit 10
tflux-atlassian issue-comment-add KAN-123 --body-file ./review.md
tflux-atlassian issue-comments KAN-123 --limit 25
tflux-atlassian users-search --query "Example User"
tflux-atlassian issue-assign KAN-123 --account-id ACCOUNT_ID
tflux-atlassian issue-update KAN-123 ./update.json
tflux-atlassian issue-link-create --link-type Blocks --inward KAN-123 --outward KAN-456
tflux-atlassian issue-attachment-add KAN-123 ./evidence.txt
tflux-atlassian issue-changelog KAN-123 --limit 25
tflux-atlassian issue-transition KAN-123 --status "In Progress"
```

`issue-search` and `project-issues` use the legacy issue-search route; `projects-list` uses the legacy project-list
route. Keep those commands out of new automation until they are backed by Atlassian's current endpoints.

The standalone comment command does not transition the issue. Use `issue-update`
with a JSON body containing a `fields` object for general edits such as summary,
description, priority, labels, parent, or assignee. Use `issue-link-delete LINK_ID`
and `issue-assign KEY --unassign` for their corresponding removal operations.

## Local Development

The repo keeps the standard ThreatFlux Rust template tooling. Install `just` 1.45.0 or newer, then run:

```bash
just dev-setup
just docs-check
just fmt
just lint
just test
just sbom
just ci
```

## Release Notes

- Release artifacts are built around the CLI binary `tflux-atlassian`.
- GitHub release tags identify artifact/source releases and can differ from the Cargo package versions embedded in the
  tagged source.
- GitHub releases attach CycloneDX SBOMs for the SDK and CLI crates.
- The container image embeds a CycloneDX SBOM at `/usr/share/doc/threatflux-atlassian/sbom.cdx.json`.
- Release publishing verifies the SDK first, publishes it, waits for crates.io index propagation, then verifies and
  publishes the CLI.
- GitHub Actions publishing should use a shared repo/org `CRATES_IO_TOKEN`; `CARGO_REGISTRY_TOKEN` remains supported as
  a compatibility fallback.

## GitHub Action Usage

The shared action is intended for thin per-repo workflows and a committed config file.

Its deduplication step currently uses the legacy issue-search route described above and inherits that endpoint's
removal risk. Issue creation uses the supported direct issue endpoint.

### Required GitHub variables and secrets

- `vars.JIRA_BASE_URL`
- `vars.JIRA_EMAIL`
- `secrets.JIRA_API_TOKEN`
- optional: `vars.JIRA_PROJECT_KEY`
- optional: `vars.JIRA_ASSIGNEE_ACCOUNT_ID`

The action accepts `JIRA_BASE_URL` and `JIRA_EMAIL` directly, then maps them onto the SDK's `JIRA_URL` and
`JIRA_USERNAME` expectations internally.

### Consumer workflow example

```yaml
name: Create Jira issue for HIGH Dependabot issues

on:
  issues:
    types: [opened]

permissions:
  contents: read

jobs:
  create-jira-issue:
    if: |
      github.event.issue.user.login == 'dependabot[bot]' ||
      github.event.issue.user.login == 'dependabot-preview[bot]'
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: ThreatFlux/threatflux-atlassian@<full-commit-sha> # Pin a reviewed commit in production
        with:
          config-path: .github/threatflux/jira-automation.yml
        env:
          JIRA_BASE_URL: ${{ vars.JIRA_BASE_URL }}
          JIRA_EMAIL: ${{ vars.JIRA_EMAIL }}
          JIRA_API_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
          JIRA_PROJECT_KEY: ${{ vars.JIRA_PROJECT_KEY }}
          JIRA_ASSIGNEE_ACCOUNT_ID: ${{ vars.JIRA_ASSIGNEE_ACCOUNT_ID }}
```

### Repo config example

Commit a config file such as `.github/threatflux/jira-automation.yml`:

```yaml
version: 1
rules:
  - id: dependabot-high-issues
    when:
      event: issues
      action: opened
      actor_in:
        - dependabot[bot]
        - dependabot-preview[bot]
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high|critical)\b'
    jira:
      project_key: ${JIRA_PROJECT_KEY:-KAN}
      issue_type: Bug
      assignee_account_id: ${JIRA_ASSIGNEE_ACCOUNT_ID:-}
      priority_by_severity:
        high: High
        critical: Highest
      summary: "[Dependabot][{{ severity_title }}] {{ issue.title }}"
      description_format: text
      description: |
        {{ severity_title }}-severity Dependabot security alert.

        Repository: {{ repository.full_name }}
        GitHub Issue: {{ issue.html_url }}

        ---
        {{ issue.body }}
      labels:
        - dependabot
        - security
      dedupe:
        strategy: sha256
        label_prefix: dependabot-alert
        fields:
          - repository.full_name
          - issue.title
```

Interpolation follows shell-style semantics:

- use `${VAR}` for required values
- use `${VAR:-default}` for optional values or defaults
- `${VAR:-default}` also falls back when GitHub passes an empty string for an unset `vars.*` value

### Action inputs and outputs

Inputs:

- `config-path`
- `dry-run`
- `log-level`
- optional `event-name`
- optional `event-path`

Outputs:

- `matched-rule-id`
- `created`
- `jira-issue-key`
- `deduped`
- `severity`

The `event-name` and `event-path` overrides exist mainly for fixture-based tests and local debugging. Normal GitHub
usage should rely on the runner-provided event context.
