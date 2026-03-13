# Usage

## SDK as a Git Dependency

Add the SDK to another Rust project:

```toml
[dependencies]
threatflux-atlassian-sdk = { git = "https://github.com/ThreatFlux/threatflux-atlassian.git", rev = "<commit-or-tag>" }
```

For a released tag:

```toml
[dependencies]
threatflux-atlassian-sdk = { git = "https://github.com/ThreatFlux/threatflux-atlassian.git", tag = "v0.4.0" }
```

## Direct Jira REST Usage

Environment variables:

- `JIRA_URL`
- `JIRA_USERNAME`
- `JIRA_API_TOKEN`
- optional: `JIRA_TIMEOUT`
- optional: `JIRA_VERIFY_SSL`
- optional: `JIRA_CERT_PATH`
- optional: `JIRA_MAX_RETRIES`

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

## Remote MCP Usage

Environment variables:

- `ATLASSIAN_CLIENT_ID`
- optional: `ATLASSIAN_CALLBACK_PORT`

Example:

```rust
use threatflux_atlassian_sdk::AtlassianRemoteClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AtlassianRemoteClient::new("client-id".to_string(), 8080)?;
    let auth = client.initialize_auth().await?;
    println!("{}", auth["auth_url"]);
    Ok(())
}
```

## CLI Usage

Build locally:

```bash
cargo build -p threatflux-atlassian-cli --release
./target/release/tflux-atlassian --help
```

Install from a pinned repo tag:

```bash
cargo install --git https://github.com/ThreatFlux/threatflux-atlassian.git --tag v0.4.0 threatflux-atlassian-cli
```

Typical commands:

```bash
tflux-atlassian profile
tflux-atlassian issue-get KAN-123
tflux-atlassian issue-search --jql "project = KAN ORDER BY created DESC" --limit 10
tflux-atlassian issue-transition KAN-123 --status "In Progress"
```

## Local Development

The repo keeps the standard ThreatFlux Rust template tooling:

```bash
make dev-setup
make fmt
make lint
make test
make sbom
make ci
```

## Release Notes

- Release artifacts are built around the CLI binary `tflux-atlassian`.
- GitHub releases attach CycloneDX SBOMs for the SDK and CLI crates.
- The container image embeds a CycloneDX SBOM at `/usr/share/doc/threatflux-atlassian/sbom.cdx.json`.
- Release publishing verifies the SDK first, publishes it, waits for crates.io index propagation, then verifies and
  publishes the CLI.
- GitHub Actions publishing should use a shared repo/org `CRATES_IO_TOKEN`; `CARGO_REGISTRY_TOKEN` remains supported as
  a compatibility fallback.

## GitHub Action Usage

The shared action is intended for thin per-repo workflows and a committed config file.

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

permissions: {}

jobs:
  create-jira-issue:
    if: |
      github.event.issue.user.login == 'dependabot[bot]' ||
      github.event.issue.user.login == 'dependabot-preview[bot]'
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: ThreatFlux/threatflux-atlassian@main
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
