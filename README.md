# threatflux-atlassian

ThreatFlux Atlassian SDK and CLI workspace, extracted from the core monorepo and layered onto the standard ThreatFlux
Rust CI/CD template.

This repo is the shared home for:

- `threatflux-atlassian-sdk`
- `threatflux-atlassian-cli`
- `threatflux-atlassian-action`

It carries the full Atlassian integration surface that previously lived in `core`:

- Jira Cloud REST automation using API-token authentication
- Atlassian Remote MCP / OAuth client support
- reusable Jira request/response types
- an operator CLI for common Jira workflows

## Crates

| Crate | Purpose |
| ----- | ------- |
| `threatflux-atlassian-sdk` | Shared Rust SDK for Jira REST and Atlassian Remote MCP |
| `threatflux-atlassian-cli` | CLI wrapper around the SDK (`tflux-atlassian`) |
| `threatflux-atlassian-action` | Config-driven GitHub Action runtime for Jira automation |

## Quick Start

### Use the SDK from another Rust project

```toml
[dependencies]
threatflux-atlassian-sdk = { git = "https://github.com/ThreatFlux/threatflux-atlassian.git", tag = "v0.4.0" }
```

```rust
use threatflux_atlassian_sdk::AtlassianClient;

# tokio_test::block_on(async {
let client = AtlassianClient::from_env().unwrap();
let issue = client.get_issue("KAN-123").await.unwrap();
println!("{}", issue.key);
# });
```

### Install the CLI

```bash
cargo install --git https://github.com/ThreatFlux/threatflux-atlassian.git --tag v0.4.0 threatflux-atlassian-cli
tflux-atlassian --help
```

### Develop locally

```bash
make dev-setup
make ci
```

Additional usage examples live in [docs/USAGE.md](docs/USAGE.md).
Template adaptation notes live in [docs/TEMPLATE_ADAPTATION.md](docs/TEMPLATE_ADAPTATION.md).

## GitHub Action

This repo now ships a reusable GitHub Action for Jira automation. The intended model is:

- keep the event trigger in the consuming repo
- commit a repo-local config file at `.github/threatflux/jira-automation.yml`
- provide Jira credentials and defaults through GitHub variables and secrets
- call `ThreatFlux/threatflux-atlassian@<tag-or-sha>` from a thin workflow

Example consumer workflow:

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
      - uses: ThreatFlux/threatflux-atlassian@<tag-or-sha> # Replace with the first released ref after merge
        with:
          config-path: .github/threatflux/jira-automation.yml
        env:
          JIRA_BASE_URL: ${{ vars.JIRA_BASE_URL }}
          JIRA_EMAIL: ${{ vars.JIRA_EMAIL }}
          JIRA_API_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
          JIRA_PROJECT_KEY: ${{ vars.JIRA_PROJECT_KEY }}
          JIRA_ASSIGNEE_ACCOUNT_ID: ${{ vars.JIRA_ASSIGNEE_ACCOUNT_ID }}
```

Use `${VAR}` in config for required values and `${VAR:-default}` for optional or defaulted values. That matters in GitHub
Actions because an undefined `vars.*` reference is often surfaced to the container as an empty string.

Starter files live in:

- [examples/github-automation/dependabot-high.yml](examples/github-automation/dependabot-high.yml)
- [examples/workflows/dependabot-jira-issues.yml](examples/workflows/dependabot-jira-issues.yml)

## Workspace Layout

```text
threatflux-atlassian/
├── .github/workflows/         # ThreatFlux CI/CD template workflows
├── action.yml                 # Shared GitHub Action metadata
├── crates/
│   ├── threatflux-atlassian-sdk/
│   ├── threatflux-atlassian-cli/
│   └── threatflux-atlassian-action/
├── examples/
├── docs/
├── Cargo.toml
├── Makefile
└── LICENSE
```

## CI/CD Template Integration

This repo keeps the standard ThreatFlux template pieces:

- pinned GitHub Actions workflows
- Rust 1.94.0 as the current pinned release/MSRV baseline
- `Makefile`-driven local CI
- release, docker, and security pipelines
- CycloneDX SBOMs attached to GitHub releases and generated in CI
- a runtime container SBOM embedded at `/usr/share/doc/threatflux-atlassian/sbom.cdx.json`

The template files were adapted for a Rust workspace with a library crate and a CLI crate instead of a single root
binary crate. The workspace now also includes a Docker-based GitHub Action runtime for config-driven Jira automation.

The release workflow publishes the SDK before the CLI and waits for the SDK version to appear in the crates.io index
before publishing the CLI. Pinned git tags like the examples above remain the safest documented consumption path until
the corresponding crates.io releases are available.

For GitHub Actions publishing, the recommended setup is a shared repo/org `CRATES_IO_TOKEN` secret so every workspace
release job uses the same token source. The workflow also accepts `CARGO_REGISTRY_TOKEN` as a compatibility fallback.

## License

See [LICENSE](./LICENSE).
