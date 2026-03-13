[![CI](https://img.shields.io/github/actions/workflow/status/ThreatFlux/threatflux-atlassian/ci.yml?branch=main&label=CI)](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/ci.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/ThreatFlux/threatflux-atlassian/security.yml?branch=main&label=Security)](https://github.com/ThreatFlux/threatflux-atlassian/actions/workflows/security.yml)
[![Coverage](https://codecov.io/gh/ThreatFlux/threatflux-atlassian/branch/main/graph/badge.svg)](https://app.codecov.io/gh/ThreatFlux/threatflux-atlassian)
[![SDK crate](https://img.shields.io/crates/v/threatflux-atlassian-sdk?label=SDK%20crate)](https://crates.io/crates/threatflux-atlassian-sdk)
[![CLI crate](https://img.shields.io/crates/v/threatflux-atlassian-cli?label=CLI%20crate)](https://crates.io/crates/threatflux-atlassian-cli)
[![SDK docs](https://img.shields.io/docsrs/threatflux-atlassian-sdk?label=SDK%20docs)](https://docs.rs/threatflux-atlassian-sdk)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Rust 1.94+](https://img.shields.io/badge/rust-1.94%2B-orange.svg)](https://www.rust-lang.org)

# threatflux-atlassian

ThreatFlux Atlassian SDK and CLI workspace for Jira Cloud REST automation, Atlassian Remote MCP/OAuth access, and
operator-facing Jira workflows.

## Features

- Shared Rust SDK for Jira issue retrieval, search, transitions, and field updates
- Remote MCP / OAuth client support for Atlassian-hosted workflows
- CLI binary `tflux-atlassian` for common operator actions
- Release automation with multi-platform artifacts, SBOMs, and crates.io publishing
- ThreatFlux CI, security, Docker, and release workflow integration

## Install

### SDK from crates.io

```toml
[dependencies]
threatflux-atlassian-sdk = "0.4"
```

### CLI from crates.io

```bash
cargo install threatflux-atlassian-cli
```

### Pinned Git Source

Prefer crates.io for normal consumers. If you need unreleased code or exact repository provenance, pin an immutable tag
or commit:

```toml
[dependencies]
threatflux-atlassian-sdk = { git = "https://github.com/ThreatFlux/threatflux-atlassian.git", rev = "<commit-or-tag>" }
```

## Quick Start

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

Expected Jira REST environment variables:

- `JIRA_URL`
- `JIRA_USERNAME`
- `JIRA_API_TOKEN`
- optional: `JIRA_TIMEOUT`
- optional: `JIRA_VERIFY_SSL`
- optional: `JIRA_CERT_PATH`
- optional: `JIRA_MAX_RETRIES`

## Documentation

### Consumer Docs

- [Usage Guide](./docs/USAGE.md)
- [Template Adaptation Notes](./docs/TEMPLATE_ADAPTATION.md)

### Internal Maintainer Docs

- [Maintainer Guide](./docs/internal/MAINTAINER_GUIDE.md)
- [Release Operations](./docs/internal/RELEASE_OPERATIONS.md)

## Workspace Layout

```text
threatflux-atlassian/
├── .github/workflows/
├── crates/
│   ├── threatflux-atlassian-sdk/
│   └── threatflux-atlassian-cli/
├── docs/
│   └── internal/
├── Cargo.toml
├── Makefile
└── LICENSE
```

## Release and Security Notes

- GitHub releases attach CycloneDX SBOMs for the SDK and CLI crates.
- The runtime container embeds a CycloneDX SBOM at `/usr/share/doc/threatflux-atlassian/sbom.cdx.json`.
- The release pipeline publishes the SDK before the CLI and waits for crates.io propagation before publishing the CLI.
- GitHub Actions publishing should use a shared repo or org `CRATES_IO_TOKEN`. `CARGO_REGISTRY_TOKEN` remains supported
  as a compatibility fallback.
- PRs into `main` require the protected review and status-check policy documented in the maintainer guide.

## License

This repository is licensed under [MIT](./LICENSE).
