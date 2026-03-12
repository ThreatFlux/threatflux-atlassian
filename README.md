# threatflux-atlassian

ThreatFlux Atlassian SDK and CLI workspace, extracted from the core monorepo and layered onto the standard ThreatFlux
Rust CI/CD template.

This repo is the shared home for:

- `threatflux-atlassian-sdk`
- `threatflux-atlassian-cli`

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

## Quick Start

### Use the SDK from another Rust project

```toml
[dependencies]
threatflux-atlassian-sdk = { git = "https://github.com/ThreatFlux/threatflux-atlassian.git", tag = "v0.3.2" }
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
cargo install --git https://github.com/ThreatFlux/threatflux-atlassian.git threatflux-atlassian-cli
tflux-atlassian --help
```

### Develop locally

```bash
make dev-setup
make ci
```

Additional usage examples live in [docs/USAGE.md](docs/USAGE.md).
Template adaptation notes live in [docs/TEMPLATE_ADAPTATION.md](docs/TEMPLATE_ADAPTATION.md).

## Workspace Layout

```text
threatflux-atlassian/
├── .github/workflows/         # ThreatFlux CI/CD template workflows
├── crates/
│   ├── threatflux-atlassian-sdk/
│   └── threatflux-atlassian-cli/
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
binary crate.

## License

See [LICENSE](./LICENSE).
