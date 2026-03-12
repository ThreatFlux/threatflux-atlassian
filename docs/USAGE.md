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
threatflux-atlassian-sdk = { git = "https://github.com/ThreatFlux/threatflux-atlassian.git", tag = "v0.3.2" }
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
- `cargo publish` must publish `threatflux-atlassian-sdk` before `threatflux-atlassian-cli`.
