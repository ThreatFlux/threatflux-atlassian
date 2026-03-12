# threatflux-atlassian-sdk

ThreatFlux Atlassian SDK for Jira and Atlassian Remote MCP integrations.

## Overview

`threatflux-atlassian-sdk` provides two integration modes:

1. **Remote MCP mode** via `AtlassianRemoteClient` (OAuth-based flow)
2. **Direct Jira REST mode** via `AtlassianClient` and `AtlassianConfig`

The crate is used by both service code and `threatflux-atlassian-cli`.

## Key Capabilities

- Jira issue and project operations
- Jira field discovery and custom field updates
- Issue transition helpers by transition ID or name
- OAuth-based Atlassian Remote MCP flows
- Environment-driven config with optional encrypted env file support
- Consistent typed errors (`AtlassianError`)

## Configuration

### Direct Jira API mode

| Variable           | Description                                                 |
| ------------------ | ----------------------------------------------------------- |
| `JIRA_URL`         | Jira base URL (for example `https://company.atlassian.net`) |
| `JIRA_USERNAME`    | Jira username/email                                         |
| `JIRA_API_TOKEN`   | Jira API token                                              |
| `JIRA_TIMEOUT`     | Optional timeout in seconds                                 |
| `JIRA_CERT_PATH`   | Optional CA certificate path                                |
| `JIRA_VERIFY_SSL`  | SSL verification toggle (`true`/`false`)                    |
| `JIRA_MAX_RETRIES` | Optional max retry count                                    |

### Remote MCP mode

`AtlassianRemoteClient::new(client_id, callback_port)` starts the OAuth-oriented MCP flow.

## Usage

### Direct mode

```rust,no_run
use threatflux_atlassian_sdk::AtlassianClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AtlassianClient::from_env()?;
    let issue = client.get_issue("SEC-123").await?;
    println!("issue key: {}", issue.key);
    Ok(())
}
```

### Remote MCP mode

```rust,no_run
use threatflux_atlassian_sdk::AtlassianRemoteClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AtlassianRemoteClient::new("your-client-id".to_string(), 8080)?;
    let auth = client.initialize_auth().await?;
    println!("Open: {}", auth["auth_url"]);
    Ok(())
}
```

## Crate Layout

```text
crates/threatflux-atlassian-sdk/
├── src/
│   ├── lib.rs          # Public exports and high-level docs
│   ├── client.rs       # Direct Jira REST client
│   ├── remote_client.rs# Remote MCP client
│   ├── config.rs       # Config loading/builders
│   ├── auth.rs         # OAuth/auth helpers
│   ├── types.rs        # Request/response models
│   └── error.rs        # Error types
└── Cargo.toml
```

## License

See [LICENSE](../../LICENSE).
