# threatflux-atlassian-cli

CLI for Atlassian Jira workflows used by ThreatFlux.

## Overview

`threatflux-atlassian-cli` provides a command-line interface (binary: `tflux-atlassian`) on top of
`threatflux-atlassian-sdk`.

It supports day-to-day Jira operations plus local credential tooling (key generation and secret encryption) for secure
environment management.

The CLI currently focuses on direct Jira REST workflows built on top of the shared SDK.

## Key Capabilities

- Fetch profile + API health
- Get/search issues and list project issues via JQL
- List/find Jira fields
- Create issues from JSON payloads
- Update story points or arbitrary custom fields
- Transition issues by status name or transition ID
- Generate FluxEncrypt-compatible RSA key pairs
- Encrypt Jira/API credentials for env-file workflows

## Configuration

The CLI uses environment-based config by default (with optional CLI overrides):

| Variable           | Description                                                 |
| ------------------ | ----------------------------------------------------------- |
| `JIRA_URL`         | Jira base URL (for example `https://company.atlassian.net`) |
| `JIRA_USERNAME`    | Jira account email/username                                 |
| `JIRA_API_TOKEN`   | Jira API token                                              |
| `JIRA_TIMEOUT`     | HTTP timeout in seconds                                     |
| `JIRA_VERIFY_SSL`  | SSL verification toggle (`true`/`false`)                    |
| `JIRA_CERT_PATH`   | Optional custom CA certificate path                         |
| `JIRA_MAX_RETRIES` | Max retries for transient failures                          |

CLI flags such as `--base-url`, `--username`, `--api-token`, `--timeout`, and `--insecure` can override env values.

## Build and Run

```bash
cargo build -p threatflux-atlassian-cli --release
./target/release/tflux-atlassian --help
```

## Examples

```bash
# Show authenticated Jira user profile
./target/release/tflux-atlassian profile

# Search issues
./target/release/tflux-atlassian issue-search --jql "project = SEC ORDER BY created DESC" --limit 25

# Get one issue
./target/release/tflux-atlassian issue-get SEC-123

# Transition issue by status
./target/release/tflux-atlassian issue-transition SEC-123 --status "In Progress"

# Generate key material
./target/release/tflux-atlassian keygen --private-out ./jira.private.pem --public-out ./jira.public.pem

# Encrypt secret with public key
./target/release/tflux-atlassian secret-encrypt \
  --public-key-path ./jira.public.pem \
  --secret-env JIRA_API_TOKEN \
  --output ./jira.token.enc
```

All successful command outputs are emitted as JSON.

## Crate Layout

```text
crates/threatflux-atlassian-cli/
├── src/
│   └── main.rs      # clap command definitions + command handlers
└── Cargo.toml
```

## License

See [LICENSE](../../LICENSE).
