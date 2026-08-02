# threatflux-atlassian-cli

CLI for Atlassian Jira workflows used by ThreatFlux.

This independent project is not affiliated with, endorsed by, or sponsored by Atlassian.

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
- Update arbitrary issue fields, story points, or custom fields
- Add and list issue comments without changing workflow state
- Assign or unassign existing issues and search Jira users
- Create/delete issue links and inspect issue changelogs
- Upload issue attachments
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
| `JIRA_TIMEOUT`     | HTTP timeout in seconds (default: `60`)                      |
| `JIRA_VERIFY_SSL`  | Only case-insensitive `false` disables verification         |
| `JIRA_CERT_PATH`   | Optional PEM or DER trust-root path                          |
| `JIRA_MAX_RETRIES` | Stored count (default: `3`); no automatic retries occur     |

CLI flags such as `--base-url`, `--username`, `--api-token`, `--timeout`, and `--insecure` can override env values.
The underlying direct client uses rustls and disables system proxy discovery, so proxy environment variables are not
honored. See the [SDK configuration reference](https://github.com/ThreatFlux/threatflux-atlassian/blob/main/docs/SDK_CONFIGURATION.md)
for exact behavior.

Prefer secret environment injection over `--api-token`, because command arguments can be visible to other local
processes and shell history.

## Installation

The latest CLI crate currently published on crates.io is 0.4.1:

```bash
cargo install threatflux-atlassian-cli --version 0.4.1 --locked
```

The current workspace source reports 0.4.2. GitHub release `v0.4.3` contains binaries built from a workspace reporting
0.4.2; GitHub release tags and Cargo package versions are separate channels.

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

# Add a standalone comment without transitioning the issue
./target/release/tflux-atlassian issue-comment-add SEC-123 --body-file ./review.md

# Find a Jira account and assign an existing issue
./target/release/tflux-atlassian users-search --query "Example User"
./target/release/tflux-atlassian issue-assign SEC-123 --account-id ACCOUNT_ID

# Update standard or custom fields from a typed update request
./target/release/tflux-atlassian issue-update SEC-123 ./update.json

# Read comments and changelog with pagination
./target/release/tflux-atlassian issue-comments SEC-123 --limit 25
./target/release/tflux-atlassian issue-changelog SEC-123 --limit 25

# Link issues and attach validation evidence
./target/release/tflux-atlassian issue-link-create \
  --link-type Blocks --inward SEC-123 --outward SEC-456
./target/release/tflux-atlassian issue-attachment-add SEC-123 ./evidence.txt

# Generate key material
./target/release/tflux-atlassian keygen --private-out ./jira.private.pem --public-out ./jira.public.pem

# Encrypt secret with public key
./target/release/tflux-atlassian secret-encrypt \
  --public-key-path ./jira.public.pem \
  --secret-env JIRA_API_TOKEN \
  --output ./jira.token.enc
```

All successful command outputs are emitted as JSON.

`issue-update` accepts a fields-only update payload:

```json
{
  "fields": {
    "summary": "Updated summary",
    "priority": { "name": "High" },
    "labels": ["automation", "reviewed"],
    "assignee": { "accountId": "ACCOUNT_ID" }
  }
}
```

## Crate Layout

```text
crates/threatflux-atlassian-cli/
├── src/
│   └── main.rs      # clap command definitions + command handlers
└── Cargo.toml
```

## License

See the [MIT License](https://github.com/ThreatFlux/threatflux-atlassian/blob/main/LICENSE).
