# threatflux-atlassian-cli

CLI for Atlassian Jira workflows used by ThreatFlux.

This independent project is not affiliated with, endorsed by, or sponsored by Atlassian.

## Overview

`threatflux-atlassian-cli` provides a command-line interface (binary: `tflux-atlassian`) on top of
`threatflux-atlassian-sdk`.

It supports day-to-day Jira operations plus local credential tooling (key generation and secret encryption) for secure
environment management.

The CLI currently focuses on direct Jira REST workflows built on top of the shared SDK.

> [!WARNING]
> `issue-search` and `project-issues` use upstream-deprecated `GET /rest/api/2/search`; `projects-list` uses deprecated
> `GET /rest/api/2/project`. Treat these commands as compatibility tools, not foundations for new automation. Atlassian
> documents enhanced search at `/rest/api/2/search/jql` and paginated project search at `/rest/api/2/project/search`.
> See the official [issue-search reference](https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/)
> and [project deprecation notice](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-removal-of-get-filters-and-get-all-projects/).

## Key Capabilities

- Fetch profile + API health
- Get issues; retained legacy commands search issues and list project issues via JQL
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
| `JIRA_HOST_POLICY` | `atlassian-cloud` (default) or `allowlist:<host>[,<host>]`   |
| `JIRA_VERIFY_SSL`  | Read only so a value meaning *disabled* is a hard error     |
| `JIRA_MAX_RETRIES` | Stored count (default: `3`); no automatic retries occur     |

Adding a trust root is a flag, not a variable: `JIRA_CERT_PATH` is no longer read, because an extra root can vouch for
whatever host the same environment chose with `JIRA_URL`. Pass `--cert-path <PATH>` instead — a command line is an
operator's deliberate choice in a way a workflow environment is not. The same rule governs `--host-policy loopback` and
`--insecure`, neither of which any environment variable can select.

CLI flags such as `--base-url`, `--username`, `--api-token`, `--timeout`, `--host-policy`, `--cert-path`, and
`--insecure` can override env values.
The underlying direct client uses rustls and disables system proxy discovery, so proxy environment variables are not
honored. See the [SDK configuration reference](https://github.com/ThreatFlux/threatflux-atlassian/blob/main/docs/SDK_CONFIGURATION.md)
for exact behavior.

Prefer secret environment injection over `--api-token`, because command arguments can be visible to other local
processes and shell history.

## Installation

Install the latest published [CLI crate](https://crates.io/crates/threatflux-atlassian-cli):

```bash
cargo install --locked threatflux-atlassian-cli
```

Prebuilt binaries are available from [GitHub Releases](https://github.com/ThreatFlux/threatflux-atlassian/releases).
Release tags identify source and binary artifacts and can differ from the Cargo package versions embedded in that
source; inspect the tagged manifest when exact package provenance matters.

## Build and Run

```bash
cargo build -p threatflux-atlassian-cli --release
./target/release/tflux-atlassian --help
```

## Examples

```bash
# Show authenticated Jira user profile
./target/release/tflux-atlassian profile

# Legacy issue search command; use Atlassian's enhanced search endpoint for new integrations
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
