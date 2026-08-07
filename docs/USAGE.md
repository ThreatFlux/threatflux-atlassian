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

<!-- BEGIN ENV_VARS -->
Required environment variables:

- `JIRA_URL` (HTTPS only; the requirement does not depend on any other variable)
- `JIRA_USERNAME`
- `JIRA_API_TOKEN`

Optional environment variables:

- `JIRA_TIMEOUT` (60 seconds by default)
- `JIRA_HOST_POLICY` (`atlassian-cloud` by default; `allowlist:<host>[,<host>]` for Data Center; `loopback` is refused)
- `JIRA_VERIFY_SSL` (`true`; only values meaning *enabled* are accepted, and one meaning *disabled* is a hard error)
- `JIRA_MAX_RETRIES` (stored as `3` by default, but no automatic retries occur)
<!-- END ENV_VARS -->

`JIRA_VERIFY_SSL` covers certificate verification only and never the scheme. HTTPS is required whatever it is set to;
the one `http://` destination the SDK admits is a literal loopback address under `HostPolicy::Loopback`, which is a code
call (`AtlassianConfigBuilder::host_policy`) that no environment variable can reach. Certificate verification itself is
relaxed only by `AtlassianConfigBuilder::verify_ssl(false)`, and only for an `https://` URL.

There is no `JIRA_CERT_PATH`: a custom trust root can vouch for whatever host the same environment named in `JIRA_URL`,
so it is settable only in code (`AtlassianConfig::with_cert_path`) or, for the CLI, with `--cert-path`.

`JIRA_HOST_POLICY` decides where the credential may be sent, and an environment that can set it can widen the allowlist
to an arbitrary `https` host. The default is a safe default rather than a containment boundary against a hostile
environment; pin it wherever the API token is pinned.

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
`/rest/api/2/project/search`, and this SDK models them, on the v3 spelling of the same two routes, in
`threatflux_atlassian_sdk::search`: `SearchRequest` and `SearchPage` for `POST /rest/api/3/search/jql`, the
token-paginated `SearchCursor` for walking it, and `ProjectSearchQuery`/`ProjectSearchPage` for
`GET /rest/api/3/project/search`. Send a search with `client.search_jql`, `client.find_issue_by_jql`, or
`client.search_cursor`; ADF-shaped reads and writes hang off `client.v3()`. Enhanced search is not a drop-in for the
legacy helpers: it paginates by opaque `nextPageToken` rather than `startAt` and returns no total, so port to `search`
rather than wrapping it behind the old signature. The project-search models are types only — no client method sends
them yet, so `get_projects` is still the sole project listing this SDK calls. See the official
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

The repo keeps the standard ThreatFlux Rust template tooling:

```bash
make dev-setup
make docs-check
make fmt
make lint
make test
make sbom
make ci
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

Its deduplication step runs on enhanced search: it builds a `SearchRequest` and walks `client.search_cursor` against
`POST /rest/api/3/search/jql`, so it no longer touches the legacy `/rest/api/2/search` route or inherits that
endpoint's removal risk. Issue creation goes through `client.v3()` against the supported direct issue endpoint.

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

Only an allowlisted name is expanded. `JIRA_PROJECT_KEY`, `JIRA_ASSIGNEE_ACCOUNT_ID` and
`JIRA_DESCRIPTION` are allowed by default; any other name fails the config load, whether or not the
variable is set. A workflow opts additional names in by setting
`THREATFLUX_CONFIG_ENV_ALLOWLIST` to a comma-separated list in the step environment, for example
`THREATFLUX_CONFIG_ENV_ALLOWLIST: TEAM_LABEL,SERVICE_TIER`. The opt-in lives in the workflow, not in
the config file, so a config proposed by a pull request cannot widen it. Credential-shaped names such
as `JIRA_API_TOKEN` or `GITHUB_TOKEN` stay refused even when they are opted in.

### Reconciliation, migration, and dedupe identity

Per-rule keys decide what happens when a delivery reconciles to a Jira issue that already exists, and how
issues labelled by an earlier scheme are still found. They are per rule rather than action inputs because
one GitHub event can match several rules routing to different projects, and those rules do not have to
agree on a policy.

**Part of this surface is schema that arrives ahead of its behaviour, and the loader refuses the part that
is not wired yet.** What ships today is the dedupe identity and the lookup that reads it. The keys that
decide what to *write* onto an issue that already exists — `on_existing` beyond its default, and the whole
`migration` block — are parsed and validated and then rejected, with an error naming the milestone they
arrive in. They are rejected rather than accepted-and-ignored on purpose: a consumer who is told a key is
not implemented yet edits their config, while a consumer who believes every duplicate delivery is being
commented onto its Jira issue, and is wrong, finds out only when somebody asks why the audit trail is
empty. Nothing consumes these keys in any released version, so nothing that works today is refused.

A config that names none of these keys behaves exactly as it did before, with one exception —
`dedupe.identity`, called out below.

#### What ships today

```yaml
# An excerpt of one rule; `when`, `extract` and the rest of `jira` are as in the example above.
rules:
  - id: dependabot-high-issues
    jira:
      dedupe:
        strategy: sha256
        identity: repo_issue
        label_prefix: dependabot-alert
        fields:
          - repository.full_name
          - issue.title
```

`jira.dedupe.identity` is the one default that is not the old behaviour, because the identity scheme itself
changed. `repo_issue` labels an issue `{label_prefix}-gh-{repository_id}-{issue_number}`: one Jira issue per
GitHub issue, stable when the GitHub issue is retitled. `fields` keeps the `0.4.x` content grouping, a
digest over `dedupe.fields`. The difference runs both ways, and the second direction is the one to plan for:
retitling a GitHub issue no longer mints a second Jira issue, but two different GitHub issues that share a
title in one repository no longer collapse onto one Jira issue either. For a feed that reuses titles across
dependency bumps that is a permanent increase in ticket volume. `identity: fields` is the opt-out for a
consumer who wants title-level grouping on purpose, and it is live: it decides both the label a rule writes
and the label it looks up, so the two can never disagree.

`dedupe.fields` stays required under either identity: it defines the SHA-256/12 rung the lookup registers
on its own, in the same query as the canonical label, which is how issues an earlier release created keep
being found instead of being duplicated on the first delivery after an upgrade. Under `identity: fields`
that rung and the canonical label are the same string, so the query carries it once.

#### Accepted by the schema, rejected until a later milestone

Setting any of these fails the config load today. The error names the key and the milestone.

<!-- BEGIN ACTION_CONFIG_GATED_KEYS -->
| Key | Rejected until |
|---|---|
| `on_existing` | M4 |
| `update.when_resolved` | M4 |
| `migration.adopt` | M4 |
| `migration.summary_fallback` | M4 |
| `migration.legacy_labels` | M4 |
<!-- END ACTION_CONFIG_GATED_KEYS -->

`on_existing` will be what the rule does with an issue it finds instead of creating one. `noop` — the
default, and the only value that loads today — writes nothing and reports the delivery as deduped, which is
what every release so far does. `update` will rewrite the issue's fields from the rule's templates,
`comment` will add a comment, and `update_and_comment` will do both.

`update.when_resolved` bounds that policy, and is rejected on the same terms: the only thing it modifies is
`on_existing`, so a config that set it would be choosing between two behaviours neither of which runs today.
It will cover the case that makes an untended rule go quiet: a Jira issue closed months ago
still carries its dedupe label, so it still matches, so every later delivery for the same identity is
silently deduped onto something nobody is reading. `skip` is today's behaviour and stays the default.
`reconcile` will apply `on_existing` to the resolved issue anyway, so the delivery is recorded rather than
dropped. There is deliberately no value that creates a second issue: both issues would carry the same
identity label, and the duplicate election would then have to undo it.

`migration.adopt` will write the canonical label onto an issue that was found through a legacy label.
Without it the legacy rungs never retire — every future delivery keeps finding the issue the old way — so
leaving it off makes the migration permanent rather than gradual. Adoption changes the issue's identity
label and nothing a reader sees, which is why it is governed here rather than by `on_existing`.

`migration.summary_fallback` will also look for an issue by its exact summary, for issues created before
any dedupe label existed. It will stay off by default because `summary ~ "..."` is a Lucene text match that
will happily return a different issue sharing words with this one; when it is on, a summary-only match is
kept only if the summary is byte-for-byte the one this rule renders.

`migration.legacy_labels` will declare label formats to recognise, in precedence order, in addition to the
two the lookup registers on its own — the canonical label and the SHA-256/12 label this Action wrote
through `0.4.x`. Those two need no configuration and are queried today. Every parameter of the hashed
preimage is a key because none of them can be inferred from a label string, and a wrong guess in a release
costs a release cycle where a wrong guess here costs an edit. Declare a format only against real label
strings and the events that produced them; a format that is close but not exact matches nothing, and
nothing is what a missed match looks like.

A format can still be worked out today, and should be: the `dedupe-label` subcommand takes a candidate
format on the command line rather than from the config, prints every label the ladder would ask for and the
exact JQL it would ask with, and touches no network. Run a candidate against a real delivery and a real
Jira label until they match, then keep it for M4. See the Action's README for the invocation.

The shape those keys take when they land:

```yaml
# Every key in this block fails the config load today. It is the schema M4 will read.
rules:
  - id: dependabot-high-issues
    on_existing: update_and_comment
    update:
      when_resolved: reconcile
    migration:
      adopt: true
      summary_fallback: false
      legacy_labels:
        - id: acme-sha256-16
          digest: sha256
          hex_chars: 16
          fields:
            - repository.full_name
            - issue.title
          label_prefix: jira-automation
          separator: "-"
          joiner: "\n"
          preimage_prefix: excluded
```

| Legacy entry key | Meaning | Default |
|---|---|---|
| `id` | Name this format is reported under; unique within the rule | required |
| `digest` | Hash the preimage is run through | required |
| `hex_chars` | Leading hex characters of the digest the label keeps | required |
| `fields` | Event field paths, in the order the preimage joins them | required |
| `label_prefix` | Prefix the label starts with | `jira.dedupe.label_prefix` |
| `separator` | Text between the prefix and the truncated digest | `-` |
| `joiner` | Text the preimage values are joined with | a newline |
| `preimage_prefix` | Whether, and where, the prefix joins the preimage | `excluded` |

#### The values each key admits

Every key that takes a fixed set of values takes exactly these. A value outside the set fails the config
load naming the set; a value inside the set that belongs to a key in the table above fails the config load
naming the milestone.

<!-- BEGIN ACTION_CONFIG_VALUES -->
| Key | Accepted values | Default |
|---|---|---|
| `on_existing` | `noop`, `update`, `comment`, `update_and_comment` | `noop` |
| `update.when_resolved` | `skip`, `reconcile` | `skip` |
| `jira.dedupe.identity` | `repo_issue`, `fields` | `repo_issue` |
| `migration.legacy_labels[].digest` | `sha1`, `sha256` | required |
| `migration.legacy_labels[].preimage_prefix` | `excluded`, `first`, `last` | `excluded` |
<!-- END ACTION_CONFIG_VALUES -->

Both tables are compared against `crates/threatflux-atlassian-action/src/config.rs` by
`scripts/check_docs.py`, in both directions, so a key cannot be documented as working while the loader
rejects it, or documented as rejected while the loader accepts it.

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
