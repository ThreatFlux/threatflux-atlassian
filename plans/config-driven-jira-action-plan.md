# Config-Driven Jira Action Plan

## Goal

Build a reusable GitHub Action in `threatflux-atlassian` that turns GitHub events into Jira issue automation through a repo-local YAML config and environment-driven credentials, so repos stop duplicating inline bash/Python workflows.

## Scope

### In scope

- Add a first-class GitHub Action to this repo.
- Support the current Dependabot-created GitHub Issue to Jira Issue flow as the initial feature.
- Drive behavior from a committed repo-local config file plus GitHub env/secrets.
- Keep Jira transport and auth in `threatflux-atlassian-sdk`.
- Add a thin automation layer that handles:
  - GitHub event loading
  - rule matching
  - severity extraction
  - dedupe lookup
  - Jira payload rendering
  - dry-run and observable outputs

### Out of scope

- Rebuilding the low-level SDK around a generic workflow engine.
- Replacing every Jira automation pattern in one pass.
- Moving this logic back into per-repo Python scripts.
- Solving non-GitHub event sources in V1.

## Current State

- `threatflux-atlassian-sdk` already supports Jira auth, issue search, and issue creation.
- `threatflux-atlassian-cli` already exposes generic Jira operations but not GitHub-event-aware automation.
- There is no `action.yml`, no action crate, and no reusable automation config layer in this repo today.
- The current Dependabot-to-Jira workflow shape exists as inline workflow logic in consumer repos, with repo variables/secrets such as:
  - `JIRA_BASE_URL`
  - `JIRA_EMAIL`
  - `JIRA_API_TOKEN`
  - `JIRA_PROJECT_KEY`
  - `JIRA_ASSIGNEE_ACCOUNT_ID`

## Crates Affected

- `crates/threatflux-atlassian-sdk`
  - keep as the Jira client and shared types layer
- `crates/threatflux-atlassian-cli`
  - optional follow-up only if we want to expose config validation or dry-run locally
- new `crates/threatflux-atlassian-action`
  - GitHub Action entrypoint and automation logic

## Files To Modify

- `Cargo.toml`
  - add the action crate to the workspace and shared dependencies needed for config/event parsing
- `README.md`
  - document the new action, required env/secrets, and consumer usage
- `docs/USAGE.md`
  - add a focused automation section with example repo config and workflow usage
- `crates/threatflux-atlassian-sdk/src/types.rs`
  - only if needed to support richer Jira payload fields or explicit action-side metadata helpers
- `crates/threatflux-atlassian-sdk/src/client.rs`
  - only if action requirements expose a real SDK gap, such as cleaner dedupe search helpers or optional Jira v3/ADF support

## Files To Create

- `action.yml`
  - published action interface
- `crates/threatflux-atlassian-action/Cargo.toml`
  - manifest for the new action crate
- `crates/threatflux-atlassian-action/src/main.rs`
  - action entrypoint
- `crates/threatflux-atlassian-action/src/config.rs`
  - YAML config parsing and validation
- `crates/threatflux-atlassian-action/src/github.rs`
  - `GITHUB_EVENT_PATH` loading and typed GitHub event extraction
- `crates/threatflux-atlassian-action/src/rules.rs`
  - rule matching, severity extraction, and dedupe key logic
- `crates/threatflux-atlassian-action/src/jira.rs`
  - Jira field rendering and create/search orchestration through the SDK
- `examples/github-automation/dependabot-high.yml`
  - starter config matching the current use case
- `examples/workflows/dependabot-jira.yml`
  - minimal consumer workflow wrapper example
- `plans/config-driven-jira-action-plan.md`
  - this plan

## Proposed Consumer Shape

### Repo workflow

Consumer repos should keep a minimal trigger workflow, for example:

- trigger on `issues: opened`
- keep `permissions: {}`
- checkout the repo
- run the shared action

That leaves event-specific trigger ownership in the consuming repo while centralizing the Jira logic in the shared action.

### Repo config

Recommended config path:

- `.github/threatflux/jira-automation.yml`

The config should stay intentionally narrow in V1 and describe:

- event matcher
- actor matcher
- severity extraction
- Jira project and assignee defaults
- priority mapping
- summary/description templates
- labels
- dedupe strategy

### Repo env/secrets

The action should rely on org/repo GitHub variables and secrets instead of hardcoded values:

- `JIRA_BASE_URL`
- `JIRA_EMAIL`
- `JIRA_API_TOKEN`
- optional repo/org vars:
  - `JIRA_PROJECT_KEY`
  - `JIRA_ASSIGNEE_ACCOUNT_ID`

## Proposed V1 Config Shape

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
        regex: '(?mi)^severity:\\s*(high|critical)\\b'
    jira:
      project_key: ${JIRA_PROJECT_KEY:-KAN}
      issue_type: Bug
      assignee_account_id: ${JIRA_ASSIGNEE_ACCOUNT_ID}
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
        strategy: sha1
        fields:
          - repository.full_name
          - issue.title
```

## Key Design Decisions

1. Keep the SDK clean.
   - GitHub event parsing, regex matching, template rendering, and dedupe policy belong in the action crate, not in the low-level Jira client.

2. Prefer config plus env over action inputs for business fields.
   - Action inputs should stay small and operational, such as `config-path`, `dry-run`, and `log-level`.
   - Jira project, assignee, labels, and templates should live in repo config.
   - Credentials and cross-repo defaults should stay in GitHub vars/secrets.

3. Start with a narrow rule engine.
   - V1 should support the current Dependabot issue flow well.
   - It should not become a second workflow language.

4. Use the existing SDK create/search path first.
   - The SDK currently models Jira issue creation around plain-text descriptions and Jira v2 endpoints.
   - V1 should standardize on that existing path unless there is a clear requirement to add Jira v3 ADF support inside the SDK.
   - If ADF becomes necessary, add it deliberately as an SDK enhancement rather than bolting raw HTTP logic into the action crate.

## Approach

1. Add a new action crate to the workspace.
   - Keep dependencies focused on `serde`, `serde_yaml`, `serde_json`, `regex`, `sha1` or `sha2`, and the existing SDK.

2. Define the action interface.
   - Create root `action.yml`.
   - Recommended inputs:
     - `config-path`
     - `dry-run`
     - `log-level`
   - Recommended outputs:
     - `matched-rule-id`
     - `created`
     - `jira-issue-key`
     - `deduped`
     - `severity`

3. Load GitHub event data from the runner.
   - Read `GITHUB_EVENT_NAME`, `GITHUB_EVENT_PATH`, and core GitHub environment variables.
   - Parse only the event shapes V1 needs:
     - `issues`
     - specifically `action=opened`

4. Load and validate repo config.
   - Read `.github/threatflux/jira-automation.yml` by default.
   - Validate required fields early and fail with actionable error messages.

5. Evaluate rules.
   - Match on event name, action, and actor.
   - Run severity extraction against `issue.body`.
   - Stop cleanly with `created=false` if no rule matches or no severity is extracted.

6. Compute dedupe state.
   - Build a stable label or search key from configured fields.
   - Search Jira through the SDK before creating a new issue.
   - Exit successfully with `deduped=true` if a matching issue already exists.

7. Render Jira fields and create the issue.
   - Render summary, description, labels, issue type, assignee, and priority from config plus extracted context.
   - Use env-backed Jira credentials and defaults.
   - Emit a created Jira key as an action output.

8. Document the adoption path.
   - Replace the current inline shell/Python workflow in consumer repos with:
     - a minimal trigger workflow
     - a repo-local config file
     - shared org/repo vars and secrets

## Testing Strategy

- Unit tests for config parsing and validation.
- Fixture-based tests for GitHub issue event parsing.
- Rule-matching tests for:
  - matching Dependabot actor
  - extracting `high` and `critical`
  - ignoring non-matching issue bodies
- Dedupe tests using mocked Jira search responses.
- End-to-end action tests using a fixture event plus a mocked Jira server.
- `actionlint` validation for the consumer example workflow.

## Risks

- If the rule schema grows too broad, the action will become hard to reason about and hard to test.
- Jira field variability across projects can push too much behavior into config if the schema is not kept narrow.
- Consumer repos still own the trigger event, so unsupported events must fail clearly rather than half-work.
- If we later need Jira v3 ADF descriptions, that should be added once in the SDK rather than patched around in the action.

## Open Questions

- Should V1 ship only as a direct action (`uses: ThreatFlux/threatflux-atlassian@vX`) or also include a reusable workflow wrapper?
- Do we want to support both plain-text Jira descriptions and ADF in config, or standardize on plain text first?
- Should the action expose a local CLI-compatible dry-run mode for debugging outside GitHub Actions?
- Should dedupe use only labels in V1, or also allow configurable JQL templates later?
