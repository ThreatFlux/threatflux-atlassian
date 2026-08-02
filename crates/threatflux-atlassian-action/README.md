# threatflux-atlassian-action

Config-driven GitHub Action runtime for Jira automation, built on top of
`threatflux-atlassian-sdk`.

This independent project is not affiliated with, endorsed by, or sponsored by Atlassian.

This crate is the executable behind the repo's root [action.yml](../../action.yml)
and is intended to:

- load a repo-local YAML automation config
- parse GitHub event payloads
- evaluate narrow Jira automation rules
- dedupe against existing Jira issues
- create Jira issues through the shared Atlassian SDK

> [!WARNING]
> Deduplication currently calls the SDK's legacy `search_issues` helper and inherits Atlassian's removal of
> `GET /rest/api/2/search`. Issue creation uses the supported direct issue endpoint. Before adopting this Action for new
> automation, plan replacement of deduplication with enhanced `/rest/api/2/search/jql`; see Atlassian's
> [issue-search reference](https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/).

See the repository [usage guide](../../docs/USAGE.md#github-action-usage) for required variables, inputs, outputs, and a
complete consumer workflow.

## License

Licensed under the [MIT License](../../LICENSE).
