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

> [!NOTE]
> Deduplication runs on enhanced search. It builds a `threatflux_atlassian_sdk::search::SearchRequest` and walks
> `client.search_cursor` against `POST /rest/api/3/search/jql`, so it no longer calls the SDK's legacy `search_issues`
> helper and does not inherit Atlassian's removal of `GET /rest/api/2/search`. That replacement — the enhanced
> `/rest/api/2/search/jql` route Atlassian's own guidance points at, which this SDK models on its v3 spelling — has
> already landed; nothing is left for an adopter to plan. Issue creation goes through `client.v3()` against the
> supported direct issue endpoint. The SDK's legacy `search_issues`, `get_project_issues`, and `get_projects` helpers
> still exist and are still deprecated by Atlassian; this Action calls none of them. See Atlassian's
> [issue-search reference](https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/).

See the repository [usage guide](../../docs/USAGE.md#github-action-usage) for required variables, inputs, outputs, and a
complete consumer workflow.

## `dedupe-label` — check the dedupe ladder before you cut over

Given no arguments the binary is the Action, which is how a GitHub runner invokes it. Given `dedupe-label` it is instead a
read-only validator: it prints every label the dedupe lookup would ask for and the exact JQL it would ask with, for one
real GitHub event payload and one real automation config. It reads those two files and prints. It opens no network
connection, reads no Jira credential, and changes nothing.

```console
$ threatflux-atlassian-action dedupe-label \
    --config .github/threatflux/jira-automation.yml \
    --event  event.json
```

The point is the *legacy* rungs. The canonical label is one this crate writes and can therefore prove; every legacy rung
is a guess about a scheme some earlier generation of routing scripts used, and its parameters — digest, truncation, field
order, joiner, separator, and whether the label prefix is part of the hashed preimage — are not recoverable from this
repository. They are configuration for that reason. Describe a guess with `--legacy`, run the printed query against your
own Jira, and correct a wrong guess with an edit instead of a release cycle:

```console
$ threatflux-atlassian-action dedupe-label \
    --config .github/threatflux/jira-automation.yml \
    --event  event.json \
    --legacy 'id=acme-sha1-12;digest=sha1;hex=12;fields=repository.full_name,issue.title;joiner=|;preimage-prefix=first'
```

The scheme this Action shipped through `0.4.x` is registered automatically and never has to be declared. Run
`threatflux-atlassian-action dedupe-label --help` for the remaining options (`--event-name`, `--rule`,
`--summary-fallback`) and the full `--legacy` grammar.

## License

Licensed under the [MIT License](../../LICENSE).
