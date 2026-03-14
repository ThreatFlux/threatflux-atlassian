# threatflux-atlassian-action

Config-driven GitHub Action runtime for Jira automation, built on top of
`threatflux-atlassian-sdk`.

This crate is the executable behind the repo's root [action.yml](../../../action.yml)
and is intended to:

- load a repo-local YAML automation config
- parse GitHub event payloads
- evaluate narrow Jira automation rules
- dedupe against existing Jira issues
- create Jira issues through the shared Atlassian SDK
