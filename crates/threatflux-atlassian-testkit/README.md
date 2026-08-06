# threatflux-atlassian-testkit

Dev-only test infrastructure for the `threatflux-atlassian` workspace. It is a workspace member so
that fixtures and harnesses are shared by the SDK, the CLI and the Action test suites, and it is
`publish = false` so it never reaches crates.io or a consumer's dependency graph.

Depend on it by path, with no `version` field, so `cargo publish` strips the entry:

```toml
[dev-dependencies]
threatflux-atlassian-testkit = { path = "../threatflux-atlassian-testkit" }
```

## Modules

| Module | Purpose |
|---|---|
| `fixtures` | GitHub `issues` deliveries, Action YAML configs and Jira response bodies, embedded with `include_str!` so they resolve regardless of the test's working directory |
| `jira_mock` | `JiraMock` over `wiremock`, with per-attempt response scripting and a request journal for exact call-count assertions |
| `golden` | Semantic JSON comparison with a pointer-path diff |
| `redaction` | `SecretScanner`, which checks four encodings of every secret |
| `logs` | Captures `tracing` output into a buffer |
| `gha` | Re-parses GitHub's `GITHUB_OUTPUT` key/value and `<<DELIM` heredoc grammar |
| `env` | Scoped environment variables that restore on drop |
| `net` | Loopback addresses, including a port that is guaranteed to refuse connections |
| `sleeper` | `RecordingSleeper`, which records requested delays and returns immediately |

## Fixtures

Fixture payloads are byte-exact. `.gitattributes` marks `fixtures/**` as binary because at least one
delivery carries CRLF on purpose and Windows is in the CI matrix, where `core.autocrlf` would
otherwise rewrite it on checkout.

Every GitHub event fixture carries `issue.id`, `issue.number`, `issue.node_id` and `repository.id`.
Event identity is keyed off those fields, so a fixture without them cannot be used to test
reconciliation.
