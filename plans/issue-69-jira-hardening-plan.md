# Issue #69 Implementation Plan — Jira Cloud v3, ADF, Idempotent Reconciliation, Secret Safety

## Summary

Issue #69 asks to harden `threatflux-atlassian` so the SDK and GitHub Action can replace duplicated
per-repo Jira routing scripts without regressing on Jira Cloud v3/ADF formatting, dedupe
compatibility, retries, or secret handling. Concretely: migrate the Jira surface from v2 to v3 with
typed ADF, adopt enhanced JQL search with page-token pagination, add `on_existing` reconciliation
with stable event identity and legacy dedupe-label recognition, apply the retry configuration that
already exists but is dead, redact secrets and Jira response bodies from logs and errors, host-validate
credential destinations, digest-pin container bases, and fix the source/tag/release version contract.
The issue estimates 16–25 engineer-days. This plan puts the honest figure at **72.5**, and explains
where the gap comes from.

Audited against `main` @ `9210b76`. Every line reference below was read at that commit; the only
change to `main` since is #70 (Makefile restoration), which touches no Rust source.

## Audit Corrections

The audit in #69 is unusually accurate. Every claim under **Secret and output handling** and
**Release identity** is CONFIRMED against source, and most of the rest is too. Six claims need
correcting before work starts, and nine material findings are missing from the issue entirely.

### Issue claims that are not fully accurate

| Claim | Status | Evidence |
|---|---|---|
| "Existing consumers use Jira v3 and Atlassian Document Format." | UNVERIFIABLE | No consumer code is in this repo. What is verifiable: this workspace has zero v3 or ADF support. `grep -i adf` over `crates/**/*.rs` hits only the rejection test at `action/config.rs:520`. `lib.rs:96` pins `API_VERSION = "2"`, asserted by a test at `lib.rs:113-115`. |
| "The Action's SHA-256/12 dedupe label is incompatible with existing SHA-256/16 and SHA-1/12 labels." | PARTIALLY TRUE | The SHA-256/12 half is exact: `rules.rs:147-153` is `Sha256` → hex → `&digest[..12]`, prefix default `jira-automation` (`rules.rs:136-141`). The two **legacy** formats are not verifiable here — `sha1` appears in the whole workspace exactly once, in a config *rejection* test (`action/config.rs:583`), with no `sha1` dependency and no reference in `docs/`, `examples/`, or `.github/`. See open question Q1. |
| "Replayed or concurrent deliveries can create duplicate issues or comments." | PARTIALLY TRUE | Concurrency is confirmed — `lib.rs:134-143` is plain check-then-act with no lock, property, or post-create re-search. **Replay is not**: `compute_dedupe_label` is pure over event fields, so an identical replayed payload dedupes correctly today. The real duplicate driver is that every shipped config hashes `issue.title` (`docs/USAGE.md:240-246`, `examples/github-automation/dependabot-high.yml:34`), so *retitling* a GitHub issue creates a second Jira issue — a mutable-identity bug. "or comments" is vacuous: the Action never posts a comment. |
| "Writes need method-aware reconciliation rather than blind retries." | PARTIALLY TRUE | Directionally right, but there is no blind-retry behaviour to replace — nothing retries at all (`client.rs:171` is a single `send()`). The concrete hazard is different: `create_issue` (`client.rs:444-458`) is POST-then-GET, so a transport retry around `make_request` would double-create, and `add_issue_attachment` (`client.rs:362-393`) bypasses `make_request` entirely. |
| Acceptance criterion 14 implies Wiremock is greenfield. | FALSE | `Cargo.toml:41` already declares `wiremock = "0.6"`; `sdk/Cargo.toml:45` dev-depends on it; `client.rs:1017/1109/1192/1231/1261` are five working `MockServer` HTTP tests over loopback. Only the **Action** wiring is missing (`action/Cargo.toml:26-27` dev-deps = `serial_test` only). |
| Implied: the Action cannot be pointed at a mock server. | FALSE (today) | `lib.rs:79-90` reads `JIRA_URL`; `config.rs:227-229` honours `JIRA_VERIFY_SSL`; `config.rs:179` only rejects non-HTTPS `&& self.verify_ssl`. `JIRA_URL=http://127.0.0.1:PORT` + `JIRA_VERIFY_SSL=false` works right now with zero source changes. The obstacle is that #69's own TLS hardening deletes exactly this path — see risk R3. |

### Confirmed but understated

| Claim | Understatement |
|---|---|
| "`JIRA_VERIFY_SSL=false` permits unsafe TLS behavior." | It also drops the HTTPS requirement. `config.rs:179` gates the scheme check on `&& self.verify_ssl`, so `JIRA_VERIFY_SSL=false` + `JIRA_URL=http://attacker.example` passes `validate()` and sends `Authorization: Basic <base64(user:token)>` in cleartext. The parse at `config.rs:228` is also neither trimmed nor strict — `" false"`, `"0"`, `"no"` all mean *enabled*. |
| "Retry classification is inconsistent because many Jira 5xx responses are converted to a non-retryable error variant." | Three axes, not one. (a) `client.rs:134-137` routes all 5xx into `JiraApi`, which `is_retryable()` (`error.rs:163-169`) does not match. (b) `From<reqwest::Error>` (`error.rs:181-188`) only calls `err.status()`, never `is_timeout()`/`is_connect()`, so timeouts and connection failures become `Http{status_code: None}` → non-retryable. (c) `AtlassianError::Timeout` is never constructed in production code (only `error.rs:240`, a test). Net: only a 429 is classified retryable, and nothing retries anyway. |
| "Source `main` declares `0.4.2` while releases/tags reach `v0.4.3`." | The drift is in the **tag**. `git show v0.4.3:Cargo.toml` also reports `0.4.2` — tag `v0.4.3` points at merge commit `1c820b3`, whose tree was never bumped. Neither `0.4.3` nor `0.4.0` was ever published to crates.io (only `0.4.1` and `0.4.2` exist there). Four divergent identities: source `0.4.2`, tag `v0.4.3`, release `v0.4.3`, registry `0.4.2`. Root cause is mechanical: `release.yml:62-77` never compares the tag to the manifest, and `release.yml:105-120` calls `gh release create` with no `--target`. |
| "Extracted values written to `GITHUB_OUTPUT` need CR/LF-safe encoding." | Encoding alone is insufficient — see NF2 below. |
| Existing tests `config::tests::test_retryable_error_detection` and `error::tests::test_retryable_errors` cover classification. | FALSE. Both (`config.rs:703-710`, `error.rs:232-249`) assert on hand-built error values and never drive a response through `ensure_success`. The `Http{Some(500)}` case they assert is a variant `ensure_success` never produces; the `Timeout` case is a variant nothing constructs. No wiremock test mounts a 429 or any 5xx. |

### Material findings not in the issue

| # | Finding | Evidence | Impact |
|---|---|---|---|
| NF1 | **None of `action.yml`'s five inputs reach the binary.** GitHub sets container-action inputs as `INPUT_` + name uppercased with *spaces* (only) replaced by `_`; hyphens are preserved. | `action.yml:5,9,13,17,20` declare `config-path`/`dry-run`/`log-level`/`event-name`/`event-path`; `lib.rs:46,48,54,58,93` read `INPUT_CONFIG_PATH`/`INPUT_DRY_RUN`/… All tests set the underscore names directly (`lib.rs:292-296`), so CI is green. | `with: dry-run: true` is silently ignored and the Action calls Jira for real; a custom `config-path` is ignored. **Blocks the dry-run canary in acceptance criterion 15.** Fix first. |
| NF2 | **Secret exfiltration via config env expansion.** `action/config.rs:86-105` walks every string in the parsed YAML and `expand_env_vars_in_string` (`:107-129`) substitutes `${[A-Z0-9_]+}`. `JIRA_API_TOKEN` matches and is in the process env (`lib.rs:84-85`). | A repo-local config with `id: "${JIRA_API_TOKEN}"` flows into `rule.id` → `rules.rs:50` → `ActionOutcome.matched_rule_id` (`lib.rs:127`) → `GITHUB_OUTPUT` (`lib.rs:203-207`), and via `jira.summary`/`description` into the created Jira issue. | Safe output *encoding* does not fix this. Needs a name denylist. **Privilege qualifier:** the sink requires writing `.github/threatflux/jira-automation.yml` in the checked-out tree, and the Action handles only `issues` events, whose checkout is the default branch — so this needs repo **write** access, not a fork-PR primitive. It is a privilege-escalation / insider path, not an anonymous one. Rank it **below NF1 and NF3** in the fix-first ordering; the fix is still cheap and lands in M0 with F4 regardless. |
| NF3 | **`create_issue` loses the key on read-back failure.** `client.rs:444-458` POSTs then separately GETs; `CreateIssueResponse` (`client.rs:22-25`) discards `id` and `self`. | A failing follow-up GET returns `Err` for an issue that *was* created. `lib.rs:69` then propagates before `write_outputs` at `:70`. | A workflow reports a failed step with empty outputs for an issue that exists — and a re-run creates a duplicate. This is a live duplicate-creation path today, with no retry involved. |
| NF4 | **Closed-issue suppression.** `jira.rs:62-68` emits only `project = "X" AND labels = "Y"` with no status/resolution filter. | Sole JQL builder in the crate. | A Jira issue closed months ago still matches its label and permanently silences a genuinely new alert with the same identity. |
| NF5 | **`scripts/check_docs.py` blocks the v3 migration.** `check_legacy_jira_guidance` (`:208-233`) *hard-requires* the literals `/rest/api/2/search`, `/rest/api/2/search/jql`, `/rest/api/2/project`, `/rest/api/2/project/search` in five documents; `ci.yml:244` makes it a blocking gate. `check_features` (`:259-268`) requires the SDK README FEATURES table to match `Cargo.toml [features]` exactly **and in order**. | Any v3 doc change turns CI red unless the checker changes in the same PR; every new cargo feature is a two-file atomic change plus a doubled `cargo hack --feature-powerset` matrix (`ci.yml:223`). |
| NF6 | **`Url::join` silently drops a context path and permits traversal.** `client.rs:149-152` does `base_url.join(endpoint.trim_start_matches('/'))`. | Base `https://h/jira` + `rest/api/2/issue/K-1` → `https://h/rest/api/2/issue/K-1`. `join("rest/api/3/issue/K-1/../../admin")` → `https://h/rest/api/3/admin`. | Data Center users are silently broken today; unencoded issue keys can escape the API path. |
| NF7 | **Clippy backlog is ~3x smaller than assumed.** Measured with `--force-warn` plus CI's own `-A` list: SDK lib **168** (92 auto-fixable, ~95 remaining after CI's allows), SDK lib tests **+1**, CLI bin **8**. | `sdk/src/lib.rs:70` and `cli/src/main.rs:1`. | Removing the blanket allow is a **1-day** job, not a multi-day cleanup. It should land **first**, so all new code is written linted. |
| NF8 | **`tokio`'s `time` feature is only transitively enabled.** Workspace `Cargo.toml:35` is `["fs","macros","rt-multi-thread","sync"]`; `time` arrives via reqwest/hyper. | `cargo tree -e features`. | `tokio::time::sleep` compiles today by feature unification alone; `cargo hack --feature-powerset --no-dev-deps` (`ci.yml:223`) can break it. Declare it explicitly before any retry work. |
| NF9 | **Jira's 255-char `summary` cap is already exceeded by the shipped template.** `action/jira.rs:26-29` renders `jira.summary` and rejects only the *empty* case — there is no length cap anywhere. Jira Cloud caps `summary` at 255 characters; GitHub issue titles run to 256; the shipped template `"[Dependabot][{{ severity_title }}] {{ issue.title }}"` (`docs/USAGE.md`, `examples/github-automation/dependabot-high.yml`) prepends roughly 20 more. | `jira.rs:26-29` vs the rendered template. | A long Dependabot title is a guaranteed Jira 400 **today**, with no code change required to trigger it and no ADF involvement. Same family as B's output-bounding regression but a live production failure rather than an introduced one. Owned by B6 (char-boundary-safe truncation, cap configurable, default 255) with a >255-char title added to G2's hostile corpus. |

Two things the audit worried about that are already handled: `.github/dependabot.yml:52-64` already
declares the `docker` ecosystem at `/`, and dependabot-core's Docker fetcher matches any filename
containing `dockerfile` case-insensitively, so `action.Dockerfile` digest bumps will be automated
(verify on the first run after pinning). And `wiremock` is already proven in-tree (see above).

Everything else in the issue — v2 endpoints, plain-text descriptions, legacy search, caller-managed
pagination, dead retry config, discarded `Retry-After`, response bodies in logs and errors,
unredacted `Debug`/`Serialize` on config and token types, no host allowlist, unsafe `GITHUB_OUTPUT`
writes, tag-pinned Docker bases, first-rule-only routing, no-op on existing issues, no summary
fallback, and the broad Clippy suppression — is CONFIRMED as written.

## Workstreams

Seven workstreams. Several independent designs converged on the same code, so ownership is assigned
once and the duplicates are struck; the merges are noted inline because they are the reason this plan
is smaller than the sum of its parts.

### A — Jira v3 endpoints and transport seam

Additive `pub mod v3` reached via `client.v3()`, **not** a runtime `ApiVersion` enum and **not** an
in-place flip. A version enum only works if every return type becomes a union, and `POST /search/jql`
(`issues`/`nextPageToken`/`isLast`) shares no shape with `GET /search` (`issues`/`total`/`startAt`/
`maxResults`). An in-place flip would break `IssueFields`, `IssueSearchResult`, the CLI
(`main.rs:338,366,400`), both examples, and `remote_client.rs`. Freezing `types.rs` and adding a lean
parallel model keeps all of them compiling.

**v3 is compiled unconditionally — no new cargo feature.** A feature would double the
`cargo hack` powerset and force a `check_docs.py` FEATURES-table edit for no isolation benefit (NF5).

`Transport` extraction (A1) is the sequencing keystone: A, E-retry and F-security would otherwise each
rewrite the same 60 lines (`client.rs:108-172`). Landing it once converts a guaranteed three-way
conflict into three additive extensions, and fixes NF6 in one place instead of adding eight more
`format!("/rest/api/3/...")` strings.

`JiraV3::create_issue` deliberately does **not** re-GET (fixes NF3), and `V3IssueFields` has every
field `Option`/`#[serde(default)]` — empirically, today's `IssueFields` fails with
`missing field 'issuetype'` on any narrowed `fields=` response, which otherwise blocks the issue's
"configurable fields" requirement outright.

`get_comments` is not optional garnish: D6's comment-marker scan and E5's comment probe both read the
comment list on an already-known issue key, and doing that through the surviving v2
`get_issue_comments` (`client.rs:266`) would parse v3 ADF comment bodies with a v2 string reader —
the same class of failure the description work exists to prevent. It is also the **Strong**-consistent
probe that makes comment replay safe (see E and the probe-consistency table).

| Task | Est. | Depends on |
|---|---|---|
| A1 — Extract `pub(crate) Transport`; `build_url` via `path_segments_mut()` (percent-encoded per segment); route all 18 v2 endpoints and `add_issue_attachment` through it; `Idempotency::{Safe,UnsafeWrite}` tag for E-retry to read | 1.5 | — |
| A3 — `client.v3()` → `JiraV3::{create_issue, update_issue, get_issue}`; `V3CreateIssueFields` with `skip_serializing_if` on every optional (fixes the current unconditional `"parent": null`, which Jira rejects on non-subtask types); `BTreeMap` custom fields for deterministic snapshots; lean all-optional `V3IssueFields` | 2.0 | A1, B1, B2 |
| A5 — v3 comments **both directions** — `JiraV3::add_comment` and `JiraV3::get_comments` (paginated), `RichText` bodies on read *and* write so v2-era string bodies still parse; issue properties: `get` (404 ⇒ `Ok(None)`), `set` (**PUT**, path `/properties/{key}`), `delete`, `list`; `IssuePropertyKey` newtype (≤255 chars); distinguish 200-updated from 201-created | 1.5 | A1, A3 |
| A6 — Deprecate `API_VERSION` (`lib.rs:96`) and retarget the assertion at `lib.rs:113-115`; rewrite `check_legacy_jira_guidance` (NF5) and the five documents whose `/rest/api/2` literals it hard-requires; update the crate-header legacy-endpoint note (`lib.rs:35-37`). **The three search-method deprecations and every call site belong to C6, not here** | 1.0 | A3, A5, C6 |

Struck as duplicates: **A2** (ADF core types) → owned by B1. **A4** (enhanced-search models) → owned
by C3; the thin `/project/search` model folds into C3 for canary preflight only, with no iteration —
nothing in this repo resolves projects. **A1's JQL half** → owned by C1. **A6's method-deprecation
half** → owned by C6.

That last one survived the previous de-duplication pass and was double-booked work, not a formatting
nit: `A6` (1.5 d) and `C6` (1.0 d) both deprecated `search_issues`/`get_project_issues`/`get_projects`
and both claimed to migrate the call sites, while M5 sequences `C6` → `A6`, so `A6` would have arrived
to find the work done and been left holding only `API_VERSION` and the checker rewrite. Ownership is
now single: **C6 deprecates the methods and migrates every call site; A6 owns `API_VERSION` and
`check_docs.py`.** The estimates move with the scope — `C6` 1.0 → 1.5, `A6` 1.5 → 1.0 — which is net
zero on the total and on M5, because the double-booking inflated one task by exactly what it deflated
the other.

### B — Typed ADF

Enum, not trait: the model must be `Serialize + Deserialize + Clone + PartialEq + JsonSchema` to match
`types.rs` convention, and `Deserialize`/`Clone`/`PartialEq` are not object-safe. Split by ADF's own
block/inline content category so invalid trees (a `hardBreak` at document top level, a `paragraph`
inside a `paragraph`) are unrepresentable.

**The `AdfNode::Unknown(serde_json::Value)` escape variant is non-negotiable and absent from the
issue.** The issue names 8 node types. Real Jira descriptions contain `table`, `panel`, `mediaSingle`,
`orderedList`, `blockquote`, `rule`, `mention`, `inlineCard`, `expand`. A closed internally-tagged enum
hard-fails on anything else (`unknown variant \`mediaSingle\``), so implementing exactly what the issue
lists would make `get_issue` fail on most human-edited issues and would make D's read-modify-write
silently destroy tables. An outer `#[serde(untagged)] { Block(AdfBlock), Unknown(Value) }` wrapper is
lossless (`to_value(parsed) == original` verified on a doc containing `table` + `mediaSingle` + nested
`panel`); `#[serde(other)]` is not — it re-serializes as `{"type":"unsupported"}`.

Accepted trade-off: a *malformed known* node (`{"type":"heading","attrs":{}}`, no `level`) degrades to
`Unknown` instead of erroring. Fine on reads, unacceptable on writes — hence `AdfDocument::validate()`
rejecting `Unknown` on every write path.

`RichText` normalizes at wire time, not construction time: `Text` **upgrades** to ADF on emit (this is
what satisfies "without falling back to plain text") and `Adf` validates and emits. No
`adf_to_plain_text` downgrade is provided — it would quietly re-create the behaviour the criterion
exists to eliminate.

**`RichText` is a v3-only type; `types.rs` stays frozen.** The previous revision migrated
`IssueFields.description` and `CreateIssueFields.description` to `Option<RichText>` and justified it
with "`Option<String>` is a hard v3 *read* blocker — under v3 the field returns an ADF object and
serde fails". That justification is wrong under workstream A's own design and is withdrawn. A's design
is additive: v2 endpoints keep talking v2 and Jira Cloud's v2 API keeps returning `description` as a
**string**; v3 responses are parsed by `V3IssueFields`, a separate type, and `JiraV3::create_issue`
does not re-GET at all. So the v2 `IssueFields` never sees an ADF object, and changing it would be a
compile break for every downstream struct literal buying nothing on the wire — the previous revision's
own rule that a v2 request may never carry `Adf` meant the v2 create path could only ever emit `Text`
anyway. It is also exactly the in-place flip workstream A rejects. Because `RichText` no longer spans
two API versions, `into_wire` loses its `ApiVersion` parameter: there is one wire form, ADF.

Consequences of confining `RichText` to v3, all of them simplifications:

- Two rows leave the SDK breaking table (`IssueFields.description`, `CreateIssueFields.description`),
  and the "Not breaking, by design" claim that `types.rs`/`IssueFields` stay source-compatible becomes
  true instead of self-contradictory.
- `add_issue_comment(&self, issue_key: &str, body: &str)` (`client.rs:250`) keeps its signature. The
  `impl Into<CommentBody>` widening is **not** needed on the v2 method and is dropped, taking the
  turbofish/fn-pointer breakage row with it. ADF comments are `JiraV3::add_comment` (A5).
- **The Action reaches ADF through the v3 seam, not through the frozen v2 types.** B6 emits via
  `client.v3()`; the v2 `CreateIssueFields` path is untouched and remains the compatibility surface for
  existing SDK consumers.
- `B2` is still M2's gate, for the real reason: `V3CreateIssueFields`/`V3IssueFields` cannot be written
  until the description type exists, so no endpoint can flip to v3 before it lands. The failure mode
  the previous revision described (issue created, follow-up GET fails deserialization, `lib.rs:69`
  propagates before `write_outputs`) is real, but it belongs to the **v2** `create_issue` and is fixed
  by E4/D4, not by retyping `types.rs`.
- F0's mechanical Clippy pass no longer collides with B2 (see F0).

`RichText::Unknown` is **read-only**. It exists so a `description` shape neither `Adf` nor `Text` can
round-trip through a read without erroring. On any write path `into_wire` returns
`AtlassianError::Validation`, mirroring `AdfDocument::validate()`'s rejection of `AdfNode::Unknown`.
Without that rule the read-tolerance escape hatch becomes a write primitive that serializes an
arbitrary caller-supplied `serde_json::Value` straight into a Jira request body — precisely the
JSON-structure-injection surface B6 rejects `description_format: adf` to avoid. Two tests: `Unknown`
round-trips on read; `Unknown` is rejected on write.

**Do not add `description_format: adf` to the Action config**, despite `action/config.rs:196-202`
looking like a ready-made switch. `jira.description` is a template interpolating attacker-controlled
`{{ issue.body }}` (`rules.rs:57-77`); a raw-ADF mode would be a JSON structure-injection primitive.
`text_to_adf` over the rendered string is safe by construction because the text never re-enters a
parser.

**Output bounding is a regression the ADF migration introduces and the issue does not budget.** A
GitHub issue body can be 65,536 characters; Jira's description limit is ~32,767. Plain text overflows
at 1:1; ADF costs ~48 bytes of JSON per line, so a 65 KB body of short lines exceeds 1.5 MB — a
guaranteed 400 and a cheap way for a hostile body to break the router.

**Summary bounding is the same family but a live bug, not an introduced one (NF9).** `jira.rs:26-29`
checks only that the rendered summary is non-empty; Jira caps `summary` at 255 characters and the
shipped Dependabot template already prepends ~20 characters to a title that can reach 256. B6 owns
both bounds so there is one truncation policy, and G2 carries a >255-char title in the hostile corpus.

| Task | Est. | Depends on |
|---|---|---|
| B1 — `sdk/src/adf/`: `AdfDocument`, `AdfBlock`, `AdfInline` (`HardBreak` **must** be a unit variant), `AdfListItem`, `AdfMark`, attrs, `Unknown` fallbacks, builders, `validate()`. **Acceptance condition — the issue's eight node types are each individually representable and round-trip:** `doc`, `paragraph`, `text`, `hardBreak`, `heading`, `bulletList`, `codeBlock`, and the `link` mark | 2.0 | — |
| B2 — `RichText { Adf, Text, Unknown }` (`#[serde(untagged)]`, variant order load-bearing) + `into_wire()`; `From<&str>`/`From<String>`/`From<&String>`/`From<AdfDocument>`; `Unknown` rejected on write with `AtlassianError::Validation`; exported for A3 to use as the v3 description/comment-body type; **`types.rs` untouched**; apply `skip_serializing_if` across `CreateIssueFields` in the same PR | 1.5 | B1 |
| B3 — `text_to_adf` + `text_to_adf_bounded(AdfLimits)`; normalize CRLF, strip C0 except `\n`/`\t`, split paragraphs on blank-line runs, never emit an empty `text` node; rustdoc states the **negative** contract (no Markdown at all) | 1.5 | B1 |
| B4 — v3 write paths carry `RichText`: `JiraV3::create_issue` description, `JiraV3::add_comment` body, new `JiraV3::update_issue_description`; `AdfDocument::validate()` enforced on every one of them; the easily-missed inline comment body in `transition_issue` (`client.rs:753-779`) stays v2/plain and is pinned by a test saying so | 1.5 | B2, B3, A3 |
| B6 — Action emits ADF **through `client.v3()`**, not through the frozen v2 `CreateIssueFields`; keep `description_format` restricted to `text` with the rationale in the rejection test; whitespace-only rendered description ⇒ `None`, not an empty doc; **summary bounding (NF9)** — char-boundary-safe truncation with an ellipsis, cap configurable, default 255 | 1.0 | B3, B4 |
| B7 — CLI `--body-adf-file`; pin that `issue-create --request` still accepts `"description": "plain string"` (it does — untagged `RichText` resolves it to `Text`) | 0.5 | B4 |

**B5 is a retired id, not a missing task.** It was folded into B4 (write paths) and B6 (Action
rendering) during de-duplication. Ids are never renumbered, so cross-references in the coverage,
semver, and sequencing tables stay stable across plan revisions; the same applies to A2, A4, D1, D5.

### C — Enhanced search, pagination, and public JQL escaping

Two new public modules, both explicitly re-exported by name (never glob — `lib.rs:79` already globs
`types::*`).

JQL escaping is **worse than "missing from the SDK"**: `client.rs:867` and `cli/main.rs:364` both
interpolate the project key raw. C1/C2 is therefore a real injection fix that is independent of the
v3 migration and lands early.

Two escaping layers, because JQL has two. Layer A `try_quote_string_literal` returns the complete
quoted token (callers can never forget the quotes) and maps `\` → `\\`, `"` → `\"`, `'` → `\'`,
LF/CR/TAB → escape sequences, other C0 and U+007F → `\uXXXX`, and **rejects** U+0000 rather than
stripping it. Order is load-bearing: backslash first. Layer B `quote_text_operand` (for `~`) Lucene-escapes
first, then feeds through Layer A.

C2's compatibility assertion is therefore **conditional, not universal**. Today's escaper
(`action/jira.rs:70-72`) is exactly `value.replace('\\', r"\\").replace('"', "\\\"")` — backslash and
double-quote only. Layer A additionally escapes `'`, LF/CR/TAB, other C0 and U+007F. For any
`label_prefix` or `project_key` containing an apostrophe or a control character the two outputs
differ, so "byte-identical to today's" is false as a blanket claim and true only over the character
set config validation admits. The divergence is intentional and is pinned by its own test rather than
hidden behind an assertion that would have to be weakened later.

**Delivering iteration, declining `Stream`.** A `futures_core::Stream` impl needs a new workspace
dependency (nothing in the tree has one), a boxed self-referential future for a borrowed async
iterator, and either a cargo feature (doubling the powerset, plus an ordered README edit) or
unconditional compilation of code no consumer needs — the Action fetches exactly one page. A ~30-line
borrowed cursor covers the requirement; adding `Stream` later is additive.

Six-clause termination contract, each with a dedicated test: (1) stop iff `nextPageToken` is absent
or empty — the token is the sole authority; (2) `isLast` is advisory, and disagreement continues
iteration with a `warn!`; (3) **an empty `issues` array with a token present does not stop iteration**
— the classic `/search/jql` migration bug; (4) an identical consecutive token is a hard error, not a
spin; (5) caps set `truncated()` and make `try_collect` fail so bulk callers cannot silently get a
partial answer; (6) **an expired or invalid page token terminates iteration and must never be
resumed.**

Clause (6) is the one the previous revision missed. `/search/jql` page tokens are time-limited, so a
slow consumer or a long `try_collect` can take a 400 *mid*-iteration. Under E1's table a 400 is
`Permanent → fail`, which is correct but not sufficient: the caller cannot tell "your JQL is invalid"
(fix the query) from "your token expired" (restart from page 1), and the two demand opposite actions.
Resuming is not an option either — restarting from page 1 against a mutating result set silently
changes the answer, so a transparent internal restart would be a correctness bug dressed as a retry.

Design: `next_page` returns `Err(AtlassianError::PageTokenExpired { page_index })` — a real variant,
not a flagged `Validation` — so a caller holding only the `Result` can tell "your token expired,
restart from page 1 deliberately" from "your JQL is invalid, fix the query" without reaching back into
the cursor. That discrimination is the whole point of clause (6), and routing it through a generic
`Validation` would have withheld it from exactly the caller who needs it.

The previous revision refused the variant "so it costs no new `AtlassianError` variant — M2 predates
E1's `#[non_exhaustive]`, so an added variant would break downstream exhaustive matches". That premise
was false twice over, and it is withdrawn from both C1 and C5. Every breaking change in this plan
lands in a single `0.5.0` (see Semver), so no downstream ever compiles against an intermediate
milestone; and `#[non_exhaustive]` is a one-line, dependency-free attribute that has been moved out of
`E1` (M3) into **`F2`** (M1), ahead of C5 — after which additive variants are free for the rest of the
plan. C5 therefore records `F2` as a dependency; it is not binding on the schedule (`F2` finishes at
4.0 d, `C5` cannot start before 6.5), but it is a real edge and is in the DAG.

`SearchCursor` still records a `TerminationReason { Exhausted, Capped, PageTokenExpired }` reachable
via `cursor.terminated_reason()`, for callers driving the cursor directly rather than inspecting an
error. `try_collect` propagates rather than returning a truncated set, consistent with
clause (5). Classification is **structural, not message-matching**: a 400 is `PageTokenExpired` only
when the failing request carried a `nextPageToken` that Jira itself issued (page index > 0); a 400 on
the first page is always a JQL error. That rule holds regardless of Atlassian's error-message wording,
which is not verifiable from this repo — the message text is a canary assertion (R10), not a
precondition. The wiremock test mounts 200 on page 1 and 400 on page 2.

| Task | Est. | Depends on |
|---|---|---|
| C1 — `pub mod jql`: `try_quote_string_literal`, `quote_text_operand`, `JqlBuilder` (field names validated against `^[A-Za-z][A-Za-z0-9_]*$` or `cf[NNNNN]`; `raw_term` is the documented unescaped escape hatch), `JqlError` → `AtlassianError::Validation` (**not** a new enum variant — a malformed JQL term *is* a validation error, and a separate variant would give a caller nothing to branch on that the message does not already carry; the "it would break exhaustive matches" rationale is withdrawn, see C5) | 1.5 | — |
| C2 — Delete `action/jira.rs:70-72`; fix `client.rs:867` and `cli/main.rs:364`; assert the emitted dedupe JQL is byte-identical to today's **for the character set reachable from a `label_prefix` and `project_key` that pass config validation**, plus an explicit divergence test naming where C1 is deliberately stricter | 0.5 | C1 |
| C3 — `pub mod search`: `SearchRequest` (`skip_serializing_if` throughout, incl. `reconcileIssues`), `SearchPage`, `SearchIssue`, `SearchIssueFields` (all fields Option/defaulted + `#[serde(flatten)] other`), `RawSearchPage`, `SearchLimits`, thin `/project/search` model | 1.5 | C1, B2 |
| C4 — `search_jql`, `search_jql_raw`, `approximate_issue_count`, `find_issue_by_jql`; POST (JQL exceeds practical URL length, and `reconcileIssues` is body-only) through A1's path builder | 1.5 | C3, A1 |
| C5 — `SearchCursor` with `next_page`/`try_collect`/`find_first`/`truncated`/`terminated_reason`; the six-clause contract; `AtlassianError::PageTokenExpired { page_index }` (free once `F2` has landed `#[non_exhaustive]`) plus `TerminationReason` on the cursor | 2.0 | C4, F2 |
| C6 — **Sole owner of the search-method deprecations.** `#[deprecated]` on `search_issues`/`get_project_issues`/`get_projects`/`IssueSearchResult` **and `AtlassianRemoteClient::search_issues` in the same release**; migrate all **9** internal call sites in the same PR — `client.rs:868`, `cli/main.rs:338,345,366`, `action/lib.rs:186`, `examples/jira_example.rs:58,92,108`, `examples/ticket_management.rs:220` — plus the **3 `rust,no_run` rustdoc examples** that demonstrate the deprecated calls (`client.rs:481,561,858`), which compile as doctests and would otherwise ship published docs advertising a deprecated API; CLI gains `--fields`/`--page-token`/`--all`/`--max-pages` and `issue-count`; `remote_client.rs:296` gets `#[allow(deprecated)]` on top of its own `#[deprecated]`, rather than being dragged through the new model | 1.5 | C5, C2 |

**Nine call sites, not seven, plus three rustdoc examples.** Enumerated from source rather than
estimated: `client.rs:868` (`get_project_issues` delegating to `search_issues`), `cli/main.rs:338`,
`:345`, `:366`, `action/lib.rs:186` (the Action's own pre-create lookup),
`examples/jira_example.rs:58`, `:92`, `:108`, and `examples/ticket_management.rs:220`. The three
`rust,no_run` doctests at `client.rs:481`, `:561` and `:858` call the deprecated methods in their
`# Example` blocks; they compile, and leaving them would publish docs that demonstrate the API being
retired. Under `RUSTFLAGS: -D warnings` (`ci.yml:29`) every one of those 12 sites has to move in the
same PR as the attribute, which is why C6 is 1.5 d and not 1.0.

`AtlassianRemoteClient::search_issues` (`remote_client.rs:296`) must be deprecated **with**
`IssueSearchResult`, not merely annotated `#[allow(deprecated)]`. The allow silences the warning
inside this crate only; a downstream caller of that still-public, still-undeprecated method would take
a deprecation warning — a hard error under `-D warnings` — from an API nothing told them was going
away. Deprecating it is consistent with the crate already documenting the Remote MCP path as retired
(`sdk/src/lib.rs` header). The alternative — leave `IssueSearchResult` undeprecated and deprecate only
the three `AtlassianClient` methods — is defensible but leaves the type as a permanent v2 tombstone.

### D — Idempotent Action reconciliation

Guiding constraint: **no consumer config change may be required to preserve today's behaviour.**
`on_existing` defaults to `noop`; today's SHA-256/12 label is auto-registered as the first legacy
ladder rung; the five existing outputs keep their meaning.

Core structure: split *decide* from *apply*. The whole matrix (no issue → create; current → no-op;
stale → update once; replay → no duplicate comment; legacy → adopt; duplicate → elect) is a pure
function. Only execution needs HTTP. That makes the issue's fixture matrix ~40 table-driven unit tests
with no mock server plus ~10 wiremock tests for the apply path.

Identity is **readable, not hashed**: `{prefix}-gh-{repository_id}-{issue_number}`. A 12-hex-char hash
is 48 bits; `{repo_id}-{issue_number}` is collision-free by construction, debuggable in the Jira UI,
and JQL-safe with no escaping. The full structured identity additionally goes into an issue property.

**The identity switch changes alert volume in both directions, and only one direction was disclosed.**
Every shipped config hashes `repository.full_name` + `issue.title`
(`docs/USAGE.md:243-245`, `examples/github-automation/dependabot-high.yml:37-39`), verified in source.
The plan already credits the fix for retitling (one GitHub issue stops minting a second Jira issue).
The symmetric effect is not a fix and is louder: today two *different* GitHub issues with the same
title in the same repo collapse onto one Jira issue; afterwards they are two. For a Dependabot feed —
which reopens the same advisory title across dependency bumps — that is a real, permanent increase in
Jira ticket volume, and it interacts with NF4, where a long-closed Jira issue currently suppresses the
whole title-group forever. It is a **third** Action behaviour change needing release notes, and the
only one that is not a bug fix.

It also does not violate the workstream's guiding constraint, but only because that constraint is
about *config* compatibility: no consumer YAML has to change, and the legacy ladder plus
`migration.adopt` keep already-tracked issues attached. Volume is a separate axis and must be stated
separately rather than folded into "no config change required". Two concrete obligations follow:

- G2 carries a fixture pair — same repository, same title, different `issue.number` — asserting **two
  distinct canonical labels**. That is the only regression test that makes the change visible.
- The Action YAML config surface offers `dedupe.identity`: `repo_issue` (default, the new behaviour)
  or `fields` (today's content hash over `dedupe.fields`), so a consumer who genuinely wants
  title-level grouping keeps it deliberately rather than by staying on a legacy rung forever. This
  belongs with the rest of the `on_existing`/`migration`/`update` schema work — task `D9`, not `D3`.

**The YAML schema itself is a task, and in the previous revision it was nobody's.** Criterion 5 is a
*user-facing config* criterion, but `D6` owns only the Rust planner types (`OnExisting`,
`ReconcilePlan`) and `D4` owns rule-ambiguity validation and outputs. Verified in source: the config
crate has no `on_existing` field, no `migration` block and no `update` block anywhere —
`AutomationConfig`/`RuleConfig` (`action/config.rs:9-21`), `JiraRuleConfig` (`:43-56`) and
`DedupeConfig` (`:59-64`) are the whole surface. Adding them is three serde structs with defaults, a
`validate()` extension (`:196`), unknown-value rejection tests following the crate's own established
pattern (`load_config_rejects_unsupported_description_format` at `:501`/`:520`, the `sha1` rejection at
`:583`), and a `USAGE.md` schema section that `scripts/check_docs.py` gates as a blocking CI step
(NF5). That is `D9`, 1.0 d, sequenced before `D6` so the planner has a config type to consume.

`D9` takes a **new** id rather than reusing the retired `D5`. `D5` is on record as struck (duplicate of
`G4`); reusing the number would break the "ids are never renumbered" convention that keeps
cross-references stable between plan revisions, which is the same reason `B5` was not recycled.

The four ladder rungs collapse into **one** JQL query
(`labels in (canonical, sha256_16, sha256_12, sha1_12)`), with precedence recovered client-side by
`rank_candidates` (tier order, ties broken by lowest numeric Jira id). Deterministic, order-independent,
one API call instead of four.

Legacy preimages are **config-driven, not hardcoded** (see Q1) — they are the `migration.legacy_labels`
block of `D9`'s schema: a wrong guess in YAML costs a config edit, a wrong guess in a release costs a
release cycle. Paired with a `dedupe-label` CLI (D8a) that
prints every ladder label and the exact JQL for a real event payload, so a consumer can diff against
live Jira before cutover. This is the highest-value de-risking artifact in the workstream, which is
why D8a is split out of the D8 doc bundle and scheduled in **M2** — it depends only on D3, so it can
be run against live Jira while Q1 is still open, rather than arriving after D7 when the answer is
already baked into a release.

Two additions absent from the issue: `migration.adopt` (write the canonical label onto legacy matches,
without which the legacy rungs are permanent and "migration" is a misnomer) and
`update.when_resolved` (covering NF4, defaulted to today's behaviour so nothing changes silently).
Schema in `D9`, behaviour in `D6`; both are priced and marked optional in R7's additions table.

Ambiguity is defined concretely: *fan-out* to different projects is legitimate and all matches execute;
*ambiguous* means two rules whose reconciliation target collides on `(project_key, label_prefix)`, which
is rejected at load naming both rule ids. Duplicate `rule.id` is also rejected (silently accepted today).

Concurrency is stated honestly in three layers — L1 prevention is a documented consumer-owned workflow
`concurrency:` group (which **cannot** be an Action output; GitHub evaluates it before the step runs,
so it is documentation, owned by D8b, and criterion 7 cannot be claimed until D8b ships),
L2 is a bounded verification search, L3 is deterministic winner election by lowest numeric Jira id —
run on **every** reconciliation pass rather than only after a create, so it repairs as well as decides.

**L2 must be a bounded re-poll; election requires two or more rows; and election must run on every
reconciliation pass, not only after a create.** The previous revision modelled index lag as "the
verification search returns zero rows". That is the wrong shape. The realistic lag outcome is *one* row
— your own — precisely because `reconcileIssues` (R9) forces index consistency for the IDs you pass,
and the only ID you have is your own. A competitor's issue, created 200 ms earlier, is still invisible.
Under the old rule two concurrent runs each see a single-element result set, each elects itself winner
by "lowest numeric Jira id", and two canonically-labelled issues survive with no `duplicate-of` link
and no signal that anything went wrong — a silent duplicate produced by the very mechanism meant to
catch duplicates.

The previous revision's corrected table fixed that specific case and still did not converge, because it
only ever asked what *this* run should do about *itself*. Three rules, in force together, are what make
convergence real:

- **R-a — no label drop below two rows.** No run removes a canonical label, its own or another's, from
  a result set of fewer than two rows. One row is indistinguishable from lag, and a drop taken on lag
  is unrecoverable.
- **R-b — after a create, self must be visible.** `reconcileIssues` guarantees *self*-visibility and
  nothing else (R9). So a post-create result that does not contain self is evidence that the **search**
  is untrustworthy, not evidence that somebody else won: it is reported as `unverified-inconsistent`
  and changes nothing. This is what makes the mutual-adopt failure — both runs seeing "one row, and it
  is not me", both dropping their own label, nobody left holding the canonical label, and the next
  delivery minting a third issue — unreachable by construction rather than by luck. Outside the
  post-create path the same shape is ordinary and safe: a run that created nothing has no own label to
  drop, and "one row, not self" is simply the issue it should reconcile against.
- **R-c — election is idempotent and repairing.** Every reconciliation pass — not only the verification
  after a create — runs the single ladder query, and whenever it sees ≥ 2 canonical-label rows it runs
  `rank_candidates` and demotes **every** non-winner it can see, whether or not one of them is its own:
  drop the canonical label, link `duplicate-of` the winner, post a marker-guarded pointer comment,
  never auto-close. Re-running over the same rows selects the same winner and performs no further
  writes, so the operation is safe to repeat and safe to interleave.

`R-c` is what closes the asymmetric case, which is the *likelier* concurrent outcome and which the
previous revision's table did not handle at all: run A creates JIRA-100 and its search sees {100, 101};
run B creates JIRA-101 and its search still lags to {101} alone. Under the old table B was
`unverified-self-only` with "no election", kept its canonical label forever, and two issues carried the
canonical label with no link between them — convergence failing through the very branch added to
prevent silent duplicates. Under `R-c`, A can see both rows and therefore demotes 101 in the same pass;
convergence does not depend on B ever learning that it lost.

| Context | Result | Status | Action |
|---|---|---|---|
| post-create | 0 rows after N polls | `unverified` | no second create; report; label stays |
| post-create | 1 row, and it is self, after N polls | `unverified-self-only` | **no election**, no second create, no label drop (`R-a`); report; convergence deferred to a later pass (`R-c`) |
| post-create | ≥ 2 rows incl. self, self ranks first | `elected-winner` | keep own label; demote every other row seen (`R-c`) |
| post-create | ≥ 2 rows incl. self, self does not rank first | `elected-loser` | drop own canonical label, link `duplicate-of` the winner, marker-guarded pointer, never close; also demote any other non-winner seen |
| post-create | any result **not** containing self — 1 row not-self, or ≥ 2 rows none of them self | `unverified-inconsistent` | report; change nothing (`R-b`) |
| steady state (this run created nothing) | 1 row | `matched` | ordinary reconcile against that issue; no election, no drop |
| steady state | ≥ 2 rows | `elected` | rank, reconcile against the winner, demote the rest (`R-c`) |

N defaults to 3 attempts with backoff through the same injectable `Sleeper` as E-retry, so the suite
stays at zero wall-clock. `reconcile-status` carries `unverified`, `unverified-self-only` and
`unverified-inconsistent` as distinct values so a workflow can alert on them; silence beats a
duplicate, but an *unlabelled* silence is worse than either. The status name `adopted` is retired from
this table: it collided with `migration.adopt`, which is legacy-label adoption and an unrelated
mechanism.

**The residual, stated rather than hidden.** If index lag hides the duplicate from *both* runs — the
symmetric-lag case, where neither ever sees two rows — both keep the canonical label until some later
pass sees both. Convergence is therefore **eventual and delivery-driven**, not immediate: it completes
on the next reconciliation pass for that identity, from either run's event or any other delivery, since
`R-c` runs the election on every pass rather than only after a create. If no further event for that
identity is ever delivered, the surplus issue keeps its label and is visible only through the
`unverified-self-only` status both runs reported. Q4's rewording of criterion 7 claims exactly that and
no more.

**Comments converge on replay and never under concurrency, and that must be said out loud.** D6 mints and scans a
comment marker and E5 probes with a marker scan, which fully solves the *replay* case: markers are
deterministic over the source event, so a re-delivered event finds its own marker and posts nothing.
Under true concurrency there is nothing to elect with — two runs both scan, both find no marker, both
post, and neither can remove the other's comment (Q3 deliberately withholds delete from the canary
token, and a general integration should not hold project-admin either). So for comments:

- **Prevention is L1 only.** The documented workflow `concurrency:` group (D8b) is the whole story.
- **Detection is L2.** Because markers are deterministic rather than random nonces, a later scan can
  see the same marker twice; D7 reports that through `reconcile-status` and `duplicate-of` instead of
  silently succeeding.
- **Removal is out of scope.** No auto-delete, no auto-close.
- G4b carries a test that *pins the duplicating behaviour* so it is a known, documented limit rather
  than a surprise found in production, in the same spirit as G2 pinning today's dedupe scheme.

Q4's proposed rewording of criterion 7 must reflect this: issues converge eventually, comments do not
converge at all.

| Task | Est. | Depends on |
|---|---|---|
| D2 — Widen `GitHubIssueEvent` with `issue.id`/`number`/`node_id`/`state`, `repository.id`/`node_id` (**required, not defaulted** — a defaulted `0` mints one garbage identity for every event); `EventIdentity`; extend the `rules.rs:82-91` field allowlist | 1.5 | G0, G1 |
| D3 — `canonical_label` + `validate_label` (≤255, `[A-Za-z0-9._-]+`); `LegacyLabelSpec`; `v0_label` reproducing `rules.rs:147-153` byte-for-byte; single-query `build_lookup_plan` + `rank_candidates`; opt-in summary fallback with mandatory exact client-side post-filter; add `sha1`/`hex` workspace deps | 2.5 | D2, C1, C5 |
| D4 — `validate_rule_ambiguity`; replace the `lib.rs:64-72` early `return` with a collecting loop; additive outputs (`matched-rule-ids`, `jira-issue-keys`, `reconcile-status`, `duplicate-of`, `results-json`); **flush outputs before propagating any error** (fixes half of NF3) | 1.5 | D3, F4 |
| D6 — Pure planner: `OnExisting`, `ReconcilePlan`/`ReconcileAction` (incl. `Demote { issue_key, winner_key }`), content-conditional updates (equal hash ⇒ no PUT at all), `ReconcileProperty` v1 with a hard 32 KB cap and LRU-50 comment map, comment marker mint/scan, `update.when_resolved`; the election ladder as pure decisions over `(created_this_run, rows)` implementing `R-a`/`R-b`/`R-c`, so every row of the L2 table is a table-driven unit test with no mock server | 2.5 | D3, D9, G4, B4, A5 |
| D7 — Apply path: `reconcile_after_ambiguous_create`; `verify_after_create` as a **bounded re-poll** (N=3, backoff, injectable `Sleeper`) returning `unverified` / `unverified-self-only` / `unverified-inconsistent` / `elected-winner` / `elected-loser`; `elect_winner` gated on **≥ 2 rows** (`R-a`), refusing to act on a post-create result that omits self (`R-b`), and invoked from **every** reconciliation pass rather than only after a create (`R-c`) — demoting every non-winner it can see, not only itself, via drop-label + `duplicate-of` link + marker-guarded pointer, never auto-closing; duplicate-comment *detection* via repeated-marker scan, reported not removed | 3.0 | D6, E4, A3 |
| D8a — `dedupe-label` CLI validator: prints every ladder label and the exact JQL for a real event payload | 0.5 | D3 |
| D8b — Migration guide; documented consumer-owned workflow `concurrency:` block (layer L1); example configs | 1.0 | D4, D7 |
| D9 — **Action YAML config surface for criterion 5**: `on_existing` on `RuleConfig` (default `noop`), the `migration` block (`adopt`, `summary_fallback`, config-driven `legacy_labels` specs — Q1's landing site), the `update` block (`when_resolved`), `dedupe.identity` (`repo_issue` default \| `fields`); `validate()` extension; unknown-value rejection tests matching `config.rs:501/520/583`; the `USAGE.md` schema section and the `check_docs.py` change it forces (NF5) | 1.0 | D2, D3 |

Struck as a duplicate: **D1** (INPUT fix) → owned by G0. **D5** (`JiraReconcileApi` trait) → owned by
G4, which builds the same seam for the test harness. `D9` is a new id, not a reuse of `D5`.

### E — Method-aware retry and reconcile-before-retry

**Retry is per-operation, not transport middleware.** A middleware sees `POST /rest/api/N/issue` and
replays it; the method-level code knows that POST created something. `create_issue` is two HTTP calls
behind one method and `add_issue_attachment` never passes through `make_request`. Corollary: do **not**
add `reqwest-middleware`/`reqwest-retry`.

Classification replaces the issue's underspecified "selected 502/503/504", which taken literally is
unsafe — a gateway error means the request may already have been applied, and blind-retrying a POST on
a 504 is exactly how duplicates are created.

`probe →` cells below are resolved by the `ProbeConsistency` axis defined immediately after the table;
they are **not** an unconditional licence to replay.

| Signal | Class | SafeRead | IdempotentWrite | UnsafeWrite |
|---|---|---|---|---|
| `is_connect()` | NotSent | replay | replay | replay |
| 429 | Throttled | replay | replay | replay |
| `is_timeout()`, 408 | Ambiguous | replay | probe → resolve | probe → resolve |
| `is_body()`/`is_decode()` | Ambiguous | replay | probe → resolve | probe → resolve |
| 503 (**with or without** `Retry-After`), 500, 502, 504 | Ambiguous | replay | probe → resolve | probe → resolve |
| 400/401/403/404/409/422, other 4xx | Permanent | fail | fail | fail |

Exactly two rows replay unconditionally on the `UnsafeWrite` column, and each does so because the
signal itself carries a statement about whether the request was applied — not because replaying is
convenient:

- **`NotSent` (`is_connect()`)** — the request failed before a connection carried it, so nothing can
  have been applied. This is why `is_connect()` must not be collapsed into a generic transport error:
  today's `From<reqwest::Error>` (`error.rs:181-188`) inspects only `err.status()`, so the signal does
  not survive to the type system at all. E1 rebuilds it.
- **`Throttled` (429 and only 429)** — 429 means the request was *rejected because too many were sent*,
  i.e. declined rather than processed; Jira Cloud's rate limiter rejects at the edge before the handler
  runs. Routing it through the probe path would be actively worse than replaying: the create probe is
  `IndexBacked`, a negative `IndexBacked` probe can never license a replay, so every routine rate-limit
  on a create would terminate as `AmbiguousWrite` and exit 75 — an ordinary throttle converted into an
  unresolvable state. The exemption is deliberate, is scoped to 429 alone, and rests on a premise
  recorded in R10 (row 7) with a fault-injection check rather than asserted as fact.

**`503` with `Retry-After` is `Ambiguous`, not `Throttled`.** The previous revision classed it as
Throttled and replayed it on all three columns, which contradicted this workstream's own reason for
rejecting the issue's "selected 502/503/504 ⇒ retry": a 503 is not a statement that the origin declined
the request, and an intermediary or gateway can emit one *after* the origin has already processed the
POST. The presence of `Retry-After` says **when** to come back; it never says **whether** the write
landed. So `Retry-After` is an input to the *delay* (E2's floor-plus-jitter rule) and never an input to
the *class*. On a create, a 503 — header or no header — takes the `IndexBacked` probe path and can
never replay. G3b row 5 asserts exactly that, because nothing else in the matrix would catch a
regression to the old behaviour.

Both unconditional rows are single table rows on purpose. If fault injection shows `is_connect()`
firing on a half-used pooled connection, or shows a 429 that Jira emitted after processing, demoting
either to `Ambiguous` is a one-row edit plus one G3b case (row 12 or row 23 respectively).

**A second axis is required: `ProbeConsistency { Strong, IndexBacked }`.** "Reconcile before retry" is
only sound when a negative probe *means* not-applied. That holds for probes that read a known issue by
key — `GET /issue/{key}` field equality, `GET /issue/{key}/comment` marker scan,
`GET /issue/{key}/properties/{key}` — because Jira serves those from the issue store, read-your-writes.
It does **not** hold for the one probe a lost create response leaves available: a `/search/jql` lookup
by dedupe label, which reads an eventually-consistent Lucene index (R1, R9). There, a negative probe is
indistinguishable from index lag, so "confirms not applied ⇒ replay" replays a POST that already
created an issue — exactly the double-create this workstream exists to prevent, manufactured by the
prevention mechanism. `reconcileIssues` cannot close the gap: it takes issue **IDs**, and a create
whose response never arrived yields no ID. `max_attempts = 1` on unkeyed creates does not help either,
since keyed creates are the Action's entire path.

| Operation | Probe | Consistency |
|---|---|---|
| update / assign / story points / custom field (`IdempotentWrite`) | `GET /issue/{key}`, field equality | Strong |
| comment (`UnsafeWrite`) | `GET /issue/{key}/comment`, marker scan | Strong |
| issue property set | `GET /issue/{key}/properties/{key}` | Strong |
| **create (`UnsafeWrite`)** | `/search/jql` by canonical label | **IndexBacked** |
| attachment (`UnsafeWrite`) | `GET /issue/{key}` attachment filename + size (E6) | Strong |

If E6 declines to implement the attachment probe, attachments fall back to `RetryPolicy::none()` — the
safe default. A probe-less `UnsafeWrite` must never be given a retry policy; that combination is what
"blind retry" means and it is rejected by construction rather than by discipline.

`run_write` therefore branches on consistency, not only on class:

- **Strong probe.** Positive ⇒ success. Negative ⇒ back off and replay. Probe itself fails ⇒
  `AmbiguousWrite`, never replay. (Unchanged; this is what makes comment and update replay legitimate.)
- **IndexBacked probe.** Positive ⇒ success. Negative **or** probe failure ⇒ `AmbiguousWrite`,
  **never replay** — after a bounded re-probe loop (default 3 attempts with backoff through the
  injectable `Sleeper`), because index lag is transient and a positive on attempt 2 or 3 converts an
  `AmbiguousWrite` into a plain success at no cost. The loop can only upgrade a negative to a
  positive; it can never license a replay.

**Retry exhaustion has a defined terminal surface.** Criterion 8 names it and the previous revision
never said what it produces, which made it untestable. The rule:

- **Reads and any write whose probe resolved.** When `max_attempts` is consumed the executor returns
  the **last classified error unchanged** — `RateLimit`, `JiraApi`, `Transport` — with `attempts` and
  the last `retry_after` recorded on it. No `RetriesExhausted` variant: it would erase the status code
  the caller needs in order to decide anything, and "we stopped trying" is executor state, not a new
  failure mode. (The cost of *adding* a variant is not the argument — `#[non_exhaustive]` lands in F2
  in M1, so additive variants are free from that point on.) `is_retryable()` therefore still reports
  `true` on the returned error, which is correct — the operation is retryable, this executor merely
  stopped.
- **A write whose probe never resolved.** `AmbiguousWrite { op, attempts, last_error }` — metadata-only
  per F2's `DiagnosticsPolicy`, since `AtlassianError` is `Clone + Serialize + Deserialize` and cannot
  hold a source. This is the only terminal state that means "state on the server is unknown", and it is
  the one E7 maps to exit 75.
- Exhaustion is distinguishable from a single failure only by `attempts`, so every G3b case asserts the
  journal count rather than the error alone.

What this actually buys, stated without overclaiming:

- **The retry layer never creates a duplicate**, under one stated premise: that a 429 means Jira
  declined the request rather than processing it (R10 row 7, fault-injection checked). Every other
  write-side signal either proves not-sent (`is_connect()`) or goes to the probe path, and on a create
  that probe is `IndexBacked` and may never license a replay — 503-with-`Retry-After` included. Every
  create-side duplicate that remains comes from true cross-process concurrency, not from replay. That
  is a real guarantee with a named premise, and it is a smaller one than "reconcile before retry"
  implies.
- **A bounded duplicate window, not prevention.** The window is the index-visibility lag between two
  concurrent deliveries; workstream D's L1/L2/L3 handle it, and only L1 prevents.
- **No issue-property claim is possible.** An entity property needs an issue id, which is the one
  thing a lost create response denies, so a property can never be a *pre*-create claim — and R2
  already establishes that properties are not JQL-indexed for a plain API-token integration, so it
  could not be discovered even if it existed. What the property genuinely provides is a
  **Strong-consistent identity confirmation**: once `reconcile_after_ambiguous_create` has an
  IndexBacked *candidate* key, reading that key's property upgrades a label match to a confirmed
  identity match. Candidate discovery stays weak; candidate confirmation is strong.
- The honest terminal state is a typed `AmbiguousWrite`, surfaced by E7 as exit 75 (`EX_TEMPFAIL`) so
  a workflow declines to auto-rerun into a duplicate.

Determinism comes from an injectable `Sleeper` (boxed, not generic — making `AtlassianClient` generic
over a clock is itself a breaking change to every downstream type mention). `tokio::time::pause()` is
unusable because wiremock shares the runtime and real socket I/O stalls under a paused clock.
`RecordingSleeper` lives in the testkit and returns immediately, so the suite never sleeps.

Server-supplied `Retry-After` is honoured as a **floor with small bounded jitter above it** — never
earlier than the server asked, never exponentially grown. The previous revision honoured it exactly,
with zero jitter, framed as a deliberate spec decision. For a single request that is right; for the
actual deployment shape it is wrong. A repository fans out concurrent `issues` deliveries into one
shared Jira rate limit, every client receives the same `Retry-After`, and with zero jitter they all
wake in the same instant and reproduce the burst that produced the 429. The rule:

```
sleep = min(retry_after + U(0, jitter_ratio × retry_after), max_retry_after)
```

`jitter_ratio` defaults to 0.1 and is configurable. The clamp is applied last so `max_retry_after`
remains the final word — it addresses a different problem (a hostile or absurd `Retry-After: 86400`
hanging a workflow for a day, also not in the issue) and the two must not be conflated. The `Jitter`
type in E2 is injectable alongside `Sleeper`, with `Jitter::none()` in tests, so `RecordingSleeper`
still asserts exact durations and the change costs nothing in the suite.

| Task | Est. | Depends on |
|---|---|---|
| E1 — `FailureClass` + `classify()`; `retry_after` on `RateLimit`/`JiraApi`; `Transport{TransportKind}`, `AmbiguousWrite`, `CreatedButUnread` variants (additive — `#[non_exhaustive]` landed in `F2`); rewrite `From<reqwest::Error>` to use `is_timeout`/`is_connect`/`is_body`/`is_request`; `parse_retry_after(raw, now)` (delta-seconds and HTTP-date); delete the duplicated `config.rs:703-710` test | 1.5 | F2 |
| E2 — `RetryPolicy`/`RetryConfig`/`Jitter`/`OpKind`/`ProbeConsistency`; `Sleeper` + `TokioSleeper`; injectable `Jitter` with `Jitter::none()` for tests; `Retry-After` honoured as a **floor + bounded jitter**, clamped last by `max_retry_after`; `RetryExecutor::{run, run_write}`; **exhaustion returns the last classified error unchanged with `attempts` recorded — no `RetriesExhausted` variant**; `AtlassianConfig.retry` with `max_retries`/`retry_delay` deprecated-but-mirrored; new env vars; **declare `tokio` `"time"` explicitly** (NF8) | 2.0 | E1 |
| E3 — Wire `SafeRead` retry into all 13 GET methods; the retried closure must own request **and** deserialize (a truncated body is `is_decode()` → Ambiguous, retryable only if the parse is inside); public `retry_read`/`retry_write` seams; convert `.expect(1)` mounts to journal assertions | 1.0 | E2 |
| E4 — `create_issue_raw` (one POST, no re-GET); one `retry_write(UnsafeWrite, IndexBacked, apply, probe)` seam applied at **both** create call sites (v2 `create_issue`, fixing NF3 for existing consumers, and `JiraV3::create_issue`); bounded re-probe (N=3, backoff) that may only upgrade negative→positive and **never** licenses a replay; negative or failed probe after N ⇒ `AmbiguousWrite`; separately retried read-back returning `CreatedButUnread{key,..}` on failure; unkeyed create is forced to `max_attempts = 1` | 2.0 | E3, D3 |
| E5 — `IdempotentWrite` for update/assign/story-points/custom-field (probe = `GET /issue/{key}` field equality, **Strong**); `UnsafeWrite` for comments (probe = `JiraV3::get_comments` marker scan, **Strong** — which is what makes comment replay legitimate where create replay is not; **the marker must be over source text, not rendered ADF** — ADF serialization is not canonical, so a rendered hash never matches on read-back and produces silent duplicate comments); `transition_*`/`create_issue_link` explicitly pinned to `RetryPolicy::none()` | 1.5 | E4, A5 |
| E6 — Bring `add_issue_attachment` onto the policy layer with a **Strong** probe (`GET /issue/{key}` attachment filename + size) or, if that is dropped, `RetryPolicy::none()`; rebuild the multipart form per attempt (`RequestBuilder::try_clone` returns `None` once a multipart body is set, and would silently degrade to no-retry with no compile error) | 0.5 | E2, F3 |
| E7 — Action surfaces `reconciled`/`attempts`/`ambiguous`; `AmbiguousWrite` → exit 75 (`EX_TEMPFAIL`) so a workflow can decline to auto-rerun | 1.0 | E4, D4 |

### F — Secret safety, supply chain, release identity

`SecretString` has **no `Serialize` impl** rather than a lossy one emitting `"<redacted>"` — a lossy
`Serialize` silently corrupts round-trips and is worse than a compile error. `expose_secret()` is the
only accessor, named so `rg expose_secret` enumerates every read site. Zeroization is documented as
best-effort. `username` stays a plain `String` (not a credential, needed for display) and is protected
instead by `HeaderValue::set_sensitive(true)` on the Basic header.

Errors become metadata-only by default with an explicit `DiagnosticsPolicy` opt-in. `AtlassianError`
derives `Clone + Serialize + Deserialize`, which rules out holding a `reqwest::Error` source or a
`HeaderMap`, so diagnostics are a serializable `ResponseDiagnostics` struct. **`ensure_success` must
capture headers before `.text()` consumes the response** — this is the seam E1 builds on, and the
reason F2 must precede E-retry.

The TLS criterion as written ("production path must not allow insecure TLS") has no checkable
definition — there is no trustworthy production signal, and `CI`/`GITHUB_ACTIONS` are settable by the
environment being defended. Implementable equivalent, which closes both env paths (the workflow env
*and* the `dotenvy::from_read_override` re-injection at `config.rs:399`) without a runtime heuristic:

> Neither the transport scheme requirement nor certificate verification may be relaxed from the
> environment. Both are relaxable **only** by an explicit code call on the config builder.
> `JIRA_VERIFY_SSL=false` becomes a hard configuration error.

**Scheme and host must be decided together — they are one rule, not two.** The previous revision
specified "unconditional HTTPS (drop `&& self.verify_ssl` at `config.rs:179`)" and expected
`HostPolicy::Loopback` to keep the loopback test path alive. It cannot: `HostPolicy` constrains the
**host**, and the check at `config.rs:179` constrains the **scheme**. Dropping the conjunction makes
`AtlassianClient::new` reject `http://127.0.0.1:PORT` no matter what the host policy says, which fails
all five existing wiremock tests — they build clients through `create_mock_client`
(`client.rs:958-967`) and one inline duplicate (`client.rs:1079-1086`) with `.base_url(server.uri())`
plus `.verify_ssl(false)`, and they pass today *only* because of that conjunction. `verify_ssl(false)`
is not even doing what it looks like there: reqwest performs no TLS at all on an `http://` URL, so
`danger_accept_invalid_certs(true)` (`client.rs:64-67`) has always been a no-op for those tests. It is
in the builder purely to buy past the scheme check.

The corrected rule, one predicate in `validate()`:

| Scheme | Host | `HostPolicy` | Result |
|---|---|---|---|
| `https` | permitted by policy | any | accept |
| `https` | not permitted by policy | any | reject (host) |
| `http` | literal `127.0.0.0/8` or `::1` | `Loopback`, set by code call | accept |
| `http` | anything else, incl. a DNS name resolving to loopback | any | reject (scheme) |
| any | any | `Loopback` requested from env | reject at parse |

Two properties follow, and they are what make criteria 10 and 14 stop being mutually exclusive:

1. **`HostPolicy::Loopback` is unreachable from the environment.** `JIRA_HOST_POLICY` parses only
   `atlassian-cloud` and `allowlist:<hosts>`; the literal token `loopback` is a hard error naming the
   code-call requirement. `AtlassianConfig::from_env*` therefore can never yield it, so
   `build_client_from_env` (`action/lib.rs:79-89`) can never reach a mock and the Action can never
   downgrade its own transport — including through the `from_read_override` re-injection, because the
   env parser is the thing that refuses.
2. **Test code, which is code, can call it.** `create_mock_client` swaps `.verify_ssl(false)` for
   `.host_policy(HostPolicy::Loopback)` and drops `verify_ssl` entirely, since it never did anything.
   `SdkJiraGateway` in G4b does the same. No cargo feature, no `#[cfg(test)]`, no `#[doc(hidden)]`.

`verify_ssl(false)` survives as an independent, code-only knob for self-signed Data Center
certificates on an `https://` URL — a genuine use case — and it no longer relaxes the scheme check at
all. `cli/main.rs:658-660` (`--insecure` → `config.verify_ssl = false`) keeps that narrowed meaning; a
developer pointing the CLI at a local mock needs the new `--host-policy loopback` flag instead, and
`--insecure` alone will (correctly) no longer admit an `http://` URL. That is a CLI behaviour change
and belongs in the release notes.

Host validation itself is a typed `HostPolicy { AtlassianCloud | Allowlist(Vec<String>) | Loopback }`,
not a hardcoded `*.atlassian.net` check — the latter would break every Jira Data Center user of a
general-purpose published SDK. `Loopback` is accepted only when every candidate host is a **literal**
address in `127.0.0.0/8` or `::1`; no DNS resolution is performed and no name is accepted, so a
`localtest.me`-style name that resolves to loopback is rejected. See R3.

| Task | Est. | Depends on |
|---|---|---|
| F0 — `[workspace.lints.clippy]` in the manifest (source `allow` silently overrides CI's `-D` flags, so `ci.yml:69-80` is vacuous today); delete both crate-root allows; `cargo clippy --fix` + ~30 hand fixes (NF7); **`derive_partial_eq_without_eq` set to `allow` at workspace level, with the rationale in a comment, rather than auto-fixed**; CI grep guard against re-introduction | 1.0 | — |
| F1 — `SecretString` (redacted `Debug`/`Display`, `ZeroizeOnDrop`, no `Serialize`); apply to `api_token`, `AccessToken`, `OAuthConfig.code_verifier`, `AuthorizationResponse.code`, `TokenResponse`, builder, CLI; drop `Serialize`/`Deserialize` from `AtlassianConfig`; `set_sensitive(true)` on the Basic header; stop logging query strings at `client.rs:154` | 1.5 | F0 |
| F2 — `ResponseDiagnostics` + `DiagnosticsPolicy{MetadataOnly, JiraErrorFields, IncludeBody}`; rewrite `ensure_success` to build `ResponseMeta` (incl. `Retry-After`) **before** the body read; extract `map_error_response` as the single seam; same for `auth.rs:209-214,282-287` and `remote_client.rs:174,184-187`; **`#[non_exhaustive]` on `AtlassianError`** — one line, no dependencies, landed here rather than in `E1` so that every later milestone can add variants additively (`C5`'s `PageTokenExpired` in M2, `E1`'s three in M3) | 1.5 | F1 |
| F3 — `HostPolicy` enforced on the **final joined URL** and separately in `add_issue_attachment`; the combined scheme+host predicate replacing `config.rs:179` (HTTPS required unless literal loopback **and** `HostPolicy::Loopback` set by code call); `JIRA_HOST_POLICY` refuses `loopback`; `JIRA_VERIFY_SSL=false` ⇒ hard error; `verify_ssl(false)` narrowed to cert verification on `https://` only; CLI gains `--host-policy`; **updates the five existing wiremock tests in this PR** (`create_mock_client` + the inline duplicate at `client.rs:1079-1086`) to `.host_policy(HostPolicy::Loopback)` with `.verify_ssl(false)` deleted; base-URL trailing-slash normalization (NF6) | 1.5 | F1, F2 |
| F4 — `OutputWriter` heredoc encoding with a content-derived delimiter (`sha256(value)` — collision-proof by construction, no RNG, `sha2` already a dep); reject NUL/`\r`/oversize; severity token allowlist `^[a-z0-9][a-z0-9._-]{0,31}$`; **env-expansion denylist** (NF2), hard error not empty expansion so it cannot fail open | 1.0 | F0 |
| F5 — `encrypted-env = ["dep:fluxencrypt","dep:dotenvy"]`, included in `full`; cfg-gate the four decrypt functions plus the four `use fluxencrypt::…` imports at `config.rs:9-12` with a loud missing-feature error; `default-features = false` on the **workspace** dep entry (a member's own `default-features = false` is silently ignored otherwise); CI `cargo tree` guard; the doubled `cargo hack --feature-powerset` matrix and the ordered SDK-README FEATURES-table edit this feature forces (NF5); consolidate the three `cargo audit --ignore RUSTSEC-2023-0071` sites (`Makefile:214`, `security.yml:44`, `security.yml:47`) into `.cargo/audit.toml` and **cross-check the fourth**, `deny.toml:85`, which `cargo-deny` reads and `.cargo/audit.toml` does not reach — `deny.toml` keeps its own `[advisories] ignore` entry and quick-check asserts the two lists agree, so the surviving second source of truth cannot silently diverge | 1.0 | F3 |
| F6 — Digest-pin all four `FROM` lines (**keep the tag alongside the digest** so Dependabot can bump); `scripts/check_image_pins.py` in quick-check | 0.5 | — |
| F7 — **Create `CHANGELOG.md` and backfill `0.4.0`–`0.4.2`** (none exists — `find . -iname 'CHANGELOG*'` returns nothing, so the contract has nothing to assert against until this lands); `scripts/check_release_contract.py` (manifest == path-dep == tag == CHANGELOG == `action.yml` `# x-release-version`); gate it in `release.yml` **before** `gh release create`, and pass `--target "$GITHUB_SHA"`; change `auto-release.yml`'s protected-branch abort to open a release PR; verify the `0.4.0`/`0.4.3` non-publication against the live crates.io index as a step, not as a premise | 1.5 | F5, F6 |
| F8 — Security documentation sweep; extend `check_docs.py` to catch env-var drift | 0.5 | F1–F7 |

**Why `derive_partial_eq_without_eq` is allowed rather than auto-fixed.** `types.rs` derives
`PartialEq` on 18 public types and `Eq` on none, so a mechanical `--fix` would add `Eq` across the
public API in M0. Adding a trait impl is additive today and a forward commitment forever: the first
future field that is not `Eq` — an `f64`, a `serde_json::Value` — forces removing it, which *is* a
breaking change. Allowing the lint with a one-line rationale costs nothing and keeps that door open.
Two corrections to how this was reported: `IssueFields` cannot receive `Eq` at all, because
`custom_fields: HashMap<String, serde_json::Value>` (`types.rs:57-59`) is not `Eq`, so the lint never
fires there; and the M2 revert it was said to cause does not exist either, since `RichText` is now
confined to the v3 models (see B) and `types.rs` is untouched.

`publish = false` on the action crate is assigned to **G0 only**, not to G0 and F7 both. It is
defence-in-depth rather than a fix: `release.yml` publishes only `SDK_PACKAGE` (`:364-372`) and
`CLI_PACKAGE` (`:416-425`), so the action crate has never been published.

### G — Test infrastructure, fixtures, canary, CI

Five structural facts drive this workstream: fixtures must land **before** the event schema widens
(widening `GitHubIssueEvent` invalidates all 15 inline JSON literals at once); `TestJiraHook` must be
**deleted, not extended** (one canned search, one canned create, no sequencing, no body assertions,
`#[cfg(test)]` so invisible to `tests/*.rs`); the e2e seam and F's hardening conflict and must be
co-designed; deterministic retry tests require an injectable sleeper, which is a constraint G places on
E rather than something G can retrofit; and the action inputs are broken end-to-end (NF1), so nothing
that runs the real Action in a workflow can be trusted until G0 lands.

New workspace member `crates/threatflux-atlassian-testkit` (`publish = false`), which deliberately does
**not** depend on the SDK — everything it exposes is raw `serde_json::Value`/`&str`. Avoids a
dev-dependency cycle, keeps it usable from all three crates, and means golden files double as wiremock
request matchers. Declared as a path-only dev-dep with **no `version` field**, so `cargo publish`
strips it.

`JiraMock::script(endpoint, [Step; N])` gives per-attempt sequencing via wiremock 0.6's
`with_priority(i+1).up_to_n_times(1)` idiom plus an unbounded final step, and a request journal so
tests assert *exact call counts* rather than just results — a test that only checks the returned key
passes while silently double-creating.

Golden comparison is **semantic JSON, not byte-wise**: `reqwest` serializes struct field order (not
stable across refactors) while `serde_json::Map` is sorted, and `make_request` takes `Option<&Value>`
so the wire is always alphabetized. "Exact ADF request snapshots" therefore means semantically exact.
No `insta` — `.snap` files are not valid JSON and so cannot double as mock fixtures, and hand-rolled
`golden.rs` is ~60 lines with zero new deps.

`SecretScanner` checks **four encodings** of every needle: raw, `base64(username:token)` (the exact
Basic-header form), percent-encoded, and JSON-string-escaped. `assert!(!log.contains(token))` passes
while the base64 Basic blob leaks — this is why it is a shared type rather than an inline assertion.

`parse_github_output` re-parses GitHub's actual kv + `<<DELIM` grammar so tests assert full map
equality; today's `output.contains("severity=high")` cannot detect a forged extra key.

**G3b's fault matrix, enumerated.** Criterion 8 names five distinct fault paths and the previous
revision carried them in a single half-clause inside an overloaded task; "retry exhaustion" appeared
nowhere in the plan outside the copied criterion text. It gets the same treatment C5's termination
contract got: named cases fixed in the plan, not left to implementer discretion. The plan's own audit
establishes this is greenfield — no wiremock test today mounts a 429 or any 5xx, and the two existing
"retry classification" tests assert on hand-built error values without driving a response through
`ensure_success`. Every case asserts **both** the exact attempt count from the request journal and the
exact sleep sequence from `RecordingSleeper` (with `Jitter::none()`), because a test that checks only
the returned value passes while silently double-sending.

| # | Case | Mount / fault | Asserted |
|---|---|---|---|
| 1 | `retry_429_retry_after_seconds` | 429 + `Retry-After: 2`, then 200 | 2 attempts; sleep == 2.0 s exactly (floor honoured) |
| 2 | `retry_429_no_retry_after` | 429 bare, then 200 | 2 attempts; sleep == the backoff schedule, not 0 |
| 3 | `retry_429_retry_after_http_date` | 429 + HTTP-date header | `parse_retry_after(raw, now)`'s date branch; sleep == date − now |
| 4 | `retry_429_retry_after_absurd_clamped` | 429 + `Retry-After: 86400` | sleep == `max_retry_after`; clamp applied last |
| 5 | `retry_503_retry_after_on_create_does_not_replay` | 503 + `Retry-After: 1` on an `UnsafeWrite` create; the mount would return 201 on a second POST | Ambiguous, **not** Throttled ⇒ `IndexBacked` probe path: create endpoint called **exactly once**, terminal `AmbiguousWrite`, header still honoured as the pre-probe sleep floor; the identical mount on `SafeRead` replays and succeeds. A regression to the previous revision's "Throttled ⇒ replay everywhere" returns a key and fails on the journal count |
| 6 | `retry_503_bare_is_ambiguous` | 503 bare | same class as row 5 ⇒ `SafeRead` replays; writes go to the probe path. Proves `Retry-After` changes the delay, never the class |
| 7–9 | `retry_500`, `retry_502`, `retry_504` | one case each | Ambiguous; **not** the issue's "selected 502/503/504 ⇒ retry" |
| 10 | `retry_timeout` | wiremock delay > client timeout | `is_timeout()` ⇒ Ambiguous; proves the signal survives `From<reqwest::Error>` |
| 11 | `retry_408` | 408 | same class as 10, different signal source |
| 12 | `retry_connect_refused` | closed port | `is_connect()` ⇒ NotSent ⇒ replay on all three columns |
| 13 | `retry_truncated_body` | 200 with truncated JSON | `is_decode()` ⇒ Ambiguous, and the retried closure owns the parse (E3) |
| 14 | `no_retry_permanent_4xx` | table-driven 400/401/403/404/409/422 | 1 attempt, zero sleeps |
| 15 | `retry_exhaustion_surfaces_last_error` | `max_attempts` consecutive 503s | attempts == `max_attempts`; terminal surface per the contract in E |
| 16–18 | `run_write_strong_{applied,not_applied,probe_failed}` | ambiguous 504 on an `IdempotentWrite` | positive ⇒ success, no replay; negative ⇒ exactly one replay; probe error ⇒ `AmbiguousWrite`, zero replays |
| 19–22 | `run_write_indexbacked_{positive,negative,probe_failed,late_positive}` | ambiguous 504 on a create | positive ⇒ success; negative after N re-probes ⇒ `AmbiguousWrite` with **zero** replays; probe error ⇒ same; negative-then-positive on re-probe 2 ⇒ success with zero replays |
| 23 | `retry_429_on_create_replays_once` | 429 bare on an `UnsafeWrite` create, then 201 | exactly 2 create attempts and **zero probes** — the 429-only exemption. Isolating it here means falsifying R10 row 7 changes one classification row and this one test |

Rows 16–22 are the assertions that make E's `ProbeConsistency` axis real rather than documentary: the
only difference between a correct implementation and the double-create the workstream exists to prevent
is whether row 20 replays, and nothing else in the suite would catch it. Rows 5 and 23 do the same job
one level up, for the *classification* half: row 5 mounts the signal the previous revision replayed
unconditionally (503 + `Retry-After`) on the one `OpKind` where replaying double-creates, and row 23
pins the single signal that is still allowed to replay there, so the boundary between them is a test
result rather than a paragraph.

G3b is priced at 1.0 d on the assumption that `G1` ships `JiraMock::script`, the request journal and
`RecordingSleeper` complete, so each row is a few lines of table-driven test. If that harness lands
thinner than specified, `G3b` is the first task in the plan to overrun.

| Task | Est. | Depends on |
|---|---|---|
| G0 — Fix `INPUT_*` resolution (hyphenated first, underscored for back-compat); extract `ActionEnv`; `publish = false` on the action crate (NF1) | 1.5 | — |
| G1 — `threatflux-atlassian-testkit` crate (`fixtures`, `jira_mock`, `golden`, `redaction`, `logs`, `gha`, `env`, `net`, `sleeper`); migrate 39 YAML + 15 JSON inline literals into fixtures, **with `issue.id`/`number`/`node_id`/`repository.id` present from day one**; **one *realistic* `issues.opened` Dependabot delivery** carrying the full webhook shape (`issue.user.login` — the field `actor_in` actually gates on, `rules.rs:27` — plus `sender`, `labels`, `state`, and the identity fields), **replacing** the 12-line hand-trimmed stub at `github.rs:43-57` rather than promoting it; `.gitattributes` `fixtures/** -text` (Windows is in the matrix and `core.autocrlf` would corrupt the CRLF payloads); re-verify `cargo deny` | 2.5 | — |
| G2 — Pin today's dedupe scheme as a golden vector **before D touches anything**; the identity-change pair (same repo, same title, different `issue.number` ⇒ two distinct canonical labels); hostile-payload corpus (CRLF, lone CR, literal `ghadelimiter_`, `${JIRA_API_TOKEN}`, JQL metacharacters, 4-byte emoji, 32 KiB body, trailing-whitespace title twin, **>255-char title** for NF9) | 1.0 | G1 |
| G3a — SDK integration suite: move the five inline wiremock tests to `tests/`, retarget at v3, convert `.expect(1)` to journal assertions; **four named ADF goldens** (multiline with hard breaks; multi-paragraph; empty/whitespace-only description asserting `None` and **no `description` key on the wire**; a lossless `Unknown` round-trip `to_value(parse(x)) == x` over a doc containing `table` + `mediaSingle`); pagination termination matrix, one case per C5 clause | 1.5 | G1, A3, A5, B4, C5 |
| G3b — Retry fault-injection matrix under `RecordingSleeper`: **23 named cases** — the classification table expanded to 15 (the `Retry-After` variants are distinct code paths, and 503-with-header vs 429 on an `UnsafeWrite` is the boundary the whole workstream turns on), plus retry exhaustion, plus the seven `run_write` probe outcomes — enumerated in the fault matrix above, not left to implementer discretion | 1.0 | G1, E3, E4, E5 |
| G4 — `JiraGateway` trait (`async-trait`; AFIT is not dyn-safe and its Send-bound lint fails under `-D warnings`) + `SdkJiraGateway`; delete `TestJiraHook` and rewrite its five tests; `run(env, gateway)`; in-memory `FakeGateway`. Side benefit: removes `#[serial]` from most of the 21 env-coupled tests and the process-CWD mutation at `lib.rs:472-480` | 2.5 | G0, G1, G3a |
| G4b — e2e reconciliation + dedupe-migration suites against a real `SdkJiraGateway` over `JiraMock` (client built with `HostPolicy::Loopback`, no `verify_ssl` relaxation); includes the index-lag cases — 0 rows, 1-row-self, 1-row-other (post-create ⇒ `unverified-inconsistent`; steady-state ⇒ `matched`), ≥2 rows — **plus the asymmetric pair**: two runs over one identity where A's verification search returns both rows and B's returns only its own, asserting that A demotes B's issue and exactly **one** canonical label survives. The four single-run cases test each run in isolation and every one of them passes against a non-converging implementation, so the pair is the only case that closes criterion 7's convergence claim. A second pair covers symmetric lag (both runs see one row), asserting two labels survive, both statuses are `unverified-self-only`, and the **next** delivery converges them (`R-c`); and a test **pinning the duplicate-comment behaviour under true concurrency** as a documented limit; **one case driving the shipped `examples/github-automation/dependabot-high.yml` end-to-end** against G1's realistic Dependabot delivery, so the `actor_in` gate (`rules.rs:27`) and the severity regex are exercised over a real body rather than a hand-trimmed stub | 1.5 | G4, D7 |
| G5 — `GITHUB_OUTPUT` tests via the real re-parser, driven through a deliberately permissive `(?s)` severity regex so encoding safety is proven independent of consumer config | 0.5 | G1, F4 |
| G6 — Secret-leak sweep across `Debug`, `Display`, serde, tracing, `GITHUB_OUTPUT`, and the binary's stderr; includes the NF2 config-expansion case and the `from_read_override` TLS-flip case | 1.0 | G1, F1, F2 |
| G7 — Scheme + host-policy matrix, one case per row of F3's predicate table (incl. non-loopback DNS names that could resolve to loopback, `http://` under every policy, and the untrimmed `verify_ssl` parse); plus the **env-reachability** tests criterion 14 needs: no `JIRA_*` combination yields `HostPolicy::Loopback` or `verify_ssl == false`, and env-built configs reject `http://` and non-Atlassian hosts | 1.0 | F3, G0 |
| G8 — Jira Cloud canary workflow: `workflow_dispatch` + weekly + label-gated PR, never `pull_request_target`, fork-guarded, secrets in a reviewed `jira-canary` Environment; **the nine-assertion capability checklist below**, run across three dispatch phases (create, update, replay) and asserting on the Action's own outputs plus a GET-back; teardown `if: always()`; job-summary capability table generated from the same nine rows | 2.0 | G0, G4b, A5, B6, D7 |
| G9 — `e2e` CI job added to `ci-success`; `codecov.yml` with `patch: 85%` and `project: informational` (**no workspace threshold** — the 64.35% baseline is held down by `remote_client.rs` 13%, `cli/main.rs` 12%, `auth.rs` 31%, none of which this issue touches); `scripts/check_supply_chain.py` | 1.0 | G3a, G3b, G4b, F7 |

**G8's nine assertions, one per criterion-15 capability.** The criterion names nine capabilities; the
previous revision committed to "eight steps" without saying which capability each proved, and three of
them — issue type, priority, labels — appeared nowhere else in the plan. All nine are reachable from
the Action's existing create path, verified in source: `action/jira.rs:37-57` builds `project`,
`summary`, `issue_type`, `assignee`, `priority`, `description` and `labels` into one
`CreateIssueRequest`, and `:32-35` appends the dedupe label to the label list. So each row below is a
GET-back comparison against a value the canary's own config chose, not new production code.

| # | Capability | Assertion | Phase |
|---|---|---|---|
| 1 | project | `fields.project.key` == the Environment's project key; the C3 `/project/search` preflight resolves it before the run | create |
| 2 | issue type | `fields.issuetype.name` == `rule.jira.issue_type` (`config.rs:45`), sent via `IssueTypeReference::by_name` (`jira.rs:41`) | create |
| 3 | priority | `fields.priority.name` == the value `priority_by_severity` (`config.rs:48`) selected for the injected severity. **Per-tenant map** — the canary Environment must supply a priority name that exists in the project's scheme, and this is the assertion most likely to fail first on a fresh tenant | create |
| 4 | assignee | `fields.assignee.accountId` == the Environment's canary accountId (Q3 prerequisite) | create |
| 5 | ADF | `fields.description.type == "doc"` with a `hardBreak` node present | create |
| 6 | labels | `fields.labels` contains **the canonical dedupe label D3 computed** for the injected event. The only live proof that the label the reconciliation ladder queries is the label Jira actually stored | create |
| 7 | update | re-dispatch with a changed body ⇒ exactly one PUT, `reconcile-status: updated`, no second issue key in `jira-issue-keys` | update |
| 8 | comment | `on_existing: update_and_comment` ⇒ `JiraV3::get_comments` (A5) shows exactly one marker-bearing comment; the replay phase adds none | update, replay |
| 9 | permissions | the least-privilege token completes 1–8 **and fails closed** on `DELETE /rest/api/3/issue`; teardown transitions to Done instead of deleting (Q3) | teardown |

Rows 2, 3 and 4 are consumer-owned configuration under the issue's own public/private boundary, so the
canary proves the *mechanism* against throwaway values held in the `jira-canary` Environment; the
values themselves are Q3 prerequisites, not plan deliverables.

## Sequencing

Six milestones over 52 tasks. Security-only fixes that do not depend on the v3 migration land first:
they are cheap, they reduce live risk immediately, and several of them (F0, G1, F2, A1) are
prerequisites that turn later merge conflicts into additive extensions.

**The milestone partition is a topological layering, verified mechanically.** Every task's milestone is
`>=` the milestone of each of its dependencies; the check was run over all 52 tasks and every edge in
the Depends-on columns, and it now reports zero inversions. Two inversions existed in the previous
revision and were the reason the parallelism claims below could not be evaluated: `G3` sat in M2 while
depending on `E3` in M3, and `E4` sat in M3 while depending on `D3` in M4. Both are fixed structurally,
not by relaxing the dependency — see M2 and M3.

**Milestones are ordering constraints, not hard gates.** A task starts when its own dependencies land,
not when its milestone's predecessor fully closes; the wall-clock figures below depend on that. Each
milestone is defined so that `main` is shippable at its close, with one explicit condition recorded
under M1.

### M0 — Independent fixes and test foundation (10.0 d)

`F0` · `G0` · `C1` · `C2` · `F4` · `G5` · `F6` · `G1` · `G2`

Nothing here depends on v3, ADF, retry, or reconciliation. Ships four real fixes on its own: the
`INPUT_*` bug that makes `dry-run` a lie (NF1), the raw JQL interpolation sinks, the `GITHUB_OUTPUT`
encoding plus the config-expansion exfiltration path (NF2), and digest-pinned container bases.

Parallelizable: `F0` and `G1` are independent of everything; `C1`→`C2` is a serial pair; `G0`, `F4`,
`F6` are independent. `G2` needs `G1`. `G5` needs only `G1` and `F4`, both here — it belongs in M0
beside `F4` rather than trailing into M4, because `F4` is the entire `GITHUB_OUTPUT` encoder and `G5`
is the only thing that proves the encoding through GitHub's real kv + `<<DELIM` grammar. Shipping `F4`
without `G5` is exactly the failure mode `G5` exists to prevent, and it is what the reduced-scope cut
below would otherwise do.

**Land `F0` first.** It is one day (NF7), it is purely mechanical, and every subsequent line of new
code is then written under the real lint policy instead of joining a backlog that has to be cleared
later inside a security diff.

**Land `G1` early.** Extracting fixtures before the event schema widens turns D2 from a 15-file rewrite
into a struct edit.

### M1 — SDK hardening and event identity (10.5 d)

`A1` · `F1` · `F2` · `F3` · `F5` · `G6` · `G7` · `D2`

Strictly serial spine: `A1` → `F1` → `F2` → `F3` → `F5`. `A1` extracts the transport seam so F, E, and
A stop competing for `client.rs:108-172`. `F2` must precede any E-retry work because both rewrite the
`client.rs:123-138` match arm; F2 leaves `ResponseMeta` with `Retry-After` already captured and E only
adds the parsed `Duration` and the class.

`G6` can start once `F2` lands; `G7` needs `F3`.

**`D2` moves here from M4.** Its only dependencies are `G0` and `G1`, both in M0 — nothing about the
event-schema widening needed the reconciliation milestone, and leaving it in M4 was half of what forced
the `E4`→`D3` inversion. It also lands the widened `GitHubIssueEvent` immediately after `G1` extracts
the fixtures, which is the whole reason `G1` is scheduled early.

Shippability condition: `F3`'s scheme tightening breaks the five existing loopback wiremock tests,
which construct clients via `create_mock_client` (`client.rs:958-967`) and one inline duplicate
(`client.rs:1079-1086`) with `.base_url(server.uri())` — an `http://127.0.0.1:PORT` URL — plus
`.verify_ssl(false)`. They pass today only because `config.rs:179` gates the scheme check on
`&& self.verify_ssl`. **`F3` must update those five tests in its own PR**, swapping `.verify_ssl(false)`
for `.host_policy(HostPolicy::Loopback)` — a two-line change in one helper plus one call site, since
`verify_ssl` was never doing anything on an `http://` URL. Deferring them to `G3a` in M2 would leave
`main` red for a whole milestone and void the shippability guarantee.

### M2 — Jira v3, ADF, enhanced search, dedupe identity (21.5 d) — critical path

`B1` → `B2` → {`B3`, `A3`} → {`A5`, `B4`} → `B6` · `C3` → `C4` → `C5` → {`D3` → {`D8a`, `D9`}, `G3a`}

The critical path runs through this milestone, but through **enhanced search**, not ADF:
`B1` → `B2` → `C3` → `C4` → `C5` → `G3a` → … See the Critical path section.

`B2` is the gate, for a narrower and more defensible reason than the previous revision gave. `RichText`
is the description and comment-body type of `V3IssueFields`/`V3CreateIssueFields`, so **A3 cannot be
written before `B2` lands** and therefore no endpoint can flip to v3 before it. The previous revision
justified the gate with "`IssueFields.description: Option<String>` is a hard v3 *read* blocker"; that
is false under workstream A's additive design — the v2 type never parses a v3 response — and the
justification is withdrawn along with the `types.rs` migration it was used to license (see B).

The failure mode it described is real but belongs to the **v2** path and is fixed elsewhere: the issue
IS created, the follow-up GET at `client.rs:444-458` fails, the caller gets `Err`, and per `lib.rs:69`
the Action never reaches `write_outputs`. `E4` removes the re-GET; `D4` flushes outputs before
propagating. Neither needs `types.rs` retyped.

Correcting the previous revision's advice: `C3`/`C4`/`C5` are **not** the branch with slack. Once `B2`
lands they are the critical chain, and `A3`/`A5`/`B4` carry 1.5 d of float. Schedule the search chain
on the engineer least likely to be interrupted.

`C5` also depends on `F2` (M1), which is new in this revision: `F2` carries the one-line
`#[non_exhaustive]` on `AtlassianError`, and `C5` adds the `PageTokenExpired` variant behind it. The
edge respects the layering (M1 < M2) and is never binding on the earliest-start schedule — `F2`
finishes at 4.0 d and `C5` cannot start before 6.5 — but it does cost the F-spine float, from 4.5 d to
2.5 d for `F0`/`F1`/`F2`. It is recorded in the Depends-on column rather than left as prose, because
the critical path and every float figure below are computed from that column.

**`G3` is split**, which is what removes the M2/M3 inversion. `G3a` (ADF goldens, pagination
termination matrix, the five relocated wiremock tests, journal assertions) depends only on M0–M2 work
and stays here. `G3b` (the retry fault matrix under `RecordingSleeper`) genuinely depends on the E-chain
— on `E3`, and once its cases were enumerated, on `E4` and `E5` as well — and moves to M3. `G4` is
retargeted at `G3a` alone, so the Action gateway seam is no longer transitively blocked on the retry
milestone.

**`D3` and `D8a` move here from M4.** `D3` depends on `D2` (M1), `C1` (M0) and `C5` (M2), so M2 is its
earliest legal milestone; keeping it in M4 was the other half of the `E4`→`D3` inversion. Landing the
canonical/legacy label ladder here also gets `D8a` — the `dedupe-label` CLI — into consumers' hands one
milestone before the reconciliation engine commits to a label format, which is the practical mitigation
for Q1. `B6` joins its own workstream here too (deps `B3`, `B4`, both M2), which closes criterion 2
inside a single milestone instead of splitting it across M2 and M4.

**`D9` is new in this revision** — the Action YAML config surface criterion 5 actually asks for, which
no task owned. It sits behind `D3` — its `migration.legacy_labels` block deserializes into `D3`'s
`LegacyLabelSpec`, and its `dedupe.identity` key selects between `D3`'s two identity schemes — and ahead
of `D6`, whose planner consumes its types. So M2 is where it belongs. It costs 1.0 d and does not
touch the critical path, but it does consume float: the identity branch `D3` → `D9` → `D6` now carries
**0.5 d** of float instead of 1.5, which is the number the compression analysis below uses. Sized at
1.0 deliberately — at 1.5 d the identity branch ties the critical path and the schedule gains a second
chain to protect.

### M3 — Retry and reconcile-before-retry (9.5 d)

`E1` → `E2` → `E3` → `E4` → `E5` → `G3b` · `E6`

Serial by construction. `E1` needs `F2`'s header capture (M1). `E4` needs `D3`'s idempotency key, and
because `D3` now lands in M2 that is a real satisfied dependency rather than the `probe_jql` hedge the
previous revision used to paper over an inversion. `E6` only needs `E2` and `F3`.

`G3b` is the tail of this milestone, not a parallel branch. Seven of its 23 cases assert `run_write`
probe outcomes, which do not exist until `E4` (the `IndexBacked` create seam) and `E5` (the `Strong`
update and comment probes) land, so its dependency set is `{G1, E3, E4, E5}` — the previous revision's
`{G1, E3}` would have left the rows that actually discriminate a correct implementation unwritable.

Runs in parallel with the head of M4 — `D4`, `G4` and `D6` reach back only into M0–M2, so they do not
wait on the E-chain. `D7` is the first M4 task that does (via `E4`), which is the honest version of the
previous revision's parallelism claim.

### M4 — Action reconciliation (12.0 d)

{`D4`, `G4`} → `D6` → `D7` → `G4b` · `E7`

`G4` (the gateway seam) is the enabling task for both testing and D6/D7; it deletes `TestJiraHook`
rather than extending it. `D6` is pure and can be written and fully tested before `D7` exists — that
split is what makes the issue's fixture matrix tractable.

`E7` needs `E4` (M3) and `D4`; slot it wherever there is slack after `D4`.

### M5 — Deprecation, release contract, canary, docs (9.0 d)

`C6` → `A6` · `B7` · `D8b` · `F7` · `F8` · `G8` · `G9`

**`D8b` is scheduled here.** In the previous revision the whole of `D8` appeared in no milestone at all
— it was the entire 1.5 d gap between the 71.0 d task table and the 69.5 d milestone total. That is not
a bookkeeping slip: `D8b` owns the documented consumer-owned workflow `concurrency:` block, which is
layer L1 of the concurrency model and the only layer that *prevents* duplicates rather than converging
after the fact, plus the migration guide and example configs. Criterion 7 cannot be claimed as reworded
in Q4 until it ships. Its dependencies (`D4`, `D7`) both close in M4.

`C6` migrates all 12 deprecated-call sites (9 call sites + 3 rustdoc examples) in the same PR as the
`#[deprecated]` attributes, because `RUSTFLAGS: -D warnings` (`ci.yml:29`) makes deprecation a hard
error. `A6` no longer duplicates any of that: it deprecates `API_VERSION` — whose only in-tree use is
the assertion at `lib.rs:113-115` — and owns the `check_docs.py` rewrite (NF5) plus the five documents
it gates, so only one PR touches that file. The `C6` → `A6` edge stays: the checker rewrite must land
after the deprecations that force the doc edits, not before.

`F7` and `G8` are the last two acceptance criteria to close. `G8` needs a real Jira tenant (Q3).

### Critical path

Computed mechanically from the Depends-on columns as the longest path through the 52-task DAG, not
asserted by hand. The previous revision published `F0` → `G1` → `B1` → `B2` → `A3` → `A5` → `G4` →
`D6` → `D7` → `G4b` → `G8`, which is not a chain that exists in this plan: `B1` has no predecessors, so
`G1` → `B1` is not an edge, and `G4` depends on `{G0, G1, G3a}`, so `A5` → `G4` is not one either. The
real path is:

**`B1` → `B2` → `C3` → `C4` → `C5` → `G3a` → `G4` → `D6` → `D7` → `G4b` → `G8`**
= 2.0 + 1.5 + 1.5 + 1.5 + 2.0 + 1.5 + 2.5 + 2.5 + 3.0 + 1.5 + 2.0 = **21.5 days**

Every edge above appears in a Depends-on column. It runs through **enhanced search**, not ADF, and it
does not start at `F0`: the security-and-retry spine `F0` → `F1` → `F2` → `E1` → `E2` → `E3` → `E4` →
`D7` → `G4b` → `G8` totals 17.0 d, and every task on its F/E head carries at least 2.0 d of float
(`E4` 2.0, `E1`–`E3` 4.5 each, `F0`–`F2` 2.5 each now that `C5` depends on `F2`); only its
`D7`/`G4b`/`G8` tail is shared with the critical path. `E3` finishes at 8.5 d while `E4` cannot start
until 11.0 d — `E4`'s binding constraint is `D3`, not the E-chain.

The chain lengthened by 0.5 d against the previous revision for one reason: `D7` moves 2.5 → 3.0. Its
apply path now demotes **every** non-winner a reconciliation pass can see and runs that election on
every pass rather than only after a create (D's `R-c`), which is the mechanism that makes the
asymmetric concurrency case converge. It is the only estimate in the plan that changed for a scope
reason this revision; the `A6`/`C6` rebalance below is net zero.

Near-critical branches, from the same computation — these are what a schedule actually has to respect,
because shaving the critical path past a branch's float simply hands criticality to that branch:

| Branch | Float |
|---|---|
| `B1`→`B2`→`C3`→`C4`→`C5`→`G3a`→`G4`→`D6`→`D7`→`G4b`→`G8` | 0.0 (critical) |
| Identity: `D3` → `D9` into `D6` | 0.5 |
| `G9` (tail, after `G4b`) | 1.0 |
| ADF: `A3`, `A5`, `B4` into `G3a` | 1.5 |
| Retry: `E4` into `D7`; `C1` into `C3`/`D3` | 2.0 |
| Security spine: `F0` → `F1` → `F2` into `C5` (and `E1`) | 2.5 |

The head is not one lever but three, because the other branches share parts of it:

- **`B1`/`B2` (3.5 d)** — shared with both the ADF and identity branches, so shaving here moves
  everything with it: 1:1 up to 2.0 d, where `C1` (float 2.0) becomes `C3`'s binding predecessor.
- **`C3`/`C4`/`C5` (5.0 d)** — exclusive to the search chain. Caps at **1.5 d**, where the ADF chain
  (`A3`/`A5`/`B4`) takes over.
- **`G3a` (1.5 d) and `G4` (2.5 d)** — cap at **0.5 d** each, where the identity chain `D3` → `D9`
  takes over at `D6`. `D9` is what reduced this from 1.5; before it existed, `G3a`/`G4` compressed 1.5.

**Tail** (`D6` → `D7` → `G4b` → `G8`, 9.0 d): strictly serial with no alternative branch, so every day
removed converts 1:1 into wall clock. Real compression levers are therefore `D7` (3.0), `D6` (2.5),
`G8` (2.0) and `G4b` (1.5) at 1:1 — not the ADF chain the previous revision named, and not `C5` beyond
the first 1.5 d.

### Wall-clock

Two independent floors: total work **72.5 engineer-days**, longest serial chain **21.5 days**. Wall
clock cannot go below either.

| Engineers | Floor | Realistic |
|---|---|---|
| 1 | 72.5 d | ~14.5 weeks |
| 2 | 36.5 d (work-bound) | ~7.5 weeks |
| 3 | 24.5 d (work-bound) | 26–30 d, once review and integration are counted |
| 4+ | 21.5 d (path-bound) | a 4th engineer buys ≤ 3 d; a 5th buys nothing |

The previous revision's "two- or three-engineer team … roughly 25–30 working days" was arithmetically
impossible for two engineers: 72.5 d of work over 2 people has a hard floor of 36.5 d regardless of
sequencing. Three engineers reach ~24.5 d only under perfect load balancing across a DAG whose critical
path is already 21.5 d, so 26–30 d is the number to plan against. Above four engineers the plan is
parallelism-bound and adding people does nothing.

## Semver and Release Impact

The crate is `0.4.2` on crates.io. Under Cargo's 0.x rules the **minor** position is the breaking
position, so **`0.4.x` → `0.5.0` is the major bump**; a `1.0` is not required. Every breaking change
below should land in one `0.5.0`.

### Breaking — SDK (published)

| Change | Milestone | Kind |
|---|---|---|
| `AtlassianConfig.api_token` → `SecretString`; `AtlassianConfig` loses `Serialize`/`Deserialize`; gains `host_policy`, `diagnostics`, `retry` fields | M1, M3 | compile |
| `AccessToken`/`OAuthConfig`/`TokenResponse` secret fields → `SecretString`; `AccessToken` loses `Serialize` (the `auth.rs:521-535` round-trip test is a de-facto contract being withdrawn) | M1 | compile |
| `AtlassianError` becomes `#[non_exhaustive]` (F2, M1 — deliberately the earliest milestone that touches `error.rs`, so the four later variants are additive); four new variants (`PageTokenExpired` in M2, `Transport`/`AmbiguousWrite`/`CreatedButUnread` in M3); `RateLimit`/`JiraApi` gain `retry_after`; `Http`/`JiraApi`/`Authentication` gain `diagnostics` | M1, M2, M3 | compile |
| `#[deprecated]` on `search_issues`, `get_project_issues`, `get_projects`, `IssueSearchResult`, `AtlassianRemoteClient::search_issues`, `API_VERSION` | M5 | build-breaking for downstreams using `-D warnings` |
| `JIRA_VERIFY_SSL=false` becomes a hard configuration error; `JIRA_HOST_POLICY=loopback` is refused at parse | M1 | runtime |
| HTTPS required unless the host is a **literal** loopback address *and* `HostPolicy::Loopback` was set by a code call; `verify_ssl(false)` no longer relaxes the scheme check | M1 | runtime |
| CLI `--insecure` narrows to certificate verification on `https://` only; pointing the CLI at a local `http://` mock now needs `--host-policy loopback` | M1 | runtime |
| `HostPolicy` default rejects non-Atlassian hosts — a working Data Center URL needs `JIRA_HOST_POLICY=allowlist:<host>` | M1 | runtime |
| `encrypted-env` becomes a real cargo feature (in `full`). A downstream on `default-features = false, features = ["direct"]` loses `JIRA_API_TOKEN_ENCRYPTED`/`ENV_FILE_ENCRYPTED` support | M1 | **silent** runtime — a loud missing-feature error at call time, not a compile error |
| `AtlassianError::JiraApi.message` no longer contains the response body | M1 | **silent** runtime — no compile error; call out prominently |
| `From<reqwest::Error>` stops producing `Http{status_code: None}` for timeouts/connect failures | M3 | **silent** runtime |
| Base URLs normalize to a trailing slash; path segments are percent-encoded | M1 | runtime (a fix — Data Center context paths are dropped today) |
| `CreateIssueFields` stops emitting `"parent": null` etc. | M2 | wire shape |

Two rows the previous revision listed are **gone**, because `RichText` no longer touches `types.rs`
(see B): `IssueFields.description`/`CreateIssueFields.description` → `Option<RichText>`, and
`add_issue_comment(&str)` → `impl Into<CommentBody>`. Both were compile breaks that bought nothing on
the wire.

Recommendation, cheapest during this bump and expensive afterwards: add `#[non_exhaustive]` to every
new v3 response type and to `ActionOutcome`, so future additive fields are not another major bump.

### Not breaking, by design

`types.rs`, `JiraIssue`, `IssueFields` field set, `CreateIssueFields` field *types*,
`add_issue_comment`'s signature, `remote_client.rs`, and all Action **YAML config** remain
source-compatible — and, with the `RichText` scope corrected, that statement no longer contradicts the
breaking table above. `on_existing` defaults to `noop`, today's SHA-256/12 label auto-registers as the
first legacy rung, `migration.summary_fallback` defaults to `false`, `update.when_resolved` defaults to
today's behaviour, and `description_format` keeps `text` as its only accepted value. `v3` is a new
module reached via `client.v3()` and is deliberately **not** glob re-exported (`lib.rs:79` already
globs `types::*`).

**Three** Action behaviour changes need release notes, not two, and the third is the loudest:

1. `dry-run: true` starts actually working (M0) — previously silently ignored, so the Action called
   Jira for real (NF1).
2. A severity capture that does not match `^[a-z0-9][a-z0-9._-]{0,31}$` stops matching (M0).
3. **Dedupe identity moves from a content hash to per-GitHub-issue identity (M2).** Two GitHub issues
   sharing a title in one repository stop collapsing onto a single Jira issue, so Jira ticket volume
   rises for feeds that reuse titles — Dependabot advisories in particular. This is a behaviour change
   in the routing semantics, not a bug fix, and unlike (1) and (2) it changes what consumers see in
   Jira rather than what the Action does internally. Mitigation and the `dedupe.identity` opt-out are
   in workstream D; the M2 rollout guidance must call it out before the first run after cutover.

### Version contract fix — M5, task F7

Four identities diverge today (source `0.4.2`, tag `v0.4.3`, release `v0.4.3`, registry `0.4.2`), and
`v0.4.0`/`v0.4.3` were never published at all. Fix:

0. **`CHANGELOG.md` does not exist** (`find . -iname 'CHANGELOG*'` returns nothing), so the checker has
   nothing to assert against until F7 creates it and backfills `0.4.0`–`0.4.2` from git history. This
   is a prerequisite of item 1, not a consequence of it, and it is the likeliest place for F7 to
   overrun. If the schedule is tight, the defensible cut is to drop the CHANGELOG clause from the
   `0.5.0` contract and add it in a follow-up — do **not** leave the clause in the checker with no
   file behind it.
1. `scripts/check_release_contract.py` asserts manifest == internal path-dep == tag == CHANGELOG section
   == `action.yml`'s `# x-release-version:` marker (a comment, since Action metadata has no `version`
   field and an unknown top-level key is a needless risk). Gate in `ci.yml` quick-check **and** in
   `release.yml` prepare.
2. `release.yml`'s `gh release create` gains `--target "$GITHUB_SHA"` — without it, a
   `workflow_dispatch` mints the tag at the default branch head, which is exactly how `v0.4.3` came to
   point at a tree declaring `0.4.2`.
3. `auto-release.yml`'s protected-branch abort changes from "give up" to "open a release PR", so the
   manifest bump and the tag can no longer diverge.
4. **Do not retag or delete `v0.4.3`** — consumers may have pinned it. Bump to `0.5.0`, publish from a
   tag whose tree declares `0.5.0`, edit the mutable `v0.4.3` release notes to record that no crates.io
   package exists for it, and add CHANGELOG entries for the never-published `0.4.0`/`0.4.3`. The
   non-publication of `0.4.0`/`0.4.3` is an **execution-time check against the live crates.io index**,
   not a premise — it is not verifiable offline and this item edits public release notes on its basis.
5. `publish = false` on the action crate — assigned to **G0**, listed here only for completeness. It is
   defence-in-depth: `release.yml` publishes `SDK_PACKAGE` (`:364-372`) and `CLI_PACKAGE` (`:416-425`)
   only, so the action crate has never been published.
6. Document consumer pinning as `uses: ThreatFlux/threatflux-atlassian@<40-char sha> # v0.5.0`. This is
   only genuinely immutable **once F6 lands** — a SHA-pinned Docker action still rebuilds
   `action.Dockerfile` from that tree, so an unpinned `debian:bookworm-slim` leaves the pin half-immutable.
   F6 and F7 jointly satisfy that criterion.

## Acceptance Criteria Coverage

| # | Criterion | Milestone | Tasks | Notes |
|---|---|---|---|---|
| 1 | Jira v3 create/update/comment and enhanced search with typed models | M2 | A3, A5, B4, C3, C4 | Six of the issue's seven listed endpoints in full, **including `GET /issue/{key}/comment`** (A5, both directions). **Partial on one:** `GET /rest/api/3/project/search` is a thin model for canary preflight with no iteration — see the declined/reduced table in R7. |
| 2 | Typed ADF, multiline descriptions and comments, no plain-text fallback | M2 | B1, B2, B3, B4, B6 | Read as a **write-path** constraint; `RichText::Text` must remain a legal *read* variant for v2-era issues. Confirm — see Q5. |
| 3 | Enhanced JQL search automatically handles multiple pages | M2 | C3, C5 | Iteration delivered; `impl Stream` declined with rationale (R7). |
| 4 | Issue properties support source-event identity and reconciliation hashes | M2, M4 | A5, D6, D7 | Properties are **storage**, not the lookup key — see R2. |
| 5 | `on_existing` supports no-op, update, comment, update-plus-comment | M2, M4 | D9, D6, D7 | Per-rule YAML, not an `action.yml` input (one event can fan out to rules with different policies). **`D9` is the user-facing half** — the config crate has no `on_existing`, `migration` or `update` block today (`action/config.rs:9-64`), and in the previous revision no task owned adding them; `D6`/`D7` are the engine behind it. |
| 6 | Legacy SHA-256/16 and SHA-1/12 labels recognized during migration | M0, M2, M4, M5 | G2, D3, D9, D8a, G4b, D8b | **Blocked on Q1.** Today's SHA-256/12 is pinned exactly; the two legacy preimages are config-driven pending consumer confirmation. |
| 7 | Replayed and concurrent events do not create duplicate issues or comments | M3, M4, M5 | D6, D7, E4, E5, G4b, D8b | Replay: fully solved, issues **and** comments. Concurrency: issues **converge eventually, not prevented** (R1) — deterministic election on every reconciliation pass, demoting every non-winner the pass can see (D's `R-a`/`R-b`/`R-c`), so the asymmetric case repairs immediately and the symmetric-lag case repairs on the next delivery; **comments neither prevent nor converge** — detection only, removal out of scope. The L1-prevention half of the Q4 rewording is documentation owned by D8b, so the criterion does not close until M5. |
| 8 | 429, transient 5xx, timeout, retry exhaustion, ambiguous-write have deterministic tests | M3, M4 | **Closing:** G3b, D7, G4b. **Enabling (ship no test):** E1, E2, E3, E4, E5 | The five named fault paths are **23 enumerated cases** in G3b, not a half-clause — see the fault matrix in G. Rows 5 and 23 pin the 503-with-`Retry-After` vs 429 boundary on the `UnsafeWrite` column, which is where the previous revision's table replayed a create. **Retry exhaustion** now has a defined terminal surface (last classified error unchanged; `AmbiguousWrite` only when a write's probe never resolved) — see E; the previous revision named it nowhere outside this criterion's own text. `RecordingSleeper` + `Jitter::none()` keep the suite at zero wall-clock and make sleep sequences assertable. |
| 9 | Tokens, Basic headers, decrypted values, Jira bodies absent from normal logs/errors | M0, M1 | F1, F2, F5, F4, G6 | `SecretScanner` checks four encodings, incl. the base64 Basic blob. Covers NF2. |
| 10 | Credential destinations host-validated; production cannot disable TLS verification | M1 | F3, G7 | Reinterpreted as "env can never relax the scheme requirement or certificate verification; only an explicit code call can" — see R3. Scheme and host are one predicate, not two. |
| 11 | GitHub output values are safely encoded | M0 | F4, G5 | Heredoc + content-derived delimiter, plus the two upstream injection sources. |
| 12 | Container base images are digest-pinned | M0 | F6 | Tag retained alongside digest so Dependabot can bump. |
| 13 | Source, package, Action, tag, release versions have a consistent contract | M5 | F7, G9 | Includes the mechanical `--target` root cause and the `v0.4.3` reconciliation decision. |
| 14 | Action has a real-client Wiremock end-to-end test for search/create/reconcile | M4 | G4, G4b (+`G7` for the residual, M1) | Real `SdkJiraGateway` over reqwest, not a fake. Wiremock is already in-tree. **Scoped caveat:** the e2e path builds its client by code call with `HostPolicy::Loopback`, so it exercises reqwest and the full request/response path but **not** `build_client_from_env` (`action/lib.rs:79-89`) — by design, since criterion 10 requires that env path to be unable to reach loopback. G7 covers the gap directly: env-built configs cannot yield `HostPolicy::Loopback` or `verify_ssl == false`, and reject `http://` and non-Atlassian hosts. The only line neither covers is `AtlassianClient::new(config)` itself. |
| 15 | Non-production Jira Cloud canary proves project, issue type, priority, assignee, ADF, labels, update, comment, permissions | M5 | G8 | Greenfield — no workflow runs this Action today. Blocked on Q3 and on G0. **Nine named capabilities ⇒ nine named assertions** (table in G), across three dispatch phases plus teardown; the previous revision's "eight steps" left issue type, priority and labels unassigned. Assertions 2–4 need tenant-specific values from the reviewed `jira-canary` Environment, which is why Q3 gained an issue-type and priority prerequisite. |
| 16 | Consumers can pin the corrected Action to a full immutable commit SHA | M0, M5 | F6, F7, G9 | Coupled: F6 makes the pin immutable, F7 gives it a version identity. |

All 16 criteria are covered, each appearing exactly once above. Two (6, 15) carry an external blocker;
one (7) needs rewording to be truthfully claimable; one (1) ships a deliberate partial on a single
endpoint.

**Reading the Tasks column.** It names the tasks that *close* the criterion. Enabling work that ships
no test and no user-visible behaviour of its own is labelled as enabling rather than counted as
coverage — criterion 8 is where that distinction was previously misleading, since `E1` deletes a test
and `E2` builds types, so crediting them made a one-clause test deliverable look like five.

### Required migration fixtures

The issue lists eleven fixtures as a deliverable section of its own, and the previous revision had no
table for them — coverage had to be reconstructed from prose across eight tasks. All eleven are owned;
one carries the same Q1 blocker as criterion 6.

| # | Fixture | Milestone | Tasks | Notes |
|---|---|---|---|---|
| 1 | Existing GitHub issue and Dependabot-created issue payloads | M0, M4 | G1, G2, G4b | The existing `github.rs:43-57` Dependabot literal is a 12-line hand-trimmed stub with none of the identity fields; `G1` **replaces** it with a realistic `issues.opened` delivery and `G4b` drives the shipped `dependabot-high.yml` against it end-to-end, exercising the `actor_in` gate (`rules.rs:27`). |
| 2 | Exact ADF request snapshots, including hard breaks and empty descriptions | M2 | B1, B3, B6, G3a | Four named goldens in `G3a`. "Exact" means **semantically** exact (sorted `serde_json::Map`), per G's golden-comparison rule. The empty case asserts `None` and **no `description` key on the wire**, which is `B6`'s whitespace-only rule. |
| 3 | All legacy and new dedupe formats | M0, M2, M4 | G2, D3, D9, D8a, D6, G4b | **Blocked on Q1** for the two legacy preimages only. `G2` pins today's SHA-256/12 byte-for-byte *before* D touches anything; `D3` reproduces it and adds the config-driven ladder; `D8a` prints every rung for a real payload. |
| 4 | No issue → create | M4 | D6, G4b | Pure-planner case. |
| 5 | Existing current issue → no-op | M4 | D6, G4b | Pure-planner case; content-equal hash ⇒ no PUT at all. |
| 6 | Existing stale issue → update/comment exactly once | M4 | D6, D7, G4b | "Exactly once" is a journal assertion, not a return-value assertion. |
| 7 | Replayed event → no duplicate comment | M3, M4 | D6, D7, E5, G4b | Deterministic marker over **source text**, not rendered ADF (R6) — a rendered hash never matches on read-back and every test would pass while duplicating. |
| 8 | Ambiguous create failure → search and recover | M3, M4 | E4, G3b, D7, G4b | `G3b` rows 19–22 own the retry-layer half (`IndexBacked` probe, never replay); `D7`'s `reconcile_after_ambiguous_create` owns the Action half. |
| 9 | Concurrent deliveries for the same event | M4 | D6, D7, G4b | All verification outcomes — 0 rows, 1-row-self, 1-row-other in both contexts, ≥2 rows with self ranking first and not — **plus the two-run pairs**: asymmetric (A sees 2 rows, B sees 1 ⇒ one label survives) and symmetric-lag (both see 1 ⇒ two labels survive, both statuses `unverified-self-only`, next delivery converges). The four single-run cases all pass against a non-converging implementation, which is why the pairs exist. Plus the test that **pins duplicate comments** as a documented limit rather than asserting a guarantee that does not exist. |
| 10 | Multi-page search | M2 | C5, G3a | One case per clause of the six-clause termination contract, including the empty-page-with-token bug and the expired-token 400 on page 2. |
| 11 | Redaction and hostile output values | M0, M1 | G2, G5, G6 | `G2` supplies the hostile corpus (CRLF, lone CR, literal `ghadelimiter_`, `${JIRA_API_TOKEN}`, JQL metacharacters, 4-byte emoji, 32 KiB body, >255-char title); `G5` drives the real GitHub kv + `<<DELIM` re-parser; `G6` sweeps four secret encodings. |

Rows 3–7 and 9 — six of the eleven — route through `D6`'s *decide*/*apply* split, so they are
table-driven unit tests over a pure function with no mock server: rows 4–7 entirely, plus the
`legacy → adopt` decision in row 3 and the `duplicate → elect` decision in row 9, whose *execution* is
`D7`'s. That is workstream D's strongest structural claim and the reason the issue's fixture matrix is
tractable at all. `G4b` appears against eight rows because it is the single
e2e suite that re-runs them through a real `SdkJiraGateway`; the unit-level coverage is what makes the
e2e list short.

## Risks and Open Questions

### Needs a maintainer decision before work starts

**Q1 — Supply the legacy dedupe label formats, or descope criterion 6.** SHA-256/16 and SHA-1/12 are
not verifiable from this repo: `sha1` appears exactly once, in a config *rejection* test
(`action/config.rs:583`), with no dependency and no reference in docs, examples, or workflows. Their
preimage (field order, joiner, whether the prefix participates in the hash) is unknown. Building a
compat layer against a guess is worse than building nothing. **Required input: the consumer's
label-generation source, or ≥3 real label strings per scheme plus the events that produced them.**
Mitigations already in the plan (config-driven preimages, the `dedupe-label` CLI) reduce a
release-cycle mistake to a config edit, but do not remove the need for the answer. ~3.5 days (G2 + D3)
is at risk.

**Q2 — `encrypted-env`: optional, or out of `full`?** The issue says "make optional **or** remove from
the Action graph" as if equivalent. They are not. Making it optional-but-in-`full` (this plan) keeps
default consumers source-compatible and removes `fluxencrypt`/`rsa` from the *Action* graph, but does
**not** discharge RUSTSEC-2023-0071 for the published SDK/CLI packages, because `rsa 0.9.10` stays in
the default graph and the advisory has `patched = []` (no fixed version exists). Genuinely clearing the
advisory means taking it out of `full`, which breaks default consumers. Recommendation: ship `0.5.0`
with it in `full`, schedule removal for `0.6.0` behind a deprecation notice. The issue must make this
call explicitly.

**Q3 — Canary tenant, and whether the canary token gets delete.** `DELETE /rest/api/3/issue` requires
project-admin, which is exactly the permission the criterion asks us to *prove* the integration needs.
Recommendation: least-privilege token **without** delete, transition to Done, dedicated throwaway
project, monthly bulk purge. Also needed: a Jira Cloud tenant, a project key, an **issue type name and a
priority name that both exist in that project's schemes** (canary assertions 2 and 3 — a
`priority_by_severity` value the tenant does not define fails the run, not the assertion), an assignee accountId, and
a reviewed `jira-canary` GitHub Environment. Note `action.yml:36-38` is `using: docker`, so `uses: ./`
rebuilds the container from source on every invocation — use the weekly schedule with buildx cache, or
consume the GHCR image `docker.yml` already publishes.

**Q4 — Is criterion 7 acceptable as reworded?** Proposed: *"Replayed events never duplicate an issue or
a comment. Concurrent events converge on a single canonical Jira **issue**: any reconciliation pass
that observes more than one canonically-labelled issue elects a deterministic winner and demotes the
rest, linking and reporting them. Convergence is **eventual and delivery-driven** — while index lag
hides the duplicate from every run, more than one issue may carry the canonical label, and each such
run reports `unverified-self-only` so a workflow can alert on it. Duplicate **comments** under true
concurrency are prevented only by the documented workflow-level concurrency group; the Action detects
and reports them but does not remove them."* See R1 and the concurrency layers in workstream D.

Two clauses are deliberate and neither was in the previous wording. **"Eventual and delivery-driven"**
is the honest limit of `R-c`: the mechanism repairs a duplicate on the first pass that can see both
rows, which is immediate in the asymmetric case and deferred to the next delivery in the symmetric-lag
case. The previous revision's proposed wording ("converge to a single canonical Jira issue, with
duplicates detected, linked, and reported") claimed more than the L2 table delivered, because that
table had no mechanism by which a run that saw only itself ever gave up its label. **The comment
clause** is separated because the previous wording left the reader to assume comments were covered by
the same mechanism. They are not — there is nothing to elect between two comments, and removal would
need delete permission that Q3 deliberately withholds.

**Q5 — Confirm criterion 2 constrains the write path only.** Under v3 a strict read-side reading is
impossible: `RichText::Text` must remain a legal read variant because v2-era issues and the
compatibility search path still return strings.

**Q6 — Delete "CounterMeasure" from the issue.** It is a leaked consumer-specific name in an issue whose
own "Public/private boundary" section says consumer specifics stay consumer-owned.

### Cross-workstream hazards

**R1 — Criterion 7 is not achievable as written.** Jira Cloud has no atomic create-if-absent, no unique
constraint on labels, and JQL is an eventually-consistent Lucene index. Two truly simultaneous
deliveries can both create. Index lag also affects the *pre*-create search: two deliveries 200 ms apart
both miss even without true simultaneity. Prevention is workflow-level (L1); the Action provides
**eventual** convergence (L3) **for issues only**. Shipping against the checkbox as written would mean
claiming a guarantee that does not exist.

There is also no atomic claim available to build one from. An issue property would be the natural
lock, but it requires an issue id — which is exactly what a create needs and does not yet have — and
R2 establishes that properties are not JQL-discoverable for a plain API-token integration anyway. A
Forge/Connect app declaring `jiraEntityProperties` could index one; a plain integration cannot. So the
honest statement is: the retry layer contributes **zero** duplicates (E4's `IndexBacked` rule, under
R10 row 7's 429 premise), and the residual duplicate window is exactly the index-visibility gap between
two concurrent deliveries. L1 is the only layer that stops that window opening; `R-c`'s repairing
election is what closes it afterwards — in the same pass when one run can see both issues, otherwise on
the next delivery for that identity.

**R2 — Issue properties cannot drive dedupe *discovery*.** The issue lists property get/set as though
properties were queryable. Jira Cloud only indexes entity properties for JQL when an app declares a
`jiraEntityProperties` module; properties written by a plain API-token integration are not indexed.
Discovery must stay label-based; properties confirm identity and content hashes on an already-known
key. A5 is built for that split. Prove it with the canary before D commits.

**R3 — The e2e test seam and the TLS/host hardening are mutually exclusive under a literal reading, and
the escape hatch has to be on the *scheme*, not the host.** The only way to point a client at a mock
today is `http://127.0.0.1:PORT` + `verify_ssl(false)`, which survives `validate()` **because**
`config.rs:179` gates the HTTPS check on `&& self.verify_ssl`. The previous revision's diagnosis —
"criteria 10 and 14 both die unless `HostPolicy::Loopback` ships in F3" — named the wrong blocker.
`HostPolicy` constrains the host; `config.rs:179` constrains the scheme. Adding a host policy while
dropping the conjunction unconditionally still rejects every `http://` URL, so it would break the five
existing wiremock tests inside M1 and leave criterion 14 with no reachable mock. The fix is the single
combined predicate in F3 — HTTPS required *unless* literal loopback **and** `HostPolicy::Loopback` set
by a code call — with `HostPolicy::Loopback` unreachable from the environment. That is what makes 10
and 14 simultaneously satisfiable rather than mutually exclusive.

Residual, stated rather than hidden: because the env can never produce `HostPolicy::Loopback`,
`build_client_from_env` is not on the e2e path. G7 covers it with direct env-reachability tests
instead of pretending the e2e test reaches it (criterion 14's coverage row records this).

Rejected alternatives, each for a concrete reason: a `dev-transport` cargo feature would be **on**
under CI's `--all-features` clippy and test runs (`ci.yml:71,149`) and could mask a production-path
regression, plus it doubles the powerset and forces a `check_docs.py` FEATURES edit; `#[cfg(test)]` is
invisible to `tests/*.rs`; `#[doc(hidden)]` is still compiled into release builds. A code-call-gated
enum variant has none of these problems: it is ordinary public API, visible to `tests/*.rs`, compiled
identically in all configurations, and refused by the env parser.

**R4 — F2 and E1 rewrite the same match arm** (`client.rs:123-138`). They cannot run in parallel. F2
lands first and extracts `map_error_response(status, retry_after, body, detail)` as the seam; E1 then
only adds classification. Similarly, **F4 and D4 both rewrite `write_outputs`** — F4 first.

**R5 — `check_docs.py` is a blocking gate that fights this work** (NF5). Any v3 doc change requires
editing the checker in the same PR; any new cargo feature requires an exactly-ordered README FEATURES
table edit, because `check_features` compares `re.findall(r"^\| \`([^\`]+)\` \|", …)` against
`list(sdk_manifest["features"])` **positionally**.

The previous revision claimed this plan adds "**zero** new cargo features". That is false: **F5 adds
`encrypted-env` and puts it in `full`.** Today's manifest is `default = ["full"]`,
`full = ["direct","remote"]`, plus the no-op markers `direct`/`remote`/`ssl-verification`, so
`encrypted-env` is the first real feature in the crate. It doubles
`cargo hack --feature-powerset --no-dev-deps` (`ci.yml:223`) and forces the ordered README edit — both
costs are now inside F5's scope line rather than denied. The accurate statement is narrower and still
useful: this plan declines a feature **everywhere the feature would be optional** (`impl Stream` in
C5/R7, a v3 gate in workstream A, a `dev-transport` seam in R3), and accepts exactly one where the
issue's own requirement — removing `fluxencrypt`/`rsa` from the Action graph — cannot be met without
it.

The alternative the adversarial review proposed — move the fluxencrypt decrypt path out of the SDK
into the CLI — is **worse and is declined**. `AtlassianConfig::from_env*` resolves
`JIRA_USERNAME_ENCRYPTED`/`JIRA_API_TOKEN_ENCRYPTED`/`ENV_FILE_ENCRYPTED` (`config.rs:388-450`), and
`build_client_from_env` (`action/lib.rs:79-89`) goes through it, so relocating the code would silently
delete an advertised capability (`docs/SDK_CONFIGURATION.md:53-87`) from both the SDK and the Action
rather than making it optional. A feature flag keeps the capability and makes its dependency graph
opt-out; that is the trade the issue actually asked for. Q2 still owns the `full` membership call.

**R6 — The comment reconciliation marker must not be a hash over rendered ADF.** ADF serialization is
not canonical (key order, mark ordering), so a rendered hash never matches on read-back — every probe
reports "not applied" and produces exactly the duplicate comments the fixtures exist to catch, while
all tests pass because both sides use the same wrong hash. Marker must be over source text or an
explicit embedded token.

**R7 — Scope items worth declining.** `impl Stream` (new dependency, self-referential future, feature
matrix cost, no consumer need). `/project/search` iteration (nothing in this repo resolves projects;
ship a thin model for canary preflight only). An `adf_to_plain_text` downgrade (re-creates the
behaviour criterion 2 eliminates). A workspace coverage threshold (the 64.35% baseline is held down by
code this issue never touches). Relocating the fluxencrypt decrypt path to the CLI (R5).

**Declined, reduced or restored against the issue's own endpoint list**, so nothing in it is absorbed
silently. One item the previous revision left ambiguous is now delivered in full; one is a deliberate
reduction and is the partial recorded on criterion 1:

| Issue item | Disposition |
|---|---|
| `GET /rest/api/3/issue/{key}/comment` | **Delivered in full** — A5 now names `get_comments` explicitly on both directions. The previous revision's undifferentiated "v3 comments" left the read side ambiguous while D6's marker mint/scan and E5's probe both depend on it. |
| `GET /rest/api/3/project/search` | **Reduced**: a thin model for canary preflight, no iteration. Nothing in this repo resolves projects. Recorded here rather than only in R7 so criterion 1's coverage row is read against a visible partial. |

Scope **additions** the issue did not ask for. Every one of these is **optional** against the issue as
written, so each is listed with its cost and what cutting it forfeits, ordered cut-first to keep-last:

| Addition | Owner | Cost | Cut first? |
|---|---|---|---|
| CLI `--body-adf-file`, `--fields`, `--page-token`, `--all`, `--max-pages`, `issue-count` | B7, part of C6 | 0.5 d outright + ~0.3 d inside C6 | **Yes — cut first.** New public surface with the weakest link to any acceptance criterion; nothing else in the plan depends on it. |
| `codecov.yml` (`patch: 85%`) + `scripts/check_supply_chain.py` | part of G9 | ~0.5 d inside G9 | **Yes.** CI enforcement, not capability. Already outside the reduced-scope cut. |
| `dedupe.identity` config key | part of D9 | ~0.2 d | Optional. Cutting it removes the only opt-out from the alert-volume change in D, leaving a legacy rung as the sole workaround. |
| `migration.adopt` | part of D9/D6 | ~0.3 d | Optional, but cutting it makes the legacy rungs permanent and "migration" a misnomer — the ladder never retires. |
| `update.when_resolved` | part of D9/D6 | ~0.2 d | Optional, but it is the only handle on NF4 (a closed Jira issue silencing a genuine alert forever). |
| `dedupe-label` CLI validator | D8a | 0.5 d | Optional by the issue's letter; **keep.** It is Q1's only mitigation and the sole way to diff generated labels against live Jira before cutover. |
| `scripts/check_image_pins.py` | part of F6 | ~0.1 d | Optional; keep. Criterion 12 is a one-time fix without it and a maintained property with it, at near-zero cost. |

Roughly **1.0 d is cuttable outright** (`D8a`, `B7`); the rest are fractions of tasks that also carry
required work, so cutting them saves less than the row suggests and costs a re-estimate of the parent
task.

**R8 — Summary fallback is a correctness hazard, not just an injection one.** JQL `~` is a stemmed,
fuzzy Lucene word match, so it produces false positives that silently *suppress* genuine alerts.
Hardened escaping makes it safe, not precise. It must be opt-in, off by default, length-capped, and
followed by an exact client-side `summary ==` comparison before it may suppress a create.

**R9 — Enhanced search returns no `total`.** Reconciliation logic wanting "how many duplicates exist"
must paginate or call `/search/approximate-count` (approximate, as named). The Action's implicit
`total` signal disappears; D must not build exactness on it.

Relatedly, and corrected from the previous revision: the `reconcileIssues` request field (up to 50
issue IDs) forces index consistency **for the IDs you pass, and only those**. The only ID you can pass
after your own create is your own, so `reconcileIssues` guarantees *self*-visibility and does nothing
whatever for a competitor's issue created milliseconds earlier. The previous revision described it as
"what makes D7's post-create verification search actually see the issue it just created" — which is
the one case that needs no help, and which, combined with treating a one-row result as an election
outcome, is how two concurrent runs could each elect themselves. It is in `SearchRequest` because
self-visibility is still worth having (it converts a 0-row result into a 1-row result, which is a
different and better-labelled state), not because it solves concurrency. D's rule `R-b` leans on the
same guarantee in the other direction: because self-visibility *is* guaranteed, a post-create result
that omits self is evidence the search is untrustworthy rather than evidence that another issue won.
See D's L2 table.

**R10 — Doc-derived, not code-verified.** Seven load-bearing facts are asserted from documentation or
platform behaviour rather than from code in this repo. All are canary, fault-injection or
throwaway-workflow assertions, and none may be treated as a premise:

| # | Assumption | Verification | If wrong |
|---|---|---|---|
| 1 | `/search/jql`'s `fields` default (why `SearchRequest::validate` rejects an empty `fields` list) | canary | C3 default changes |
| 2 | The `maxResults` ceiling | canary | C3/C5 caps change |
| 3 | JQL's accepted escape sequences | canary | **C1's escape table changes** — highest-value check |
| 4 | `nextPageToken` absence is the authoritative end-of-pages signal | canary | C5 clause (1) changes |
| 5 | **NF1: GitHub sets container-action inputs as `INPUT_` + name uppercased with *spaces only* replaced by `_`, leaving hyphens intact** | a throwaway `workflow_dispatch` job invoking the action with `with: config-path: /nonexistent` and dumping `env \| grep ^INPUT_` — ten minutes | G0's fix is wrong, M0's headline value evaporates, criterion 15 stays blocked |
| 6 | An expired `/search/jql` page token surfaces as a 400 distinguishable from a JQL error | canary; C5's classifier is deliberately **structural** (page index > 0 + Jira-issued token) so it survives being wrong about the message text | C5 clause (6) reports `PageTokenExpired` for some JQL errors on page ≥ 2 — a labelling error, not a correctness one |
| 7 | **A Jira Cloud 429 is emitted by the rate limiter before the request is processed**, so a 429 on a POST means nothing was created. This is the only premise under E's "the retry layer never creates a duplicate" | canary (drive a create into the rate limit and confirm no issue was created) plus the G3b row 23 boundary test | 429 must be demoted from `Throttled` to `Ambiguous` on the `UnsafeWrite` column — one classification row and one G3b case, at the cost of turning routine throttling on a create into `AmbiguousWrite` |

Rows 5 and 7 are the ones the previous revision omitted. Row 7 was worse than omitted: the previous
revision did not merely assert the 429 premise, it silently extended it to 503-with-`Retry-After` and
replayed both on creates. Row 5 was a load-bearing claim asserted as fact while genuinely doc-derived
facts each got a verification step. NF1 drives "fix
first", the whole M0 value proposition, and the criterion-15 blocker. It matches the runner's
documented behaviour and `@actions/core`'s `name.replace(/ /g,'_').toUpperCase()`, but it is worth ten
minutes to pin. Related and worth stating with it: the shipped
`examples/workflows/dependabot-jira-issues.yml:24` passes `config-path:` with a value identical to the
code default, which is exactly why the bug has gone unnoticed — and why **no existing consumer will
see a regression when it is fixed**.

Two further assumptions carry execution-time checks rather than canary ones: that `0.4.0`/`0.4.3` were
never published to crates.io (F7 item 4 edits public release notes on that basis and is not checkable
offline), and that dependabot-core's Docker fetcher matches `action.Dockerfile` — verify on the first
Dependabot run after F6 pins the digests.

**R11 — Existing `.expect(1)` wiremock mounts** (`client.rs:1120,1130,…`) will trip the moment a
retryable status is induced. G3a converts them to journal assertions; do not let a rebase silently
change those counts.

## Estimate

**Bottom-up total: 72.5 engineer-days** (70–80 with normal variance), against the issue's 16–25.
Longest serial chain 21.5 d (see Critical path).

| Milestone | Tasks | Days |
|---|---|---|
| M0 — Independent fixes and test foundation | F0, G0, C1, C2, F4, G5, F6, G1, G2 | 10.0 |
| M1 — SDK hardening and event identity | A1, F1, F2, F3, F5, G6, G7, D2 | 10.5 |
| M2 — Jira v3, ADF, enhanced search, dedupe identity | B1, B2, B3, A3, A5, B4, B6, C3, C4, C5, D3, D8a, D9, G3a | 21.5 |
| M3 — Retry and reconcile-before-retry | E1, E2, E3, E4, E5, E6, G3b | 9.5 |
| M4 — Action reconciliation | D4, G4, D6, D7, G4b, E7 | 12.0 |
| M5 — Deprecation, release contract, canary, docs | C6, A6, B7, D8b, F7, F8, G8, G9 | 9.0 |
| **Total** | **52 tasks** | **72.5** |

Three numbers have to agree and do: the per-task estimates in the seven workstream tables sum to
**72.5**; the tasks actually placed in milestones sum to **72.5**; the milestone rows above sum to
**72.5**. Per-workstream: A 6.0, B 8.0, C 8.5, D 13.5, E 9.5, F 10.0, G 17.0.

The figure has moved once per revision, each time for a named reason. The first published 71.0 / 70.5 /
69.5 for those same three quantities: the 1.5 d gap was unscheduled `D8` and the remaining 0.5 d was
two hand-carried rounding errors in the M4 and M5 rows, which brought all three to 71.0. The second
added `D9` (1.0 d, M2) — the Action YAML config surface criterion 5 asks for and no task owned — taking
all three to 72.0. This revision moves three estimates and nets **+0.5**:

| Task | Was | Now | Why |
|---|---|---|---|
| `D7` | 2.5 | **3.0** | The apply path now demotes every non-winner a pass can see and runs the election on every pass, not only after a create (`R-c`) — the mechanism that makes the asymmetric concurrency case converge. Critical path, so this is the whole of the +0.5 on the 21.5 d chain. |
| `C6` | 1.0 | **1.5** | Sole owner of the search-method deprecations plus 12 verified edit sites (9 call sites + 3 rustdoc examples) under `-D warnings`. |
| `A6` | 1.5 | **1.0** | Loses the method deprecations it duplicated from `C6`; keeps `API_VERSION` and the `check_docs.py` rewrite. |

`C6` and `A6` are equal and opposite by construction — the previous revision double-booked the same
deprecation work in both — so M5 and the total are unaffected by that pair. Workstream A moves 6.5 →
6.0 and C moves 8.0 → 8.5 accordingly.

Three tasks absorbed scope during review without a re-estimate and are therefore where the 70–80 band
gets spent first, in this order: **`F7` (1.5)** now creates `CHANGELOG.md` and backfills three releases
before its checker can assert anything — it carries an explicit descope (drop the CHANGELOG clause from
the `0.5.0` contract); **`F5` (1.0)** now owns the doubled `cargo hack` powerset, the positionally
compared README FEATURES table and the four-site RUSTSEC consolidation; **`G3b` (1.0)** now owns 23
enumerated cases and is only that cheap if `G1`'s harness lands complete. None is on the critical path,
so an overrun in any of them costs days on the total and nothing on the 21.5 d chain. Two further
candidates *are* critical and were deliberately not re-priced: `D6` (2.5) absorbed the `R-a`/`R-b`/`R-c`
election decisions and stayed at 2.5 because those are pure decisions over `(created_this_run, rows)` —
the execution they imply is what moved `D7` to 3.0; and `G4b` (1.5) absorbed the asymmetric and
symmetric-lag two-run pairs, which are two more scripted `JiraMock` scenarios in a suite that already
has the harness. An overrun in either is 1:1 wall clock, so they are the two to watch.

The raw sum of the seven independent workstream designs was 81 days; de-duplicating the overlapping
ownership (ADF types, enhanced-search models, the JQL module, the Action gateway seam, the `INPUT_*`
fix, the fixture corpus) removed 10, giving 71.0. `D9`, which none of the seven original designs
contained because each assumed another owned the config schema, added 1.0; `D7`'s repairing election
added the last 0.5.

### Why the issue's estimate is ~3x low

The issue's per-line split assumes additive work. Six items are construction, not addition, and none of
them is named in the issue:

1. **There is no Action test seam.** `TestJiraHook` holds one canned search and one canned create,
   cannot sequence responses across attempts, has no representation for update/comment/property calls,
   and is `#[cfg(test)]` so `tests/*.rs` cannot see it. Every test in the acceptance criteria needs a
   mechanism it cannot provide. That is a migration of 5 tests plus a new trait, not a fixture file.
2. **There are zero fixtures in the repo** — no `*.json`, no `fixtures/`, no snapshot library, and 54
   inline literals that all break the moment the event schema widens. The corpus is built from nothing,
   and it has to land *before* the schema change to be worth anything.
3. **Retry-After, 5xx, and timeout tests are blocked on a type change.** `ensure_success` consumes the
   `Response` with `.text()` before headers can be read, and `RateLimit` carries only a `String`. The
   "deterministic tests" line item is strictly downstream of reworking `ensure_success` and
   `AtlassianError` — it cannot be scheduled in parallel with the retry work.
4. **The v3 move is gated on the ADF model existing first.** `RichText` is the description and
   comment-body type of every v3 request and response type, so the whole ADF workstream (B1 → B2) is a
   prerequisite for the endpoint switch rather than a parallel track. The issue's line split prices v3
   endpoints and ADF as independent items; they are strictly serial.
5. **The canary is greenfield infrastructure.** No workflow runs this Action at all today
   (`grep 'uses: ./'` over `.github/workflows/` returns nothing) and `docker.yml` never builds
   `action.Dockerfile`. New workflow, real tenant, new secrets, teardown policy.
6. **Redaction is a breaking refactor of a published crate**, not a set of `Debug` impls — public
   fields, derived `Serialize`, direct field mutation in the CLI, and an existing test asserting token
   serialization as a contract.

Two of the issue's line items are also mis-sized in the other direction: removing the Clippy
suppression is ~1 day, not the multi-day cleanup the warning count suggests (NF7), and Wiremock does not
need to be introduced (it is already proven in-tree).

### Reduced scope, if 72.5 days is not available

A defensible **44.0-day** cut that still leaves `main` materially safer. Every line respects the
dependency table; the previous revision's ~42-day cut did not, and it also priced M0–M2 from the old
under-counted milestone rows:

| Keep | Days | Running |
|---|---|---|
| **M0 + M1** in full — the entire security surface plus the `dry-run` fix, the JQL injection sinks, digest pins, and the widened event schema | 20.5 | 20.5 |
| **M2** in full — v3, ADF, enhanced search, and (already inside M2) `D3` + `D8a`, the dedupe identity and its validator CLI | 21.5 | 42.0 |
| less `D9` — the reconciliation config schema, which has no engine behind it until `D6`/`D7` | −1.0 | 41.0 |
| `D4` — multi-rule execution and additive outputs; fixes half of NF3 by flushing outputs before propagating an error | 1.5 | 42.5 |
| `F7` — release contract (`F6` is already in M0) | 1.5 | **44.0** |

`D9` is the one thing dropped out of an otherwise-full M2, and dropping it is the safer choice rather
than a saving: shipping `on_existing` / `migration` / `update` as *accepted config* while `D6`/`D7` are
deferred would let a consumer set `on_existing: update` and get a silent no-op. If `D9` is kept anyway
(45.0 d), its `validate()` must reject every `on_existing` value except `noop` until the engine lands.

- Defer **M3** (retry) — nothing retries today, so deferring holds the status quo rather than
  regressing. **But `E4` cannot be cherry-picked for 2 d.** The previous revision proposed keeping it
  alone to close NF3; `E4` depends on `E3` → `E2` → `E1`, and its `CreatedButUnread` variant is
  introduced by `E1` and executed by `E2`/`E3`. Taking the NF3 create-path fix therefore costs
  `E1`+`E2`+`E3`+`E4` = **6.5 d**, bringing the cut to **50.5 d**. The alternative is to descope `E4` to
  `create_issue_raw` alone (one POST, no re-GET, no retry executor, ~0.5 d), which removes the
  double-create-on-rerun path without the retry machinery. Pick one explicitly; do not budget 2 d.
- Defer **M4** reconciliation to a follow-up issue. `D2` and `D3` are already bought in M0–M2 above, so
  the follow-up starts from a stable identity rather than from scratch.
- Defer the canary (criterion 15) and the legacy-dedupe migration (criterion 6) pending Q1 and Q3.

That closes **9 of 16 criteria outright** — 1, 2, 3, 9, 10, 11, 12, 13, 16 — leaves criterion 4
**partial** (`A5` ships issue properties, but `D6`/`D7` supply the reconciliation hashes), and defers
**six**: 5, 6, 7, 8, 14, 15. Criterion 1 closes with the same `/project/search` reduction the full plan
carries, not an extra one. Criterion 11 closes because `G5` sits in M0 beside `F4`; it did not in the
previous revision, which is what made shipping the `GITHUB_OUTPUT` encoder untested the default cut.
Note that criterion 8 is *forfeited* by the M3 deferral rather than held at status quo: its
deterministic fault tests are `G3b`, which lives in M3. The previous revision's "closes 11 of 16,
defers five" counted criterion 4 as closed and criterion 8 as unaffected.

Criteria 13 and 16 close on `F6`+`F7`; `G9`, which their coverage rows also credit, is CI plumbing
(`e2e` job, `codecov.yml`, `check_supply_chain.py`) and is not in this cut. Add `G9` (1.0 d) if the CI
enforcement is wanted with the contract.
