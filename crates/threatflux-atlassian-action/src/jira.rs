//! The Jira request the Action sends, and the query it looks an issue up with.
//!
//! # The create goes out over v3, as ADF
//!
//! [`build_create_issue_request`] builds a
//! [`V3CreateIssueRequest`], not the v2
//! [`CreateIssueRequest`](threatflux_atlassian_sdk::CreateIssueRequest). The v2
//! model carries a description as a `String`, so an Action built on it can only
//! ever send Jira plain text -- exactly the fallback typed ADF exists to
//! eliminate. The v2 types stay frozen for the SDK consumers that already
//! depend on them; the Action reaches ADF through the parallel v3 model.
//!
//! The description is converted from the *rendered template* with
//! [`text_to_adf_bounded`], which interprets no markup at all. That is the
//! property that makes the conversion safe on this path: the template
//! interpolates `{{ issue.body }}`, so the text is written by whoever opened the
//! GitHub issue, and it must never re-enter a parser on its way to Jira. Every
//! character it holds ends up inside the string of a `text` node, where it can
//! only ever be read as characters. The matching config-side rule is that
//! `description_format` admits `text` and nothing else -- see
//! [`crate::config`] and the rejection test that carries the rationale.
//!
//! # Both fields are bounded
//!
//! [`JiraFieldLimits`] holds the two ceilings, so there is one truncation policy
//! rather than one per field:
//!
//! - **`summary`** is capped at [`DEFAULT_MAX_SUMMARY_CHARS`] characters. Jira
//!   Cloud rejects a longer one with a 400, and the shipped Dependabot template
//!   prepends about twenty characters to a GitHub title that reaches 256 -- so
//!   an ordinary long title is a guaranteed failed run with no hostile input
//!   involved. The cut lands on a character boundary and is marked with
//!   [`TRUNCATION_MARKER`].
//! - **`description`** is bounded by [`AdfLimits`]. ADF costs tens of bytes of
//!   JSON per node, so a 65 KB issue body would otherwise produce a request of
//!   well over a megabyte.
//!
//! Both truncate rather than reject, for the same reason: this is an alerting
//! path, and refusing an over-long body would let its author delete the alert.

use crate::config::RuleConfig;
use crate::github::GitHubIssueEvent;
use crate::rules::{render_template, RuleMatch};
use anyhow::{Context, Result};
use threatflux_atlassian_sdk::adf::{
    text_to_adf_bounded, AdfBlock, AdfDocument, AdfInline, AdfLimits, RichText, TRUNCATION_MARKER,
};
use threatflux_atlassian_sdk::jql::JqlBuilder;
use threatflux_atlassian_sdk::v3::{
    V3CreateIssueFields, V3CreateIssueRequest, V3NamedRef, V3ProjectRef, V3User,
};

/// Characters Jira Cloud accepts in an issue `summary`.
///
/// Jira answers a longer one with a 400 and no issue. A GitHub issue title runs
/// to 256 characters on its own, before a template prefix such as
/// `[Dependabot][Critical] ` adds any more, so this ceiling is reachable without
/// anybody trying.
pub const DEFAULT_MAX_SUMMARY_CHARS: usize = 255;

/// What [`build_create_issue_request_with_limits`] will let a request grow to.
///
/// One type for both bounded fields, so the Action has a single truncation
/// policy: over the limit is cut and marked, never refused. `#[non_exhaustive]`,
/// so a field added later is not a breaking change -- build one from
/// [`DEFAULT`](Self::DEFAULT) and the `with_*` methods rather than from a struct
/// literal.
///
/// ```
/// use threatflux_atlassian_action::jira::JiraFieldLimits;
///
/// let tight = JiraFieldLimits::DEFAULT.with_max_summary_chars(80);
/// assert_eq!(tight.max_summary_chars, 80);
/// assert_eq!(tight.description, JiraFieldLimits::DEFAULT.description);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct JiraFieldLimits {
    /// Largest number of `char`s the rendered `summary` may carry.
    pub max_summary_chars: usize,
    /// What the rendered description may grow to once it is ADF.
    pub description: AdfLimits,
}

impl JiraFieldLimits {
    /// [`DEFAULT_MAX_SUMMARY_CHARS`] characters of summary and
    /// [`AdfLimits::DEFAULT`] of description -- what
    /// [`build_create_issue_request`] applies.
    pub const DEFAULT: Self = Self {
        max_summary_chars: DEFAULT_MAX_SUMMARY_CHARS,
        description: AdfLimits::DEFAULT,
    };

    /// These limits with [`max_summary_chars`](Self::max_summary_chars)
    /// replaced.
    #[must_use]
    pub const fn with_max_summary_chars(mut self, max_summary_chars: usize) -> Self {
        self.max_summary_chars = max_summary_chars;
        self
    }

    /// These limits with [`description`](Self::description) replaced.
    #[must_use]
    pub const fn with_description(mut self, description: AdfLimits) -> Self {
        self.description = description;
        self
    }
}

impl Default for JiraFieldLimits {
    /// [`JiraFieldLimits::DEFAULT`].
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// `value` cut to at most `max_chars` characters, on a character boundary.
///
/// The budget is spent in `char`s and the cut is taken with
/// [`str::chars`], so a multi-byte character at the boundary is kept whole or
/// dropped whole -- never split into invalid UTF-8, and never a panic from a
/// byte index landing inside one. A value that was cut ends with
/// [`TRUNCATION_MARKER`], and the marker is charged to the budget rather than
/// added on top of it, so the result holds at most `max_chars` characters even
/// when it was truncated. This is the SDK's own marker and policy, so a cut
/// summary and a cut description read the same way.
///
/// A `max_chars` of zero yields an empty string; the caller decides what an
/// empty field means.
#[must_use]
pub fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }

    let mut truncated: String = value.chars().take(max_chars - 1).collect();
    truncated.push(TRUNCATION_MARKER);
    truncated
}

/// Builds the v3 create request for a matched rule, at [`JiraFieldLimits::DEFAULT`].
pub fn build_create_issue_request(
    rule: &RuleConfig,
    event: &GitHubIssueEvent,
    rule_match: &RuleMatch,
) -> Result<V3CreateIssueRequest> {
    build_create_issue_request_with_limits(rule, event, rule_match, JiraFieldLimits::DEFAULT)
}

/// [`build_create_issue_request`] with the caller choosing the ceilings.
///
/// # Errors
///
/// Fails when the rendered summary is empty, when the severity has no
/// `priority_by_severity` entry, or when `limits.max_summary_chars` is too small
/// to carry a summary at all.
pub fn build_create_issue_request_with_limits(
    rule: &RuleConfig,
    event: &GitHubIssueEvent,
    rule_match: &RuleMatch,
    limits: JiraFieldLimits,
) -> Result<V3CreateIssueRequest> {
    let priority = rule
        .jira
        .priority_by_severity
        .get(&rule_match.severity)
        .cloned()
        .ok_or_else(|| {
            // Previewed rather than echoed: this error is returned from `main`
            // and printed into the step log, and under a permissive consumer
            // regex the severity is whatever the issue body put in the capture
            // -- unbounded, and free to carry the newline a `::error::` needs to
            // be read as a workflow command.
            anyhow::anyhow!(
                "No Jira priority mapping for severity {}",
                crate::output::preview(&rule_match.severity)
            )
        })?;

    let rendered_summary = render_template(&rule.jira.summary, event, rule_match)?;
    if rendered_summary.trim().is_empty() {
        anyhow::bail!("Rendered Jira summary cannot be empty");
    }
    let summary = truncate_chars(&rendered_summary, limits.max_summary_chars);
    if summary.is_empty() {
        // Only reachable through a caller-chosen limit of zero. Nothing of the
        // summary is named: it is a rendered template over an issue body.
        anyhow::bail!(
            "A Jira summary limit of {} characters cannot carry a summary",
            limits.max_summary_chars
        );
    }

    // A description that says nothing becomes no description at all rather than
    // an ADF document holding nothing: Jira would store the empty document, and
    // the issue would show a description field that exists and says nothing.
    // `None` omits the key from the request entirely.
    //
    // The question is asked of the *document*, after the conversion, rather than
    // of the text before it. A guard on the text has to know which characters
    // the conversion drops, and it got that wrong: `str::trim` spends Unicode
    // `White_Space`, which holds no C0 control except U+000B and U+000C, while
    // `text_to_adf_bounded` strips every control character but `\n` and `\t`.
    // So a rendered description of U+0001 was "not blank" to the text guard and
    // an empty document to the conversion, and the request went out carrying
    // `"description": {"type":"doc","version":1,"content":[]}` -- the exact
    // outcome this omission exists to prevent. Asking the document settles the
    // whitespace case and the control-character case for one reason, and takes
    // a caller-chosen `AdfLimits` of zero with them.
    let rendered_description = render_template(&rule.jira.description, event, rule_match)?;
    let document = text_to_adf_bounded(&rendered_description, limits.description);
    let description = (!says_nothing(&document)).then_some(RichText::Adf(document));

    let mut labels = rule.jira.labels.clone();
    if !labels.iter().any(|value| value == &rule_match.dedupe_label) {
        labels.push(rule_match.dedupe_label.clone());
    }

    // Every optional the rule does not set is absent from the body rather than
    // `null`: `components` and `parent` above all, which Jira rejects as `null`
    // on any issue type that is not a subtask.
    let mut fields = V3CreateIssueFields::new(
        V3ProjectRef::by_key(rule.jira.project_key.as_str()),
        summary,
        V3NamedRef::by_name(rule.jira.issue_type.as_str()),
    )
    .with_priority(V3NamedRef::by_name(priority))
    .with_labels(labels);
    fields.description = description;
    fields.assignee = rule
        .jira
        .assignee_account_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(V3User::by_account_id);

    Ok(V3CreateIssueRequest::new(fields))
}

/// Whether `document` would render as a Jira description that says nothing.
///
/// True for a document with no blocks, and true for one whose every `text` node
/// is blank -- the `"   "` case, which [`text_to_adf_bounded`] keeps as a
/// paragraph holding three spaces rather than dropping. Both have to be one
/// predicate: two guards on different sides of the conversion disagree at the
/// edges, which is how a control-character-only description used to reach Jira
/// as an empty document.
///
/// A block this function does not recognise counts as content. The conversion
/// emits only paragraphs of `text` and `hardBreak`, so that arm is unreachable
/// for the documents built here; if a later shape reaches it, keeping a
/// description that might say something is the safe direction, and dropping one
/// silently is not.
fn says_nothing(document: &AdfDocument) -> bool {
    document.content.iter().all(|block| match block {
        AdfBlock::Paragraph { content, .. } => content.iter().all(|inline| match inline {
            AdfInline::Text { text, .. } => text.trim().is_empty(),
            AdfInline::HardBreak => true,
            _ => false,
        }),
        _ => false,
    })
}

/// Builds the single-label query the `0.4.x` releases sent.
///
/// **Nothing in the Action sends this query any more.** The reconciliation path
/// goes through [`crate::rules::dedupe::build_lookup_plan`], whose one query
/// carries every rung of the ladder in a `labels IN (...)` clause; a lookup for
/// this shape would ask for one label and miss the issues the other rungs exist
/// to find. What is left here is the historical shape itself: the golden corpus
/// in `tests/dedupe_v0_golden.rs` pins the exact text `0.4.x` emitted, and the
/// character sweep below pins the escaping against the escaper this replaced.
/// Both are compatibility records, so both need the query that was sent then
/// rather than the one that is sent now.
///
/// The emitted text is load-bearing for that reason: the shape stays
/// `project = "<key>" AND labels = "<label>"` and the escaping stays
/// byte-compatible with the escaper this replaced. That compatibility is
/// unconditional for a config that loads: the characters the two escapers spell
/// differently -- the apostrophe and the control characters, U+0000 among them --
/// are exactly the set [`crate::config::is_forbidden_jira_text_char`] refuses in
/// `jira.project_key` and `jira.dedupe.label_prefix`, and none of them can be in
/// a Jira label anyway.
///
/// # Errors
///
/// Fails when the project key or `dedupe_label` contains U+0000, which JQL has no
/// escape sequence for.
pub fn try_build_dedupe_jql(rule: &RuleConfig, dedupe_label: &str) -> Result<String> {
    JqlBuilder::new()
        .eq("project", &rule.jira.project_key)
        .and_then(|builder| builder.eq("labels", dedupe_label))
        .and_then(JqlBuilder::build)
        .with_context(|| format!("Rule '{}' cannot build a dedupe JQL query", rule.id))
}

/// [`try_build_dedupe_jql`] for callers that have no error channel.
///
/// # Panics
///
/// Panics on the one input [`try_build_dedupe_jql`] rejects, a U+0000 in the
/// project key or the dedupe label. It fails closed rather than sending Jira a
/// query with an embedded NUL.
///
/// The panicking form is safe here only because, like
/// [`try_build_dedupe_jql`], it is no longer on any path a run takes. The
/// Action's reconciliation is [`crate::rules::dedupe::build_lookup_plan`], which
/// is fallible for exactly this reason: it is called from a function whose
/// caller writes the step outputs afterwards, so a panic there would abort
/// before a single output was published. What is left for this form is the
/// golden-vector table, which has nowhere to put an error anyway.
pub fn build_dedupe_jql(rule: &RuleConfig, dedupe_label: &str) -> String {
    try_build_dedupe_jql(rule, dedupe_label).unwrap_or_else(|error| panic!("{error:#}"))
}

#[cfg(test)]
mod tests {
    use super::{
        build_create_issue_request, build_create_issue_request_with_limits, build_dedupe_jql,
        truncate_chars, try_build_dedupe_jql, JiraFieldLimits, DEFAULT_MAX_SUMMARY_CHARS,
    };
    use crate::config::{is_forbidden_jira_text_char, load_config_from_str, RuleConfig};
    use crate::github::{load_issue_event_from_str, GitHubIssueEvent};
    use crate::rules::{evaluate_rule, RuleMatch};
    use serde_json::{json, Value};
    use threatflux_atlassian_sdk::v3::V3CreateIssueRequest;
    use threatflux_atlassian_testkit::fixtures;

    /// The request as it will appear on the wire.
    ///
    /// Every assertion about what Jira receives goes through this rather than
    /// through the typed members: an absent key and a `null` one are the same
    /// value in Rust and different requests to Jira, and only the serialized
    /// form tells them apart.
    fn wire(request: &V3CreateIssueRequest) -> Value {
        serde_json::to_value(request).expect("a create request is always serializable")
    }

    /// The `fields.description` of a built request, as JSON.
    fn wire_description(request: &V3CreateIssueRequest) -> Value {
        wire(request)["fields"]["description"].clone()
    }

    /// Every `text` node's string in a serialized ADF document, concatenated.
    ///
    /// Assertions about what a description *says* go through this rather than
    /// through `Value::to_string`: serde escapes a control character, so a
    /// search for one in the serialized JSON finds the escape sequence and not
    /// the character, and passes on a document that carries it.
    fn adf_text(document: &Value) -> String {
        fn walk(value: &Value, collected: &mut String) {
            match value {
                Value::Array(items) => {
                    for item in items {
                        walk(item, collected);
                    }
                }
                Value::Object(members) => {
                    if members.get("type") == Some(&Value::String("text".to_string())) {
                        if let Some(Value::String(text)) = members.get("text") {
                            collected.push_str(text);
                        }
                    }
                    for member in members.values() {
                        walk(member, collected);
                    }
                }
                _ => {}
            }
        }

        let mut collected = String::new();
        walk(document, &mut collected);
        collected
    }

    /// The escaper this module used before the query moved onto the SDK's `jql`
    /// builder, kept verbatim as the compatibility oracle. Live dedupe matches
    /// issues labelled by releases that emitted exactly this text.
    fn pre_migration_dedupe_jql(project_key: &str, dedupe_label: &str) -> String {
        fn escape_jql_literal(value: &str) -> String {
            value.replace('\\', r"\\").replace('"', "\\\"")
        }

        format!(
            r#"project = "{}" AND labels = "{}""#,
            escape_jql_literal(project_key),
            escape_jql_literal(dedupe_label)
        )
    }

    /// `project_key` and `label_prefix` are spliced in as written, so a caller
    /// passing a value that needs quoting has to quote it.
    fn dedupe_config_yaml(project_key: &str, label_prefix: &str) -> String {
        format!(
            concat!(
                "version: 1\n",
                "rules:\n",
                "  - id: dependabot-high-issues\n",
                "    when:\n",
                "      event: issues\n",
                "      action: opened\n",
                "    extract:\n",
                "      severity:\n",
                "        from: issue.body\n",
                "        regex: '(?mi)^severity:\\s*(high|critical)\\b'\n",
                "    jira:\n",
                "      project_key: {project_key}\n",
                "      issue_type: Bug\n",
                "      priority_by_severity:\n",
                "        high: High\n",
                "      summary: test\n",
                "      description: test\n",
                "      dedupe:\n",
                "        strategy: sha256\n",
                "        label_prefix: {label_prefix}\n",
                "        fields: [repository.full_name, issue.title]\n",
            ),
            project_key = project_key,
            label_prefix = label_prefix,
        )
    }

    fn load_dedupe_rule(project_key: &str, label_prefix: &str) -> RuleConfig {
        let yaml = dedupe_config_yaml(project_key, label_prefix);
        let mut config = load_config_from_str(&yaml).expect("config should load");
        config.rules.remove(0)
    }

    /// [`load_dedupe_rule`] for a config that is expected not to load.
    fn dedupe_rule_error(project_key: &str, label_prefix: &str) -> String {
        load_config_from_str(&dedupe_config_yaml(project_key, label_prefix))
            .expect_err("the config should be rejected")
            .to_string()
    }

    /// Every character the two escapers have to agree on. The BMP is exhaustive
    /// for the interesting part: Unicode category Cc, which `char::is_control`
    /// reports, is U+0000-U+001F plus U+007F-U+009F and nothing else.
    fn sweep_characters() -> impl Iterator<Item = char> {
        const ASTRAL: [char; 5] = [
            '\u{1_0000}',
            '\u{1_f680}',
            '\u{2_0000}',
            '\u{e_0001}',
            '\u{10_ffff}',
        ];

        (0u32..=0xffff).filter_map(char::from_u32).chain(ASTRAL)
    }

    /// The escape the SDK emits for a control character other than LF, CR and TAB.
    fn unicode_escape(ch: char) -> String {
        format!("\\u{:04x}", u32::from(ch))
    }

    #[test]
    fn build_create_issue_request_maps_priority_assignee_labels_and_description() {
        let config = load_config_from_str(fixtures::action_config("jira-multiline-description"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-critical-package"),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let request = build_create_issue_request(&config.rules[0], &event, &matched)
            .expect("request should build");

        assert_eq!(request.fields.project.key.as_deref(), Some("KAN"));
        assert_eq!(request.fields.issue_type.name.as_deref(), Some("Bug"));
        assert_eq!(
            request
                .fields
                .assignee
                .as_ref()
                .and_then(|value| value.account_id.as_deref()),
            Some("account-123")
        );
        assert_eq!(
            request
                .fields
                .priority
                .as_ref()
                .and_then(|value| value.name.as_deref()),
            Some("Highest")
        );
        assert!(request
            .fields
            .summary
            .starts_with("[Dependabot][Critical] Bump foo"));
        assert!(request
            .fields
            .labels
            .as_ref()
            .expect("labels should be present")
            .iter()
            .any(|value| value == &matched.dedupe_label));
        // The description is an ADF document, not a string. The typed member
        // no longer has a `&str` to inspect, so the assertion moves onto the
        // wire form, which is where the claim was really about anyway.
        let description = wire_description(&request);
        assert_eq!(description["type"], "doc");
        assert!(
            description.to_string().contains("ThreatFlux/demo"),
            "the rendered repository never reached the document: {description}"
        );
    }

    #[test]
    fn build_create_issue_request_sends_the_description_as_adf_and_never_as_a_string() {
        // The whole point of routing the Action through `client.v3()`: the
        // frozen v2 `CreateIssueFields` types `description` as `Option<String>`
        // and could only ever have sent plain text. A blank-line run becomes a
        // second paragraph and a single newline becomes a `hardBreak`, which is
        // the multiline formatting a string body cannot express.
        let config = load_config_from_str(fixtures::action_config("jira-multiline-description"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            &fixtures::github_event_with_issue_body(
                "issues-opened-dependabot-high",
                "Severity: high\nfirst line\nsecond line",
            ),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let request = build_create_issue_request(&config.rules[0], &event, &matched)
            .expect("request should build");
        let description = wire_description(&request);

        assert!(
            !description.is_string(),
            "a v3 description may never be a bare string: {description}"
        );
        assert_eq!(description["type"], "doc");
        assert_eq!(description["version"], 1);
        assert!(
            description["content"]
                .as_array()
                .expect("a doc has a content array")
                .len()
                > 1,
            "the blank-line runs did not become separate paragraphs: {description}"
        );
        assert!(
            description.to_string().contains(r#"{"type":"hardBreak"}"#),
            "a single newline did not become a hard break: {description}"
        );
    }

    #[test]
    fn a_whitespace_only_description_puts_no_description_key_on_the_wire() {
        // `None`, not an ADF document holding one empty paragraph. Jira would
        // store the empty document happily, and the issue would then show a
        // description that exists and says nothing -- worse than none at all,
        // because a later read-modify-write cannot tell it from a description
        // somebody meant to leave blank.
        let config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load");
        let rule = &config.rules[0];
        assert_eq!(
            rule.jira.description, "{{ issue.body }}",
            "this test needs a description that renders to whatever the body is"
        );

        for body in ["", "   ", "\n\n", " \t \r\n \u{a0}"] {
            let event = event_with_body(&format!("Severity: high{body}"));
            let matched = evaluate_rule(rule, &event)
                .expect("rule evaluation should succeed")
                .expect("rule should match");
            let mut rule = rule.clone();
            rule.jira.description = body.to_string();

            let request = build_create_issue_request(&rule, &event, &matched)
                .expect("a blank description must not fail the run");

            assert!(
                request.fields.description.is_none(),
                "{body:?} became a description"
            );
            assert!(
                wire(&request)["fields"]
                    .as_object()
                    .expect("fields is an object")
                    .get("description")
                    .is_none(),
                "{body:?} put a description key on the wire: {}",
                wire(&request)
            );
        }
    }

    #[test]
    fn a_control_character_only_description_puts_no_description_key_on_the_wire() {
        // The same claim as the test above, for the characters `str::trim` does
        // not consider whitespace. `trim` spends Unicode `White_Space`, which
        // holds U+000B and U+000C but none of the other C0 controls -- so
        // U+0001 and U+007F are "not blank" to the guard, while the ADF
        // conversion's `normalize` strips every control except `\n` and `\t`.
        // Deciding emptiness before the conversion therefore produced
        // `{"type":"doc","version":1,"content":[]}` on the wire: an empty
        // document, which is exactly the description that exists and says
        // nothing the omission is here to prevent.
        //
        // The last case is the one that pins *how* this is decided rather than
        // only that it is. A space next to a control character survives the
        // strip as a paragraph holding one space, so it is not an empty
        // document -- keeping the old text guard and adding an
        // `AdfDocument::is_empty` check beside it would let it through, and
        // would then be sending a description for `" \u{1}"` while omitting one
        // for `" "`. Asking the document what it says answers both.
        let config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load");
        let rule = &config.rules[0];
        let event = event_with_body("Severity: high\nthe alert");
        let matched = evaluate_rule(rule, &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        for description in [
            "\u{1}",
            "\u{7f}",
            "\u{0}",
            "\u{1}\u{2}\u{3}",
            " \u{1}\n\u{9b}",
        ] {
            let mut rule = rule.clone();
            rule.jira.description = description.to_string();

            let request = build_create_issue_request(&rule, &event, &matched)
                .expect("a description of control characters must not fail the run");

            assert!(
                request.fields.description.is_none(),
                "{description:?} became a description"
            );
            assert!(
                wire(&request)["fields"]
                    .as_object()
                    .expect("fields is an object")
                    .get("description")
                    .is_none(),
                "{description:?} put a description key on the wire: {}",
                wire(&request)
            );
        }

        // And the rule stays "the document came out empty", not "strip and
        // give up": one surviving character is still a description.
        let mut rule = rule.clone();
        rule.jira.description = "\u{1}the alert".to_string();
        let request =
            build_create_issue_request(&rule, &event, &matched).expect("request should build");
        assert_eq!(adf_text(&wire_description(&request)), "the alert");
    }

    #[test]
    fn a_description_that_is_present_but_only_whitespace_on_one_line_still_reaches_jira() {
        // The rule is "nothing but whitespace", not "contains whitespace": a
        // description whose first line is blank still carries content and has
        // to go out whole.
        let config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load");
        let mut rule = config.rules[0].clone();
        rule.jira.description = "   \n{{ issue.body }}".to_string();

        let event = event_with_body("Severity: high\nthe alert");
        let matched = evaluate_rule(&rule, &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let request =
            build_create_issue_request(&rule, &event, &matched).expect("request should build");

        assert!(request.fields.description.is_some());
        assert!(
            wire_description(&request).to_string().contains("the alert"),
            "the body did not reach the document"
        );
    }

    #[test]
    fn a_body_that_is_itself_an_adf_document_reaches_jira_as_text() {
        // The positive half of `description_format: adf` being refused (see
        // `config::tests::load_config_rejects_the_adf_format_that_would_let_a_config_choose_json_structure`).
        // The body here *is* a complete ADF document, written by whoever opened
        // the GitHub issue. It must land inside a `text` node as characters,
        // never be spliced into the request as structure: the emitted document
        // has this crate's own root, one paragraph, and a text node whose
        // string is the payload verbatim.
        const FORGED: &str =
            r#"{"type":"doc","version":1,"content":[{"type":"heading","attrs":{"level":1}}]}"#;

        let config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load");
        let rule = &config.rules[0];
        let event = event_with_body(&format!("Severity: high\n{FORGED}"));
        let matched = evaluate_rule(rule, &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let request =
            build_create_issue_request(rule, &event, &matched).expect("request should build");
        let description = wire_description(&request);

        assert_eq!(
            description,
            json!({
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Severity: high"},
                        {"type": "hardBreak"},
                        {"type": "text", "text": FORGED}
                    ]
                }]
            }),
            "the body chose the structure of the document"
        );
    }

    #[test]
    fn build_create_issue_request_omits_every_field_the_rule_does_not_set() {
        // Jira rejects `"parent": null` on any issue type that is not a
        // subtask, and a `null` for a field the project's create screen does
        // not expose fails the same way. The v2 model spelled both of those as
        // an explicit `null`; nothing unset may appear at all.
        let config = load_config_from_str(fixtures::action_config("jira-blank-assignee"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-high"),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let request = build_create_issue_request(&config.rules[0], &event, &matched)
            .expect("request should build");
        let fields = wire(&request)["fields"]
            .as_object()
            .expect("fields is an object")
            .clone();

        for absent in ["parent", "components", "assignee"] {
            assert!(
                !fields.contains_key(absent),
                "'{absent}' reached the wire: {fields:?}"
            );
        }
        assert_eq!(
            wire(&request)["fields"]["project"],
            json!({"key": "KAN"}),
            "an unset project id reached the wire"
        );
    }

    #[test]
    fn build_dedupe_jql_targets_project_and_label() {
        let config = load_config_from_str(fixtures::action_config("jira-dedupe-prefix"))
            .expect("config should load");

        let jql = build_dedupe_jql(&config.rules[0], "dependabot-alert-48fe1f86b5f0");
        assert_eq!(
            jql,
            r#"project = "KAN" AND labels = "dependabot-alert-48fe1f86b5f0""#
        );
    }

    #[test]
    fn build_create_issue_request_errors_when_priority_mapping_is_missing() {
        let config = load_config_from_str(fixtures::action_config("jira-missing-priority-mapping"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-critical"),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let error = build_create_issue_request(&config.rules[0], &event, &matched)
            .expect_err("missing priority mapping should fail");
        assert!(error.to_string().contains("No Jira priority mapping"));
    }

    /// A consumer config whose severity capture is deliberately unconstrained.
    ///
    /// `(?s)` makes `.` match a newline, so capture group 1 is whatever the
    /// issue body puts between the markers: up to the whole body, newlines and
    /// control characters included. This is the configuration shape the threat
    /// model is built on, and the severity it yields is the key
    /// `priority_by_severity` is looked up by.
    const PERMISSIVE_SEVERITY_CONFIG: &str = r"
version: 1
rules:
  - id: permissive-severity-capture
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?s)<severity>(.*)</severity>'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
";

    #[test]
    fn a_missing_priority_mapping_does_not_render_the_body_it_read_the_severity_from() {
        // This error is returned from `main`, so it is printed into the step
        // log. Under a permissive capture the severity is body text an issue
        // author chose, up to the ~64 KiB GitHub accepts, so interpolating it
        // raw published an unbounded value and let a `\n::error::` reach the log
        // as the start of a line, which is where the runner reads a workflow
        // command.
        let config = load_config_from_str(PERMISSIVE_SEVERITY_CONFIG).expect("config should load");
        let rule = &config.rules[0];
        let padding = "a".repeat(4096);
        let event = event_with_body(&format!(
            "<severity>high\n::error::forged{padding}::end-of-payload</severity>"
        ));
        let matched = evaluate_rule(rule, &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let error = build_create_issue_request(rule, &event, &matched)
            .expect_err("the captured severity is not in the mapping");
        let rendered = format!("{error:#}");

        assert!(
            rendered.len() < 200,
            "the error is unbounded ({} bytes): {rendered}",
            rendered.len()
        );
        assert!(
            !rendered.contains("::end-of-payload"),
            "the end of the body reached the error: {rendered}"
        );
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "a body newline reached the error: {rendered}"
        );
        assert!(
            rendered.contains("No Jira priority mapping"),
            "the error stopped naming its failure: {rendered}"
        );
    }

    /// A consumer config that lifts a whole `Severity:` line off the body.
    ///
    /// Nothing here is unusual: `(?m)^severity:\s*(.+)$` is the obvious way to
    /// read a labelled line, and `high` is the token the shipped examples map.
    /// It is the pairing with a CRLF-authored body that used to put a bare
    /// carriage return into the key this priority is looked up by.
    const LINE_ANCHORED_SEVERITY_CONFIG: &str = r"
version: 1
rules:
  - id: line-anchored-severity-capture
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(.+)$'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: '[{{ severity_title }}] {{ issue.title }}'
      description: 'Severity: {{ severity }}'
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
";

    fn event_with_body(body: &str) -> GitHubIssueEvent {
        load_issue_event_from_str(
            "issues",
            &fixtures::github_event_with_issue_body("issues-opened-dependabot-high", body),
        )
        .expect("event should parse")
    }

    #[test]
    fn build_create_issue_request_treats_a_crlf_body_like_the_lf_body_it_matches() {
        // Rust's `regex` ends a `(?m)$` before a `\n` only and `.` matches a
        // `\r`, so this config over a CRLF-authored body captures "high\r".
        // That token is the key `priority_by_severity` is looked up by, so a
        // capture artifact used to miss the mapping and fail the whole run --
        // no Jira issue created for an issue body whose only sin is its line
        // endings. The two bodies differ by one byte per line and must
        // reconcile identically.
        let config =
            load_config_from_str(LINE_ANCHORED_SEVERITY_CONFIG).expect("config should load");
        let rule = &config.rules[0];

        let lf_event = event_with_body("Severity: high\nPackage: foo");
        let crlf_event = event_with_body("Severity: high\r\nPackage: foo");

        let lf_match = evaluate_rule(rule, &lf_event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");
        let crlf_match = evaluate_rule(rule, &crlf_event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        assert_eq!(crlf_match.severity, lf_match.severity);
        assert_eq!(crlf_match.severity_title, lf_match.severity_title);

        let lf_request = build_create_issue_request(rule, &lf_event, &lf_match)
            .expect("an LF-authored body creates the issue");
        let crlf_request = build_create_issue_request(rule, &crlf_event, &crlf_match)
            .expect("a CRLF-authored body must create the same issue, not fail the run");

        assert_eq!(
            crlf_request
                .fields
                .priority
                .as_ref()
                .and_then(|value| value.name.as_deref()),
            Some("High")
        );
        assert_eq!(crlf_request.fields.summary, lf_request.fields.summary);
        assert_eq!(
            crlf_request.fields.description,
            lf_request.fields.description
        );
        assert!(
            !crlf_request.fields.summary.contains('\r'),
            "a bare carriage return may not reach the Jira summary"
        );
        // The description is ADF now, so the claim is asserted over the text of
        // every node rather than over one string. It is deliberately not
        // asserted over `to_string()` of the document: serde escapes a real
        // `\r` as the two characters `\` and `r`, so a search for `'\r'` in the
        // serialized JSON would pass on a document that carries one.
        let description = wire_description(&crlf_request);
        assert_eq!(description["type"], "doc");
        assert!(
            !adf_text(&description).contains('\r'),
            "a bare carriage return may not reach the Jira description: {description}"
        );
    }

    #[test]
    fn build_create_issue_request_skips_blank_assignee_account_id() {
        let config = load_config_from_str(fixtures::action_config("jira-blank-assignee"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-high"),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let request = build_create_issue_request(&config.rules[0], &event, &matched)
            .expect("request should build");

        assert!(request.fields.assignee.is_none());
    }

    #[test]
    fn build_create_issue_request_errors_when_rendered_summary_is_empty() {
        let config = load_config_from_str(fixtures::action_config("jira-summary-from-body"))
            .expect("config should load");
        let event = event_with_body("");
        let matched = RuleMatch {
            rule_id: "dependabot-high-issues".to_string(),
            severity: "high".to_string(),
            severity_title: "High".to_string(),
            dedupe_label: "dependabot-alert-123456789abc".to_string(),
        };

        let error = build_create_issue_request(&config.rules[0], &event, &matched)
            .expect_err("empty rendered summary should fail");
        assert!(error
            .to_string()
            .contains("Rendered Jira summary cannot be empty"));
    }

    /// The shipped Dependabot summary template, and what it renders to for the
    /// `issues-opened-dependabot-high` fixture minus the GitHub title.
    const SUMMARY_PREFIX: &str = "[Dependabot][High] ";

    /// Builds the request the shipped `dependabot-high` rule makes for a GitHub
    /// issue titled `title`.
    fn request_for_title(title: &str, limits: JiraFieldLimits) -> V3CreateIssueRequest {
        let config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load");
        let rule = &config.rules[0];

        let mut payload = fixtures::github_event_json("issues-opened-dependabot-high");
        payload["issue"]["title"] = Value::String(title.to_string());
        payload["issue"]["body"] = Value::String("Severity: high".to_string());
        let event =
            load_issue_event_from_str("issues", &payload.to_string()).expect("event should parse");

        let matched = evaluate_rule(rule, &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");
        build_create_issue_request_with_limits(rule, &event, &matched, limits)
            .expect("request should build")
    }

    #[test]
    fn a_github_title_that_fills_the_field_is_truncated_instead_of_failing_the_run() {
        // Live bug, not a hypothetical: Jira Cloud caps `summary` at 255
        // characters, a GitHub issue title reaches 256 on its own, and the
        // shipped template prepends 19 more before the title starts. So an
        // ordinary long Dependabot title was a guaranteed Jira 400 and a red
        // step, with no hostile input and no ADF involved.
        assert_eq!(SUMMARY_PREFIX.chars().count(), 19);

        let title = "B".repeat(256);
        let request = request_for_title(&title, JiraFieldLimits::DEFAULT);
        let summary = &request.fields.summary;

        assert_eq!(summary.chars().count(), DEFAULT_MAX_SUMMARY_CHARS);
        assert!(
            summary.starts_with(SUMMARY_PREFIX),
            "the template prefix was cut instead of the title: {summary}"
        );
        assert!(
            summary.ends_with('…'),
            "a cut summary has to say it was cut: {summary}"
        );
        assert_eq!(
            *summary,
            format!(
                "{}…",
                format!("{SUMMARY_PREFIX}{title}")
                    .chars()
                    .take(DEFAULT_MAX_SUMMARY_CHARS - 1)
                    .collect::<String>()
            )
        );
    }

    #[test]
    fn a_summary_that_exactly_fills_the_field_is_left_whole() {
        // The cap is inclusive; a summary of exactly 255 characters is a
        // summary Jira accepts, and marking it truncated would be a lie.
        let title = "B".repeat(DEFAULT_MAX_SUMMARY_CHARS - SUMMARY_PREFIX.chars().count());
        let request = request_for_title(&title, JiraFieldLimits::DEFAULT);

        assert_eq!(
            request.fields.summary.chars().count(),
            DEFAULT_MAX_SUMMARY_CHARS
        );
        assert!(!request.fields.summary.contains('…'));
        assert!(request.fields.summary.ends_with('B'));
    }

    #[test]
    fn truncating_a_summary_never_splits_a_multi_byte_character() {
        // The failure this rules out is not cosmetic. Cutting with a byte index
        // -- `&summary[..255]` -- panics when the index lands inside a
        // character, and cutting with unchecked bytes produces invalid UTF-8.
        // A 4-byte emoji is the widest case, and a title made of them puts a
        // character boundary at every 4th byte, so byte 255 is guaranteed to
        // fall inside one. Emoji in a Dependabot title are ordinary.
        const ROCKET: char = '\u{1f680}';
        assert_eq!(ROCKET.len_utf8(), 4);

        let title: String = std::iter::repeat_n(ROCKET, 300).collect();
        let request = request_for_title(&title, JiraFieldLimits::DEFAULT);
        let summary = &request.fields.summary;

        assert_eq!(summary.chars().count(), DEFAULT_MAX_SUMMARY_CHARS);
        assert!(
            summary.len() > DEFAULT_MAX_SUMMARY_CHARS,
            "the cap is spent in characters, not bytes: {} bytes",
            summary.len()
        );
        assert!(
            !summary.contains('\u{fffd}'),
            "a character was cut in half: {summary}"
        );
        // Every character that survived is whole: the summary is the prefix,
        // then only complete rockets, then the marker.
        let kept = summary
            .strip_prefix(SUMMARY_PREFIX)
            .expect("the prefix survives")
            .strip_suffix('…')
            .expect("a cut summary is marked");
        assert!(kept.chars().all(|value| value == ROCKET), "{summary}");
        assert_eq!(
            kept.chars().count(),
            DEFAULT_MAX_SUMMARY_CHARS - SUMMARY_PREFIX.chars().count() - 1
        );
    }

    #[test]
    fn a_multi_byte_character_straddling_the_cap_is_dropped_whole() {
        // The boundary case in isolation: the character the budget cannot
        // afford is the one the marker replaces, and it leaves nothing behind.
        assert_eq!(truncate_chars("aa\u{1f680}bb", 0), "");
        assert_eq!(truncate_chars("aa\u{1f680}bb", 1), "…");
        assert_eq!(truncate_chars("aa\u{1f680}bb", 2), "a…");
        assert_eq!(truncate_chars("aa\u{1f680}bb", 3), "aa…");
        assert_eq!(truncate_chars("aa\u{1f680}bb", 4), "aa\u{1f680}…");
        // Five characters is the whole of it, so nothing is cut and nothing is
        // marked -- the cap is inclusive.
        assert_eq!(truncate_chars("aa\u{1f680}bb", 5), "aa\u{1f680}bb");
        assert_eq!(truncate_chars("aa\u{1f680}bb", 6), "aa\u{1f680}bb");

        for max_chars in 0..8 {
            let truncated = truncate_chars("aa\u{1f680}bb", max_chars);
            assert!(
                truncated.chars().count() <= max_chars,
                "{max_chars}: {truncated:?} is over budget"
            );
        }
    }

    #[test]
    fn the_summary_cap_is_configurable() {
        let title = "B".repeat(256);

        let tight = request_for_title(&title, JiraFieldLimits::DEFAULT.with_max_summary_chars(40));
        assert_eq!(tight.fields.summary.chars().count(), 40);
        assert!(tight.fields.summary.ends_with('…'));

        let loose = request_for_title(
            &title,
            JiraFieldLimits::DEFAULT.with_max_summary_chars(1_000),
        );
        assert_eq!(
            loose.fields.summary.chars().count(),
            SUMMARY_PREFIX.chars().count() + 256
        );
        assert!(!loose.fields.summary.contains('…'));
    }

    #[test]
    fn a_summary_cap_that_cannot_carry_a_summary_is_reported_rather_than_sent_empty() {
        // Only reachable through a caller-chosen limit of zero, but Jira
        // rejects an empty `summary` too, so silently sending one would trade
        // a clear local error for a remote 400.
        let config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-high"),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let error = build_create_issue_request_with_limits(
            &config.rules[0],
            &event,
            &matched,
            JiraFieldLimits::DEFAULT.with_max_summary_chars(0),
        )
        .expect_err("a limit of zero cannot carry a summary");
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("cannot carry a summary"),
            "unexpected error: {rendered}"
        );
        assert!(
            !rendered.contains("Dependabot"),
            "the summary is a rendered template over an issue body and may not be echoed: {rendered}"
        );
    }

    #[test]
    fn an_over_long_description_is_truncated_rather_than_rejected() {
        // The other half of the same policy. This sits on an alerting path: a
        // 65 KB body is something any author can paste and any hostile author
        // can craft, and rejecting one would let them delete the alert.
        let config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load");
        let rule = &config.rules[0];
        let event = event_with_body(&format!("Severity: high\n{}", "b".repeat(70_000)));
        let matched = evaluate_rule(rule, &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let request = build_create_issue_request(rule, &event, &matched)
            .expect("an over-long body must not fail the run");
        let description = wire_description(&request);

        assert_eq!(description["type"], "doc");
        let text = adf_text(&description);
        assert!(
            text.chars().count() <= JiraFieldLimits::DEFAULT.description.max_chars,
            "the description is unbounded: {} characters",
            text.chars().count()
        );
        assert!(
            text.ends_with('…'),
            "a cut description has to say it was cut"
        );
    }

    #[test]
    fn build_dedupe_jql_escapes_special_characters() {
        let config = load_config_from_str(fixtures::action_config("jira-quoted-project-key"))
            .expect("config should load");

        let jql = build_dedupe_jql(&config.rules[0], r#"dependabot-alert-foo"bar\baz"#);
        assert_eq!(
            jql,
            r#"project = "K\"AN" AND labels = "dependabot-alert-foo\"bar\\baz""#
        );
    }

    #[test]
    fn build_dedupe_jql_is_byte_identical_to_the_pre_migration_builder() {
        let mut rule = load_dedupe_rule("KAN", "dependabot-alert");
        let mut diverged = Vec::new();

        for ch in sweep_characters() {
            rule.jira.project_key = format!("K{ch}AN");
            let dedupe_label = format!("dependabot{ch}alert-48fe1f86b5f0");

            let Ok(emitted) = try_build_dedupe_jql(&rule, &dedupe_label) else {
                assert_eq!(ch, '\0', "only U+0000 may be rejected, not {ch:?}");
                continue;
            };

            if emitted != pre_migration_dedupe_jql(&rule.jira.project_key, &dedupe_label) {
                diverged.push(ch);
            }
        }

        let expected: Vec<char> = sweep_characters()
            .filter(|ch| *ch != '\0' && is_forbidden_jira_text_char(*ch))
            .collect();
        assert_eq!(diverged, expected);
    }

    #[test]
    fn every_character_a_config_can_carry_reaches_the_query_byte_identically() {
        // The guarantee is unconditional rather than "for the character set
        // config validation admits": every character the two escapers disagree
        // on is one `validate_config` now refuses, so a config that loads at all
        // emits the bytes earlier releases emitted, and its issues keep matching.
        let mut rule = load_dedupe_rule("KAN", "dependabot-alert");

        for ch in sweep_characters().filter(|ch| !is_forbidden_jira_text_char(*ch)) {
            rule.jira.project_key = format!("K{ch}AN");
            let dedupe_label = format!("dependabot{ch}alert-48fe1f86b5f0");

            assert_eq!(
                try_build_dedupe_jql(&rule, &dedupe_label).expect("character is representable"),
                pre_migration_dedupe_jql(&rule.jira.project_key, &dedupe_label),
                "escape for {ch:?}"
            );
        }
    }

    #[test]
    fn build_dedupe_jql_diverges_from_the_pre_migration_builder_only_where_jql_is_stricter() {
        // (character, what the deleted escaper emitted, what the SDK escaper emits)
        let cases = [
            ('\'', "'", r"\'".to_string()),
            ('\n', "\n", r"\n".to_string()),
            ('\r', "\r", r"\r".to_string()),
            ('\t', "\t", r"\t".to_string()),
            ('\u{1}', "\u{1}", unicode_escape('\u{1}')),
            ('\u{7f}', "\u{7f}", unicode_escape('\u{7f}')),
            ('\u{9b}', "\u{9b}", unicode_escape('\u{9b}')),
        ];

        let mut rule = load_dedupe_rule("KAN", "dependabot-alert");
        for (ch, pre_migration, hardened) in cases {
            rule.jira.project_key = format!("K{ch}AN");
            let dedupe_label = format!("dependabot{ch}alert-48fe1f86b5f0");

            assert_eq!(
                try_build_dedupe_jql(&rule, &dedupe_label).expect("character is representable"),
                format!(
                    r#"project = "K{hardened}AN" AND labels = "dependabot{hardened}alert-48fe1f86b5f0""#
                ),
                "escape for {ch:?}"
            );
            assert_eq!(
                pre_migration_dedupe_jql(&rule.jira.project_key, &dedupe_label),
                format!(
                    r#"project = "K{pre_migration}AN" AND labels = "dependabot{pre_migration}alert-48fe1f86b5f0""#
                ),
                "pre-migration escape for {ch:?}"
            );
        }
    }

    #[test]
    fn config_validation_rejects_every_character_the_escapers_disagree_on() {
        // YAML double-quoted escape, and the character it decodes to. Each of
        // these loaded clean before M0, which is what made the byte-identity
        // guarantee conditional and what let a NUL reach the JQL builder.
        let cases = [
            ("\\x27", '\''),
            ("\\n", '\n'),
            ("\\r", '\r'),
            ("\\t", '\t'),
            ("\\x01", '\u{1}'),
            ("\\x7f", '\u{7f}'),
            ("\\x9b", '\u{9b}'),
            ("\\0", '\0'),
        ];

        for (escape, ch) in cases {
            assert!(
                is_forbidden_jira_text_char(ch),
                "{ch:?} should be in the forbidden set"
            );

            let key_error = dedupe_rule_error(&format!("\"K{escape}AN\""), "dependabot-alert");
            assert!(
                key_error.contains("jira.project_key"),
                "{ch:?}: unexpected error: {key_error}"
            );

            let prefix_error = dedupe_rule_error("KAN", &format!("\"dependabot{escape}alert\""));
            assert!(
                prefix_error.contains("jira.dedupe.label_prefix"),
                "{ch:?}: unexpected error: {prefix_error}"
            );
        }
    }

    #[test]
    fn try_build_dedupe_jql_rejects_a_nul_the_pre_migration_escaper_interpolated_raw() {
        let mut rule = load_dedupe_rule("KAN", "dependabot-alert");
        rule.jira.project_key = "K\0AN".to_string();

        let error = try_build_dedupe_jql(&rule, "dependabot-alert-48fe1f86b5f0")
            .expect_err("a NUL has no JQL escape sequence");
        assert!(error
            .to_string()
            .contains("cannot build a dedupe JQL query"));
        assert!(format!("{error:#}").contains("NUL character"));

        assert!(
            pre_migration_dedupe_jql(&rule.jira.project_key, "dependabot-alert-48fe1f86b5f0")
                .contains('\0')
        );
    }

    #[test]
    #[should_panic(expected = "NUL character")]
    fn build_dedupe_jql_fails_closed_on_a_nul() {
        let mut rule = load_dedupe_rule("KAN", "dependabot-alert");
        rule.jira.project_key = "K\0AN".to_string();

        let _ = build_dedupe_jql(&rule, "dependabot-alert-48fe1f86b5f0");
    }

    #[test]
    fn a_computed_dedupe_label_reaches_the_query_escaped() {
        // `dep"bot` needs escaping and both escapers spell it the same way, so a
        // consumer running this prefix keeps matching the issues it labelled
        // before the migration.
        let rule = load_dedupe_rule("KAN", "\"dep\\\"bot\"");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-high"),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&rule, &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let digest = matched
            .dedupe_label
            .strip_prefix("dep\"bot-")
            .expect("label carries the configured prefix");

        assert_eq!(
            build_dedupe_jql(&rule, &matched.dedupe_label),
            format!(r#"project = "KAN" AND labels = "dep\"bot-{digest}""#)
        );
        assert_eq!(
            build_dedupe_jql(&rule, &matched.dedupe_label),
            pre_migration_dedupe_jql("KAN", &matched.dedupe_label)
        );
    }

    #[test]
    fn a_label_prefix_whose_query_would_have_moved_is_refused_at_load() {
        // `dep'bot` is the case that motivated the gate: the apostrophe is
        // escaped as `\'` now and was emitted raw before, so this config would
        // have silently stopped matching its own existing Jira issues.
        let error = dedupe_rule_error("KAN", "\"dep'bot\"");
        assert!(
            error.contains("jira.dedupe.label_prefix") && error.contains("U+0027"),
            "unexpected error: {error}"
        );
    }
}
