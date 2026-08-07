use crate::config::RuleConfig;
use crate::github::GitHubIssueEvent;
use crate::rules::{render_template, RuleMatch};
use anyhow::{Context, Result};
use std::collections::HashMap;
use threatflux_atlassian_sdk::{
    jql::JqlBuilder, CreateIssueFields, CreateIssueRequest, IssueTypeReference, PriorityReference,
    ProjectReference, UserReference,
};

pub fn build_create_issue_request(
    rule: &RuleConfig,
    event: &GitHubIssueEvent,
    rule_match: &RuleMatch,
) -> Result<CreateIssueRequest> {
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
    let summary = render_template(&rule.jira.summary, event, rule_match)?;
    if summary.trim().is_empty() {
        anyhow::bail!("Rendered Jira summary cannot be empty");
    }
    let description = render_template(&rule.jira.description, event, rule_match)?;
    let mut labels = rule.jira.labels.clone();
    if !labels.iter().any(|value| value == &rule_match.dedupe_label) {
        labels.push(rule_match.dedupe_label.clone());
    }

    Ok(CreateIssueRequest {
        fields: CreateIssueFields {
            project: ProjectReference::by_key(&rule.jira.project_key),
            summary,
            issue_type: IssueTypeReference::by_name(&rule.jira.issue_type),
            description: Some(description),
            assignee: rule
                .jira
                .assignee_account_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(UserReference::by_account_id),
            priority: Some(PriorityReference {
                name: Some(priority),
                id: None,
            }),
            labels: Some(labels),
            components: None,
            parent: None,
            custom_fields: HashMap::new(),
        },
    })
}

/// Builds the query that finds an issue already carrying `dedupe_label`.
///
/// The emitted text is load-bearing beyond this process: it has to keep matching
/// Jira issues labelled by earlier releases, so the shape stays
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
/// query with an embedded NUL. Callers that can report an error use
/// [`try_build_dedupe_jql`], and the Action's own reconciliation path does: a
/// panic there would abort before the step outputs are written. What is left
/// for this form is a caller with no error channel, such as a golden-vector
/// table that would have nowhere to put the error anyway.
pub fn build_dedupe_jql(rule: &RuleConfig, dedupe_label: &str) -> String {
    try_build_dedupe_jql(rule, dedupe_label).unwrap_or_else(|error| panic!("{error:#}"))
}

#[cfg(test)]
mod tests {
    use super::{build_create_issue_request, build_dedupe_jql, try_build_dedupe_jql};
    use crate::config::{is_forbidden_jira_text_char, load_config_from_str, RuleConfig};
    use crate::github::{load_issue_event_from_str, GitHubIssueEvent};
    use crate::rules::{evaluate_rule, RuleMatch};
    use threatflux_atlassian_testkit::fixtures;

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
        assert!(request
            .fields
            .description
            .as_deref()
            .expect("description should be present")
            .contains("ThreatFlux/demo"));
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
        assert!(
            !crlf_request
                .fields
                .description
                .as_deref()
                .expect("description should be present")
                .contains('\r'),
            "a bare carriage return may not reach the Jira description"
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
