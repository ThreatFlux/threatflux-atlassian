use crate::config::RuleConfig;
use crate::github::GitHubIssueEvent;
use crate::output::strip_trailing_carriage_return;
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::sync::LazyLock;

pub(crate) const SUPPORTED_EVENT_NAME: &str = "issues";

static TEMPLATE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}").expect("valid regex"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule_id: String,
    pub severity: String,
    pub severity_title: String,
    pub dedupe_label: String,
}

pub fn evaluate_rule(rule: &RuleConfig, event: &GitHubIssueEvent) -> Result<Option<RuleMatch>> {
    if rule.when.event != SUPPORTED_EVENT_NAME || rule.when.action != event.action {
        return Ok(None);
    }

    if !rule.when.actor_in.is_empty() && !rule.when.actor_in.contains(&event.issue.user.login) {
        return Ok(None);
    }

    let body = event.issue.body.as_deref().unwrap_or_default();
    let pattern = Regex::new(&rule.extract.severity.regex)?;
    let Some(captures) = pattern.captures(body) else {
        return Ok(None);
    };

    // The capture is repaired here, where it is made, because every consumer of
    // the token reads it from this struct: the `priority_by_severity` lookup in
    // `crate::jira::build_create_issue_request`, the `{{ severity }}` and
    // `{{ severity_title }}` substitutions rendered into the Jira summary and
    // description, the returned `ActionOutcome`, and the `severity` step output.
    // Repairing it only at the output layer left the first of those looking up
    // `"high\r"` in a config that maps `high`, which failed the run and created
    // no Jira issue at all. See `crate::output::strip_trailing_carriage_return`
    // for why exactly one trailing byte is an artifact rather than a value.
    let severity = strip_trailing_carriage_return(
        &captures
            .get(1)
            .map(|value| value.as_str())
            .unwrap_or_default()
            .to_lowercase(),
    )
    .to_string();
    // Checked after the repair: a capture of nothing but a carriage return
    // carries no severity, and reporting it as a match would publish an empty
    // `severity` under a matched rule id -- a state a workflow cannot tell from
    // the empty severity that means no rule matched at all.
    if severity.is_empty() {
        return Ok(None);
    }

    let severity_title = title_case(&severity);
    let dedupe_label = compute_dedupe_label(rule, event)?;

    Ok(Some(RuleMatch {
        rule_id: rule.id.clone(),
        severity,
        severity_title,
        dedupe_label,
    }))
}

pub fn render_template(
    template: &str,
    event: &GitHubIssueEvent,
    rule_match: &RuleMatch,
) -> Result<String> {
    let mut rendered = String::with_capacity(template.len());
    let mut last = 0;

    for captures in TEMPLATE_PATTERN.captures_iter(template) {
        let matched = captures.get(0).expect("match should exist");
        rendered.push_str(&template[last..matched.start()]);

        let key = captures
            .get(1)
            .expect("template key capture should exist")
            .as_str();
        let value = resolve_template_value(key, event, rule_match)?;
        rendered.push_str(&value);
        last = matched.end();
    }

    rendered.push_str(&template[last..]);
    Ok(rendered)
}

/// Every event field a config may name, in a template or in `dedupe.fields`.
///
/// `resolve_event_value` must answer for each entry: a path listed here and not
/// resolved there loads as a valid config and fails the run instead.
pub(crate) const SUPPORTED_EVENT_FIELD_PATHS: &[&str] = &[
    "issue.id",
    "issue.number",
    "issue.node_id",
    "issue.state",
    "issue.title",
    "issue.body",
    "issue.html_url",
    "issue.user.login",
    "repository.id",
    "repository.node_id",
    "repository.full_name",
];

pub(crate) fn is_supported_event_field_path(path: &str) -> bool {
    SUPPORTED_EVENT_FIELD_PATHS.contains(&path)
}

fn is_supported_template_key(key: &str) -> bool {
    matches!(key, "severity" | "severity_title" | "dedupe_label")
        || is_supported_event_field_path(key)
}

pub(crate) fn validate_template(label: &str, template: &str) -> Result<()> {
    for captures in TEMPLATE_PATTERN.captures_iter(template) {
        let key = captures
            .get(1)
            .expect("template key capture should exist")
            .as_str();
        if !is_supported_template_key(key) {
            anyhow::bail!("{label} references unknown template field '{key}'");
        }
    }
    Ok(())
}

pub(crate) fn resolve_event_value(path: &str, event: &GitHubIssueEvent) -> Result<String> {
    match path {
        "issue.id" => Ok(event.issue.id.to_string()),
        "issue.number" => Ok(event.issue.number.to_string()),
        "issue.node_id" => Ok(event.issue.node_id.clone()),
        "issue.state" => Ok(event.issue.state.clone()),
        "issue.title" => Ok(event.issue.title.clone()),
        "issue.body" => Ok(event.issue.body.clone().unwrap_or_default()),
        "issue.html_url" => Ok(event.issue.html_url.clone()),
        "issue.user.login" => Ok(event.issue.user.login.clone()),
        "repository.id" => Ok(event.repository.id.to_string()),
        "repository.node_id" => Ok(event.repository.node_id.clone()),
        "repository.full_name" => Ok(event.repository.full_name.clone()),
        _ => anyhow::bail!("Unsupported event field path: {path}"),
    }
}

fn resolve_template_value(
    key: &str,
    event: &GitHubIssueEvent,
    rule_match: &RuleMatch,
) -> Result<String> {
    match key {
        "severity" => Ok(rule_match.severity.clone()),
        "severity_title" => Ok(rule_match.severity_title.clone()),
        "dedupe_label" => Ok(rule_match.dedupe_label.clone()),
        _ => resolve_event_value(key, event),
    }
}

fn compute_dedupe_label(rule: &RuleConfig, event: &GitHubIssueEvent) -> Result<String> {
    let prefix = rule
        .jira
        .dedupe
        .label_prefix
        .clone()
        .unwrap_or_else(|| "jira-automation".to_string());
    let mut values = Vec::with_capacity(rule.jira.dedupe.fields.len());
    for field in &rule.jira.dedupe.fields {
        values.push(resolve_event_value(field, event)?);
    }

    let mut hasher = Sha256::new();
    hasher.update(values.join("\n").as_bytes());
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest, "{byte:02x}").expect("write to string");
    }
    Ok(format!("{prefix}-{}", &digest[..12]))
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    chars.next().map_or_else(String::new, |first| {
        format!("{}{}", first.to_uppercase(), chars.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_rule, render_template, resolve_event_value, title_case, validate_template,
        SUPPORTED_EVENT_FIELD_PATHS,
    };
    use crate::config::load_config_from_str;
    use crate::github::{load_issue_event_from_str, GitHubIssueEvent};
    use threatflux_atlassian_testkit::fixtures;

    /// A config that dedupes on the repository and issue identity instead of on
    /// content, which is what the widened field allowlist makes expressible.
    const IDENTITY_DEDUPE_CONFIG: &str = r"
version: 1
rules:
  - id: identity-dedupe
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high|critical)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: '{{ repository.id }}-{{ issue.number }}'
      description: '{{ issue.node_id }} {{ issue.state }} {{ repository.node_id }}'
      dedupe:
        strategy: sha256
        fields: [repository.id, issue.number]
";

    fn parse_event(name: &str) -> GitHubIssueEvent {
        load_issue_event_from_str("issues", fixtures::github_event(name))
            .expect("event should parse")
    }

    #[test]
    fn evaluate_rule_extracts_high_severity_and_dedupe_label() {
        let config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-openssl"),
        )
        .expect("event should parse");

        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        assert_eq!(matched.rule_id, "dependabot-high-issues");
        assert_eq!(matched.severity, "high");
        assert_eq!(matched.severity_title, "High");
        assert!(matched.dedupe_label.starts_with("dependabot-alert-"));
        assert_eq!(matched.dedupe_label.len(), "dependabot-alert-".len() + 12);
    }

    #[test]
    fn evaluate_rule_skips_non_matching_actor() {
        let config = load_config_from_str(fixtures::action_config("actor-gate-minimal"))
            .expect("config should load");
        let event =
            load_issue_event_from_str("issues", fixtures::github_event("issues-opened-human-high"))
                .expect("event should parse");

        let matched =
            evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed");
        assert!(matched.is_none());
    }

    #[test]
    fn render_template_substitutes_known_fields() {
        let config = load_config_from_str(fixtures::action_config("template-render"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-critical"),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let rendered = render_template(
            "{{ repository.full_name }} {{ severity_title }} {{ issue.title }}",
            &event,
            &matched,
        )
        .expect("template should render");

        assert_eq!(rendered, "ThreatFlux/demo Critical Bump foo");
    }

    #[test]
    fn render_template_rejects_unknown_fields() {
        let config = load_config_from_str(fixtures::action_config("minimal-critical"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-critical"),
        )
        .expect("event should parse");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let error = render_template("{{ unknown.value }}", &event, &matched)
            .expect_err("unknown field should fail");
        assert!(error.to_string().contains("Unsupported event field path"));
    }

    #[test]
    fn validate_template_accepts_supported_fields() {
        validate_template(
            "test template",
            "{{ repository.full_name }} {{ severity_title }} {{ dedupe_label }}",
        )
        .expect("supported template fields should validate");
    }

    #[test]
    fn validate_template_rejects_unknown_fields() {
        let error = validate_template("test template", "{{ issue.titel }}")
            .expect_err("unknown template fields should fail validation");
        assert!(error.to_string().contains("unknown template field"));
    }

    #[test]
    fn evaluate_rule_returns_none_when_issue_body_is_missing() {
        let config = load_config_from_str(fixtures::action_config("minimal-critical"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-null-body"),
        )
        .expect("event should parse");

        let matched =
            evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed");
        assert!(matched.is_none());
    }

    #[test]
    fn evaluate_rule_returns_none_for_non_matching_action() {
        let config = load_config_from_str(fixtures::action_config("action-edited"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-high"),
        )
        .expect("event should parse");

        let matched =
            evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed");
        assert!(matched.is_none());
    }

    #[test]
    fn evaluate_rule_returns_none_for_empty_capture() {
        let config = load_config_from_str(fixtures::action_config("empty-capture-regex"))
            .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-high"),
        )
        .expect("event should parse");

        let matched =
            evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed");
        assert!(matched.is_none());
    }

    /// A consumer config whose severity capture is deliberately unconstrained,
    /// so that the capture can be made to be exactly one carriage return.
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

    fn evaluate_over_body(config_yaml: &str, body: &str) -> Option<super::RuleMatch> {
        let config = load_config_from_str(config_yaml).expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            &fixtures::github_event_with_issue_body("issues-opened-dependabot-high", body),
        )
        .expect("event should parse");

        evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed")
    }

    #[test]
    fn evaluate_rule_repairs_a_crlf_capture_artifact_at_the_capture() {
        // `(?m)$` ends before a `\n` only and `.` matches a `\r`, so this is what
        // an ordinary line-anchored config captures out of a CRLF-authored body.
        // Every consumer of the token reads it from here -- the priority lookup
        // first -- so the repair belongs here and not at the output.
        let matched = evaluate_over_body(
            r"
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
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
",
            "Severity: high\r\nPackage: foo",
        )
        .expect("rule should match");

        assert_eq!(matched.severity, "high");
        assert_eq!(matched.severity_title, "High");
    }

    #[test]
    fn evaluate_rule_returns_none_for_a_capture_that_is_only_a_carriage_return() {
        // The repair leaves nothing behind, and a rule that matched with an empty
        // severity would publish a `severity` output no workflow could tell from
        // the one that means no rule matched at all.
        let matched = evaluate_over_body(PERMISSIVE_SEVERITY_CONFIG, "<severity>\r</severity>");
        assert!(matched.is_none());
    }

    #[test]
    fn evaluate_rule_keeps_an_interior_carriage_return() {
        // Only a trailing one is a line-ending artifact. An interior `\r` is part
        // of the captured value and stays, for the encoder to refuse.
        let matched = evaluate_over_body(
            PERMISSIVE_SEVERITY_CONFIG,
            "<severity>high\rcreated=true</severity>",
        )
        .expect("rule should match");

        assert_eq!(matched.severity, "high\rcreated=true");
    }

    #[test]
    fn title_case_returns_empty_string_for_empty_input() {
        assert!(title_case("").is_empty());
    }

    #[test]
    fn every_supported_field_path_resolves_and_validates() {
        let event = parse_event("issues-opened-dependabot");

        for path in SUPPORTED_EVENT_FIELD_PATHS {
            let value = resolve_event_value(path, &event).unwrap_or_else(|error| {
                panic!("allowlisted path '{path}' did not resolve: {error}")
            });
            assert!(!value.is_empty(), "'{path}' resolved to nothing");

            validate_template("test template", &format!("{{{{ {path} }}}}")).unwrap_or_else(
                |error| panic!("allowlisted path '{path}' is not a template key: {error}"),
            );
        }
    }

    #[test]
    fn resolve_event_value_reads_the_identity_fields() {
        let event = parse_event("issues-opened-dependabot");

        for (path, expected) in [
            ("issue.id", "2147000123"),
            ("issue.number", "123"),
            ("issue.node_id", "I_kwDOI7Vczs5xAAB7"),
            ("issue.state", "open"),
            ("repository.id", "598178766"),
            ("repository.node_id", "R_kgDOI7Vczg"),
        ] {
            assert_eq!(
                resolve_event_value(path, &event).expect("identity path should resolve"),
                expected,
                "path '{path}'"
            );
        }
    }

    #[test]
    fn render_template_substitutes_the_identity_fields() {
        let config = load_config_from_str(IDENTITY_DEDUPE_CONFIG).expect("config should load");
        let event = parse_event("issues-opened-dependabot");
        let matched = evaluate_rule(&config.rules[0], &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        assert_eq!(
            render_template(&config.rules[0].jira.summary, &event, &matched)
                .expect("summary should render"),
            "598178766-123"
        );
        assert_eq!(
            render_template(&config.rules[0].jira.description, &event, &matched)
                .expect("description should render"),
            "I_kwDOI7Vczs5xAAB7 open R_kgDOI7Vczg"
        );
    }

    #[test]
    fn a_config_can_dedupe_on_the_issue_identity_instead_of_on_content() {
        let config = load_config_from_str(IDENTITY_DEDUPE_CONFIG).expect("config should load");
        let rule = &config.rules[0];

        let one = parse_event("issues-opened-dependabot");
        let two = parse_event("issues-opened-dependabot-high");
        assert_eq!(one.repository.id, two.repository.id);
        assert_ne!(one.issue.number, two.issue.number);

        let first = evaluate_rule(rule, &one)
            .expect("rule evaluation should succeed")
            .expect("rule should match");
        let second = evaluate_rule(rule, &two)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        // The content hash the shipped configs use cannot tell these two apart;
        // an identity-keyed one has to, which is the whole point of the fields.
        assert_ne!(
            first.dedupe_label, second.dedupe_label,
            "two issues in one repository must not share a dedupe label"
        );
    }

    #[test]
    fn a_retitle_does_not_move_an_identity_keyed_dedupe_label() {
        let config = load_config_from_str(IDENTITY_DEDUPE_CONFIG).expect("config should load");
        let rule = &config.rules[0];

        let before = evaluate_rule(rule, &parse_event("issues-opened-dependabot"))
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let mut payload = fixtures::github_event_json("issues-opened-dependabot");
        payload["issue"]["title"] =
            serde_json::Value::String("Bump openssl from 1.0 to 1.1.1".to_string());
        let retitled = load_issue_event_from_str("issues", &payload.to_string())
            .expect("the retitled delivery should parse");
        let after = evaluate_rule(rule, &retitled)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        assert_eq!(before.dedupe_label, after.dedupe_label);
    }
}
