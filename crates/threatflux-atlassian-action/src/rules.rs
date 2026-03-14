use crate::config::RuleConfig;
use crate::github::GitHubIssueEvent;
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
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

    let severity = captures
        .get(1)
        .map(|value| value.as_str())
        .unwrap_or_default()
        .to_lowercase();
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

pub(crate) fn is_supported_event_field_path(path: &str) -> bool {
    matches!(
        path,
        "issue.title"
            | "issue.body"
            | "issue.html_url"
            | "issue.user.login"
            | "repository.full_name"
    )
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
        "issue.title" => Ok(event.issue.title.clone()),
        "issue.body" => Ok(event.issue.body.clone().unwrap_or_default()),
        "issue.html_url" => Ok(event.issue.html_url.clone()),
        "issue.user.login" => Ok(event.issue.user.login.clone()),
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
    let digest = format!("{:x}", hasher.finalize());
    Ok(format!("{prefix}-{}", &digest[..12]))
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    chars.next().map_or_else(String::new, |first| {
        format!("{}{}", first.to_uppercase(), chars.as_str())
    })
}

#[cfg(test)]
#[allow(clippy::needless_raw_string_hashes)]
mod tests {
    use super::{evaluate_rule, render_template, title_case};
    use crate::config::load_config_from_str;
    use crate::github::load_issue_event_from_str;

    #[test]
    fn evaluate_rule_extracts_high_severity_and_dedupe_label() {
        let config = load_config_from_str(
            r#"
version: 1
rules:
  - id: dependabot-high-issues
    when:
      event: issues
      action: opened
      actor_in:
        - dependabot[bot]
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high|critical)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      assignee_account_id: account-123
      priority_by_severity:
        high: High
        critical: Highest
      summary: "[Dependabot][{{ severity_title }}] {{ issue.title }}"
      description: "{{ issue.body }}"
      labels: [dependabot, security]
      dedupe:
        strategy: sha256
        label_prefix: dependabot-alert
        fields:
          - repository.full_name
          - issue.title
"#,
        )
        .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            r#"{
  "action": "opened",
  "issue": {
    "title": "Bump openssl from 1.0 to 1.1",
    "body": "Package: openssl\nSeverity: high\nPatched versions: 1.1.1",
    "html_url": "https://github.com/ThreatFlux/demo/issues/123",
    "user": { "login": "dependabot[bot]" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
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
        let config = load_config_from_str(
            r#"
version: 1
rules:
  - id: dependabot-high-issues
    when:
      event: issues
      action: opened
      actor_in:
        - dependabot[bot]
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high|critical)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#,
        )
        .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            r#"{
  "action": "opened",
  "issue": {
    "title": "Regular issue",
    "body": "Severity: high",
    "html_url": "https://github.com/ThreatFlux/demo/issues/456",
    "user": { "login": "wyatt" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
        )
        .expect("event should parse");

        let matched =
            evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed");
        assert!(matched.is_none());
    }

    #[test]
    fn render_template_substitutes_known_fields() {
        let config = load_config_from_str(
            r#"
version: 1
rules:
  - id: dependabot-high-issues
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
        critical: Highest
      summary: "[Dependabot][{{ severity_title }}] {{ issue.title }}"
      description: "{{ repository.full_name }} {{ issue.html_url }} {{ issue.body }}"
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
"#,
        )
        .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            r#"{
  "action": "opened",
  "issue": {
    "title": "Bump foo",
    "body": "Severity: critical",
    "html_url": "https://github.com/ThreatFlux/demo/issues/1",
    "user": { "login": "dependabot[bot]" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
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
        let config = load_config_from_str(
            r#"
version: 1
rules:
  - id: dependabot-high-issues
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
        critical: Highest
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
"#,
        )
        .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            r#"{
  "action": "opened",
  "issue": {
    "title": "Bump foo",
    "body": "Severity: critical",
    "html_url": "https://github.com/ThreatFlux/demo/issues/1",
    "user": { "login": "dependabot[bot]" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
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
    fn evaluate_rule_returns_none_when_issue_body_is_missing() {
        let config = load_config_from_str(
            r#"
version: 1
rules:
  - id: dependabot-high-issues
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
        critical: Highest
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
"#,
        )
        .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            r#"{
  "action": "opened",
  "issue": {
    "title": "Bump foo",
    "body": null,
    "html_url": "https://github.com/ThreatFlux/demo/issues/1",
    "user": { "login": "dependabot[bot]" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
        )
        .expect("event should parse");

        let matched =
            evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed");
        assert!(matched.is_none());
    }

    #[test]
    fn evaluate_rule_returns_none_for_non_matching_action() {
        let config = load_config_from_str(
            r#"
version: 1
rules:
  - id: dependabot-high-issues
    when:
      event: issues
      action: edited
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high|critical)\b'
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
"#,
        )
        .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            r#"{
  "action": "opened",
  "issue": {
    "title": "Bump foo",
    "body": "Severity: high",
    "html_url": "https://github.com/ThreatFlux/demo/issues/1",
    "user": { "login": "dependabot[bot]" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
        )
        .expect("event should parse");

        let matched =
            evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed");
        assert!(matched.is_none());
    }

    #[test]
    fn evaluate_rule_returns_none_for_empty_capture() {
        let config = load_config_from_str(
            r#"
version: 1
rules:
  - id: dependabot-high-issues
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*()'
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
"#,
        )
        .expect("config should load");
        let event = load_issue_event_from_str(
            "issues",
            r#"{
  "action": "opened",
  "issue": {
    "title": "Bump foo",
    "body": "Severity: high",
    "html_url": "https://github.com/ThreatFlux/demo/issues/1",
    "user": { "login": "dependabot[bot]" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
        )
        .expect("event should parse");

        let matched =
            evaluate_rule(&config.rules[0], &event).expect("rule evaluation should succeed");
        assert!(matched.is_none());
    }

    #[test]
    fn title_case_returns_empty_string_for_empty_input() {
        assert!(title_case("").is_empty());
    }
}
