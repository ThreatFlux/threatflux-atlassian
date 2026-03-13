use crate::config::RuleConfig;
use crate::github::GitHubIssueEvent;
use crate::rules::{render_template, RuleMatch};
use anyhow::Result;
use std::collections::HashMap;
use threatflux_atlassian_sdk::{
    CreateIssueFields, CreateIssueRequest, IssueTypeReference, PriorityReference, ProjectReference,
    UserReference,
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
            anyhow::anyhow!(
                "No Jira priority mapping for severity '{}'",
                rule_match.severity
            )
        })?;
    let summary = render_template(&rule.jira.summary, event, rule_match)?;
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
                .as_ref()
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

pub fn build_dedupe_jql(rule: &RuleConfig, dedupe_label: &str) -> String {
    format!(
        r#"project = "{}" AND labels = "{}""#,
        escape_jql_literal(&rule.jira.project_key),
        escape_jql_literal(dedupe_label)
    )
}

fn escape_jql_literal(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"")
}

#[cfg(test)]
#[allow(clippy::needless_raw_string_hashes)]
mod tests {
    use super::{build_create_issue_request, build_dedupe_jql};
    use crate::config::load_config_from_str;
    use crate::github::load_issue_event_from_str;
    use crate::rules::evaluate_rule;

    #[test]
    fn build_create_issue_request_maps_priority_assignee_labels_and_description() {
        let config = load_config_from_str(
            r#"
version: 1
rules:
  - id: dependabot-high-issues
    when:
      event: issues
      action: opened
      actor_in: ["dependabot[bot]"]
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
      description: |
        {{ severity_title }}-severity Dependabot security alert.

        Repository: {{ repository.full_name }}
        GitHub Issue: {{ issue.html_url }}

        ---
        {{ issue.body }}
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
    "title": "Bump foo",
    "body": "Severity: critical\nPackage: foo",
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
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        label_prefix: dependabot-alert
        fields: [repository.full_name, issue.title]
"#,
        )
        .expect("config should load");

        let jql = build_dedupe_jql(&config.rules[0], "dependabot-alert-48fe1f86b5f0");
        assert_eq!(
            jql,
            r#"project = "KAN" AND labels = "dependabot-alert-48fe1f86b5f0""#
        );
    }

    #[test]
    fn build_create_issue_request_errors_when_priority_mapping_is_missing() {
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

        let error = build_create_issue_request(&config.rules[0], &event, &matched)
            .expect_err("missing priority mapping should fail");
        assert!(error.to_string().contains("No Jira priority mapping"));
    }

    #[test]
    fn build_dedupe_jql_escapes_special_characters() {
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
      project_key: "K\"AN"
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

        let jql = build_dedupe_jql(&config.rules[0], r#"dependabot-alert-foo"bar\baz"#);
        assert_eq!(
            jql,
            r#"project = "K\"AN" AND labels = "dependabot-alert-foo\"bar\\baz""#
        );
    }
}
