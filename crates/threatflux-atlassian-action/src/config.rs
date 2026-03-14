use crate::rules::{is_supported_event_field_path, validate_template, SUPPORTED_EVENT_NAME};
use anyhow::Result;
use regex::Regex;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutomationConfig {
    pub version: u32,
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleConfig {
    pub id: String,
    pub when: WhenConfig,
    pub extract: ExtractConfig,
    pub jira: JiraRuleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhenConfig {
    pub event: String,
    pub action: String,
    #[serde(default)]
    pub actor_in: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractConfig {
    pub severity: SeverityExtractConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeverityExtractConfig {
    pub from: String,
    pub regex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JiraRuleConfig {
    pub project_key: String,
    pub issue_type: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub assignee_account_id: Option<String>,
    pub priority_by_severity: BTreeMap<String, String>,
    pub summary: String,
    #[serde(default = "default_description_format")]
    pub description_format: String,
    pub description: String,
    #[serde(default)]
    pub labels: Vec<String>,
    pub dedupe: DedupeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DedupeConfig {
    pub strategy: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub label_prefix: Option<String>,
    pub fields: Vec<String>,
}

fn default_description_format() -> String {
    "text".to_string()
}

fn empty_string_as_none<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.and_then(|inner| {
        if inner.trim().is_empty() {
            None
        } else {
            Some(inner)
        }
    }))
}

pub fn load_config_from_str(raw: &str) -> Result<AutomationConfig> {
    let mut value: Value = serde_yaml::from_str(raw)?;
    expand_env_vars_in_value(&mut value)?;
    let config: AutomationConfig = serde_yaml::from_value(value)?;
    validate_config(&config)?;
    Ok(config)
}

fn expand_env_vars_in_value(value: &mut Value) -> Result<()> {
    match value {
        Value::String(inner) => {
            *inner = expand_env_vars_in_string(inner)?;
        }
        Value::Sequence(items) => {
            for item in items {
                expand_env_vars_in_value(item)?;
            }
        }
        Value::Mapping(entries) => {
            for entry in entries.values_mut() {
                expand_env_vars_in_value(entry)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn expand_env_vars_in_string(raw: &str) -> Result<String> {
    let pattern = Regex::new(r"\$\{([A-Z0-9_]+)(:-([^}]*))?\}")?;
    let mut rendered = String::with_capacity(raw.len());
    let mut last = 0;

    for captures in pattern.captures_iter(raw) {
        let matched = captures.get(0).expect("match should exist");
        rendered.push_str(&raw[last..matched.start()]);

        let name = captures
            .get(1)
            .expect("env var capture should exist")
            .as_str();
        let default = captures.get(3).map(|value| value.as_str());
        let value = resolve_env_var(name, default)?;

        rendered.push_str(&value);
        last = matched.end();
    }

    rendered.push_str(&raw[last..]);
    Ok(rendered)
}

fn resolve_env_var(name: &str, default: Option<&str>) -> Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => default.map_or_else(|| Ok(String::new()), |value| Ok(value.to_string())),
        Err(_) => default.map_or_else(
            || anyhow::bail!("Missing required environment variable: {name}"),
            |value| Ok(value.to_string()),
        ),
    }
}

fn validate_config(config: &AutomationConfig) -> Result<()> {
    if config.version != 1 {
        anyhow::bail!("Unsupported config version: {}", config.version);
    }

    if config.rules.is_empty() {
        anyhow::bail!("Config must contain at least one rule");
    }

    for rule in &config.rules {
        if rule.id.trim().is_empty() {
            anyhow::bail!("Rule id cannot be empty");
        }

        if rule.when.event.trim().is_empty() || rule.when.action.trim().is_empty() {
            anyhow::bail!("Rule '{}' must define non-empty event and action", rule.id);
        }

        if rule.when.event != SUPPORTED_EVENT_NAME {
            anyhow::bail!(
                "Rule '{}' has unsupported event '{}'; supported events: {}",
                rule.id,
                rule.when.event,
                SUPPORTED_EVENT_NAME
            );
        }

        if rule.extract.severity.from != "issue.body" {
            anyhow::bail!(
                "Rule '{}' has unsupported severity source '{}'",
                rule.id,
                rule.extract.severity.from
            );
        }

        let severity_pattern = Regex::new(&rule.extract.severity.regex)?;
        if severity_pattern.captures_len() < 2 {
            anyhow::bail!(
                "Rule '{}' severity regex must define capture group 1 for extraction",
                rule.id
            );
        }

        if rule.jira.project_key.trim().is_empty() || rule.jira.issue_type.trim().is_empty() {
            anyhow::bail!(
                "Rule '{}' must define non-empty jira.project_key and jira.issue_type",
                rule.id
            );
        }

        if rule.jira.summary.trim().is_empty() {
            anyhow::bail!("Rule '{}' must define a non-empty jira.summary", rule.id);
        }

        if rule.jira.description_format != "text" {
            anyhow::bail!(
                "Rule '{}' has unsupported description format '{}'",
                rule.id,
                rule.jira.description_format
            );
        }

        if rule.jira.dedupe.fields.is_empty() {
            anyhow::bail!("Rule '{}' must define at least one dedupe field", rule.id);
        }

        for field in &rule.jira.dedupe.fields {
            if !is_supported_event_field_path(field) {
                anyhow::bail!(
                    "Rule '{}' has unsupported dedupe field '{}'",
                    rule.id,
                    field
                );
            }
        }

        if rule.jira.dedupe.strategy != "sha256" {
            anyhow::bail!(
                "Rule '{}' has unsupported dedupe strategy '{}'",
                rule.id,
                rule.jira.dedupe.strategy
            );
        }

        validate_template(
            &format!("Rule '{}' jira.summary", rule.id),
            &rule.jira.summary,
        )?;
        validate_template(
            &format!("Rule '{}' jira.description", rule.id),
            &rule.jira.description,
        )?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::needless_raw_string_hashes)]
#[allow(clippy::literal_string_with_formatting_args)]
mod tests {
    use super::load_config_from_str;
    use serial_test::serial;

    #[test]
    #[serial]
    fn load_config_expands_env_defaults_and_values() {
        std::env::set_var("JIRA_ASSIGNEE_ACCOUNT_ID", "account-123");

        let yaml = r#"
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
      project_key: ${JIRA_PROJECT_KEY:-KAN}
      issue_type: Bug
      assignee_account_id: ${JIRA_ASSIGNEE_ACCOUNT_ID:-}
      priority_by_severity:
        high: High
        critical: Highest
      summary: "[Dependabot][{{ severity_title }}] {{ issue.title }}"
      description: |
        Repo: {{ repository.full_name }}
      labels: [dependabot, security]
      dedupe:
        strategy: sha256
        label_prefix: dependabot-alert
        fields:
          - repository.full_name
          - issue.title
"#;

        let config = load_config_from_str(yaml).expect("config should load");
        let rule = &config.rules[0];

        assert_eq!(config.version, 1);
        assert_eq!(rule.jira.project_key, "KAN");
        assert_eq!(
            rule.jira.assignee_account_id.as_deref(),
            Some("account-123")
        );
        assert_eq!(rule.jira.description_format, "text");
    }

    #[test]
    #[serial]
    fn load_config_treats_empty_env_as_unset_when_default_is_present() {
        std::env::set_var("JIRA_PROJECT_KEY", "");
        std::env::remove_var("JIRA_ASSIGNEE_ACCOUNT_ID");

        let yaml = r#"
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
      project_key: ${JIRA_PROJECT_KEY:-KAN}
      issue_type: Bug
      assignee_account_id: ${JIRA_ASSIGNEE_ACCOUNT_ID:-}
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#;

        let config = load_config_from_str(yaml).expect("config should load");
        let rule = &config.rules[0];

        assert_eq!(rule.jira.project_key, "KAN");
        assert_eq!(rule.jira.assignee_account_id, None);
    }

    #[test]
    #[serial]
    fn load_config_treats_whitespace_env_as_unset_when_default_is_present() {
        std::env::set_var("JIRA_PROJECT_KEY", "   ");

        let yaml = r#"
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
      project_key: ${JIRA_PROJECT_KEY:-KAN}
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#;

        let config = load_config_from_str(yaml).expect("config should load");
        assert_eq!(config.rules[0].jira.project_key, "KAN");
    }

    #[test]
    #[serial]
    fn load_config_rejects_missing_required_env_value() {
        std::env::remove_var("JIRA_PROJECT_KEY");

        let yaml = r#"
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
      project_key: ${JIRA_PROJECT_KEY}
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#;

        let error = load_config_from_str(yaml).expect_err("missing env should fail");
        assert_eq!(
            error.to_string(),
            "Missing required environment variable: JIRA_PROJECT_KEY"
        );
    }

    #[test]
    #[serial]
    fn load_config_keeps_empty_required_env_when_no_default_is_provided() {
        std::env::set_var("JIRA_PROJECT_KEY", "");

        let yaml = r#"
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
      project_key: ${JIRA_PROJECT_KEY}
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#;

        let error =
            load_config_from_str(yaml).expect_err("empty required env should fail validation");
        assert!(error.to_string().contains("jira.project_key"));
    }

    #[test]
    #[serial]
    fn load_config_expands_env_values_without_yaml_structure_injection() {
        std::env::set_var("JIRA_DESCRIPTION", "first line\njira:\n  injected: value");

        let yaml = r#"
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
      description: ${JIRA_DESCRIPTION}
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#;

        let config = load_config_from_str(yaml).expect("config should load");
        let rule = &config.rules[0];

        assert_eq!(rule.jira.issue_type, "Bug");
        assert_eq!(
            rule.jira.description,
            "first line\njira:\n  injected: value"
        );
    }

    #[test]
    fn load_config_rejects_invalid_version() {
        let error = load_config_from_str(
            r#"
version: 2
rules:
  - id: x
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
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
        .expect_err("invalid version should fail");
        assert!(error.to_string().contains("Unsupported config version"));
    }

    #[test]
    fn load_config_rejects_unsupported_description_format() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: x
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description_format: adf
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#,
        )
        .expect_err("unsupported format should fail");
        assert!(error.to_string().contains("unsupported description format"));
    }

    #[test]
    fn load_config_rejects_unsupported_severity_source() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: x
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.title
        regex: '(?mi)^severity:\s*(high)\b'
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
        .expect_err("unsupported severity source should fail");
        assert!(error.to_string().contains("unsupported severity source"));
    }

    #[test]
    fn load_config_rejects_unsupported_dedupe_strategy() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: x
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha1
        fields: [issue.title]
"#,
        )
        .expect_err("unsupported dedupe strategy should fail");
        assert!(error.to_string().contains("unsupported dedupe strategy"));
    }

    #[test]
    fn load_config_rejects_empty_rules() {
        let error =
            load_config_from_str("version: 1\nrules: []\n").expect_err("empty rules should fail");
        assert!(error.to_string().contains("at least one rule"));
    }

    #[test]
    fn load_config_rejects_empty_rule_id() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: "  "
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
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
        .expect_err("empty rule id should fail");
        assert!(error.to_string().contains("Rule id cannot be empty"));
    }

    #[test]
    fn load_config_rejects_empty_event_or_action() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: ""
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
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
        .expect_err("empty event should fail");
        assert!(error
            .to_string()
            .contains("must define non-empty event and action"));
    }

    #[test]
    fn load_config_rejects_unsupported_event() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: pull_request
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
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
        .expect_err("unsupported event should fail");
        assert!(error.to_string().contains("unsupported event"));
    }

    #[test]
    fn load_config_rejects_empty_project_key_or_issue_type() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: ""
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
        .expect_err("empty project key should fail");
        assert!(error.to_string().contains("jira.project_key"));
    }

    #[test]
    fn load_config_rejects_empty_summary() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: "   "
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#,
        )
        .expect_err("empty summary should fail");
        assert!(error.to_string().contains("non-empty jira.summary"));
    }

    #[test]
    fn load_config_rejects_unknown_summary_template_field() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: "{{ issue.titel }}"
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#,
        )
        .expect_err("unknown summary template field should fail");
        assert!(error.to_string().contains("jira.summary"));
        assert!(error.to_string().contains("unknown template field"));
    }

    #[test]
    fn load_config_rejects_unknown_description_template_field() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: "{{ issue.titel }}"
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#,
        )
        .expect_err("unknown description template field should fail");
        assert!(error.to_string().contains("jira.description"));
        assert!(error.to_string().contains("unknown template field"));
    }

    #[test]
    fn load_config_rejects_unsupported_dedupe_field() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.name]
"#,
        )
        .expect_err("unsupported dedupe field should fail");
        assert!(error.to_string().contains("unsupported dedupe field"));
    }

    #[test]
    fn load_config_rejects_empty_dedupe_fields() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: []
"#,
        )
        .expect_err("empty dedupe fields should fail");
        assert!(error.to_string().contains("at least one dedupe field"));
    }

    #[test]
    fn load_config_rejects_severity_regex_without_capture_group() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*high\b'
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
        .expect_err("missing capture group should fail");
        assert!(error.to_string().contains("capture group 1"));
    }

    #[test]
    fn load_config_rejects_unknown_template_field_in_summary() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: "{{ issue.titel }}"
      description: test
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#,
        )
        .expect_err("unknown template field in summary should fail");
        assert!(error.to_string().contains("unknown template field"));
        assert!(error.to_string().contains("issue.titel"));
    }

    #[test]
    fn load_config_rejects_unknown_template_field_in_description() {
        let error = load_config_from_str(
            r#"
version: 1
rules:
  - id: test
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: "{{ repo.full_name }}"
      dedupe:
        strategy: sha256
        fields: [issue.title]
"#,
        )
        .expect_err("unknown template field in description should fail");
        assert!(error.to_string().contains("unknown template field"));
        assert!(error.to_string().contains("repo.full_name"));
    }
}
