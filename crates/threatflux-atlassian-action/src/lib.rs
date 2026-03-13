pub mod config;
pub mod github;
pub mod jira;
pub mod rules;

use anyhow::Result;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
#[cfg(test)]
use std::sync::Mutex;
use threatflux_atlassian_sdk::{AtlassianClient, AtlassianConfig};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionOutcome {
    pub matched_rule_id: Option<String>,
    pub created: bool,
    pub jira_issue_key: Option<String>,
    pub deduped: bool,
    pub severity: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct TestJiraHook {
    search_result: std::result::Result<Option<String>, String>,
    create_result: std::result::Result<String, String>,
}

#[cfg(test)]
static TEST_JIRA_HOOK: Mutex<Option<TestJiraHook>> = Mutex::new(None);

#[cfg(test)]
fn current_test_jira_hook() -> Option<TestJiraHook> {
    TEST_JIRA_HOOK
        .lock()
        .expect("hook lock should succeed")
        .clone()
}

pub async fn run_from_env() -> Result<ActionOutcome> {
    init_tracing();

    let config_path = env::var("INPUT_CONFIG_PATH")
        .unwrap_or_else(|_| ".github/threatflux/jira-automation.yml".to_string());
    let dry_run = parse_bool_input("INPUT_DRY_RUN");

    let config_raw = fs::read_to_string(&config_path)?;
    let config = config::load_config_from_str(&config_raw)?;

    let event_name = env::var("INPUT_EVENT_NAME").or_else(|_| env::var("GITHUB_EVENT_NAME"))?;
    let event_path = env::var("INPUT_EVENT_PATH").or_else(|_| env::var("GITHUB_EVENT_PATH"))?;
    let event_payload = fs::read_to_string(event_path)?;
    let event = github::load_issue_event_from_str(&event_name, &event_payload)?;

    for rule in &config.rules {
        let Some(rule_match) = rules::evaluate_rule(rule, &event)? else {
            continue;
        };

        let outcome = execute_rule(rule, &event, &rule_match, dry_run).await?;
        write_outputs(&outcome)?;
        return Ok(outcome);
    }

    let outcome = ActionOutcome::default();
    write_outputs(&outcome)?;
    Ok(outcome)
}

fn build_client_from_env() -> Result<AtlassianClient> {
    let base_url = env::var("JIRA_BASE_URL")
        .or_else(|_| env::var("JIRA_URL"))
        .map_err(|_| anyhow::anyhow!("Missing Jira base URL: set JIRA_BASE_URL or JIRA_URL"))?;
    let username = env::var("JIRA_EMAIL")
        .or_else(|_| env::var("JIRA_USERNAME"))
        .map_err(|_| anyhow::anyhow!("Missing Jira username: set JIRA_EMAIL or JIRA_USERNAME"))?;
    let api_token = env::var("JIRA_API_TOKEN")
        .map_err(|_| anyhow::anyhow!("Missing Jira API token: set JIRA_API_TOKEN"))?;

    let config =
        AtlassianConfig::from_env_with_overrides(Some(base_url), Some(username), Some(api_token))?;
    Ok(AtlassianClient::new(config)?)
}

fn init_tracing() {
    let level = env::var("INPUT_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_target(false)
        .without_time()
        .try_init();
}

fn parse_bool_input(name: &str) -> bool {
    env::var(name).is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
}

async fn finalize_action<SearchFn, SearchFut, CreateFn, CreateFut>(
    rule: &config::RuleConfig,
    event: &github::GitHubIssueEvent,
    rule_match: &rules::RuleMatch,
    search_fn: SearchFn,
    create_fn: CreateFn,
) -> Result<ActionOutcome>
where
    SearchFn: FnOnce(String) -> SearchFut,
    SearchFut: Future<Output = Result<Option<String>>>,
    CreateFn: FnOnce(threatflux_atlassian_sdk::CreateIssueRequest) -> CreateFut,
    CreateFut: Future<Output = Result<String>>,
{
    let mut outcome = ActionOutcome {
        matched_rule_id: Some(rule_match.rule_id.clone()),
        created: false,
        jira_issue_key: None,
        deduped: false,
        severity: Some(rule_match.severity.clone()),
    };

    let jql = jira::build_dedupe_jql(rule, &rule_match.dedupe_label);
    if let Some(issue_key) = search_fn(jql).await? {
        outcome.deduped = true;
        outcome.jira_issue_key = Some(issue_key);
        return Ok(outcome);
    }

    let request = jira::build_create_issue_request(rule, event, rule_match)?;
    outcome.created = true;
    outcome.jira_issue_key = Some(create_fn(request).await?);
    Ok(outcome)
}

async fn execute_rule(
    rule: &config::RuleConfig,
    event: &github::GitHubIssueEvent,
    rule_match: &rules::RuleMatch,
    dry_run: bool,
) -> Result<ActionOutcome> {
    let outcome = ActionOutcome {
        matched_rule_id: Some(rule_match.rule_id.clone()),
        created: false,
        jira_issue_key: None,
        deduped: false,
        severity: Some(rule_match.severity.clone()),
    };

    if dry_run {
        return Ok(outcome);
    }

    #[cfg(test)]
    if let Some(hook) = current_test_jira_hook() {
        let search_result = hook.search_result.clone();
        let create_result = hook.create_result.clone();
        return finalize_action(
            rule,
            event,
            rule_match,
            |_jql| async move { search_result.map_err(anyhow::Error::msg) },
            |_request| async move { create_result.map_err(anyhow::Error::msg) },
        )
        .await;
    }

    let client = build_client_from_env()?;
    let client_ref = &client;
    finalize_action(
        rule,
        event,
        rule_match,
        |jql| async move {
            let existing = client_ref.search_issues(&jql, 0, 1).await?;
            Ok(existing.issues.first().map(|issue| issue.key.clone()))
        },
        |request| async move {
            let issue = client_ref.create_issue(request).await?;
            Ok(issue.key)
        },
    )
    .await
}

fn write_outputs(outcome: &ActionOutcome) -> Result<()> {
    let Some(path) = env::var_os("GITHUB_OUTPUT") else {
        return Ok(());
    };

    let mut handle = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(
        handle,
        "matched-rule-id={}",
        outcome.matched_rule_id.clone().unwrap_or_default()
    )?;
    writeln!(handle, "created={}", outcome.created)?;
    writeln!(
        handle,
        "jira-issue-key={}",
        outcome.jira_issue_key.clone().unwrap_or_default()
    )?;
    writeln!(handle, "deduped={}", outcome.deduped)?;
    writeln!(
        handle,
        "severity={}",
        outcome.severity.clone().unwrap_or_default()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_client_from_env, parse_bool_input, run_from_env, write_outputs, ActionOutcome,
        TestJiraHook, TEST_JIRA_HOOK,
    };
    use serial_test::serial;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    #[serial]
    async fn run_from_env_dry_run_writes_outputs_for_matching_rule() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        fs::write(
            &config_path,
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
        .expect("config should be written");
        fs::write(
            &event_path,
            r#"{
  "action": "opened",
  "issue": {
    "title": "Bump foo",
    "body": "Severity: high\nPackage: foo",
    "html_url": "https://github.com/ThreatFlux/demo/issues/1",
    "user": { "login": "dependabot[bot]" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
        )
        .expect("event should be written");

        std::env::set_var("INPUT_CONFIG_PATH", config_path.display().to_string());
        std::env::set_var("INPUT_DRY_RUN", "true");
        std::env::set_var("INPUT_EVENT_NAME", "issues");
        std::env::set_var("INPUT_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("INPUT_LOG_LEVEL", "debug");
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let outcome = run_from_env().await.expect("dry run should succeed");
        let output = fs::read_to_string(&output_path).expect("github output should exist");

        assert_eq!(
            outcome.matched_rule_id.as_deref(),
            Some("dependabot-high-issues")
        );
        assert_eq!(outcome.severity.as_deref(), Some("high"));
        assert!(!outcome.created);
        assert!(!outcome.deduped);
        assert!(output.contains("matched-rule-id=dependabot-high-issues"));
        assert!(output.contains("created=false"));
        assert!(output.contains("severity=high"));

        cleanup_env(&[
            "INPUT_CONFIG_PATH",
            "INPUT_DRY_RUN",
            "INPUT_EVENT_NAME",
            "INPUT_EVENT_PATH",
            "INPUT_LOG_LEVEL",
            "GITHUB_OUTPUT",
        ]);
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_writes_empty_outputs_when_no_rule_matches() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        fs::write(
            &config_path,
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
      summary: "{{ issue.title }}"
      description: "{{ issue.body }}"
      dedupe:
        strategy: sha256
        fields:
          - repository.full_name
          - issue.title
"#,
        )
        .expect("config should be written");
        fs::write(
            &event_path,
            r#"{
  "action": "opened",
  "issue": {
    "title": "Regular issue",
    "body": "Severity: medium",
    "html_url": "https://github.com/ThreatFlux/demo/issues/2",
    "user": { "login": "wyatt" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
        )
        .expect("event should be written");

        std::env::set_var("INPUT_CONFIG_PATH", config_path.display().to_string());
        std::env::set_var("INPUT_DRY_RUN", "true");
        std::env::set_var("INPUT_EVENT_NAME", "issues");
        std::env::set_var("INPUT_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let outcome = run_from_env()
            .await
            .expect("no-match dry run should succeed");
        let output = fs::read_to_string(&output_path).expect("github output should exist");

        assert_eq!(outcome.matched_rule_id, None);
        assert_eq!(outcome.severity, None);
        assert!(!outcome.created);
        assert!(!outcome.deduped);
        assert!(output.contains("matched-rule-id="));
        assert!(output.contains("created=false"));
        assert!(output.contains("deduped=false"));

        cleanup_env(&[
            "INPUT_CONFIG_PATH",
            "INPUT_DRY_RUN",
            "INPUT_EVENT_NAME",
            "INPUT_EVENT_PATH",
            "GITHUB_OUTPUT",
        ]);
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_dedupes_existing_issue() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");
        set_test_jira_hook(
            Ok(Some("KAN-42".to_string())),
            Ok("KAN-should-not-create".to_string()),
        );

        std::env::set_var("INPUT_CONFIG_PATH", config_path.display().to_string());
        std::env::set_var("INPUT_EVENT_NAME", "issues");
        std::env::set_var("INPUT_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let outcome = run_from_env().await.expect("dedupe should succeed");
        let output = fs::read_to_string(&output_path).expect("github output should exist");

        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-42"));
        assert!(outcome.deduped);
        assert!(!outcome.created);
        assert!(output.contains("jira-issue-key=KAN-42"));
        assert!(output.contains("deduped=true"));

        cleanup_env(&[
            "INPUT_CONFIG_PATH",
            "INPUT_EVENT_NAME",
            "INPUT_EVENT_PATH",
            "GITHUB_OUTPUT",
        ]);
        clear_test_jira_hook();
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_creates_issue_when_no_duplicate_exists() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: critical\nPackage: foo");
        set_test_jira_hook(Ok(None), Ok("KAN-77".to_string()));

        std::env::set_var("INPUT_CONFIG_PATH", config_path.display().to_string());
        std::env::set_var("INPUT_EVENT_NAME", "issues");
        std::env::set_var("INPUT_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let outcome = run_from_env().await.expect("create should succeed");
        let output = fs::read_to_string(&output_path).expect("github output should exist");

        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-77"));
        assert!(outcome.created);
        assert!(!outcome.deduped);
        assert!(output.contains("jira-issue-key=KAN-77"));
        assert!(output.contains("created=true"));

        cleanup_env(&[
            "INPUT_CONFIG_PATH",
            "INPUT_EVENT_NAME",
            "INPUT_EVENT_PATH",
            "GITHUB_OUTPUT",
        ]);
        clear_test_jira_hook();
    }

    #[test]
    #[serial]
    fn build_client_from_env_supports_action_aliases() {
        std::env::set_var("JIRA_BASE_URL", "https://example.atlassian.net");
        std::env::set_var("JIRA_EMAIL", "bot@threatflux.dev");
        std::env::set_var("JIRA_API_TOKEN", "secret");

        let result = build_client_from_env();
        assert!(result.is_ok());

        cleanup_env(&["JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN"]);
    }

    #[test]
    #[serial]
    fn build_client_from_env_reports_missing_configuration() {
        cleanup_env(&[
            "JIRA_BASE_URL",
            "JIRA_URL",
            "JIRA_EMAIL",
            "JIRA_USERNAME",
            "JIRA_API_TOKEN",
        ]);
        let error = build_client_from_env().expect_err("missing env should fail");
        assert!(error.to_string().contains("Missing Jira base URL"));
    }

    #[test]
    #[serial]
    fn parse_bool_input_handles_true_and_false_values() {
        std::env::set_var("INPUT_DRY_RUN", "yes");
        assert!(parse_bool_input("INPUT_DRY_RUN"));
        std::env::set_var("INPUT_DRY_RUN", "false");
        assert!(!parse_bool_input("INPUT_DRY_RUN"));
        cleanup_env(&["INPUT_DRY_RUN"]);
    }

    #[test]
    #[serial]
    fn parse_bool_input_returns_false_when_unset() {
        cleanup_env(&["INPUT_DRY_RUN"]);
        assert!(!parse_bool_input("INPUT_DRY_RUN"));
    }

    #[test]
    #[serial]
    fn write_outputs_is_noop_without_github_output() {
        cleanup_env(&["GITHUB_OUTPUT"]);
        let result = write_outputs(&ActionOutcome::default());
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn write_outputs_writes_all_fields_when_present() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");
        let output_path = temp_root.join("github-output.txt");

        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());
        let outcome = ActionOutcome {
            matched_rule_id: Some("rule-1".to_string()),
            created: true,
            jira_issue_key: Some("KAN-9".to_string()),
            deduped: false,
            severity: Some("critical".to_string()),
        };

        write_outputs(&outcome).expect("outputs should be written");
        let output = fs::read_to_string(&output_path).expect("github output should exist");

        assert!(output.contains("matched-rule-id=rule-1"));
        assert!(output.contains("jira-issue-key=KAN-9"));
        assert!(output.contains("severity=critical"));

        cleanup_env(&["GITHUB_OUTPUT"]);
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }

    fn cleanup_env(names: &[&str]) {
        for name in names {
            std::env::remove_var(name);
        }
    }

    fn write_standard_config(path: &std::path::Path) {
        fs::write(
            path,
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
        .expect("config should be written");
    }

    fn write_matching_event(path: &std::path::Path, body: &str) {
        fs::write(
            path,
            serde_json::json!({
                "action": "opened",
                "issue": {
                    "title": "Bump foo",
                    "body": body,
                    "html_url": "https://github.com/ThreatFlux/demo/issues/1",
                    "user": { "login": "dependabot[bot]" }
                },
                "repository": { "full_name": "ThreatFlux/demo" }
            })
            .to_string(),
        )
        .expect("event should be written");
    }

    fn set_test_jira_hook(
        search_result: std::result::Result<Option<String>, String>,
        create_result: std::result::Result<String, String>,
    ) {
        *TEST_JIRA_HOOK.lock().expect("hook lock should succeed") = Some(TestJiraHook {
            search_result,
            create_result,
        });
    }

    fn clear_test_jira_hook() {
        *TEST_JIRA_HOOK.lock().expect("hook lock should succeed") = None;
    }
}
