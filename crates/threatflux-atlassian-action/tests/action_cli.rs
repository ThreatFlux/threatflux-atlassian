use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}"))
}

#[test]
fn action_binary_supports_dry_run_fixture_execution() {
    let temp_root = unique_temp_dir("threatflux-atlassian-action-bin");
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
    "title": "Bump foo",
    "body": "Severity: high\nPackage: foo",
    "html_url": "https://github.com/ThreatFlux/demo/issues/1",
    "user": { "login": "dependabot[bot]" }
  },
  "repository": { "full_name": "ThreatFlux/demo" }
}"#,
    )
    .expect("event should be written");

    let status = Command::new(env!("CARGO_BIN_EXE_threatflux-atlassian-action"))
        .env("INPUT_CONFIG_PATH", config_path.display().to_string())
        .env("INPUT_DRY_RUN", "true")
        .env("INPUT_EVENT_NAME", "issues")
        .env("INPUT_EVENT_PATH", event_path.display().to_string())
        .env("GITHUB_OUTPUT", output_path.display().to_string())
        .status()
        .expect("binary should execute");

    assert!(status.success());

    let output = fs::read_to_string(&output_path).expect("github output should exist");
    assert!(output.contains("matched-rule-id=dependabot-high-issues"));
    assert!(output.contains("severity=high"));
}
