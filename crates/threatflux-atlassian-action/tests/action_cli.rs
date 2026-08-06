use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use threatflux_atlassian_testkit::fixtures;
use threatflux_atlassian_testkit::gha::github_output_map;

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
        fixtures::action_config("dependabot-high-plain-templates"),
    )
    .expect("config should be written");

    fs::write(
        &event_path,
        fixtures::github_event("issues-opened-dependabot-high-package"),
    )
    .expect("event should be written");

    // The hyphenated names are the ones the GitHub runner sets for a container
    // action; the binary is invoked here exactly as the runner invokes it.
    let status = Command::new(env!("CARGO_BIN_EXE_threatflux-atlassian-action"))
        .env_remove("INPUT_CONFIG_PATH")
        .env_remove("INPUT_DRY_RUN")
        .env_remove("INPUT_EVENT_NAME")
        .env_remove("INPUT_EVENT_PATH")
        .env_remove("JIRA_BASE_URL")
        .env_remove("JIRA_URL")
        .env("INPUT_CONFIG-PATH", config_path.display().to_string())
        .env("INPUT_DRY-RUN", "true")
        .env("INPUT_EVENT-NAME", "issues")
        .env("INPUT_EVENT-PATH", event_path.display().to_string())
        .env("GITHUB_OUTPUT", output_path.display().to_string())
        .status()
        .expect("binary should execute");

    assert!(status.success());

    let raw = fs::read_to_string(&output_path).expect("github output should exist");
    let output = github_output_map(&raw).expect("the runner must be able to parse the output file");
    assert_eq!(output["matched-rule-id"], "dependabot-high-issues");
    assert_eq!(output["severity"], "high");
}
