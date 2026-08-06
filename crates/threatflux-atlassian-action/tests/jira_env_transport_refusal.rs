//! The Action's own environment path cannot reach a cleartext or non-Atlassian
//! Jira.
//!
//! `build_client_from_env` is the one client construction in the workspace that
//! is driven entirely by the workflow environment, and it is deliberately *not*
//! on the end-to-end path: the mock suite builds its client by code call with
//! the loopback host policy, which no environment variable can select. So this
//! suite drives the shipped binary instead, with a delivery that really does
//! match a rule, and asserts on the refusal the run dies with.
//!
//! Each case runs with `dry-run: false`, so the run reaches the Jira client. No
//! case reaches the network: the refusal happens while the configuration is
//! being validated, and the two hosts used here are a closed loopback port and a
//! name in the RFC 2606 `.invalid` domain, so even a regression that skipped the
//! check would fail locally rather than dial a third party.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use threatflux_atlassian_testkit::fixtures;
use threatflux_atlassian_testkit::net::closed_loopback_url;

/// Variables the parent process may carry that would otherwise decide a run.
///
/// The `INPUT_*` entries are the underscored aliases of the hyphenated names the
/// runner sets, and the rest is every credential and transport variable the SDK
/// reads.
const CLEARED_VARS: [&str; 18] = [
    "INPUT_CONFIG_PATH",
    "INPUT_DRY_RUN",
    "INPUT_EVENT_NAME",
    "INPUT_EVENT_PATH",
    "INPUT_LOG_LEVEL",
    "INPUT_LOG-LEVEL",
    "JIRA_BASE_URL",
    "JIRA_URL",
    "JIRA_EMAIL",
    "JIRA_USERNAME",
    "JIRA_API_TOKEN",
    "JIRA_CERT_PATH",
    "JIRA_HOST_POLICY",
    "JIRA_MAX_RETRIES",
    "JIRA_TIMEOUT",
    "JIRA_VERIFY_SSL",
    "ENV_FILE_ENCRYPTED",
    "ENV_FILE_ENCRYPTED_PATH",
];

struct Delivery {
    root: PathBuf,
    config_path: PathBuf,
    event_path: PathBuf,
    output_path: PathBuf,
}

impl Delivery {
    /// Writes a delivery that matches the `dependabot-high-issues` rule.
    fn write(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "threatflux-atlassian-env-transport-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("temp dir should be created");

        let delivery = Self {
            config_path: root.join("jira-automation.yml"),
            event_path: root.join("event.json"),
            output_path: root.join("github-output.txt"),
            root,
        };

        fs::write(
            &delivery.config_path,
            fixtures::action_config("dependabot-high-plain-templates"),
        )
        .expect("config should be written");
        fs::write(
            &delivery.event_path,
            fixtures::github_event("issues-opened-dependabot-high-package"),
        )
        .expect("event should be written");

        delivery
    }

    /// The binary invoked as the runner invokes it, with `dry-run` as given.
    fn command(&self, dry_run: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_threatflux-atlassian-action"));
        for name in CLEARED_VARS {
            command.env_remove(name);
        }
        command
            .env("INPUT_CONFIG-PATH", path_arg(&self.config_path))
            .env("INPUT_DRY-RUN", if dry_run { "true" } else { "false" })
            .env("INPUT_EVENT-NAME", "issues")
            .env("INPUT_EVENT-PATH", path_arg(&self.event_path))
            .env("GITHUB_OUTPUT", path_arg(&self.output_path));
        command
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A path as the process should receive it.
///
/// `display()` rather than `{:?}`: the debug form of a Windows path doubles its
/// separators, and the child would be handed a path that does not exist.
fn path_arg(path: &Path) -> String {
    path.display().to_string()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Runs a delivery whose Jira credentials point somewhere the SDK must refuse.
fn assert_refused(label: &str, jira_env: &[(&str, String)], expected: &str) {
    let delivery = Delivery::write(label);
    let mut command = delivery.command(false);
    command
        .env("JIRA_EMAIL", "bot@example.com")
        .env("JIRA_API_TOKEN", "api-token");
    for (name, value) in jira_env {
        command.env(name, value);
    }

    let output = command.output().expect("binary should execute");
    let stderr = stderr_of(&output);

    assert!(
        !output.status.success(),
        "{label}: the run succeeded against a destination the SDK must refuse; stderr: {stderr}"
    );
    assert!(
        stderr.contains(expected),
        "{label}: expected a refusal naming {expected:?}, got: {stderr}"
    );
}

/// The control: the same delivery, matched and executed without a Jira client.
///
/// Without it every assertion above could be satisfied by a run that failed for
/// an unrelated reason and never reached the transport at all.
#[test]
fn the_delivery_these_cases_use_matches_a_rule() {
    let delivery = Delivery::write("control");
    let output = delivery
        .command(true)
        .output()
        .expect("binary should execute");

    assert!(
        output.status.success(),
        "the control run failed: {}",
        stderr_of(&output)
    );
    let written = fs::read_to_string(&delivery.output_path).expect("outputs should be written");
    assert!(
        written.contains("dependabot-high-issues"),
        "the control run matched no rule: {written}"
    );
}

#[test]
fn a_cleartext_base_url_is_refused_on_the_scheme() {
    assert_refused(
        "cleartext",
        &[("JIRA_BASE_URL", closed_loopback_url())],
        "must use https",
    );
}

#[test]
fn the_jira_url_spelling_of_the_base_url_is_refused_the_same_way() {
    // `build_client_from_env` accepts either spelling, so the alias is a second
    // door into the same check rather than a way around it.
    assert_refused(
        "cleartext-alias",
        &[("JIRA_URL", closed_loopback_url())],
        "must use https",
    );
}

#[test]
fn the_workflow_environment_cannot_select_the_loopback_host_policy() {
    assert_refused(
        "loopback-policy",
        &[
            ("JIRA_BASE_URL", closed_loopback_url()),
            ("JIRA_HOST_POLICY", "loopback".to_string()),
        ],
        "settable only by",
    );
}

#[test]
fn the_workflow_environment_cannot_disable_certificate_verification() {
    assert_refused(
        "verify-ssl",
        &[
            ("JIRA_BASE_URL", closed_loopback_url()),
            ("JIRA_VERIFY_SSL", "false".to_string()),
        ],
        "cannot disable certificate verification",
    );
}

#[test]
fn a_non_atlassian_host_is_refused_under_the_default_policy() {
    assert_refused(
        "non-atlassian",
        &[("JIRA_BASE_URL", "https://jira.invalid/context".to_string())],
        "not permitted by the 'atlassian-cloud' host policy",
    );
}

#[test]
fn an_allowlisted_data_center_host_still_has_to_be_https() {
    assert_refused(
        "allowlisted-cleartext",
        &[
            ("JIRA_BASE_URL", "http://jira.invalid/context".to_string()),
            ("JIRA_HOST_POLICY", "allowlist:jira.invalid".to_string()),
        ],
        "must use https",
    );
}
