//! Secret-leak sweep over the Action's observable channels.
//!
//! The Action is a container binary, so what escapes it is what a workflow log
//! shows and what the runner reads back: its stderr, its stdout, and the
//! `GITHUB_OUTPUT` file. Every case here runs the real binary the way the runner
//! runs it, with the Jira credential in its environment, and asserts the
//! canary's **absence** from all three — in every encoding
//! [`SecretScanner`] knows, because a credential that reached a log through
//! base64 or percent-encoding is just as leaked as one that reached it raw.
//!
//! The NF2 config-expansion path is the reason this file exists at the binary
//! level rather than only in `config.rs`: the sink for an expanded credential is
//! `GITHUB_OUTPUT`, and only a process that actually writes one can be swept.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use threatflux_atlassian_testkit::gha::github_output_map;
use threatflux_atlassian_testkit::redaction::SecretScanner;
use threatflux_atlassian_testkit::{fixtures, net};

/// The credential every case in this file plants in the Action's environment.
///
/// The `/` and `+` keep the percent-encoded form distinct from the raw one, so
/// the scanner is checking four encodings rather than reporting four and
/// checking one.
const TOKEN: &str = "CANARY-tok3n/4f21c7a9+must-not-escape";

/// The account the credential belongs to, which is half of the `Basic` blob.
const USERNAME: &str = "canary-bot@example.com";

/// Scans for the credential in every encoding, including the `Basic` blob.
fn scanner() -> SecretScanner {
    SecretScanner::new().with_basic_credentials("jira api token", USERNAME, TOKEN)
}

/// Distinguishes two directories claimed inside the same clock tick.
static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Creates a scratch directory for one run of the binary.
///
/// The counter is not belt and braces: the cases here run in parallel and the
/// clock this reads reports microsecond granularity on some platforms, so two
/// of them can stamp the same nanosecond value, land in one directory, and read
/// each other's config file.
fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{nanos}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("temp dir should be created");
    path
}

/// What one run of the Action binary left behind.
struct Run {
    success: bool,
    stdout: String,
    stderr: String,
    github_output: String,
}

impl Run {
    /// Asserts that no channel this run wrote carries the credential.
    fn assert_no_credential_escaped(&self, context: &str) {
        // A run that wrote nothing anywhere would satisfy every absence
        // assertion below, so the sweep first establishes it has something to
        // sweep.
        assert!(
            !self.stderr.is_empty() || !self.stdout.is_empty() || !self.github_output.is_empty(),
            "{context}: the run produced no observable output at all, so the sweep is vacuous"
        );

        for (channel, rendered) in [
            ("stderr", &self.stderr),
            ("stdout", &self.stdout),
            ("GITHUB_OUTPUT", &self.github_output),
        ] {
            scanner().assert_clean(&format!("{context}: the Action's {channel}"), rendered);
        }
    }
}

/// One invocation of the Action binary, as the runner invokes it.
///
/// The credential is always present, because a sweep of a process that never
/// held the secret proves nothing. `log-level` is `trace` for the same reason:
/// the sweep has to cover the most verbose output the binary can produce, not
/// the default filter's subset.
fn run_action(config_yaml: &str, event_json: &str, extra_env: &[(&str, &str)]) -> Run {
    let root = unique_temp_dir("threatflux-action-secret-sweep");
    let config_path = root.join("jira-automation.yml");
    let event_path = root.join("event.json");
    let output_path = root.join("github-output.txt");

    fs::write(&config_path, config_yaml).expect("config should be written");
    fs::write(&event_path, event_json).expect("event should be written");

    let mut command = Command::new(env!("CARGO_BIN_EXE_threatflux-atlassian-action"));
    command
        // The parent process is a developer machine or a CI runner, either of
        // which may already carry these; a case that inherited one would be
        // testing the wrong environment.
        .env_remove("INPUT_CONFIG_PATH")
        .env_remove("INPUT_DRY_RUN")
        .env_remove("INPUT_LOG_LEVEL")
        .env_remove("INPUT_EVENT_NAME")
        .env_remove("INPUT_EVENT_PATH")
        .env_remove("JIRA_BASE_URL")
        .env_remove("JIRA_URL")
        .env_remove("JIRA_EMAIL")
        .env_remove("JIRA_USERNAME")
        .env_remove("JIRA_HOST_POLICY")
        .env_remove("JIRA_VERIFY_SSL")
        .env_remove("ENV_FILE_ENCRYPTED")
        .env_remove("ENV_FILE_ENCRYPTED_PATH")
        .env_remove("THREATFLUX_CONFIG_ENV_ALLOWLIST")
        .env("INPUT_CONFIG-PATH", path_arg(&config_path))
        .env("INPUT_EVENT-NAME", "issues")
        .env("INPUT_EVENT-PATH", path_arg(&event_path))
        .env("INPUT_LOG-LEVEL", "trace")
        .env("GITHUB_OUTPUT", path_arg(&output_path))
        .env("JIRA_API_TOKEN", TOKEN)
        .env("JIRA_USERNAME", USERNAME);

    for (name, value) in extra_env {
        command.env(name, value);
    }

    let Output {
        status,
        stdout,
        stderr,
    } = command.output().expect("binary should execute");

    Run {
        success: status.success(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        github_output: fs::read_to_string(&output_path).unwrap_or_default(),
    }
}

/// Renders a path for an environment variable.
///
/// `Path::display` rather than `{:?}`, which doubles a Windows separator and
/// would hand the binary a path it cannot open.
fn path_arg(path: &Path) -> String {
    path.display().to_string()
}

/// The `minimal-critical` fixture with one field expanding `name`.
fn config_expanding(field: &str, name: &str) -> String {
    let (site, replacement) = match field {
        "id" => ("id: dependabot-high-issues", format!("id: \"${{{name}}}\"")),
        "summary" => ("summary: test", format!("summary: \"${{{name}}}\"")),
        "description" => ("description: test", format!("description: \"${{{name}}}\"")),
        other => panic!("no substitution site for field '{other}'"),
    };
    let yaml = fixtures::action_config("minimal-critical").replace(site, &replacement);
    assert!(
        yaml.contains(&replacement),
        "substitution site '{field}' moved"
    );
    yaml
}

fn critical_event() -> &'static str {
    fixtures::github_event("issues-opened-dependabot-critical")
}

#[test]
fn a_config_expanding_the_credential_is_refused_without_echoing_it() {
    // NF2 end to end. `rule.id` is the field that reaches `GITHUB_OUTPUT`
    // directly; `summary` and `description` reach the created Jira issue. All
    // three are refused at load, before the process has anything to write.
    for field in ["id", "summary", "description"] {
        let run = run_action(
            &config_expanding(field, "JIRA_API_TOKEN"),
            critical_event(),
            &[("INPUT_DRY-RUN", "true")],
        );

        assert!(
            !run.success,
            "{field}: a denied expansion must fail the run"
        );
        assert!(
            run.stderr
                .contains("may not expand environment variable 'JIRA_API_TOKEN'"),
            "{field}: unexpected stderr: {}",
            run.stderr
        );
        assert!(
            run.github_output.is_empty(),
            "{field}: a refused config must publish no outputs: {}",
            run.github_output
        );
        run.assert_no_credential_escaped(&format!("expansion of {field}"));
    }
}

#[test]
fn opting_the_credential_name_in_does_not_get_it_past_the_binary() {
    // The allowlist is workflow-controlled, so a workflow can widen it. The
    // denylist is the second gate and is not negotiable; this is the case where
    // a consumer opts in without thinking.
    let run = run_action(
        &config_expanding("summary", "JIRA_API_TOKEN"),
        critical_event(),
        &[
            ("INPUT_DRY-RUN", "true"),
            ("THREATFLUX_CONFIG_ENV_ALLOWLIST", "JIRA_API_TOKEN"),
        ],
    );

    assert!(!run.success, "an opted-in credential name must still fail");
    assert!(
        run.stderr.contains("credential denylist entry 'TOKEN'"),
        "unexpected stderr: {}",
        run.stderr
    );
    run.assert_no_credential_escaped("an opted-in credential name");
}

#[test]
fn a_credential_name_the_denylist_cannot_see_is_refused_just_as_quietly() {
    // `MY_PAT` reads as an ordinary name to a substring denylist over a
    // namespace this Action does not own. The allowlist is what refuses it, and
    // the refusal has to be as quiet as the denylist's.
    let run = run_action(
        &config_expanding("summary", "MY_PAT"),
        critical_event(),
        &[("INPUT_DRY-RUN", "true"), ("MY_PAT", TOKEN)],
    );

    assert!(!run.success, "a name outside the allowlist must fail");
    assert!(
        run.stderr
            .contains("may not expand environment variable 'MY_PAT'"),
        "unexpected stderr: {}",
        run.stderr
    );
    run.assert_no_credential_escaped("a name outside the allowlist");
}

#[test]
fn a_failing_jira_client_build_never_echoes_the_credential() {
    // The Action's own credential path: a real run, no dry-run, that gets as far
    // as building a client and is refused by the host policy. The error a
    // workflow log then shows is produced while the process is holding the
    // token.
    let destination = net::closed_loopback_url();
    let run = run_action(
        fixtures::action_config("dependabot-high-plain-templates"),
        fixtures::github_event("issues-opened-dependabot-high-package"),
        &[
            ("INPUT_DRY-RUN", "false"),
            ("JIRA_URL", destination.as_str()),
        ],
    );

    assert!(!run.success, "a cleartext destination must fail the run");
    assert!(
        !run.stderr.contains("Missing Jira API token"),
        "the run must have got past credential resolution, or it never held the \
         token and the sweep proves nothing: {}",
        run.stderr
    );
    assert!(
        run.stderr.contains("127.0.0.1"),
        "the refusal should name the destination it refused: {}",
        run.stderr
    );
    run.assert_no_credential_escaped("a refused Jira destination");
}

#[test]
fn a_missing_event_payload_fails_without_echoing_the_credential() {
    // The failure mode that reports a path, which is the other arbitrary value
    // this process handles. The credential is in the environment throughout.
    let run = run_action(
        fixtures::action_config("dependabot-high-plain-templates"),
        "{ not json",
        &[("INPUT_DRY-RUN", "true")],
    );

    assert!(!run.success, "an unparseable event must fail the run");
    run.assert_no_credential_escaped("an unparseable event payload");
}

#[test]
fn a_successful_dry_run_publishes_outputs_and_no_credential() {
    // The channel that outlives the run. `GITHUB_OUTPUT` is read back by the
    // runner and its values become workflow expressions, so a credential that
    // reached it would propagate past this process entirely.
    let run = run_action(
        fixtures::action_config("dependabot-high-plain-templates"),
        fixtures::github_event("issues-opened-dependabot-high-package"),
        &[("INPUT_DRY-RUN", "true")],
    );

    assert!(run.success, "a dry run should succeed: {}", run.stderr);

    let outputs = github_output_map(&run.github_output)
        .expect("the runner must be able to parse the output file");
    assert_eq!(outputs["matched-rule-id"], "dependabot-high-issues");
    assert_eq!(outputs["severity"], "high");
    assert_eq!(outputs["created"], "false");

    run.assert_no_credential_escaped("a successful dry run");
}

#[test]
fn an_event_body_naming_the_credential_is_not_expanded_into_an_output() {
    // Environment expansion runs over the parsed *config*, and template
    // rendering runs over the event. A `${JIRA_API_TOKEN}` carried in an issue
    // body must therefore stay literal: if rendering re-entered the expander,
    // an attacker-controlled body would be the same exfiltration primitive NF2
    // describes, without needing write access to the config at all.
    let event = fixtures::github_event_with_issue_body(
        "issues-opened-dependabot-high-package",
        "Severity: high\n${JIRA_API_TOKEN}\n",
    );
    let run = run_action(
        fixtures::action_config("dependabot-high-plain-templates"),
        &event,
        &[("INPUT_DRY-RUN", "true")],
    );

    assert!(run.success, "a dry run should succeed: {}", run.stderr);

    let outputs = github_output_map(&run.github_output)
        .expect("the runner must be able to parse the output file");
    assert_eq!(
        outputs["severity"], "high",
        "the rule must still have matched, or nothing was exercised"
    );

    run.assert_no_credential_escaped("an event body naming the credential");
}
