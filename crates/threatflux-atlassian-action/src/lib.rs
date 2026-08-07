pub mod config;
pub mod env;
pub mod github;
pub mod jira;
pub mod output;
pub mod rules;

use crate::env::{resolve_env_alias, ActionEnv};
use crate::output::{preview_path, OutputError, OutputWriter};
use crate::rules::dedupe::{build_lookup_plan, rank_candidates, LadderTier, LookupOptions};
use anyhow::Result;
use std::fs;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::path::Path;
#[cfg(test)]
use std::sync::Mutex;
use threatflux_atlassian_sdk::search::{SearchIssue, SearchRequest};
#[cfg(test)]
use threatflux_atlassian_sdk::HostPolicy;
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
    /// The rows the lookup query answers with, not the winner.
    ///
    /// The election is [`rank_candidates`]'s and the hook may not pre-empt it: a
    /// hook that handed back a key would leave the rung precedence, the
    /// duplicate tiebreak and the summary post-filter untested on the one path
    /// that runs them.
    search_result: std::result::Result<Vec<SearchIssue>, String>,
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

// A test that drives the real SDK client needs a loopback mock server, and the
// SDK deliberately refuses to reach `HostPolicy::Loopback` from the environment
// -- which is the only input `build_client_from_env` has. The override is
// `#[cfg(test)]`, so no such path is compiled into the shipped binary at all.
#[cfg(test)]
static TEST_HOST_POLICY: Mutex<Option<HostPolicy>> = Mutex::new(None);

#[cfg(test)]
fn current_test_host_policy() -> Option<HostPolicy> {
    TEST_HOST_POLICY
        .lock()
        .expect("host policy lock should succeed")
        .clone()
}

pub async fn run_from_env() -> Result<ActionOutcome> {
    let action_env = ActionEnv::from_env()?;
    init_tracing(&action_env.log_level);

    let config_raw = fs::read_to_string(&action_env.config_path)?;
    let config = config::load_config_from_str(&config_raw)?;

    let event_name = action_env.require_event_name()?;
    let event_path = action_env.require_event_path()?;
    let event_payload = fs::read_to_string(event_path)?;
    let event = github::load_issue_event_from_str(event_name, &event_payload)?;

    for rule in &config.rules {
        let Some(rule_match) = rules::evaluate_rule(rule, &event)? else {
            continue;
        };

        let outcome = execute_rule(rule, &event, &rule_match, action_env.dry_run).await?;
        write_outputs(&outcome)?;
        return Ok(outcome);
    }

    let outcome = ActionOutcome::default();
    write_outputs(&outcome)?;
    Ok(outcome)
}

fn build_client_from_env() -> Result<AtlassianClient> {
    let base_url = resolve_env_alias("JIRA_BASE_URL", "JIRA_URL")
        .ok_or_else(|| anyhow::anyhow!("Missing Jira base URL: set JIRA_BASE_URL or JIRA_URL"))?;
    let username = resolve_env_alias("JIRA_EMAIL", "JIRA_USERNAME")
        .ok_or_else(|| anyhow::anyhow!("Missing Jira username: set JIRA_EMAIL or JIRA_USERNAME"))?;
    let api_token = std::env::var("JIRA_API_TOKEN")
        .map_err(|_| anyhow::anyhow!("Missing Jira API token: set JIRA_API_TOKEN"))?;

    #[allow(unused_mut, reason = "only the test build mutates the host policy")]
    let mut config =
        AtlassianConfig::from_env_with_overrides(Some(base_url), Some(username), Some(api_token))?;

    #[cfg(test)]
    if let Some(policy) = current_test_host_policy() {
        config.host_policy = policy;
    }

    Ok(AtlassianClient::new(config)?)
}

fn init_tracing(level: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_target(false)
        .without_time()
        .try_init();
}

/// The tier name a log line may carry.
///
/// A `&'static str` from a closed match rather than the tier's own `Debug`:
/// [`LadderTier::Legacy`] carries a `spec_id` that comes from a repo-local
/// config, and an unbounded config value has no business in a log line.
const fn tier_name(tier: &LadderTier) -> &'static str {
    match tier {
        LadderTier::Canonical => "canonical",
        LadderTier::Legacy { .. } => "legacy",
        LadderTier::SummaryFallback => "summary-fallback",
    }
}

async fn finalize_action<SearchFn, SearchFut, CreateFn, CreateFut>(
    rule: &config::RuleConfig,
    event: &github::GitHubIssueEvent,
    rule_match: &rules::RuleMatch,
    search_fn: SearchFn,
    create_fn: CreateFn,
) -> Result<ActionOutcome>
where
    SearchFn: FnOnce(SearchRequest) -> SearchFut,
    SearchFut: Future<Output = Result<Vec<SearchIssue>>>,
    CreateFn: FnOnce(threatflux_atlassian_sdk::v3::V3CreateIssueRequest) -> CreateFut,
    CreateFut: Future<Output = Result<String>>,
{
    let mut outcome = ActionOutcome {
        matched_rule_id: Some(rule_match.rule_id.clone()),
        created: false,
        jira_issue_key: None,
        deduped: false,
        severity: Some(rule_match.severity.clone()),
    };

    // The whole ladder, not the single label this delivery would write.
    //
    // Looking up only `rule_match.dedupe_label` is what made the identity
    // change unsafe to ship: an issue an earlier release created carries the
    // `v0` digest and nothing else, so a query for the canonical label alone
    // returns no rows, falls through to the create below, and mints a second
    // Jira issue for an issue that is already tracked -- once for every tracked
    // issue in every consumer, on the first delivery after the upgrade.
    //
    // It is still one query and one round trip: `build_lookup_plan` puts every
    // rung in one `labels IN (...)` clause and `rank_candidates` recovers the
    // precedence from the rows, client-side and deterministically.
    //
    // Fallible rather than panicking, like the builder it replaces: this
    // function returns `Result` and its caller writes the step outputs after
    // it, so an abort here would leave the step with no outputs at all.
    //
    // `LookupOptions::default` and not something read off the rule, because the
    // two knobs that would add rungs -- `migration.legacy_labels` and
    // `migration.summary_fallback` -- are refused at load time until the
    // reconciliation engine can honour them. Reading them here would be reading
    // keys no configuration that loads can set.
    let plan = build_lookup_plan(rule, event, &LookupOptions::default())?;
    let rows = search_fn(plan.search_request()).await?;
    let candidates = rank_candidates(&plan, &rows);

    if let Some(winner) = candidates.first() {
        // Bounded by construction: two counts and a `&'static str`. The labels,
        // the query and the summaries the rows carry stay out of it.
        tracing::info!(
            rows = rows.len(),
            candidates = candidates.len(),
            tier = tier_name(&winner.tier),
            "the delivery reconciles onto an existing Jira issue"
        );
        outcome.deduped = true;
        outcome.jira_issue_key = Some(winner.issue_key.clone());
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
            |_request| async move { search_result.map_err(anyhow::Error::msg) },
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
        // Enhanced search, and through the cursor rather than a bare
        // `search_jql`. Both choices are forced by what the answer is used for.
        //
        // Enhanced search, because the classification reads each row's `labels`
        // and `summary` and the legacy GET route has no field selection to ask
        // for them; a row that came back without its labels would be ranked as
        // "no match", which fails closed and then creates a duplicate.
        //
        // The cursor, because an empty page carrying a next-page token is not
        // proof that nothing matched -- the SDK documents exactly that -- and
        // reading one as "no such issue" is the same duplicate by a different
        // route. `try_collect` walks past empty pages and refuses rather than
        // truncating at a cap, so a partial answer can never be mistaken for an
        // absent one. The ladder is one query, so the normal case is still the
        // single round trip it was.
        |request| async move { Ok(client_ref.search_cursor(&request).try_collect().await?) },
        // v3, so the description goes out as ADF rather than as the plain
        // string the frozen v2 `CreateIssueFields` can carry. The v3 create is
        // also one round trip by construction -- it answers with the key and
        // never reads the issue back -- so no second call can return an error
        // for an issue Jira already has, past the point of no return and before
        // `write_outputs` publishes the key.
        |request| async move { Ok(client_ref.v3().create_issue(request).await?.key) },
    )
    .await
}

/// Appends the step outputs to `GITHUB_OUTPUT`, if there is one to append to.
///
/// An unset `GITHUB_OUTPUT` is the ordinary local case and writes nothing. A
/// `GITHUB_OUTPUT` that cannot be *opened* is degraded the same way
/// [`write_outcome`] degrades a value the encoder refuses, and for the same
/// reason: this runs after the irreversible Jira write, and the open failing
/// means the file was never touched, so the run loses its outputs and nothing
/// else. Failing here would report a reconciliation that succeeded as a red
/// step over a sink problem the reconciliation cannot be blamed for.
///
/// The line between that and the sink failure [`write_outcome`] still returns is
/// what was written when it broke: an open that fails wrote nothing, while a
/// write that fails part-way may have left half an entry on disk, which makes
/// every later entry untrustworthy and has to go red. The path is previewed
/// rather than echoed because `GITHUB_OUTPUT` is an arbitrary environment value.
fn write_outputs(outcome: &ActionOutcome) -> Result<()> {
    let Some(path) = std::env::var_os("GITHUB_OUTPUT") else {
        return Ok(());
    };

    let handle = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(
                path = %preview_path(&Path::new(&path).display().to_string()),
                reason = %error,
                "GITHUB_OUTPUT could not be opened, so the step publishes no outputs; nothing was written and the reconciliation itself succeeded"
            );
            return Ok(());
        }
    };
    write_outcome(&mut OutputWriter::new(handle), outcome)
}

/// Writes the five step outputs, skipping any one value the encoder refuses.
///
/// This runs after the Jira create or dedupe, which is irreversible and whose
/// issue key is already known: the create is one round trip and the key comes
/// back in its own response, so no call made after the issue exists can take the
/// key away again. An output that cannot be encoded may therefore cost that
/// output and nothing else. Failing here would report a reconciliation that
/// succeeded as a red step, and would take with it every output already written
/// -- the issue key above all, which the caller then has no way to learn. So
/// every entry is attempted, each refusal is logged by
/// [`skip_if_unencodable`], and the step still succeeds.
///
/// The refusals themselves are unchanged: the encoder still writes no value it
/// cannot represent as exactly one entry. A failure of the *Jira* write is a
/// different thing entirely and still fails the run -- it propagates out of
/// `execute_rule` before this function is ever reached.
///
/// `severity` stays last because it is the only value an event body reaches
/// directly, so it is the likeliest to be the one skipped.
fn write_outcome<W: Write>(writer: &mut OutputWriter<W>, outcome: &ActionOutcome) -> Result<()> {
    skip_if_unencodable(
        writer.write_optional("matched-rule-id", outcome.matched_rule_id.as_deref()),
    )?;
    skip_if_unencodable(writer.write_bool("created", outcome.created))?;
    skip_if_unencodable(
        writer.write_optional("jira-issue-key", outcome.jira_issue_key.as_deref()),
    )?;
    skip_if_unencodable(writer.write_bool("deduped", outcome.deduped))?;
    skip_if_unencodable(writer.write_severity("severity", outcome.severity.as_deref()))?;
    Ok(())
}

/// Turns a refusal to encode one entry into a logged skip.
///
/// An [`OutputError`] means the value could not be represented and nothing was
/// written for it, so the sink is intact and the remaining entries still go out;
/// that is the failure this degrades. Anything else is the sink itself failing,
/// which may have left a partial entry on disk and cannot be written around, so
/// it is still returned. The log line is bounded -- no `OutputError` renders the
/// value it rejected, and an over-long name is previewed -- because a severity
/// or a rule id can carry an arbitrary event body.
fn skip_if_unencodable(result: Result<()>) -> Result<()> {
    let Err(error) = result else {
        return Ok(());
    };

    match error.downcast::<OutputError>() {
        Ok(unencodable) => {
            tracing::warn!(
                output = unencodable.name(),
                reason = %unencodable,
                "step output could not be encoded and was skipped; the reconciliation itself succeeded and the remaining outputs are written"
            );
            Ok(())
        }
        Err(sink_failure) => Err(sink_failure),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_client_from_env, build_lookup_plan, finalize_action, run_from_env,
        skip_if_unencodable, write_outcome, write_outputs, ActionOutcome, HostPolicy, LadderTier,
        LookupOptions, OutputError, OutputWriter, SearchIssue, TestJiraHook, TEST_HOST_POLICY,
        TEST_JIRA_HOOK,
    };
    use crate::config::{load_config_from_str, RuleConfig, DEDUPE_IDENTITY_FIELDS};
    use crate::github::{load_issue_event_from_str, GitHubIssueEvent};
    use crate::rules::dedupe::{v0_label, LOOKUP_FIELDS};
    use crate::rules::evaluate_rule;
    use serde_json::json;
    use serial_test::serial;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use threatflux_atlassian_testkit::env::EnvGuard;
    use threatflux_atlassian_testkit::fixtures;
    use threatflux_atlassian_testkit::gha::github_output_map;
    use threatflux_atlassian_testkit::jira_mock::{JiraMock, Step};
    use threatflux_atlassian_testkit::logs;

    /// Reads `GITHUB_OUTPUT` back through the runner's own grammar.
    ///
    /// `raw.contains("severity=high")` passes on a file that also carries a
    /// forged entry, so every assertion here goes through the parsed map.
    fn output_map(path: &std::path::Path) -> BTreeMap<String, String> {
        let raw = fs::read_to_string(path).expect("github output should exist");
        github_output_map(&raw).expect("the runner must be able to parse the output file")
    }

    /// Every variable a run reads, in both spellings, plus the Jira credentials.
    ///
    /// The runner-spelling tests clear all of them so a leftover underscored
    /// alias from another test cannot make a broken hyphenated reader look
    /// fixed, and so an unset Jira base URL proves no Jira call was attempted.
    const RUN_ENV_VARIABLES: &[&str] = &[
        "INPUT_CONFIG-PATH",
        "INPUT_CONFIG_PATH",
        "INPUT_DRY-RUN",
        "INPUT_DRY_RUN",
        "INPUT_LOG-LEVEL",
        "INPUT_LOG_LEVEL",
        "INPUT_EVENT-NAME",
        "INPUT_EVENT_NAME",
        "INPUT_EVENT-PATH",
        "INPUT_EVENT_PATH",
        "GITHUB_EVENT_NAME",
        "GITHUB_EVENT_PATH",
        "GITHUB_OUTPUT",
        "JIRA_BASE_URL",
        "JIRA_URL",
        "JIRA_EMAIL",
        "JIRA_USERNAME",
        "JIRA_API_TOKEN",
        "JIRA_VERIFY_SSL",
    ];

    /// Sets the inputs exactly as the GitHub runner does: `INPUT_` + the
    /// `action.yml` name uppercased, hyphens intact, and nothing else set.
    fn set_runner_inputs(
        guard: &mut EnvGuard,
        config_path: &std::path::Path,
        event_path: &std::path::Path,
        output_path: &std::path::Path,
        dry_run: &str,
    ) {
        for name in RUN_ENV_VARIABLES {
            guard.remove(name);
        }
        guard
            .set("INPUT_CONFIG-PATH", config_path.display().to_string())
            .set("INPUT_DRY-RUN", dry_run)
            .set("INPUT_LOG-LEVEL", "debug")
            .set("INPUT_EVENT-NAME", "issues")
            .set("INPUT_EVENT-PATH", event_path.display().to_string())
            .set("GITHUB_OUTPUT", output_path.display().to_string());
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_honors_dry_run_from_the_runner_input_names() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");
        clear_test_jira_hook();

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "true");

        let outcome = run_from_env()
            .await
            .expect("dry-run must be honored when only the runner spellings are set");
        let output = output_map(&output_path);

        assert_eq!(
            outcome.matched_rule_id.as_deref(),
            Some("dependabot-high-issues")
        );
        assert_eq!(outcome.severity.as_deref(), Some("high"));
        assert!(!outcome.created);
        assert!(!outcome.deduped);
        assert_eq!(outcome.jira_issue_key, None);
        assert_eq!(output["matched-rule-id"], "dependabot-high-issues");
        assert_eq!(output["created"], "false");
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_calls_jira_when_the_runner_dry_run_input_is_false() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");
        clear_test_jira_hook();

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "false");

        let error = run_from_env()
            .await
            .expect_err("a non-dry run must reach the Jira client");
        assert!(
            error.to_string().contains("Missing Jira base URL"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_reads_the_config_path_from_the_runner_input_name() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("custom-location.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");
        clear_test_jira_hook();

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "true");

        let outcome = run_from_env()
            .await
            .expect("a custom config-path must not fall back to the default path");
        assert_eq!(
            outcome.matched_rule_id.as_deref(),
            Some("dependabot-high-issues")
        );
    }

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
            fixtures::action_config("dependabot-high-no-assignee"),
        )
        .expect("config should be written");
        fs::write(
            &event_path,
            fixtures::github_event("issues-opened-dependabot-high-package"),
        )
        .expect("event should be written");

        std::env::set_var("INPUT_CONFIG_PATH", config_path.display().to_string());
        std::env::set_var("INPUT_DRY_RUN", "true");
        std::env::set_var("INPUT_EVENT_NAME", "issues");
        std::env::set_var("INPUT_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("INPUT_LOG_LEVEL", "debug");
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let outcome = run_from_env().await.expect("dry run should succeed");
        let output = output_map(&output_path);

        assert_eq!(
            outcome.matched_rule_id.as_deref(),
            Some("dependabot-high-issues")
        );
        assert_eq!(outcome.severity.as_deref(), Some("high"));
        assert!(!outcome.created);
        assert!(!outcome.deduped);
        assert_eq!(output["matched-rule-id"], "dependabot-high-issues");
        assert_eq!(output["created"], "false");
        assert_eq!(output["severity"], "high");

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
            fixtures::action_config("dependabot-high-plain-summary"),
        )
        .expect("config should be written");
        fs::write(
            &event_path,
            fixtures::github_event("issues-opened-human-medium"),
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
        let output = output_map(&output_path);

        assert_eq!(outcome.matched_rule_id, None);
        assert_eq!(outcome.severity, None);
        assert!(!outcome.created);
        assert!(!outcome.deduped);
        assert_eq!(output["matched-rule-id"], "");
        assert_eq!(output["created"], "false");
        assert_eq!(output["deduped"], "false");

        cleanup_env(&[
            "INPUT_CONFIG_PATH",
            "INPUT_DRY_RUN",
            "INPUT_EVENT_NAME",
            "INPUT_EVENT_PATH",
            "GITHUB_EVENT_NAME",
            "GITHUB_EVENT_PATH",
            "GITHUB_OUTPUT",
        ]);
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_treats_blank_event_overrides_as_unset() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");

        std::env::set_var("INPUT_CONFIG_PATH", config_path.display().to_string());
        std::env::set_var("INPUT_DRY_RUN", "true");
        std::env::set_var("INPUT_EVENT_NAME", "");
        std::env::set_var("INPUT_EVENT_PATH", "   ");
        std::env::set_var("GITHUB_EVENT_NAME", "issues");
        std::env::set_var("GITHUB_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let outcome = run_from_env()
            .await
            .expect("blank event overrides should fall back to github event env");
        let output = output_map(&output_path);

        assert_eq!(
            outcome.matched_rule_id.as_deref(),
            Some("dependabot-high-issues")
        );
        assert_eq!(outcome.severity.as_deref(), Some("high"));
        assert_eq!(output["matched-rule-id"], "dependabot-high-issues");

        cleanup_env(&[
            "INPUT_CONFIG_PATH",
            "INPUT_DRY_RUN",
            "INPUT_EVENT_NAME",
            "INPUT_EVENT_PATH",
            "GITHUB_EVENT_NAME",
            "GITHUB_EVENT_PATH",
            "GITHUB_OUTPUT",
        ]);
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_treats_blank_config_path_as_default() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        let config_root = temp_root.join(".github").join("threatflux");
        fs::create_dir_all(&config_root).expect("config dir should be created");

        let config_path = config_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");

        std::env::set_var("INPUT_CONFIG_PATH", "   ");
        std::env::set_var("INPUT_DRY_RUN", "true");
        std::env::set_var("INPUT_EVENT_NAME", "issues");
        std::env::set_var("INPUT_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let current_dir = std::env::current_dir().expect("cwd should be readable");
        std::env::set_current_dir(&temp_root).expect("cwd should switch to temp root");

        let outcome = run_from_env()
            .await
            .expect("blank config path should fall back to the default path");
        let output = output_map(&output_path);

        std::env::set_current_dir(current_dir).expect("cwd should be restored");

        assert_eq!(
            outcome.matched_rule_id.as_deref(),
            Some("dependabot-high-issues")
        );
        assert_eq!(outcome.severity.as_deref(), Some("high"));
        assert_eq!(output["matched-rule-id"], "dependabot-high-issues");

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
    async fn run_from_env_never_routes_the_jira_token_into_the_step_outputs() {
        const CANARY: &str = "ATATT-canary-must-never-appear";

        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        // `rule.id` becomes `matched-rule-id`, which is a step output; before
        // the denylist this loaded clean and published the token.
        fs::write(
            &config_path,
            fixtures::action_config("dependabot-high")
                .replace("id: dependabot-high-issues", r#"id: "${JIRA_API_TOKEN}""#),
        )
        .expect("config should be written");
        write_matching_event(&event_path, "Severity: high\nPackage: foo");
        clear_test_jira_hook();

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "true");
        guard.set("JIRA_API_TOKEN", CANARY);

        let error = run_from_env()
            .await
            .expect_err("a config expanding the credential must not run");
        assert!(
            !error.to_string().contains(CANARY),
            "the error echoed the token"
        );
        assert!(
            !output_path.exists()
                || !fs::read_to_string(&output_path)
                    .expect("output should be readable")
                    .contains(CANARY),
            "the token reached GITHUB_OUTPUT"
        );
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
            Ok(vec![labelled_row(
                "KAN-42",
                "10042",
                &[&standard_canonical_label()],
            )]),
            Ok("KAN-should-not-create".to_string()),
        );

        std::env::set_var("INPUT_CONFIG_PATH", config_path.display().to_string());
        std::env::set_var("INPUT_EVENT_NAME", "issues");
        std::env::set_var("INPUT_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let outcome = run_from_env().await.expect("dedupe should succeed");
        let output = output_map(&output_path);

        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-42"));
        assert!(outcome.deduped);
        assert!(!outcome.created);
        assert_eq!(output["jira-issue-key"], "KAN-42");
        assert_eq!(output["deduped"], "true");

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
        set_test_jira_hook(Ok(Vec::new()), Ok("KAN-77".to_string()));

        std::env::set_var("INPUT_CONFIG_PATH", config_path.display().to_string());
        std::env::set_var("INPUT_EVENT_NAME", "issues");
        std::env::set_var("INPUT_EVENT_PATH", event_path.display().to_string());
        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());

        let outcome = run_from_env().await.expect("create should succeed");
        let output = output_map(&output_path);

        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-77"));
        assert!(outcome.created);
        assert!(!outcome.deduped);
        assert_eq!(output["jira-issue-key"], "KAN-77");
        assert_eq!(output["created"], "true");

        cleanup_env(&[
            "INPUT_CONFIG_PATH",
            "INPUT_EVENT_NAME",
            "INPUT_EVENT_PATH",
            "GITHUB_OUTPUT",
        ]);
        clear_test_jira_hook();
    }

    /// The Jira endpoints one reconciliation touches, in the order it touches
    /// them. The third is the one a create must never depend on.
    ///
    /// The search is enhanced search, which is what lets the lookup ask for the
    /// `labels` and `summary` its client-side ranking classifies rows by; the
    /// legacy GET route has no field selection and would answer with rows the
    /// ranking could only read as unlabelled.
    const SEARCH_ENDPOINT: &str = "/rest/api/3/search/jql";
    const CREATE_ENDPOINT: &str = "/rest/api/3/issue";
    const READBACK_ENDPOINT: &str = "/rest/api/3/issue/KAN-77";

    #[tokio::test]
    #[serial]
    async fn run_from_env_publishes_the_key_of_a_created_issue_the_api_will_not_read_back() {
        // The create POST is the irreversible half and it answers with the key,
        // so nothing after it may cost the run that key. Reading the created
        // issue back turned any transient 5xx on the *second* round trip -- or a
        // token that can create but not read -- into a red step that published
        // no outputs at all: a live Jira issue whose key the workflow has no way
        // to learn. This runs against a real client and a real socket rather
        // than the test hook, because the round trip that used to be there is
        // exactly what is under test.
        //
        // Under v3 the guarantee is structural rather than a choice of method:
        // `JiraV3::create_issue` has no read-back to skip. The mock still stubs
        // a 503 on the read-back route and the run still has to succeed, so the
        // call-count assertion below stays a real regression guard against a
        // second round trip creeping back onto the create path.
        let mock = JiraMock::start().await;
        // `search-empty` is a v2-shaped body -- it carries `startAt`, `total`
        // and `maxResults`, which enhanced search does not send and `SearchPage`
        // does not model -- stubbed onto a v3 endpoint. It parses, because
        // `SearchPage` ignores keys it does not model and reads the absent
        // `nextPageToken` as "last page", which is the answer this test wants.
        // It is still the wrong shape for the route, and the fixture lives in
        // the testkit rather than here; see the note in
        // `run_from_env_dedupes_at_the_wire_on_the_ladder_query_it_planned`.
        mock.stub(
            "POST",
            SEARCH_ENDPOINT,
            Step::json_str(200, fixtures::jira_body("search-empty")),
        )
        .await;
        mock.stub(
            "POST",
            CREATE_ENDPOINT,
            Step::json_str(201, fixtures::jira_body("create-issue-response")),
        )
        .await;
        mock.stub("GET", READBACK_ENDPOINT, Step::status(503)).await;

        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");
        clear_test_jira_hook();

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "false");
        guard
            .set("JIRA_BASE_URL", mock.uri())
            .set("JIRA_EMAIL", "action@example.com")
            .set("JIRA_API_TOKEN", "test-token");
        // The mock listens on http, which the client refuses unless the host is
        // a literal loopback address under HostPolicy::Loopback. No environment
        // variable can select that policy, by design, so a test that drives the
        // real client selects it in code.
        set_test_host_policy(HostPolicy::Loopback);

        let outcome = run_from_env()
            .await
            .expect("an issue Jira created must not be reported as a failed step");
        let output = output_map(&output_path);

        assert!(outcome.created);
        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-77"));
        assert_eq!(output["jira-issue-key"], "KAN-77");
        assert_eq!(output["created"], "true");
        mock.assert_call_count("POST", CREATE_ENDPOINT, 1).await;
        mock.assert_call_count("GET", READBACK_ENDPOINT, 0).await;

        clear_test_host_policy();
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_dedupes_at_the_wire_on_the_ladder_query_it_planned() {
        // The other half of the ladder's proof. Everything else asserts the
        // query at the `LookupPlan` level and stubs the reconciliation above the
        // client, so the hop from `plan.search_request()` to the bytes in the
        // POST body is correct only by construction. Here it is read back out of
        // the mock's journal: the recorded `jql` has to be the planned one byte
        // for byte, and the recorded `fields` has to be `LOOKUP_FIELDS`, because
        // a lookup that asks a different question or comes back without the
        // `labels` it classifies by ranks every row as "no match" and mints a
        // duplicate Jira issue for an issue that is already tracked.
        //
        // The row is labelled with the *v0* digest and nothing else, which is
        // what an issue an earlier release created carries, so this is the
        // DEDUPE-FOUND path end to end through the real client: one search, no
        // create.
        //
        // The page body is `search-one-issue` with the row's labels swapped for
        // the digest this delivery looks for. Like `search-empty` above it is a
        // v2-shaped body -- `startAt`, `total` and `maxResults` are not fields
        // of an enhanced-search page -- and it parses only because `SearchPage`
        // ignores what it does not model. The fixtures live in the testkit, so
        // reshaping them is a change to that crate rather than to this one; the
        // assertions below do not depend on the extra keys either way.
        let (rule, event) = standard_rule_and_event("Severity: high\nPackage: foo");
        let plan = build_lookup_plan(&rule, &event, &LookupOptions::default())
            .expect("the shipped rule plans a lookup for its own fixture");
        let legacy = plan
            .labels()
            .iter()
            .find(|entry| matches!(entry.tier, LadderTier::Legacy { .. }))
            .expect("the v0 rung is auto-registered")
            .label
            .clone();
        assert_eq!(
            legacy,
            v0_label("dependabot-alert", &rule.jira.dedupe.fields, &event)
                .expect("the v0 label resolves"),
            "the row has to carry the digest an earlier release wrote"
        );
        assert_ne!(
            legacy,
            plan.canonical_label(),
            "the row must be reachable only on the legacy rung, or this test is vacuous"
        );

        let mut page = fixtures::jira_body_json("search-one-issue");
        page["issues"][0]["fields"]["labels"] = json!([legacy]);

        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH_ENDPOINT, Step::json(200, &page))
            .await;
        // Stubbed so that a create would *succeed* rather than 404. A create
        // this run makes has to be caught by the call count below, not by the
        // run failing for an unrelated reason.
        mock.stub(
            "POST",
            CREATE_ENDPOINT,
            Step::json_str(201, fixtures::jira_body("create-issue-response")),
        )
        .await;

        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");
        clear_test_jira_hook();

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "false");
        guard
            .set("JIRA_BASE_URL", mock.uri())
            .set("JIRA_EMAIL", "action@example.com")
            .set("JIRA_API_TOKEN", "test-token");
        // As above: http on loopback is reachable only under
        // `HostPolicy::Loopback`, which no environment variable can select.
        set_test_host_policy(HostPolicy::Loopback);

        let outcome = run_from_env()
            .await
            .expect("an issue the ladder finds must reconcile, not fail the step");
        let output = output_map(&output_path);

        clear_test_host_policy();

        let journal = mock.journal().await;
        let search = journal
            .iter()
            .find(|request| request.method == "POST" && request.path == SEARCH_ENDPOINT)
            .expect("the run has to ask Jira the lookup question");
        let body = search
            .body_json()
            .expect("the enhanced-search request is a JSON body");

        assert_eq!(
            body["jql"].as_str(),
            Some(plan.jql()),
            "the query on the wire is not the query the plan built"
        );
        assert_eq!(
            body["fields"],
            json!(LOOKUP_FIELDS),
            "the lookup stopped asking for the fields it classifies rows by"
        );
        mock.assert_call_count("POST", SEARCH_ENDPOINT, 1).await;
        mock.assert_call_count("POST", CREATE_ENDPOINT, 0).await;

        assert!(outcome.deduped);
        assert!(!outcome.created);
        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-42"));
        assert_eq!(output["deduped"], "true");
        assert_eq!(output["created"], "false");
        assert_eq!(output["jira-issue-key"], "KAN-42");
    }

    /// A consumer config whose severity capture is deliberately unconstrained.
    ///
    /// `(?s)` makes `.` match a newline, so capture group 1 is whatever the
    /// issue body puts between the markers. The priority mapping is keyed by the
    /// token that capture yields, so the reconciliation runs to completion and
    /// the only thing left that could fail is the output writing.
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
        'high - see ghsa-1234': High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
";

    #[tokio::test]
    #[serial]
    async fn run_from_env_does_not_fail_a_run_whose_jira_issue_was_created() {
        // The Jira create is irreversible and has already happened by the time
        // the outputs are written, so an unusual severity token may not turn a
        // successful reconciliation into a red step whose issue key is live.
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        fs::write(&config_path, PERMISSIVE_SEVERITY_CONFIG).expect("config should be written");
        write_matching_event(&event_path, "<severity>high - see GHSA-1234</severity>");
        set_test_jira_hook(Ok(Vec::new()), Ok("KAN-88".to_string()));

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "false");

        let outcome = run_from_env()
            .await
            .expect("a created Jira issue must not be reported as a failed step");
        let output = output_map(&output_path);

        assert!(outcome.created);
        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-88"));
        assert_eq!(output.len(), 5);
        assert_eq!(output["jira-issue-key"], "KAN-88");
        assert_eq!(output["created"], "true");
        assert_eq!(output["severity"], "high - see ghsa-1234");

        clear_test_jira_hook();
    }

    /// A consumer config whose severity capture is anchored at `$`.
    ///
    /// Nothing here is unusual or hostile -- it is the obvious way to lift a
    /// whole `Severity:` line out of an issue body. It is the pairing with a
    /// CRLF-authored body that produces a value the encoder cannot carry.
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
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
";

    #[tokio::test]
    #[serial]
    async fn run_from_env_creates_the_jira_issue_for_a_crlf_authored_severity_line() {
        // Rust's `regex` ends a `(?m)$` before a `\n` only and `.` matches a
        // `\r`, so this ordinary config over a CRLF-authored body captures
        // "high\r". That token is the key `priority_by_severity` is looked up
        // by, so the artifact used to miss the mapping and fail the run outright
        // -- an issue body whose only difference is its line endings got no Jira
        // issue at all. The capture is repaired where it is made, so every layer
        // below it sees the token the config maps.
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let output_path = temp_root.join("github-output.txt");

        fs::write(&config_path, LINE_ANCHORED_SEVERITY_CONFIG).expect("config should be written");
        write_matching_event(&event_path, "Severity: high\r\nPackage: foo");
        set_test_jira_hook(Ok(Vec::new()), Ok("KAN-77".to_string()));

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "false");

        let outcome = run_from_env()
            .await
            .expect("a CRLF-authored body must still reconcile into a Jira issue");
        let output = output_map(&output_path);

        assert!(outcome.created);
        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-77"));
        assert_eq!(
            outcome.severity.as_deref(),
            Some("high"),
            "the returned severity has to agree with the token Jira was given"
        );
        assert_eq!(output.len(), 5);
        assert_eq!(output["jira-issue-key"], "KAN-77");
        assert_eq!(output["created"], "true");
        assert_eq!(
            output["severity"], "high",
            "the trailing capture artifact is repaired rather than dropped"
        );

        clear_test_jira_hook();
    }

    /// Asserts a `GITHUB_OUTPUT` the run must never have published into.
    fn assert_no_outputs_published(path: &std::path::Path) {
        let published = fs::read_to_string(path).unwrap_or_default();
        assert!(
            published.is_empty(),
            "a failed Jira write must publish no outputs, found: {published:?}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_fails_the_step_when_the_jira_write_fails() {
        // Everything `write_outcome` degrades is degraded *because* the Jira
        // write already succeeded. The converse is the load-bearing half and it
        // holds only by ordering -- `execute_rule(...).await?` runs before
        // `write_outputs` -- so it is asserted rather than assumed: a Jira
        // failure fails the step, and the step publishes nothing that would let
        // a downstream job read a `created` or a `jira-issue-key` for a
        // reconciliation that never happened.
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        let search_output_path = temp_root.join("search-github-output.txt");
        let create_output_path = temp_root.join("create-github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");

        let mut guard = EnvGuard::new();
        set_runner_inputs(
            &mut guard,
            &config_path,
            &event_path,
            &search_output_path,
            "false",
        );

        set_test_jira_hook(
            Err("jira search rejected the query".to_string()),
            Err("jira create must not be reached".to_string()),
        );
        let error = run_from_env()
            .await
            .expect_err("a failed Jira search must fail the step");
        assert!(
            error.to_string().contains("jira search rejected the query"),
            "unexpected error: {error:#}"
        );
        assert_no_outputs_published(&search_output_path);

        guard.set("GITHUB_OUTPUT", create_output_path.display().to_string());
        set_test_jira_hook(Ok(Vec::new()), Err("jira create was refused".to_string()));
        let error = run_from_env()
            .await
            .expect_err("a failed Jira create must fail the step");
        assert!(
            error.to_string().contains("jira create was refused"),
            "unexpected error: {error:#}"
        );
        assert_no_outputs_published(&create_output_path);

        clear_test_jira_hook();
    }

    #[tokio::test]
    #[serial]
    async fn run_from_env_does_not_fail_a_reconciled_run_whose_output_sink_cannot_be_opened() {
        // Same point of no return as the encoder refusals: the Jira issue exists
        // and its key is known. An unopenable `GITHUB_OUTPUT` costs the step its
        // outputs and nothing else -- there is no partial entry to worry about,
        // because nothing was written -- so it may not turn a reconciliation
        // that succeeded into a red step.
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");

        let config_path = temp_root.join("jira-automation.yml");
        let event_path = temp_root.join("event.json");
        // The parent directory is deliberately never created, so the open fails.
        let output_path = temp_root
            .join("no-such-directory")
            .join("github-output.txt");

        write_standard_config(&config_path);
        write_matching_event(&event_path, "Severity: high\nPackage: foo");
        set_test_jira_hook(Ok(Vec::new()), Ok("KAN-77".to_string()));

        let mut guard = EnvGuard::new();
        set_runner_inputs(&mut guard, &config_path, &event_path, &output_path, "false");

        let outcome = run_from_env()
            .await
            .expect("a live Jira issue must not be reported as a failed step");

        assert!(outcome.created);
        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-77"));
        assert!(
            !output_path.exists(),
            "the sink could not be opened, so nothing may have been written"
        );

        clear_test_jira_hook();
    }

    #[tokio::test]
    async fn finalize_action_reports_an_unbuildable_dedupe_query_instead_of_aborting() {
        // `finalize_action` is on a `Result` path whose caller writes the step
        // outputs; a panic here exits 101 before `write_outputs` runs, so the
        // step publishes nothing at all. U+0000 is the one input the JQL builder
        // cannot escape, and `validate_config` now rejects it at load, so the
        // only way to reach the builder with one is to construct it here.
        let mut rule = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("config should load")
            .rules
            .remove(0);
        rule.jira.project_key = "K\0AN".to_string();

        let event = load_issue_event_from_str(
            "issues",
            fixtures::github_event("issues-opened-dependabot-high"),
        )
        .expect("event should parse");
        let rule_match = evaluate_rule(&rule, &event)
            .expect("rule evaluation should succeed")
            .expect("rule should match");

        let searched = Cell::new(false);
        let created = Cell::new(false);
        let error = finalize_action(
            &rule,
            &event,
            &rule_match,
            |_request| {
                searched.set(true);
                async { Ok(Vec::new()) }
            },
            |_request| {
                created.set(true);
                async { Ok("KAN-1".to_string()) }
            },
        )
        .await
        .expect_err("a query that cannot be built must be reported, not panicked");

        assert!(
            format!("{error:#}").contains("cannot build a dedupe lookup plan"),
            "unexpected error: {error:#}"
        );
        assert!(!searched.get(), "no Jira search may be attempted");
        assert!(!created.get(), "no Jira issue may be created");
    }

    /// Drives `finalize_action` with `answer` standing in for Jira.
    ///
    /// Returns the outcome and whether the create closure was reached, which is
    /// the assertion that matters: a duplicate Jira issue is what a missed
    /// lookup produces.
    async fn reconcile_with<F>(
        rule: &RuleConfig,
        event: &GitHubIssueEvent,
        answer: F,
    ) -> (ActionOutcome, bool)
    where
        F: FnOnce(&str) -> Vec<SearchIssue>,
    {
        let rule_match = evaluate_rule(rule, event)
            .expect("rule evaluation should succeed")
            .expect("the rule matches its own fixture");
        // An atomic rather than a `Cell`, so that the future this helper returns
        // is `Send` and stays as spawnable as the code it stands in for.
        let created = AtomicBool::new(false);

        let outcome = finalize_action(
            rule,
            event,
            &rule_match,
            |request| {
                let rows = answer(request.jql());
                async move { Ok(rows) }
            },
            |_request| {
                created.store(true, Ordering::SeqCst);
                async { Ok("KAN-DUPLICATE".to_string()) }
            },
        )
        .await
        .expect("the reconciliation should succeed");

        (outcome, created.load(Ordering::SeqCst))
    }

    /// [`reconcile_with`], answering the way Jira answers a `labels IN` query.
    ///
    /// A row comes back only when the query actually asks for a label that row
    /// carries, which is the whole point: a stub that answered every query with
    /// the same rows would pass on a lookup that asked for the wrong label, and
    /// asking for the wrong label is the defect under test.
    async fn reconcile_against(
        rule: &RuleConfig,
        event: &GitHubIssueEvent,
        rows: Vec<SearchIssue>,
    ) -> (ActionOutcome, bool) {
        reconcile_with(rule, event, |jql| {
            rows.into_iter()
                .filter(|row| {
                    row.fields
                        .labels
                        .iter()
                        .any(|label| jql.contains(label.as_str()))
                })
                .collect()
        })
        .await
    }

    #[tokio::test]
    async fn an_issue_an_earlier_release_labelled_is_deduped_rather_than_duplicated() {
        // The regression the identity change shipped with. A GitHub issue that
        // `0.4.x` already tracked carries the SHA-256/12 digest label and
        // nothing else; the delivery that follows the upgrade writes -- and used
        // to look up -- only `{prefix}-gh-{repo}-{number}`. That query returned
        // no rows, fell through to the create, and minted a SECOND Jira issue
        // for an issue that was already tracked. Once per tracked issue, per
        // consumer, on the first delivery after the upgrade.
        let (rule, event) = standard_rule_and_event("Severity: high\nPackage: foo");
        let legacy = v0_label("dependabot-alert", &rule.jira.dedupe.fields, &event)
            .expect("the v0 label resolves");
        let canonical = evaluate_rule(&rule, &event)
            .expect("rule evaluation should succeed")
            .expect("the rule matches")
            .dedupe_label;
        assert_ne!(
            legacy, canonical,
            "the two rungs have to be different labels or this test is vacuous"
        );

        let (outcome, created) = reconcile_against(
            &rule,
            &event,
            vec![labelled_row("KAN-77", "10077", &[&legacy])],
        )
        .await;

        assert!(
            outcome.deduped,
            "an issue reachable on the v0 rung must reconcile, not duplicate"
        );
        assert!(!created, "no second Jira issue may be minted");
        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-77"));
        assert!(!outcome.created);
    }

    #[tokio::test]
    async fn the_canonical_rung_outranks_the_legacy_one_on_the_reconciliation_path() {
        // The ladder's precedence has to survive the trip through
        // `finalize_action`, not only the unit test of `rank_candidates`: two
        // rows, and the one carrying the label this release writes wins.
        let (rule, event) = standard_rule_and_event("Severity: high\nPackage: foo");
        let legacy = v0_label("dependabot-alert", &rule.jira.dedupe.fields, &event)
            .expect("the v0 label resolves");
        let canonical = evaluate_rule(&rule, &event)
            .expect("rule evaluation should succeed")
            .expect("the rule matches")
            .dedupe_label;

        let (outcome, created) = reconcile_against(
            &rule,
            &event,
            vec![
                labelled_row("KAN-OLD", "10001", &[&legacy]),
                labelled_row("KAN-NEW", "10002", &[&canonical]),
            ],
        )
        .await;

        assert!(outcome.deduped);
        assert!(!created);
        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-NEW"));
    }

    #[tokio::test]
    async fn a_row_no_rung_claims_does_not_suppress_the_create() {
        // The decision is `rank_candidates`', not "the query returned
        // something". Answered unconditionally rather than through
        // `reconcile_against`, because a `labels IN` query cannot itself produce
        // an unclaimed row -- the summary fallback is what will, in M4 -- and a
        // fake that filtered the row out first would assert nothing about the
        // path under test. Attaching to a row the ladder does not claim would be
        // attaching to the wrong Jira issue, silently and permanently.
        let (rule, event) = standard_rule_and_event("Severity: high\nPackage: foo");

        let (outcome, created) = reconcile_with(&rule, &event, |_jql| {
            vec![labelled_row("KAN-OTHER", "10003", &["some-other-label"])]
        })
        .await;

        assert!(!outcome.deduped);
        assert!(created, "an unclaimed row may not suppress the create");
        assert_eq!(outcome.jira_issue_key.as_deref(), Some("KAN-DUPLICATE"));
    }

    #[tokio::test]
    async fn the_fields_identity_looks_up_and_writes_the_same_label() {
        // `jira.dedupe.identity: fields` is the documented opt-out from this
        // release's identity change, and the release notes point consumers at it
        // to hold ticket volume down. It has to be real on the reconciliation
        // path: the delivery must find the `0.4.x` issue and must not find one
        // that only carries the canonical label, or the opt-out is a key that
        // validates and changes nothing.
        let (mut rule, event) = standard_rule_and_event("Severity: high\nPackage: foo");
        rule.jira.dedupe.identity = DEDUPE_IDENTITY_FIELDS.to_string();

        let legacy = v0_label("dependabot-alert", &rule.jira.dedupe.fields, &event)
            .expect("the v0 label resolves");
        let written = evaluate_rule(&rule, &event)
            .expect("rule evaluation should succeed")
            .expect("the rule matches")
            .dedupe_label;
        assert_eq!(
            written, legacy,
            "under `identity: fields` the written label is the 0.4.x digest"
        );

        let (found, created) = reconcile_against(
            &rule,
            &event,
            vec![labelled_row("KAN-42", "10042", &[&legacy])],
        )
        .await;
        assert!(found.deduped, "the 0.4.x issue has to be found");
        assert!(!created);
        assert_eq!(found.jira_issue_key.as_deref(), Some("KAN-42"));

        // And the canonical label is not in the query at all under this
        // identity, so a row carrying only it is somebody else's issue.
        let canonical =
            crate::rules::dedupe::canonical_label("dependabot-alert", &event.identity());
        let (missed, created) = reconcile_against(
            &rule,
            &event,
            vec![labelled_row("KAN-99", "10099", &[&canonical])],
        )
        .await;
        assert!(!missed.deduped);
        assert!(created);
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
    fn build_client_from_env_falls_back_to_aliases_when_primary_values_are_blank() {
        std::env::set_var("JIRA_BASE_URL", "");
        std::env::set_var("JIRA_URL", "https://example.atlassian.net");
        std::env::set_var("JIRA_EMAIL", "   ");
        std::env::set_var("JIRA_USERNAME", "bot@threatflux.dev");
        std::env::set_var("JIRA_API_TOKEN", "secret");

        let result = build_client_from_env();
        assert!(result.is_ok());

        cleanup_env(&[
            "JIRA_BASE_URL",
            "JIRA_URL",
            "JIRA_EMAIL",
            "JIRA_USERNAME",
            "JIRA_API_TOKEN",
        ]);
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
    fn write_outputs_is_noop_without_github_output() {
        cleanup_env(&["GITHUB_OUTPUT"]);
        let result = write_outputs(&ActionOutcome::default());
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn write_outputs_degrades_a_sink_it_cannot_open() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");
        // The parent directory is deliberately never created, so the open fails.
        let output_path = temp_root
            .join("no-such-directory")
            .join("github-output.txt");

        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());
        let (result, log) = logs::capture(|| {
            write_outputs(&ActionOutcome {
                matched_rule_id: Some("rule-1".to_string()),
                created: true,
                jira_issue_key: Some("KAN-9".to_string()),
                deduped: false,
                severity: Some("high".to_string()),
            })
        });
        result.expect("a sink that cannot be opened must not fail the run");

        assert!(!output_path.exists());
        // Degraded, not silent: the only record a run leaves of its lost outputs
        // is this line, so it has to carry the level, the path and the reason.
        assert!(log.contains("WARN"), "log was: {log}");
        // The tail, not the head: `preview_path` keeps the identifying end of the
        // path, and a raw prefix would not match anyway because the preview escapes
        // the separators a Windows path is full of.
        assert!(
            log.contains("github-output.txt"),
            "log did not name the path: {log}"
        );
        assert!(log.contains("could not be opened"), "log was: {log}");

        cleanup_env(&["GITHUB_OUTPUT"]);
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
        let output = output_map(&output_path);

        assert_eq!(output["matched-rule-id"], "rule-1");
        assert_eq!(output["jira-issue-key"], "KAN-9");
        assert_eq!(output["severity"], "critical");

        cleanup_env(&["GITHUB_OUTPUT"]);
    }

    #[test]
    #[serial]
    fn write_outputs_writes_empty_strings_for_missing_optional_fields() {
        let temp_root = unique_temp_dir("threatflux-atlassian-action");
        fs::create_dir_all(&temp_root).expect("temp dir should be created");
        let output_path = temp_root.join("github-output.txt");

        std::env::set_var("GITHUB_OUTPUT", output_path.display().to_string());
        write_outputs(&ActionOutcome::default()).expect("outputs should be written");
        let output = output_map(&output_path);

        assert_eq!(output["matched-rule-id"], "");
        assert_eq!(output["jira-issue-key"], "");
        assert_eq!(output["severity"], "");

        cleanup_env(&["GITHUB_OUTPUT"]);
    }

    fn outcome_output(outcome: &ActionOutcome) -> anyhow::Result<BTreeMap<String, String>> {
        let mut writer = OutputWriter::new(Vec::new());
        let result = write_outcome(&mut writer, outcome);
        let raw = String::from_utf8(writer.into_inner()).expect("output should be utf-8");
        result?;
        Ok(github_output_map(&raw).expect("the runner must be able to parse the output file"))
    }

    #[test]
    fn write_outcome_emits_exactly_the_five_declared_outputs() {
        let output = outcome_output(&ActionOutcome::default()).expect("defaults should be written");

        assert_eq!(
            output.keys().collect::<Vec<_>>(),
            vec![
                "created",
                "deduped",
                "jira-issue-key",
                "matched-rule-id",
                "severity"
            ]
        );
    }

    #[test]
    fn write_outcome_cannot_be_made_to_forge_an_output() {
        // `matched_rule_id` is the config's `rule.id` verbatim, so a repo-local
        // config is what supplies this value.
        let outcome = ActionOutcome {
            matched_rule_id: Some(
                "rule-1\ncreated=true\njira-issue-key=KAN-666\ndeduped=true".to_string(),
            ),
            created: false,
            jira_issue_key: None,
            deduped: false,
            severity: Some("high".to_string()),
        };

        let output = outcome_output(&outcome).expect("a hostile rule id must still be written");

        assert_eq!(output.len(), 5);
        assert_eq!(output["created"], "false");
        assert_eq!(output["deduped"], "false");
        assert_eq!(output["jira-issue-key"], "");
        assert_eq!(
            output["matched-rule-id"],
            "rule-1\ncreated=true\njira-issue-key=KAN-666\ndeduped=true"
        );
    }

    #[test]
    fn write_outcome_carries_a_hostile_severity_without_forging_an_output() {
        // A permissive consumer regex puts the issue body straight into
        // `severity`. The encoding, not a token gate, is what keeps that to one
        // entry -- and the Jira write is already done, so refusing it here would
        // only cost the step its outputs.
        let outcome = ActionOutcome {
            severity: Some("high\ncreated=true\njira-issue-key=EVIL-1".to_string()),
            ..ActionOutcome::default()
        };

        let output =
            outcome_output(&outcome).expect("a hostile severity must still be written safely");

        assert_eq!(output.len(), 5);
        assert_eq!(output["created"], "false");
        assert_eq!(output["jira-issue-key"], "");
        assert_eq!(
            output["severity"],
            "high\ncreated=true\njira-issue-key=EVIL-1"
        );
    }

    #[test]
    fn write_outcome_skips_an_unencodable_severity_instead_of_failing_the_run() {
        // An interior bare carriage return is one of the values the encoder
        // cannot carry. By the time it is written the Jira issue exists and its
        // key is known, so this costs the `severity` output and nothing else --
        // failing here would report a reconciliation that succeeded as a red
        // step and would take the live issue key down with it.
        let outcome = ActionOutcome {
            matched_rule_id: Some("rule-1".to_string()),
            created: true,
            jira_issue_key: Some("KAN-9".to_string()),
            deduped: false,
            severity: Some("high\rcreated=true".to_string()),
        };

        let output = outcome_output(&outcome)
            .expect("one unencodable output must not destroy a run that reached Jira");

        assert_eq!(output["jira-issue-key"], "KAN-9");
        assert_eq!(output["created"], "true");
        assert_eq!(output["matched-rule-id"], "rule-1");
        assert_eq!(output["deduped"], "false");
        assert!(
            !output.contains_key("severity"),
            "the value the encoder refused must not reach the file"
        );
        assert_eq!(output.len(), 4);
    }

    #[test]
    fn write_outcome_writes_every_later_output_after_one_is_skipped() {
        // The skip is per entry, not a stop: `matched-rule-id` is the first of
        // the five, and the four behind it -- the issue key included -- still
        // have to reach the file.
        let outcome = ActionOutcome {
            matched_rule_id: Some("rule-1\rforged".to_string()),
            created: true,
            jira_issue_key: Some("KAN-9".to_string()),
            deduped: true,
            severity: Some("high".to_string()),
        };

        let output =
            outcome_output(&outcome).expect("a refused first output must not stop the rest");

        assert_eq!(output.len(), 4);
        assert!(!output.contains_key("matched-rule-id"));
        assert_eq!(output["created"], "true");
        assert_eq!(output["jira-issue-key"], "KAN-9");
        assert_eq!(output["deduped"], "true");
        assert_eq!(output["severity"], "high");
    }

    #[test]
    fn an_unreadable_entropy_source_is_a_skipped_output_not_a_failed_run() {
        // The delimiter nonce is drawn inside `write`, which is past the Jira
        // write. It is reported rather than panicked so that it lands here, as
        // one skipped entry.
        skip_if_unencodable(Err(anyhow::Error::new(OutputError::EntropyUnavailable {
            name: "severity".to_string(),
        })))
        .expect("an entropy failure after the Jira write must degrade, not abort");
    }

    #[test]
    fn write_outcome_still_fails_when_the_sink_itself_fails() {
        // A sink that cannot be appended to is not a per-entry refusal: it may
        // have left a partial entry on disk and no later entry can be trusted,
        // so the step has to go red.
        struct BrokenSink;

        impl std::io::Write for BrokenSink {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "GITHUB_OUTPUT is gone",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = OutputWriter::new(BrokenSink);
        let error = write_outcome(&mut writer, &ActionOutcome::default())
            .expect_err("a failing sink must not be degraded into a green step");

        assert!(
            error.downcast_ref::<std::io::Error>().is_some(),
            "unexpected error: {error:#}"
        );
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
        fs::write(path, fixtures::action_config("dependabot-high"))
            .expect("config should be written");
    }

    fn write_matching_event(path: &std::path::Path, body: &str) {
        fs::write(
            path,
            fixtures::github_event_with_issue_body("issues-opened-dependabot-high", body),
        )
        .expect("event should be written");
    }

    /// One row of a lookup result, carrying the fields the ranking reads.
    fn labelled_row(key: &str, id: &str, labels: &[&str]) -> SearchIssue {
        serde_json::from_value(json!({
            "id": id,
            "key": key,
            "fields": { "labels": labels },
        }))
        .expect("the search issue fixture should parse")
    }

    /// The rule and delivery `write_standard_config` and `write_matching_event`
    /// pair, so a hook can be primed with the labels that delivery looks for.
    fn standard_rule_and_event(body: &str) -> (RuleConfig, GitHubIssueEvent) {
        let mut config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("the shipped config should load");
        let event = load_issue_event_from_str(
            "issues",
            &fixtures::github_event_with_issue_body("issues-opened-dependabot-high", body),
        )
        .expect("event should parse");
        (config.rules.remove(0), event)
    }

    /// The label the standard config writes for the standard delivery.
    ///
    /// Derived rather than spelled out, so a change to the identity scheme moves
    /// the fixture rows with it instead of leaving them matching nothing.
    fn standard_canonical_label() -> String {
        let (rule, event) = standard_rule_and_event("Severity: high\nPackage: foo");
        evaluate_rule(&rule, &event)
            .expect("rule evaluation should succeed")
            .expect("the shipped rule matches its own fixture")
            .dedupe_label
    }

    fn set_test_jira_hook(
        search_result: std::result::Result<Vec<SearchIssue>, String>,
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

    fn set_test_host_policy(policy: HostPolicy) {
        *TEST_HOST_POLICY
            .lock()
            .expect("host policy lock should succeed") = Some(policy);
    }

    fn clear_test_host_policy() {
        *TEST_HOST_POLICY
            .lock()
            .expect("host policy lock should succeed") = None;
    }
}
