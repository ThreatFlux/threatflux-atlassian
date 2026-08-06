//! Byte-exact payload fixtures shared by the workspace test suites.
//!
//! Fixtures are embedded with `include_str!` rather than read from disk: a test
//! that changes the process working directory (or a binary run from a different
//! one) would otherwise resolve a relative fixture path differently from the
//! test that ran before it.
//!
//! Every GitHub event fixture carries `issue.id`, `issue.number`,
//! `issue.node_id` and `repository.id`. Event identity is keyed off those
//! fields, so a fixture missing them cannot be used to test reconciliation.

use serde_json::Value;

macro_rules! fixture_table {
    ($dir:literal, $ext:literal, [$($name:literal),* $(,)?]) => {
        &[$(($name, include_str!(concat!("../fixtures/", $dir, "/", $name, ".", $ext)))),*]
    };
}

/// Action automation YAML, one file per inline literal the tests used to carry.
const ACTION_CONFIGS: &[(&str, &str)] = fixture_table!(
    "action-config",
    "yml",
    [
        "action-edited",
        "actor-gate-minimal",
        "dependabot-high",
        "dependabot-high-no-assignee",
        "dependabot-high-plain-summary",
        "dependabot-high-plain-templates",
        "empty-capture-regex",
        "env-description-injection",
        "env-empty-with-default",
        "env-expansion-defaults",
        "env-required-no-default",
        "env-whitespace-with-default",
        "jira-blank-assignee",
        "jira-dedupe-prefix",
        "jira-missing-priority-mapping",
        "jira-multiline-description",
        "jira-quoted-project-key",
        "jira-summary-from-body",
        "minimal-critical",
        "reject-blank-event",
        "reject-blank-project-key",
        "reject-blank-rule-id",
        "reject-blank-summary",
        "reject-dedupe-strategy-sha1",
        "reject-description-format-adf",
        "reject-empty-dedupe-fields",
        "reject-empty-rules",
        "reject-severity-regex-without-capture",
        "reject-severity-source-issue-title",
        "reject-unknown-description-template-field",
        "reject-unknown-description-template-field-repo",
        "reject-unknown-summary-template-field",
        "reject-unsupported-dedupe-field",
        "reject-unsupported-event",
        "reject-version-2",
        "template-render",
    ]
);

/// GitHub webhook deliveries for the `issues` event.
const GITHUB_EVENTS: &[(&str, &str)] = fixture_table!(
    "github",
    "json",
    [
        "issues-opened-dependabot",
        "issues-opened-dependabot-critical",
        "issues-opened-dependabot-critical-package",
        "issues-opened-dependabot-crlf",
        "issues-opened-dependabot-high",
        "issues-opened-dependabot-high-package",
        "issues-opened-dependabot-null-body",
        "issues-opened-dependabot-openssl",
        "issues-opened-human-high",
        "issues-opened-human-medium",
    ]
);

/// Jira response bodies, for mock scripts and golden comparisons.
const JIRA_BODIES: &[(&str, &str)] = fixture_table!(
    "jira",
    "json",
    [
        "create-issue-response",
        "error-rate-limited",
        "search-empty",
        "search-one-issue",
    ]
);

fn lookup(kind: &str, table: &'static [(&'static str, &'static str)], name: &str) -> &'static str {
    table
        .iter()
        .find_map(|(key, body)| (*key == name).then_some(*body))
        .unwrap_or_else(|| {
            panic!(
                "unknown {kind} fixture '{name}'; known fixtures: {}",
                names(table).join(", ")
            )
        })
}

fn names(table: &'static [(&'static str, &'static str)]) -> Vec<&'static str> {
    table.iter().map(|(key, _)| *key).collect()
}

/// Returns the raw YAML of an Action automation config fixture.
///
/// # Panics
///
/// Panics if `name` is not a known fixture, naming every fixture that is.
pub fn action_config(name: &str) -> &'static str {
    lookup("action config", ACTION_CONFIGS, name)
}

/// Returns the raw JSON of a GitHub `issues` delivery fixture.
///
/// # Panics
///
/// Panics if `name` is not a known fixture, naming every fixture that is.
pub fn github_event(name: &str) -> &'static str {
    lookup("github event", GITHUB_EVENTS, name)
}

/// Returns a GitHub `issues` delivery fixture parsed into a [`Value`].
///
/// # Panics
///
/// Panics if `name` is not a known fixture or if the fixture is not valid JSON.
pub fn github_event_json(name: &str) -> Value {
    serde_json::from_str(github_event(name))
        .unwrap_or_else(|error| panic!("github event fixture '{name}' is not valid JSON: {error}"))
}

/// Returns a GitHub `issues` delivery fixture with `issue.body` replaced.
///
/// Hostile-body cases are the same delivery with one field swapped; rewriting
/// the whole payload for each would put the identity fields back in the test.
///
/// # Panics
///
/// Panics if `name` is not a known fixture or if the fixture is not valid JSON.
pub fn github_event_with_issue_body(name: &str, body: &str) -> String {
    let mut event = github_event_json(name);
    event["issue"]["body"] = Value::String(body.to_string());
    event.to_string()
}

/// Returns the raw JSON of a Jira response fixture.
///
/// # Panics
///
/// Panics if `name` is not a known fixture, naming every fixture that is.
pub fn jira_body(name: &str) -> &'static str {
    lookup("jira body", JIRA_BODIES, name)
}

/// Returns a Jira response fixture parsed into a [`Value`].
///
/// # Panics
///
/// Panics if `name` is not a known fixture or if the fixture is not valid JSON.
pub fn jira_body_json(name: &str) -> Value {
    serde_json::from_str(jira_body(name))
        .unwrap_or_else(|error| panic!("jira body fixture '{name}' is not valid JSON: {error}"))
}

/// Names every Action automation config fixture.
pub fn action_config_names() -> Vec<&'static str> {
    names(ACTION_CONFIGS)
}

/// Names every GitHub `issues` delivery fixture.
pub fn github_event_names() -> Vec<&'static str> {
    names(GITHUB_EVENTS)
}

/// Names every Jira response fixture.
pub fn jira_body_names() -> Vec<&'static str> {
    names(JIRA_BODIES)
}

#[cfg(test)]
mod tests {
    use super::{
        action_config, action_config_names, github_event, github_event_json, github_event_names,
        github_event_with_issue_body, jira_body_json, jira_body_names,
    };

    #[test]
    fn every_github_event_carries_the_identity_fields() {
        for name in github_event_names() {
            let event = github_event_json(name);
            assert!(
                event["issue"]["id"].is_u64(),
                "{name}: issue.id must be a number"
            );
            assert!(
                event["issue"]["number"].is_u64(),
                "{name}: issue.number must be a number"
            );
            assert!(
                event["issue"]["node_id"].is_string(),
                "{name}: issue.node_id must be a string"
            );
            assert!(
                event["repository"]["id"].is_u64(),
                "{name}: repository.id must be a number"
            );
        }
    }

    #[test]
    fn every_github_event_carries_the_webhook_shape_the_action_gates_on() {
        for name in github_event_names() {
            let event = github_event_json(name);
            assert!(
                event["issue"]["user"]["login"].is_string(),
                "{name}: issue.user.login is the field actor_in gates on"
            );
            assert!(event["sender"]["login"].is_string(), "{name}: sender.login");
            assert!(event["issue"]["labels"].is_array(), "{name}: issue.labels");
            assert_eq!(event["issue"]["state"], "open", "{name}: issue.state");
            assert_eq!(event["action"], "opened", "{name}: action");
        }
    }

    #[test]
    fn dependabot_delivery_is_a_full_webhook_payload() {
        let event = github_event_json("issues-opened-dependabot");

        assert_eq!(event["issue"]["user"]["login"], "dependabot[bot]");
        assert_eq!(event["issue"]["user"]["type"], "Bot");
        assert_eq!(event["sender"]["login"], "dependabot[bot]");
        assert_eq!(event["repository"]["full_name"], "ThreatFlux/demo");
        assert_eq!(event["issue"]["number"], 123);
        assert_eq!(
            event["issue"]["labels"]
                .as_array()
                .expect("labels should be an array")
                .len(),
            2
        );
        assert!(event["installation"]["id"].is_u64());
    }

    #[test]
    fn crlf_fixture_survives_checkout_with_its_line_endings() {
        let raw = github_event("issues-opened-dependabot-crlf");
        assert!(
            raw.contains("\r\n"),
            "the CRLF fixture lost its carriage returns; check .gitattributes"
        );
    }

    #[test]
    fn fixture_names_are_sorted_and_unique() {
        for names in [
            action_config_names(),
            github_event_names(),
            jira_body_names(),
        ] {
            let mut sorted = names.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(names, sorted, "fixture names must be sorted and unique");
        }
    }

    #[test]
    fn every_action_config_fixture_resolves_and_is_non_empty() {
        for name in action_config_names() {
            assert!(
                action_config(name).starts_with("version:"),
                "{name}: action config fixtures start at the version key"
            );
        }
    }

    #[test]
    fn every_jira_fixture_is_valid_json() {
        for name in jira_body_names() {
            assert!(jira_body_json(name).is_object(), "{name}");
        }
    }

    #[test]
    fn issue_body_can_be_swapped_without_losing_identity() {
        let raw =
            github_event_with_issue_body("issues-opened-dependabot", "Severity: critical\r\n");
        let event: serde_json::Value =
            serde_json::from_str(&raw).expect("patched event should parse");

        assert_eq!(event["issue"]["body"], "Severity: critical\r\n");
        assert_eq!(event["issue"]["number"], 123);
        assert!(event["repository"]["id"].is_u64());
    }

    #[test]
    #[should_panic(expected = "unknown action config fixture 'nope'")]
    fn unknown_fixture_names_the_known_ones() {
        let _ = action_config("nope");
    }
}
