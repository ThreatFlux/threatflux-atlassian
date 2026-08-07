//! The GitHub `issues` delivery, narrowed to the fields the Action reads.
//!
//! `issue.id`, `issue.number`, `issue.node_id`, `repository.id` and
//! `repository.node_id` carry no `#[serde(default)]` on purpose. A delivery that
//! omits them has no identity, and a defaulted `0` would hand every such
//! delivery the same one -- so reconciliation keyed on it would treat unrelated
//! issues as the same issue. Refusing to parse is the recoverable failure.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitHubIssueEvent {
    pub action: String,
    pub issue: Issue,
    pub repository: Repository,
}

impl GitHubIssueEvent {
    /// The stable identity of the issue this delivery is about.
    pub fn identity(&self) -> EventIdentity {
        EventIdentity {
            repository_id: self.repository.id,
            repository_node_id: self.repository.node_id.clone(),
            issue_id: self.issue.id,
            issue_number: self.issue.number,
            issue_node_id: self.issue.node_id.clone(),
        }
    }
}

/// Everything about a delivery that survives an edit to the issue.
///
/// Titles, bodies, labels and state all change over the life of an issue; these
/// five fields do not, which is what makes them safe to key a Jira issue on.
/// `repository_id` and `issue_number` are the human-readable pair -- the id is
/// stable across a repository rename and the number is what the issue is called
/// in the UI -- and the node ids are the GraphQL handles for the same objects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EventIdentity {
    pub repository_id: u64,
    pub repository_node_id: String,
    pub issue_id: u64,
    pub issue_number: u64,
    pub issue_node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Issue {
    pub id: u64,
    pub number: u64,
    pub node_id: String,
    pub state: String,
    pub title: String,
    pub body: Option<String>,
    pub html_url: String,
    pub user: Actor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Repository {
    pub id: u64,
    pub node_id: String,
    pub full_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub login: String,
}

pub fn load_issue_event_from_str(event_name: &str, payload: &str) -> Result<GitHubIssueEvent> {
    if event_name != "issues" {
        anyhow::bail!("Unsupported GitHub event '{event_name}'; expected 'issues'");
    }

    let event: GitHubIssueEvent = serde_json::from_str(payload)?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::{load_issue_event_from_str, EventIdentity, GitHubIssueEvent};
    use serde_json::Value;
    use threatflux_atlassian_testkit::fixtures;

    /// The five identity fields plus `issue.state`, as `(container, field)`
    /// pairs. Every one of them is required, and none may gain a default.
    const REQUIRED_FIELDS: &[(&str, &str)] = &[
        ("issue", "id"),
        ("issue", "number"),
        ("issue", "node_id"),
        ("issue", "state"),
        ("repository", "id"),
        ("repository", "node_id"),
    ];

    fn parse(name: &str) -> GitHubIssueEvent {
        load_issue_event_from_str("issues", fixtures::github_event(name))
            .expect("event should parse")
    }

    #[test]
    fn load_issue_event_parses_dependabot_issue_payload() {
        let payload = fixtures::github_event("issues-opened-dependabot");

        let event = load_issue_event_from_str("issues", payload).expect("event should parse");

        assert_eq!(event.action, "opened");
        assert_eq!(event.issue.user.login, "dependabot[bot]");
        assert_eq!(event.repository.full_name, "ThreatFlux/demo");
        assert_eq!(event.issue.title, "Bump openssl from 1.0 to 1.1");
        assert_eq!(
            event.issue.html_url,
            "https://github.com/ThreatFlux/demo/issues/123"
        );
        assert!(event
            .issue
            .body
            .as_deref()
            .is_some_and(|body| body.contains("Severity: high")));
    }

    #[test]
    fn load_issue_event_models_the_identity_fields_the_delivery_carries() {
        let payload = fixtures::github_event("issues-opened-dependabot");
        let raw: Value = serde_json::from_str(payload).expect("fixture should parse");

        let event = load_issue_event_from_str("issues", payload)
            .expect("a full delivery must parse into the event type");

        assert_eq!(event.issue.id, 2_147_000_123);
        assert_eq!(event.issue.number, 123);
        assert_eq!(event.issue.node_id, "I_kwDOI7Vczs5xAAB7");
        assert_eq!(event.issue.state, "open");
        assert_eq!(event.repository.id, 598_178_766);
        assert_eq!(event.repository.node_id, "R_kgDOI7Vczg");

        assert_eq!(raw["issue"]["id"], event.issue.id);
        assert_eq!(raw["issue"]["number"], event.issue.number);
        assert_eq!(raw["issue"]["node_id"], event.issue.node_id);
        assert_eq!(raw["issue"]["state"], event.issue.state);
        assert_eq!(raw["repository"]["id"], event.repository.id);
        assert_eq!(raw["repository"]["node_id"], event.repository.node_id);
    }

    #[test]
    fn every_fixture_delivery_parses_with_a_populated_identity() {
        for name in fixtures::github_event_names() {
            let identity = parse(name).identity();

            assert_ne!(identity.issue_id, 0, "{name}: issue.id");
            assert_ne!(identity.issue_number, 0, "{name}: issue.number");
            assert_ne!(identity.repository_id, 0, "{name}: repository.id");
            assert!(!identity.issue_node_id.is_empty(), "{name}: issue.node_id");
            assert!(
                !identity.repository_node_id.is_empty(),
                "{name}: repository.node_id"
            );
        }
    }

    #[test]
    fn load_issue_event_rejects_a_delivery_missing_a_required_field() {
        for (container, field) in REQUIRED_FIELDS {
            let mut payload = fixtures::github_event_json("issues-opened-dependabot");
            payload[container]
                .as_object_mut()
                .expect("the fixture container should be an object")
                .remove(*field)
                .expect("the fixture should carry the field being removed");

            let error = load_issue_event_from_str("issues", &payload.to_string()).expect_err(
                "a delivery without an identity may not be defaulted into a shared one",
            );
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing field `{field}`")),
                "removing {container}.{field} produced: {error}"
            );
        }
    }

    #[test]
    fn identity_distinguishes_two_issues_in_one_repository() {
        let first = parse("issues-opened-dependabot").identity();
        let second = parse("issues-opened-dependabot-high").identity();

        assert_eq!(first.repository_id, second.repository_id);
        assert_eq!(first.repository_node_id, second.repository_node_id);
        assert_ne!(
            first, second,
            "two issues in one repository must not share an identity"
        );
        assert_ne!(first.issue_id, second.issue_id);
        assert_ne!(first.issue_number, second.issue_number);
        assert_ne!(first.issue_node_id, second.issue_node_id);
    }

    #[test]
    fn identity_survives_an_edit_to_the_mutable_content() {
        let before = parse("issues-opened-dependabot").identity();

        let mut payload = fixtures::github_event_json("issues-opened-dependabot");
        payload["issue"]["title"] = Value::String("Bump openssl from 1.0 to 1.1.1".to_string());
        payload["issue"]["body"] = Value::String("Severity: critical".to_string());
        payload["issue"]["state"] = Value::String("closed".to_string());
        payload["action"] = Value::String("edited".to_string());
        let after = load_issue_event_from_str("issues", &payload.to_string())
            .expect("the edited delivery should parse")
            .identity();

        assert_eq!(
            before, after,
            "identity is what a retitle, a rewrite and a close all leave alone"
        );
    }

    #[test]
    fn identity_round_trips_through_json() {
        let identity = parse("issues-opened-dependabot").identity();

        let encoded = serde_json::to_value(&identity).expect("identity should serialize");
        assert_eq!(
            encoded,
            serde_json::json!({
                "repository_id": 598_178_766,
                "repository_node_id": "R_kgDOI7Vczg",
                "issue_id": 2_147_000_123,
                "issue_number": 123,
                "issue_node_id": "I_kwDOI7Vczs5xAAB7",
            })
        );

        let decoded: EventIdentity =
            serde_json::from_value(encoded).expect("identity should deserialize");
        assert_eq!(decoded, identity);
    }

    #[test]
    fn load_issue_event_rejects_non_issue_events() {
        let error = load_issue_event_from_str("pull_request", "{}")
            .expect_err("non-issue events should fail");
        assert!(
            error.to_string().contains("issues"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_issue_event_rejects_invalid_json() {
        let error =
            load_issue_event_from_str("issues", "{").expect_err("invalid payload should fail");
        assert!(error.to_string().contains("EOF"));
    }
}
