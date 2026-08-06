use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitHubIssueEvent {
    pub action: String,
    pub issue: Issue,
    pub repository: Repository,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Issue {
    pub title: String,
    pub body: Option<String>,
    pub html_url: String,
    pub user: Actor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Repository {
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
    use super::load_issue_event_from_str;
    use threatflux_atlassian_testkit::fixtures;

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
    fn load_issue_event_ignores_the_webhook_fields_it_does_not_model_yet() {
        let payload = fixtures::github_event("issues-opened-dependabot");
        let raw: serde_json::Value = serde_json::from_str(payload).expect("fixture should parse");

        assert!(raw["issue"]["id"].is_u64());
        assert!(raw["issue"]["number"].is_u64());
        assert!(raw["issue"]["node_id"].is_string());
        assert!(raw["repository"]["id"].is_u64());
        assert_eq!(raw["sender"]["login"], "dependabot[bot]");
        assert_eq!(raw["issue"]["state"], "open");

        load_issue_event_from_str("issues", payload)
            .expect("a full delivery must still parse into the narrow event type");
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
