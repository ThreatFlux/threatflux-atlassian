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

    #[test]
    fn load_issue_event_parses_dependabot_issue_payload() {
        let payload = r#"{
  "action": "opened",
  "issue": {
    "title": "Bump openssl from 1.0 to 1.1",
    "body": "Severity: high\nPackage: openssl",
    "html_url": "https://github.com/ThreatFlux/demo/issues/123",
    "user": {
      "login": "dependabot[bot]"
    }
  },
  "repository": {
    "full_name": "ThreatFlux/demo"
  }
}"#;

        let event = load_issue_event_from_str("issues", payload).expect("event should parse");

        assert_eq!(event.action, "opened");
        assert_eq!(event.issue.user.login, "dependabot[bot]");
        assert_eq!(event.repository.full_name, "ThreatFlux/demo");
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
