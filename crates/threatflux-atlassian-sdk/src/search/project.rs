//! A deliberately thin model of paginated project search.
//!
//! `GET /rest/api/3/project/search` replaces the removed non-paginated project
//! listing. Nothing in this workspace resolves projects as part of its normal
//! work — a project key arrives from configuration and goes straight into a
//! query — so this models one page and stops there. There is no cursor and no
//! iteration helper: the use it exists for is a preflight that asks whether a
//! configured key names a project that the credentials can see, which is
//! answered by the first page or not at all.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// A project, as both a search result and an issue's `project` field.
///
/// The same shape serves both because Jira sends the same object in both
/// places; the keys this type does not model are preserved in
/// [`other`](Self::other) rather than dropped.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SearchProject {
    /// Numeric project id, as the string Jira sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Project key, such as `KAN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Project type key, such as `software` or `service_desk`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_type_key: Option<String>,

    /// Every other key, `avatarUrls`, `simplified` and `style` included.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// One page of `GET /rest/api/3/project/search`.
///
/// Project search paginates by offset — it is a different endpoint from
/// enhanced issue search and predates the token scheme — so `startAt`, `total`
/// and `isLast` are all present here and all absent from
/// [`SearchPage`](super::SearchPage). Do not carry a habit from one to the
/// other.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProjectSearchPage {
    /// The projects on this page.
    #[serde(default)]
    pub values: Vec<SearchProject>,

    /// Whether this is the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_last: Option<bool>,

    /// How many projects match in total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,

    /// The offset this page starts at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_at: Option<u64>,

    /// The page size the server applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u64>,
}

impl ProjectSearchPage {
    /// The project on this page whose key is `key`, if one is.
    ///
    /// Compared case-insensitively over ASCII: Jira normalizes project keys to
    /// upper case on creation, so a configured `kan` names the project a search
    /// answers as `KAN`, and a preflight that missed it would report a
    /// perfectly valid key as unknown.
    ///
    /// This searches one page. The endpoint's `query` parameter matches on key
    /// *and* name, so a preflight that asks for a key it cannot find on the
    /// first page should narrow the query rather than paginate.
    pub fn find_by_key(&self, key: &str) -> Option<&SearchProject> {
        self.values.iter().find(|project| {
            project
                .key
                .as_ref()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(key))
        })
    }
}

/// The query string of `GET /rest/api/3/project/search`.
///
/// ```
/// use threatflux_atlassian_sdk::search::ProjectSearchQuery;
///
/// let query = ProjectSearchQuery::matching("KAN").with_max_results(1);
///
/// assert_eq!(query.query_params().get("query").map(String::as_str), Some("KAN"));
/// assert_eq!(query.query_params().get("maxResults").map(String::as_str), Some("1"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectSearchQuery {
    /// Literal text matched against project key and name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    query: Option<String>,

    /// Page size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_results: Option<u32>,

    /// Offset of the first result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start_at: Option<u32>,
}

impl ProjectSearchQuery {
    /// A query for projects whose key or name matches `query`.
    pub fn matching(query: impl Into<String>) -> Self {
        Self {
            query: Some(query.into()),
            ..Self::default()
        }
    }

    /// Sets the page size.
    #[must_use]
    pub const fn with_max_results(mut self, max_results: u32) -> Self {
        self.max_results = Some(max_results);
        self
    }

    /// Sets the offset of the first result.
    #[must_use]
    pub const fn with_start_at(mut self, start_at: u32) -> Self {
        self.start_at = Some(start_at);
        self
    }

    /// The text being matched, when one was set.
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// The page size, when one was set.
    pub const fn max_results(&self) -> Option<u32> {
        self.max_results
    }

    /// The offset, when one was set.
    pub const fn start_at(&self) -> Option<u32> {
        self.start_at
    }

    /// This query as the parameters to hang off the request URL.
    ///
    /// A parameter that was never set is absent from the map rather than
    /// present and empty, because an empty `query` is not the same request as
    /// no `query` at all.
    pub fn query_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(query) = &self.query {
            params.insert("query".to_string(), query.clone());
        }
        if let Some(max_results) = self.max_results {
            params.insert("maxResults".to_string(), max_results.to_string());
        }
        if let Some(start_at) = self.start_at {
            params.insert("startAt".to_string(), start_at.to_string());
        }
        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn page() -> ProjectSearchPage {
        serde_json::from_value(json!({
            "self": "https://example.atlassian.net/rest/api/3/project/search?maxResults=2",
            "maxResults": 2,
            "startAt": 0,
            "total": 2,
            "isLast": true,
            "values": [
                {"id": "10000", "key": "KAN", "name": "Kanban",
                 "projectTypeKey": "software", "simplified": true,
                 "avatarUrls": {"48x48": "https://example.test/a"}},
                {"id": "10001", "key": "OPS", "name": "Operations"}
            ]
        }))
        .expect("deserializes")
    }

    #[test]
    fn a_page_parses_with_its_offset_pagination_intact() {
        let page = page();

        assert_eq!(page.values.len(), 2);
        assert_eq!(page.total, Some(2));
        assert_eq!(page.start_at, Some(0));
        assert_eq!(page.max_results, Some(2));
        assert_eq!(page.is_last, Some(true));
    }

    #[test]
    fn an_unmodelled_project_key_survives() {
        let project = page().values.first().cloned().expect("one project");

        assert_eq!(project.key.as_deref(), Some("KAN"));
        assert_eq!(project.project_type_key.as_deref(), Some("software"));
        assert_eq!(project.other.get("simplified"), Some(&json!(true)));
        assert_eq!(
            project.other.get("avatarUrls"),
            Some(&json!({"48x48": "https://example.test/a"}))
        );
    }

    #[test]
    fn a_project_field_on_an_issue_uses_the_same_shape() {
        let project: SearchProject =
            serde_json::from_value(json!({"id": "10000", "key": "KAN", "name": "Kanban"}))
                .expect("deserializes");

        assert_eq!(project.name.as_deref(), Some("Kanban"));
        assert!(project.other.is_empty());
    }

    #[test]
    fn a_key_is_found_case_insensitively() {
        let page = page();

        assert_eq!(
            page.find_by_key("kan")
                .and_then(|project| project.id.as_deref()),
            Some("10000")
        );
        assert_eq!(
            page.find_by_key("OPS")
                .and_then(|project| project.id.as_deref()),
            Some("10001")
        );
        assert!(page.find_by_key("NOPE").is_none());
    }

    #[test]
    fn a_keyless_project_is_not_matched_by_an_empty_key() {
        let page: ProjectSearchPage =
            serde_json::from_value(json!({"values": [{"id": "10000"}]})).expect("deserializes");

        assert!(page.find_by_key("").is_none());
    }

    #[test]
    fn an_empty_page_parses() {
        let page: ProjectSearchPage =
            serde_json::from_value(json!({"values": [], "isLast": true})).expect("deserializes");

        assert!(page.values.is_empty());
        assert!(page.find_by_key("KAN").is_none());
    }

    #[test]
    fn an_unset_parameter_is_absent_rather_than_empty() {
        let params = ProjectSearchQuery::default().query_params();

        assert!(params.is_empty());
    }

    #[test]
    fn a_populated_query_renders_jiras_own_parameter_names() {
        let query = ProjectSearchQuery::matching("KAN")
            .with_max_results(1)
            .with_start_at(50);
        let params = query.query_params();

        assert_eq!(query.query(), Some("KAN"));
        assert_eq!(query.max_results(), Some(1));
        assert_eq!(query.start_at(), Some(50));
        assert_eq!(params.get("query").map(String::as_str), Some("KAN"));
        assert_eq!(params.get("maxResults").map(String::as_str), Some("1"));
        assert_eq!(params.get("startAt").map(String::as_str), Some("50"));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn a_query_round_trips_through_json() {
        let query = ProjectSearchQuery::matching("KAN").with_max_results(1);
        let json = serde_json::to_string(&query).expect("serializes");

        assert_eq!(
            serde_json::from_str::<ProjectSearchQuery>(&json).expect("deserializes"),
            query
        );
        assert_eq!(json, r#"{"query":"KAN","maxResults":1}"#);
    }
}
