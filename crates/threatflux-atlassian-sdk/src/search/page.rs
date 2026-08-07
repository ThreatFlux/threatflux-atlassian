//! The enhanced-search response: one page of issues, and the issues on it.

use super::project::SearchProject;
use crate::adf::RichText;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// One page of `POST /rest/api/3/search/jql`.
///
/// # The token is the authority, `isLast` is advisory
///
/// Iteration continues while [`next_token`](Self::next_token) is `Some`, and
/// stops when it is `None`. Three consequences are easy to get wrong and are
/// therefore stated rather than implied:
///
/// - A page whose [`issues`](Self::issues) are empty **is not** the end of the
///   iteration. Jira may answer with no issues and a token, and a caller that
///   stops on an empty page silently loses every later result.
/// - [`is_last`](Self::is_last) is not always present, and when it is, it can
///   disagree with the token. [`is_last_disagrees`](Self::is_last_disagrees)
///   reports that so a caller can log it; the token still decides.
/// - There is no `total` and no `startAt`. Enhanced search does not count the
///   result set, so "how many match" is a separate approximate-count call and
///   never a field on a page.
///
/// ```
/// use threatflux_atlassian_sdk::search::SearchPage;
///
/// let page: SearchPage = serde_json::from_str(
///     r#"{"issues":[],"nextPageToken":"eyJ0IjoxfQ==","isLast":false}"#,
/// )?;
///
/// assert!(page.issues.is_empty());
/// assert_eq!(page.next_token(), Some("eyJ0IjoxfQ=="));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SearchPage {
    /// The issues on this page, in the order Jira returned them.
    #[serde(default, deserialize_with = "null_as_default")]
    pub issues: Vec<SearchIssue>,

    /// The opaque token that asks for the page after this one.
    ///
    /// Absent on the last page. Read it through
    /// [`next_token`](Self::next_token), which also treats an empty string as
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,

    /// Jira's own claim about whether this is the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_last: Option<bool>,
}

/// One page of `POST /rest/api/3/search/jql` with the issues left untyped.
///
/// [`SearchPage`] models the fields this crate reads and preserves the rest;
/// this type does not model any of them. It exists for a caller who asked for a
/// field set the typed model would flatten into
/// [`SearchIssueFields::other`](SearchIssueFields::other) anyway — a report over
/// twenty custom fields, a schema probe — and who would rather work with the
/// JSON directly than through a map lookup.
///
/// Pagination behaves identically, and for the same reasons: see [`SearchPage`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RawSearchPage {
    /// The issues on this page, exactly as Jira sent them.
    #[serde(default, deserialize_with = "null_as_default")]
    pub issues: Vec<Value>,

    /// The opaque token that asks for the page after this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,

    /// Jira's own claim about whether this is the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_last: Option<bool>,
}

impl SearchPage {
    /// The token for the next page, or `None` when iteration is over.
    ///
    /// An empty-string token counts as absent. Jira treats a blank token as "no
    /// token" and answers with the first page, so honouring one would loop over
    /// page one rather than terminate.
    pub fn next_token(&self) -> Option<&str> {
        next_token(self.next_page_token.as_deref())
    }

    /// Whether [`is_last`](Self::is_last) contradicts the token.
    ///
    /// True when Jira says this is the last page yet hands back a token, or
    /// says it is not yet hands back none. Worth logging, never worth acting
    /// on: the token decides either way.
    pub fn is_last_disagrees(&self) -> bool {
        disagrees(self.is_last, self.next_token().is_some())
    }
}

impl RawSearchPage {
    /// The token for the next page, or `None` when iteration is over.
    ///
    /// As [`SearchPage::next_token`].
    pub fn next_token(&self) -> Option<&str> {
        next_token(self.next_page_token.as_deref())
    }

    /// Whether [`is_last`](Self::is_last) contradicts the token.
    ///
    /// As [`SearchPage::is_last_disagrees`].
    pub fn is_last_disagrees(&self) -> bool {
        disagrees(self.is_last, self.next_token().is_some())
    }
}

/// One issue on a [`SearchPage`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct SearchIssue {
    /// Numeric issue id, as the string Jira sends.
    pub id: String,

    /// Issue key, such as `KAN-42`.
    pub key: String,

    /// Absolute URL of the issue's REST resource.
    #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
    pub self_url: Option<String>,

    /// The fields the request asked for.
    #[serde(default)]
    pub fields: SearchIssueFields,

    /// Every other top-level key Jira sent — `expand`, `renderedFields`,
    /// `properties`, `changelog` — preserved rather than dropped.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

impl SearchIssue {
    /// [`id`](Self::id) parsed as a number.
    ///
    /// Jira sends the id as a string, and comparing two ids as strings orders
    /// `10100` before `9999`. Any caller ranking candidates — electing one
    /// winner out of a duplicate set, say — needs the numeric order, and any
    /// caller filling `reconcileIssues` needs the number itself.
    ///
    /// `None` when the id is not a number, which a well-formed response never
    /// produces.
    pub fn numeric_id(&self) -> Option<i64> {
        self.id.parse().ok()
    }
}

/// The fields of one issue on a [`SearchPage`].
///
/// # Every field is optional, and unmodelled fields survive
///
/// A caller chooses the field set with
/// [`SearchRequest::with_fields`](super::SearchRequest::with_fields), so any
/// field here may be missing from any given response — that is the normal case,
/// not an error, and nothing in this type is required. Equally, an instance
/// defines custom fields this crate has never heard of; those land in
/// [`other`](Self::other) and re-serialize exactly as they arrived rather than
/// being dropped on a read-modify-write.
///
/// ```
/// use threatflux_atlassian_sdk::search::SearchIssue;
///
/// // Asked for `summary` alone, plus a custom field this crate does not model.
/// let issue: SearchIssue = serde_json::from_str(
///     r#"{"id":"10042","key":"KAN-42",
///         "fields":{"summary":"Bump openssl","customfield_10001":{"value":"High"}}}"#,
/// )?;
///
/// assert_eq!(issue.fields.summary.as_deref(), Some("Bump openssl"));
/// assert_eq!(issue.fields.status, None);
/// assert_eq!(
///     issue.fields.field("customfield_10001"),
///     Some(&serde_json::json!({"value": "High"}))
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SearchIssueFields {
    /// Issue summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Issue description.
    ///
    /// [`RichText`] rather than `String` because v3 answers with an ADF
    /// document and v2-era data answers with a string; both parse, and neither
    /// needs the caller to know which arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<RichText>,

    /// Issue labels.
    ///
    /// Empty both when the issue has no labels and when the request did not ask
    /// for them, and skipped on the way out rather than emitted as `[]`: adding
    /// a key Jira did not send would misreport "not requested" as "requested,
    /// and there were none".
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub labels: Vec<String>,

    /// Issue status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<SearchStatus>,

    /// Issue type.
    #[serde(rename = "issuetype", default, skip_serializing_if = "Option::is_none")]
    pub issue_type: Option<SearchNamedRef>,

    /// Issue priority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<SearchNamedRef>,

    /// Assignee, absent when the issue is unassigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<SearchUser>,

    /// Reporter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporter: Option<SearchUser>,

    /// The project the issue belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<SearchProject>,

    /// Creation timestamp, in Jira's own ISO 8601 rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Last-updated timestamp, in Jira's own ISO 8601 rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,

    /// Resolution timestamp, absent while the issue is unresolved.
    #[serde(
        rename = "resolutiondate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resolution_date: Option<String>,

    /// Every field this type does not model, custom fields included.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

impl SearchIssueFields {
    /// Reads a field this type does not model out of [`other`](Self::other).
    ///
    /// Takes the wire name, so a custom field is `field("customfield_10001")`.
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.other.get(name)
    }

    /// The status name, such as `To Do`.
    pub fn status_name(&self) -> Option<&str> {
        self.status
            .as_ref()
            .and_then(|status| status.name.as_deref())
    }

    /// The status *category* key: `new`, `indeterminate` or `done`.
    ///
    /// The category is the portable signal. A status *name* is per-project
    /// configuration — one instance's `Closed` is another's `Shipped` — while
    /// the three category keys are fixed by Jira, so a check for "is this issue
    /// finished" belongs here rather than on the name.
    pub fn status_category_key(&self) -> Option<&str> {
        self.status
            .as_ref()
            .and_then(|status| status.status_category.as_ref())
            .and_then(|category| category.key.as_deref())
    }

    /// Whether [`labels`](Self::labels) contains `label`, compared exactly.
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.iter().any(|candidate| candidate == label)
    }
}

/// An issue status, with only the two parts that are portable modelled.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SearchStatus {
    /// Status name, such as `In Progress`. Per-project configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The category the status belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_category: Option<SearchStatusCategory>,

    /// Every other key, `id` and `iconUrl` included.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// The fixed category behind a per-project status.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SearchStatusCategory {
    /// `new`, `indeterminate` or `done`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// Display name, such as `Done`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Every other key. `id` lives here because Jira sends it as a number on
    /// this object and as a string almost everywhere else, and a model that
    /// picked one of those would fail to parse the other.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// The `{id, name}` shape Jira uses for an issue type, a priority, a
/// resolution and their kin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SearchNamedRef {
    /// Entity id, as the string Jira sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Display name, such as `Bug` or `High`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Every other key, `iconUrl` and `subtask` included.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// A user as a search response renders one.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SearchUser {
    /// Atlassian account id, the only stable user identifier on Cloud.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,

    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Email address, which most instances withhold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,

    /// Whether the account is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,

    /// Every other key, `avatarUrls` included.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// The token to send for the next page, treating a blank one as absent.
fn next_token(token: Option<&str>) -> Option<&str> {
    token.filter(|token| !token.is_empty())
}

/// Whether `is_last` contradicts the presence of a token.
const fn disagrees(is_last: Option<bool>, has_token: bool) -> bool {
    match is_last {
        Some(is_last) => is_last == has_token,
        None => false,
    }
}

/// Reads `null` as the type's default rather than failing.
///
/// Jira answers a list-valued field it has nothing for with `[]`, but a
/// narrowed field set, a permission filter or a `failFast: false` partial
/// response can put a `null` there instead. A parse error on the whole page is
/// far too expensive an answer to "this issue has no labels".
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_page() -> Value {
        json!({
            "issues": [{
                "id": "10042",
                "key": "KAN-42",
                "self": "https://example.atlassian.net/rest/api/3/issue/10042",
                "fields": {
                    "summary": "Bump openssl from 1.0 to 1.1",
                    "labels": ["dependabot", "gh-901234-77"],
                    "status": {
                        "id": "10000",
                        "name": "To Do",
                        "statusCategory": {"id": 2, "key": "new", "name": "To Do"}
                    },
                    "issuetype": {"id": "10001", "name": "Task", "subtask": false},
                    "priority": {"id": "2", "name": "High"},
                    "assignee": {"accountId": "5b10a2", "displayName": "Ana", "active": true},
                    "reporter": {"accountId": "5b10a3"},
                    "project": {"id": "10000", "key": "KAN", "name": "Kanban"},
                    "created": "2026-08-01T09:00:00.000+0000",
                    "updated": "2026-08-02T09:00:00.000+0000",
                    "resolutiondate": null
                }
            }],
            "nextPageToken": "eyJ0IjoxfQ==",
            "isLast": false
        })
    }

    #[test]
    fn a_full_page_parses_into_the_modelled_fields() {
        let page: SearchPage = serde_json::from_value(full_page()).expect("deserializes");
        let issue = page.issues.first().expect("one issue");

        assert_eq!(issue.id, "10042");
        assert_eq!(issue.key, "KAN-42");
        assert_eq!(issue.numeric_id(), Some(10_042));
        assert_eq!(
            issue.self_url.as_deref(),
            Some("https://example.atlassian.net/rest/api/3/issue/10042")
        );
        assert_eq!(
            issue.fields.summary.as_deref(),
            Some("Bump openssl from 1.0 to 1.1")
        );
        assert_eq!(issue.fields.status_name(), Some("To Do"));
        assert_eq!(issue.fields.status_category_key(), Some("new"));
        assert_eq!(
            issue
                .fields
                .issue_type
                .as_ref()
                .and_then(|kind| kind.name.as_deref()),
            Some("Task")
        );
        assert_eq!(
            issue
                .fields
                .priority
                .as_ref()
                .and_then(|priority| priority.name.as_deref()),
            Some("High")
        );
        assert_eq!(
            issue
                .fields
                .assignee
                .as_ref()
                .and_then(|user| user.account_id.as_deref()),
            Some("5b10a2")
        );
        assert_eq!(
            issue
                .fields
                .project
                .as_ref()
                .and_then(|project| project.key.as_deref()),
            Some("KAN")
        );
        assert_eq!(issue.fields.resolution_date, None);
        assert!(issue.fields.has_label("gh-901234-77"));
        assert!(!issue.fields.has_label("gh-901234-7"));
        assert_eq!(page.next_token(), Some("eyJ0IjoxfQ=="));
        assert!(!page.is_last_disagrees());
    }

    #[test]
    fn a_narrow_field_set_parses_rather_than_failing() {
        let page: SearchPage = serde_json::from_value(json!({
            "issues": [{"id": "10042", "key": "KAN-42", "fields": {"summary": "only this"}}]
        }))
        .expect("a narrowed response must not be a deserialization error");
        let fields = &page.issues.first().expect("one issue").fields;

        assert_eq!(fields.summary.as_deref(), Some("only this"));
        assert_eq!(fields.status, None);
        assert_eq!(fields.issue_type, None);
        assert_eq!(fields.priority, None);
        assert_eq!(fields.assignee, None);
        assert_eq!(fields.reporter, None);
        assert_eq!(fields.project, None);
        assert_eq!(fields.description, None);
        assert_eq!(fields.created, None);
        assert_eq!(fields.updated, None);
        assert_eq!(fields.resolution_date, None);
        assert!(fields.labels.is_empty());
    }

    #[test]
    fn an_issue_with_no_fields_object_at_all_parses() {
        let page: SearchPage = serde_json::from_value(json!({
            "issues": [{"id": "10042", "key": "KAN-42"}, {"id": "1", "key": "KAN-1", "fields": {}}]
        }))
        .expect("deserializes");

        assert_eq!(page.issues.len(), 2);
        assert_eq!(page.issues[0].fields, SearchIssueFields::default());
        assert_eq!(page.issues[1].fields, SearchIssueFields::default());
    }

    #[test]
    fn an_unmodelled_field_survives_a_round_trip() {
        let original = json!({
            "id": "10042",
            "key": "KAN-42",
            "expand": "operations,changelog",
            "renderedFields": {"description": "<p>hi</p>"},
            "fields": {
                "summary": "kept",
                "customfield_10001": {"value": "High", "id": "1"},
                "timetracking": {"remainingEstimate": "1d"},
                "votes": null
            }
        });

        let issue: SearchIssue = serde_json::from_value(original.clone()).expect("deserializes");

        assert_eq!(
            issue.fields.field("customfield_10001"),
            Some(&json!({"value": "High", "id": "1"}))
        );
        assert_eq!(
            issue.other.get("expand"),
            Some(&json!("operations,changelog"))
        );
        assert_eq!(
            serde_json::to_value(&issue).expect("serializes"),
            original,
            "an unmodelled key must be re-emitted exactly as it arrived"
        );
    }

    #[test]
    fn a_description_parses_as_adf_or_as_a_string() {
        let adf: SearchIssueFields = serde_json::from_value(json!({
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph",
                             "content": [{"type": "text", "text": "typed"}]}]
            }
        }))
        .expect("deserializes");
        assert!(matches!(adf.description, Some(RichText::Adf(_))));

        let text: SearchIssueFields =
            serde_json::from_value(json!({"description": "v2-era string"})).expect("deserializes");
        assert_eq!(
            text.description,
            Some(RichText::Text("v2-era string".to_string()))
        );

        let absent: SearchIssueFields =
            serde_json::from_value(json!({"description": null})).expect("deserializes");
        assert_eq!(absent.description, None);
    }

    #[test]
    fn a_null_list_reads_as_an_empty_one() {
        let fields: SearchIssueFields =
            serde_json::from_value(json!({"labels": null})).expect("deserializes");
        assert!(fields.labels.is_empty());

        let page: SearchPage =
            serde_json::from_value(json!({"issues": null})).expect("deserializes");
        assert!(page.issues.is_empty());
    }

    #[test]
    fn an_empty_page_with_a_token_is_not_the_end_of_the_iteration() {
        let page: SearchPage = serde_json::from_value(json!({
            "issues": [],
            "nextPageToken": "more",
            "isLast": false
        }))
        .expect("deserializes");

        assert!(page.issues.is_empty());
        assert_eq!(
            page.next_token(),
            Some("more"),
            "an empty page with a token must not read as exhausted"
        );
    }

    #[test]
    fn a_blank_token_reads_as_exhausted() {
        for body in [
            json!({"issues": []}),
            json!({"issues": [], "nextPageToken": ""}),
            json!({"issues": [], "nextPageToken": null}),
        ] {
            let page: SearchPage = serde_json::from_value(body.clone()).expect("deserializes");
            assert_eq!(
                page.next_token(),
                None,
                "body {body} should read as the last page"
            );
        }
    }

    #[test]
    fn is_last_is_reported_when_it_contradicts_the_token() {
        let claims_last_but_paginates: SearchPage =
            serde_json::from_value(json!({"issues": [], "nextPageToken": "more", "isLast": true}))
                .expect("deserializes");
        assert!(claims_last_but_paginates.is_last_disagrees());
        assert_eq!(claims_last_but_paginates.next_token(), Some("more"));

        let claims_more_but_ends: SearchPage =
            serde_json::from_value(json!({"issues": [], "isLast": false})).expect("deserializes");
        assert!(claims_more_but_ends.is_last_disagrees());
        assert_eq!(claims_more_but_ends.next_token(), None);

        let silent: SearchPage =
            serde_json::from_value(json!({"issues": [], "nextPageToken": "more"}))
                .expect("deserializes");
        assert!(
            !silent.is_last_disagrees(),
            "an absent isLast cannot disagree with anything"
        );
    }

    #[test]
    fn an_offset_paginated_body_yields_no_token() {
        // A v2 `GET /search` body. It must not accidentally paginate: every
        // signal enhanced search uses is absent from it.
        let page: SearchPage = serde_json::from_value(json!({
            "startAt": 0,
            "maxResults": 50,
            "total": 12,
            "issues": [{"id": "10042", "key": "KAN-42", "fields": {"summary": "s"}}]
        }))
        .expect("deserializes");

        assert_eq!(page.next_token(), None);
        assert_eq!(page.is_last, None);
        assert_eq!(page.issues.len(), 1);
    }

    #[test]
    fn a_raw_page_keeps_every_issue_verbatim() {
        let body = json!({
            "issues": [{"id": "10042", "key": "KAN-42",
                        "fields": {"customfield_10001": [1, 2, 3]}}],
            "nextPageToken": "more"
        });
        let page: RawSearchPage = serde_json::from_value(body.clone()).expect("deserializes");

        assert_eq!(
            page.issues,
            body["issues"].as_array().expect("array").clone()
        );
        assert_eq!(page.next_token(), Some("more"));
        assert!(!page.is_last_disagrees());
        assert_eq!(serde_json::to_value(&page).expect("serializes"), body);
    }

    #[test]
    fn a_raw_page_reports_a_contradicted_token_too() {
        let page: RawSearchPage =
            serde_json::from_value(json!({"issues": [], "nextPageToken": "", "isLast": false}))
                .expect("deserializes");

        assert_eq!(page.next_token(), None);
        assert!(page.is_last_disagrees());
    }

    #[test]
    fn a_non_numeric_id_reports_no_number_rather_than_panicking() {
        let issue: SearchIssue =
            serde_json::from_value(json!({"id": "not-a-number", "key": "KAN-1"}))
                .expect("deserializes");

        assert_eq!(issue.numeric_id(), None);
    }

    #[test]
    fn numeric_ids_order_the_way_ranking_needs_them_to() {
        let low: SearchIssue =
            serde_json::from_value(json!({"id": "9999", "key": "KAN-1"})).expect("deserializes");
        let high: SearchIssue =
            serde_json::from_value(json!({"id": "10100", "key": "KAN-2"})).expect("deserializes");

        assert!(low.id > high.id, "string order is the trap this exists for");
        assert!(low.numeric_id() < high.numeric_id());
    }

    #[test]
    fn a_status_category_id_parses_whichever_json_type_it_arrives_as() {
        for id in [json!(2), json!("2")] {
            let fields: SearchIssueFields = serde_json::from_value(json!({
                "status": {"name": "Done", "statusCategory": {"id": id, "key": "done"}}
            }))
            .expect("a status category id must not decide whether the page parses");

            assert_eq!(fields.status_category_key(), Some("done"));
        }
    }

    #[test]
    fn a_page_serializes_without_the_absent_keys() {
        let page = SearchPage::default();

        assert_eq!(
            serde_json::to_value(&page).expect("serializes"),
            json!({"issues": []})
        );
    }
}
