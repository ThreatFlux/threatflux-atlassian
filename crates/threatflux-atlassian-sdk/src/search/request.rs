//! The enhanced-search request body and its validation.

use crate::error::{bounded, AtlassianError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Page size Jira applies when a request carries no `maxResults`.
///
/// Sent only when a caller asks for a different one: [`SearchRequest`] omits
/// `maxResults` entirely rather than restating the server's own default.
pub const DEFAULT_MAX_RESULTS: u32 = 50;

/// Largest `maxResults` the enhanced-search endpoint accepts.
///
/// Doc-derived rather than observed from this repository, and pinned by a
/// canary rather than trusted: if Atlassian's ceiling differs, this constant and
/// [`SearchRequest::validate`] are the only places that change.
pub const MAX_RESULTS_CEILING: u32 = 5_000;

/// The fields [`SearchRequest::new`] asks for.
///
/// `POST /rest/api/3/search/jql` does **not** default to a useful field set: a
/// request that names no fields comes back with issue ids and nothing else. So
/// this crate names a set rather than letting the server choose one, and it is
/// the set this crate's own reconciliation reads — enough to identify an issue
/// ([`summary`](super::SearchIssueFields::summary)), see whether it is still
/// open ([`status`](super::SearchIssueFields::status)), match a dedupe label
/// ([`labels`](super::SearchIssueFields::labels)), and order two candidates by
/// recency ([`updated`](super::SearchIssueFields::updated)).
///
/// Replace it with [`SearchRequest::with_fields`]. Asking for ids alone is
/// spelled `with_fields(["id"])`, not with an empty list — see
/// [`SearchRequest::validate`].
pub const DEFAULT_FIELDS: &[&str] = &["summary", "status", "labels", "updated"];

/// The field-set expansion that asks for every field Jira has.
pub const ALL_FIELDS: &str = "*all";

/// Largest number of issue properties one request may ask for.
pub const MAX_PROPERTIES: usize = 5;

/// Largest number of issue ids `reconcileIssues` accepts.
pub const MAX_RECONCILE_ISSUES: usize = 50;

/// Longest accepted field name or property key, in characters.
const MAX_TOKEN_CHARS: usize = 255;

/// Characters of a rejected token that reach an error message.
const PREVIEW_CHARS: usize = 48;

/// Why a field name or property key was rejected.
mod reasons {
    pub(super) const BLANK: &str = "it is empty or only whitespace";
    pub(super) const COMMA: &str =
        "it carries a comma; pass one entry per name rather than a comma-separated list";
    pub(super) const CONTROL: &str = "it carries a control character";
    pub(super) const PADDED: &str = "it carries leading or trailing whitespace";
    pub(super) const TOO_LONG: &str = "it is longer than 255 characters";
}

/// Why a [`SearchRequest`] cannot be sent.
///
/// Converts into [`AtlassianError::Validation`]: a malformed request is a
/// validation failure, and the message carries everything a caller could branch
/// on that the variant does not.
///
/// Every message is bounded. A rejected name reaches it as a truncated,
/// escaped preview and never as the caller's whole string, because these
/// messages are logged as well as returned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SearchRequestError {
    /// The JQL was empty or only whitespace, which would match every issue.
    #[error("search request JQL cannot be blank")]
    BlankJql,

    /// No fields were named. See [`SearchRequest::validate`].
    #[error(
        "search request names no fields; the endpoint would return issue ids only, so ask for [\"id\"] deliberately if that is what you want"
    )]
    EmptyFields,

    /// A field name is not usable.
    #[error("fields[{index}] {preview} is not a usable field name: {reason}")]
    InvalidFieldName {
        /// Position of the offending entry in the `fields` list.
        index: usize,
        /// Bounded, escaped preview of the rejected name.
        preview: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A property key is not usable.
    #[error("properties[{index}] {preview} is not a usable property key: {reason}")]
    InvalidPropertyKey {
        /// Position of the offending entry in the `properties` list.
        index: usize,
        /// Bounded, escaped preview of the rejected key.
        preview: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// `maxResults` was zero or above the endpoint's ceiling.
    #[error("maxResults must be between 1 and {ceiling}, not {requested}")]
    MaxResultsOutOfRange {
        /// What the caller asked for.
        requested: u32,
        /// [`MAX_RESULTS_CEILING`].
        ceiling: u32,
    },

    /// A page token was present but blank, which would silently restart
    /// iteration from the first page.
    #[error("nextPageToken is present but blank; omit it to start from the first page")]
    BlankPageToken,

    /// `expand` was present but blank.
    #[error("expand is present but blank; omit it instead")]
    BlankExpand,

    /// More properties were asked for than the endpoint accepts.
    #[error("search request asks for {count} properties, over the limit of {limit}")]
    TooManyProperties {
        /// How many were asked for.
        count: usize,
        /// [`MAX_PROPERTIES`].
        limit: usize,
    },

    /// More issue ids were passed to `reconcileIssues` than it accepts.
    #[error("reconcileIssues carries {count} ids, over the limit of {limit}")]
    TooManyReconcileIssues {
        /// How many ids were passed.
        count: usize,
        /// [`MAX_RECONCILE_ISSUES`].
        limit: usize,
    },

    /// A `reconcileIssues` entry was not a positive Jira issue id.
    #[error("reconcileIssues[{index}] is {id}, which is not a positive issue id")]
    InvalidReconcileIssueId {
        /// Position of the offending entry.
        index: usize,
        /// The rejected id. Numeric, so it is bounded by its own type.
        id: i64,
    },
}

impl From<SearchRequestError> for AtlassianError {
    fn from(err: SearchRequestError) -> Self {
        Self::validation(err.to_string())
    }
}

/// The body of `POST /rest/api/3/search/jql`.
///
/// # Pagination is by token, not by offset
///
/// There is no `startAt` here and there is none in [`SearchPage`]. Enhanced
/// search hands back an opaque
/// [`nextPageToken`](super::SearchPage::next_page_token) which the next request
/// echoes into
/// [`with_next_page_token`](Self::with_next_page_token). Offset pagination is
/// not merely unsupported by this type — it is unsupported by the endpoint, and
/// a caller carrying a `startAt` counter has a bug rather than a missing
/// feature.
///
/// # Every optional is omitted rather than sent as null
///
/// Each field below carries `skip_serializing_if`, `reconcileIssues` included,
/// so a request built by [`new`](Self::new) puts exactly two keys on the wire.
/// An absent key and a null one are not the same request — a null asserts a
/// value where silence asks for the default — and this type only ever sends the
/// former.
///
/// ```
/// use threatflux_atlassian_sdk::search::SearchRequest;
/// use serde_json::json;
///
/// let request = SearchRequest::new(r#"project = "KAN" AND labels = "gh-1-2""#);
/// request.validate()?;
///
/// assert_eq!(
///     serde_json::to_value(&request)?,
///     json!({
///         "jql": r#"project = "KAN" AND labels = "gh-1-2""#,
///         "fields": ["summary", "status", "labels", "updated"]
///     })
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [`SearchPage`]: super::SearchPage
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchRequest {
    /// The query. Build it with [`JqlBuilder`](crate::jql::JqlBuilder) rather
    /// than by interpolating caller text into a format string.
    jql: String,

    /// The token from the previous page, absent on the first request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_page_token: Option<String>,

    /// Page size. Absent means [`DEFAULT_MAX_RESULTS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_results: Option<u32>,

    /// The fields to return for each issue.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,

    /// Response expansion, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expand: Option<String>,

    /// Issue property keys to return alongside the fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    properties: Vec<String>,

    /// Whether `fields` names field keys rather than field ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fields_by_keys: Option<bool>,

    /// Whether Jira should fail the request on the first field error rather
    /// than returning partial issues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fail_fast: Option<bool>,

    /// Issue ids whose index entries Jira must reconcile before answering.
    ///
    /// This forces index consistency **for the ids passed and only those**. The
    /// one id available after a create is your own, so it converts "my own new
    /// issue is not in the index yet" into "it is" and does nothing whatever
    /// for an issue somebody else created a moment earlier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reconcile_issues: Vec<i64>,
}

impl SearchRequest {
    /// A request for `jql` over [`DEFAULT_FIELDS`].
    pub fn new(jql: impl Into<String>) -> Self {
        Self {
            jql: jql.into(),
            next_page_token: None,
            max_results: None,
            fields: DEFAULT_FIELDS.iter().copied().map(String::from).collect(),
            expand: None,
            properties: Vec::new(),
            fields_by_keys: None,
            fail_fast: None,
            reconcile_issues: Vec::new(),
        }
    }

    /// Replaces the requested fields.
    #[must_use]
    pub fn with_fields<I, S>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.fields = fields.into_iter().map(Into::into).collect();
        self
    }

    /// Asks for every field ([`ALL_FIELDS`]).
    ///
    /// Convenient and expensive: a page of `*all` issues carries every custom
    /// field the instance defines, which is what
    /// [`SearchIssueFields::other`](super::SearchIssueFields::other) is for.
    #[must_use]
    pub fn with_all_fields(self) -> Self {
        self.with_fields([ALL_FIELDS])
    }

    /// Sets the page size. Validated against [`MAX_RESULTS_CEILING`].
    #[must_use]
    pub const fn with_max_results(mut self, max_results: u32) -> Self {
        self.max_results = Some(max_results);
        self
    }

    /// Sets the token that asks for the page after the one it came from.
    #[must_use]
    pub fn with_next_page_token(mut self, token: impl Into<String>) -> Self {
        self.next_page_token = Some(token.into());
        self
    }

    /// Sets or clears the page token in place.
    ///
    /// The in-place form exists for a cursor, which holds one request and walks
    /// it forward a page at a time rather than rebuilding it.
    pub fn set_next_page_token(&mut self, token: Option<String>) {
        self.next_page_token = token;
    }

    /// Sets the `expand` parameter.
    #[must_use]
    pub fn with_expand(mut self, expand: impl Into<String>) -> Self {
        self.expand = Some(expand.into());
        self
    }

    /// Replaces the requested issue property keys.
    #[must_use]
    pub fn with_properties<I, S>(mut self, properties: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.properties = properties.into_iter().map(Into::into).collect();
        self
    }

    /// Declares that [`fields`](Self::fields) names field keys, not ids.
    #[must_use]
    pub const fn with_fields_by_keys(mut self, fields_by_keys: bool) -> Self {
        self.fields_by_keys = Some(fields_by_keys);
        self
    }

    /// Asks Jira to fail rather than return issues with unreadable fields.
    #[must_use]
    pub const fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = Some(fail_fast);
        self
    }

    /// Replaces the ids Jira must reconcile before answering.
    ///
    /// See the field documentation for what this does and does not guarantee.
    #[must_use]
    pub fn with_reconcile_issues<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = i64>,
    {
        self.reconcile_issues = ids.into_iter().collect();
        self
    }

    /// The query this request carries.
    pub fn jql(&self) -> &str {
        &self.jql
    }

    /// The fields this request asks for.
    pub fn fields(&self) -> &[String] {
        &self.fields
    }

    /// The page size, when one was set.
    pub const fn max_results(&self) -> Option<u32> {
        self.max_results
    }

    /// The page token, when this request asks for a page after the first.
    ///
    /// A caller classifying a failure needs this: a rejection of a request that
    /// carried a Jira-issued token is a different fault from a rejection of the
    /// first page, and only the first page's rejection means the JQL is wrong.
    pub fn next_page_token(&self) -> Option<&str> {
        self.next_page_token.as_deref()
    }

    /// The `expand` parameter, when one was set.
    pub fn expand(&self) -> Option<&str> {
        self.expand.as_deref()
    }

    /// The issue property keys this request asks for.
    pub fn properties(&self) -> &[String] {
        &self.properties
    }

    /// Whether `fields` was declared to name field keys.
    pub const fn fields_by_keys(&self) -> Option<bool> {
        self.fields_by_keys
    }

    /// Whether Jira was asked to fail fast on a field error.
    pub const fn fail_fast(&self) -> Option<bool> {
        self.fail_fast
    }

    /// The ids Jira is asked to reconcile before answering.
    pub fn reconcile_issues(&self) -> &[i64] {
        &self.reconcile_issues
    }

    /// Checks everything that can be checked without asking Jira.
    ///
    /// The two rules worth stating outright, because neither is obvious from
    /// the endpoint:
    ///
    /// - **An empty `fields` list is rejected.** Sending no fields is legal and
    ///   returns issue ids only, so an empty list is far likelier to be a
    ///   caller who meant "all of them" than one who meant "none of them". A
    ///   caller who does mean ids only says so with `with_fields(["id"])`.
    /// - **A blank `nextPageToken` is rejected.** Jira treats it as absent and
    ///   answers with the first page, so a cursor that lost its token would
    ///   loop over page one forever rather than fail.
    ///
    /// # Errors
    ///
    /// [`SearchRequestError`], one variant per rule above.
    pub fn validate(&self) -> Result<(), SearchRequestError> {
        if self.jql.trim().is_empty() {
            return Err(SearchRequestError::BlankJql);
        }

        if self.fields.is_empty() {
            return Err(SearchRequestError::EmptyFields);
        }

        for (index, field) in self.fields.iter().enumerate() {
            if let Some(reason) = token_problem(field) {
                return Err(SearchRequestError::InvalidFieldName {
                    index,
                    preview: preview(field),
                    reason,
                });
            }
        }

        if let Some(max_results) = self.max_results {
            if max_results == 0 || max_results > MAX_RESULTS_CEILING {
                return Err(SearchRequestError::MaxResultsOutOfRange {
                    requested: max_results,
                    ceiling: MAX_RESULTS_CEILING,
                });
            }
        }

        if self
            .next_page_token
            .as_ref()
            .is_some_and(|token| token.trim().is_empty())
        {
            return Err(SearchRequestError::BlankPageToken);
        }

        if self
            .expand
            .as_ref()
            .is_some_and(|expand| expand.trim().is_empty())
        {
            return Err(SearchRequestError::BlankExpand);
        }

        if self.properties.len() > MAX_PROPERTIES {
            return Err(SearchRequestError::TooManyProperties {
                count: self.properties.len(),
                limit: MAX_PROPERTIES,
            });
        }

        for (index, property) in self.properties.iter().enumerate() {
            if let Some(reason) = token_problem(property) {
                return Err(SearchRequestError::InvalidPropertyKey {
                    index,
                    preview: preview(property),
                    reason,
                });
            }
        }

        if self.reconcile_issues.len() > MAX_RECONCILE_ISSUES {
            return Err(SearchRequestError::TooManyReconcileIssues {
                count: self.reconcile_issues.len(),
                limit: MAX_RECONCILE_ISSUES,
            });
        }

        for (index, id) in self.reconcile_issues.iter().enumerate() {
            if *id <= 0 {
                return Err(SearchRequestError::InvalidReconcileIssueId { index, id: *id });
            }
        }

        Ok(())
    }
}

/// Why `token` cannot be sent as a field name or property key, if it cannot.
fn token_problem(token: &str) -> Option<&'static str> {
    if token.trim().is_empty() {
        return Some(reasons::BLANK);
    }
    if token.contains(',') {
        return Some(reasons::COMMA);
    }
    if token.chars().any(char::is_control) {
        return Some(reasons::CONTROL);
    }
    if token.trim() != token {
        return Some(reasons::PADDED);
    }
    if token.chars().count() > MAX_TOKEN_CHARS {
        return Some(reasons::TOO_LONG);
    }
    None
}

/// A bounded, escaped preview of a rejected token.
fn preview(value: &str) -> String {
    let truncated = bounded(value, PREVIEW_CHARS);
    if truncated.len() == value.len() {
        format!("{truncated:?}")
    } else {
        format!("{truncated:?} (truncated)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// The keys of a serialized request, in `serde_json::Map`'s own order.
    fn keys(value: &Value) -> Vec<String> {
        value
            .as_object()
            .expect("a request serializes to an object")
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn a_new_request_sends_only_the_jql_and_the_default_fields() {
        let request = SearchRequest::new("project = \"KAN\"");
        request.validate().expect("the default request is valid");

        assert_eq!(
            serde_json::to_value(&request).expect("serializes"),
            json!({
                "jql": "project = \"KAN\"",
                "fields": ["summary", "status", "labels", "updated"]
            })
        );
    }

    #[test]
    fn every_optional_is_omitted_rather_than_sent_as_null() {
        let request = SearchRequest::new("project = \"KAN\"");
        let body = serde_json::to_value(&request).expect("serializes");

        assert_eq!(keys(&body), vec!["fields".to_string(), "jql".to_string()]);
        for absent in [
            "nextPageToken",
            "maxResults",
            "expand",
            "properties",
            "fieldsByKeys",
            "failFast",
            "reconcileIssues",
        ] {
            assert!(body.get(absent).is_none(), "{absent} should be omitted");
        }
    }

    #[test]
    fn reconcile_issues_is_omitted_when_empty_and_sent_when_set() {
        let empty = SearchRequest::new("project = \"KAN\"").with_reconcile_issues([]);
        assert!(serde_json::to_value(&empty)
            .expect("serializes")
            .get("reconcileIssues")
            .is_none());

        let populated = SearchRequest::new("project = \"KAN\"").with_reconcile_issues([10_042]);
        assert_eq!(
            serde_json::to_value(&populated)
                .expect("serializes")
                .get("reconcileIssues"),
            Some(&json!([10_042]))
        );
    }

    #[test]
    fn the_wire_names_are_jiras_own() {
        let request = SearchRequest::new("project = \"KAN\"")
            .with_next_page_token("token-1")
            .with_max_results(25)
            .with_fields(["id"])
            .with_expand("names")
            .with_properties(["threatflux.reconcile"])
            .with_fields_by_keys(true)
            .with_fail_fast(false)
            .with_reconcile_issues([10_042, 10_043]);
        request
            .validate()
            .expect("a fully populated request is valid");

        assert_eq!(
            serde_json::to_value(&request).expect("serializes"),
            json!({
                "jql": "project = \"KAN\"",
                "nextPageToken": "token-1",
                "maxResults": 25,
                "fields": ["id"],
                "expand": "names",
                "properties": ["threatflux.reconcile"],
                "fieldsByKeys": true,
                "failFast": false,
                "reconcileIssues": [10_042, 10_043]
            })
        );
    }

    #[test]
    fn a_request_round_trips_through_json() {
        let request = SearchRequest::new("project = \"KAN\"")
            .with_max_results(10)
            .with_properties(["a"])
            .with_reconcile_issues([7]);
        let json = serde_json::to_string(&request).expect("serializes");

        assert_eq!(
            serde_json::from_str::<SearchRequest>(&json).expect("deserializes"),
            request
        );
    }

    #[test]
    fn there_is_no_start_at_on_the_wire_or_in_the_type() {
        let rejected = serde_json::from_value::<SearchRequest>(json!({
            "jql": "project = \"KAN\"",
            "startAt": 0
        }));

        assert!(
            rejected.is_err(),
            "offset pagination is not part of enhanced search and must not deserialize"
        );
    }

    #[test]
    fn the_page_token_is_readable_for_failure_classification() {
        let first = SearchRequest::new("project = \"KAN\"");
        assert_eq!(first.next_page_token(), None);

        let later = first.with_next_page_token("token-2");
        assert_eq!(later.next_page_token(), Some("token-2"));

        let mut cursor_request = later;
        cursor_request.set_next_page_token(None);
        assert_eq!(cursor_request.next_page_token(), None);
    }

    #[test]
    fn a_blank_jql_is_rejected() {
        assert_eq!(
            SearchRequest::new("   \t ").validate(),
            Err(SearchRequestError::BlankJql)
        );
    }

    #[test]
    fn an_empty_field_list_is_rejected_because_the_server_default_is_ids_only() {
        let empty = SearchRequest::new("project = \"KAN\"").with_fields(Vec::<String>::new());

        assert_eq!(empty.validate(), Err(SearchRequestError::EmptyFields));
        assert!(SearchRequest::new("project = \"KAN\"")
            .with_fields(["id"])
            .validate()
            .is_ok());
    }

    #[test]
    fn an_unusable_field_name_is_rejected_by_position_and_reason() {
        let cases = [
            ("", reasons::BLANK),
            ("   ", reasons::BLANK),
            ("summary,status", reasons::COMMA),
            ("sum\nmary", reasons::CONTROL),
            (" summary", reasons::PADDED),
        ];

        for (name, reason) in cases {
            let request = SearchRequest::new("project = \"KAN\"").with_fields(["summary", name]);
            assert_eq!(
                request.validate(),
                Err(SearchRequestError::InvalidFieldName {
                    index: 1,
                    preview: preview(name),
                    reason,
                }),
                "field name {name:?} should be rejected"
            );
        }
    }

    #[test]
    fn an_over_long_field_name_is_rejected() {
        let long = "f".repeat(MAX_TOKEN_CHARS + 1);
        let request = SearchRequest::new("project = \"KAN\"").with_fields([long.clone()]);

        assert_eq!(
            request.validate(),
            Err(SearchRequestError::InvalidFieldName {
                index: 0,
                preview: preview(&long),
                reason: reasons::TOO_LONG,
            })
        );
        assert!(SearchRequest::new("project = \"KAN\"")
            .with_fields(["f".repeat(MAX_TOKEN_CHARS)])
            .validate()
            .is_ok());
    }

    #[test]
    fn a_rejected_name_reaches_the_message_bounded_and_escaped() {
        let hostile = "x".repeat(4096);
        let request =
            SearchRequest::new("project = \"KAN\"").with_fields([format!("{hostile},{hostile}")]);
        let message = request
            .validate()
            .expect_err("a comma-bearing name is rejected")
            .to_string();

        assert!(
            message.len() < 200,
            "an error message must not carry an unbounded caller value: {} chars",
            message.len()
        );
        assert!(message.contains("(truncated)"), "message was {message}");
    }

    #[test]
    fn max_results_is_bounded_at_both_ends() {
        let zero = SearchRequest::new("project = \"KAN\"").with_max_results(0);
        assert_eq!(
            zero.validate(),
            Err(SearchRequestError::MaxResultsOutOfRange {
                requested: 0,
                ceiling: MAX_RESULTS_CEILING,
            })
        );

        let over =
            SearchRequest::new("project = \"KAN\"").with_max_results(MAX_RESULTS_CEILING + 1);
        assert_eq!(
            over.validate(),
            Err(SearchRequestError::MaxResultsOutOfRange {
                requested: MAX_RESULTS_CEILING + 1,
                ceiling: MAX_RESULTS_CEILING,
            })
        );

        assert!(SearchRequest::new("project = \"KAN\"")
            .with_max_results(MAX_RESULTS_CEILING)
            .validate()
            .is_ok());
        assert!(SearchRequest::new("project = \"KAN\"")
            .with_max_results(1)
            .validate()
            .is_ok());
    }

    #[test]
    fn a_blank_page_token_is_rejected_rather_than_silently_restarting() {
        assert_eq!(
            SearchRequest::new("project = \"KAN\"")
                .with_next_page_token("  ")
                .validate(),
            Err(SearchRequestError::BlankPageToken)
        );
    }

    #[test]
    fn a_blank_expand_is_rejected() {
        assert_eq!(
            SearchRequest::new("project = \"KAN\"")
                .with_expand(" ")
                .validate(),
            Err(SearchRequestError::BlankExpand)
        );
    }

    #[test]
    fn the_property_list_is_bounded_and_its_keys_are_checked() {
        let too_many =
            SearchRequest::new("project = \"KAN\"").with_properties(["a", "b", "c", "d", "e", "f"]);
        assert_eq!(
            too_many.validate(),
            Err(SearchRequestError::TooManyProperties {
                count: 6,
                limit: MAX_PROPERTIES,
            })
        );

        let blank = SearchRequest::new("project = \"KAN\"").with_properties(["ok", ""]);
        assert_eq!(
            blank.validate(),
            Err(SearchRequestError::InvalidPropertyKey {
                index: 1,
                preview: preview(""),
                reason: reasons::BLANK,
            })
        );
    }

    #[test]
    fn reconcile_issues_is_bounded_and_its_ids_are_checked() {
        let ids: Vec<i64> = (1..=i64::try_from(MAX_RECONCILE_ISSUES).expect("fits") + 1).collect();
        let too_many = SearchRequest::new("project = \"KAN\"").with_reconcile_issues(ids);
        assert_eq!(
            too_many.validate(),
            Err(SearchRequestError::TooManyReconcileIssues {
                count: MAX_RECONCILE_ISSUES + 1,
                limit: MAX_RECONCILE_ISSUES,
            })
        );

        let negative = SearchRequest::new("project = \"KAN\"").with_reconcile_issues([10_042, 0]);
        assert_eq!(
            negative.validate(),
            Err(SearchRequestError::InvalidReconcileIssueId { index: 1, id: 0 })
        );
    }

    #[test]
    fn all_fields_asks_for_the_expansion_rather_than_an_empty_list() {
        let request = SearchRequest::new("project = \"KAN\"").with_all_fields();

        assert_eq!(request.fields(), ["*all".to_string()]);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn a_rejection_converts_into_a_validation_error() {
        let err = AtlassianError::from(SearchRequestError::BlankJql);

        assert!(
            matches!(err, AtlassianError::Validation { ref message } if message.contains("blank")),
            "unexpected error {err:?}"
        );
    }

    #[test]
    fn the_getters_report_what_was_set() {
        let request = SearchRequest::new("project = \"KAN\"")
            .with_fields(["summary"])
            .with_max_results(7)
            .with_expand("names")
            .with_properties(["p"])
            .with_fields_by_keys(false)
            .with_fail_fast(true)
            .with_reconcile_issues([3]);

        assert_eq!(request.jql(), "project = \"KAN\"");
        assert_eq!(request.fields(), ["summary".to_string()]);
        assert_eq!(request.max_results(), Some(7));
        assert_eq!(request.expand(), Some("names"));
        assert_eq!(request.properties(), ["p".to_string()]);
        assert_eq!(request.fields_by_keys(), Some(false));
        assert_eq!(request.fail_fast(), Some(true));
        assert_eq!(request.reconcile_issues(), [3]);
    }
}
