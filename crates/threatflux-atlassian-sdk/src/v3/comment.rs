//! The v3 comment model, in both directions.
//!
//! A comment body is a [`RichText`] on the way out **and** on the way in. The
//! write side is obvious -- v3 carries a body as ADF and a bare string is
//! rejected. The read side is the one worth spelling out: a Jira project that
//! predates this crate holds comments whose bodies were written through v2 and
//! are still stored as strings, and Jira answers a v3 read of such a comment
//! with the string it has. A reader typed `String` fails on today's ADF
//! comments; a reader typed [`AdfDocument`](crate::adf::AdfDocument) fails on
//! yesterday's string ones. `RichText` reads both, which is the whole reason
//! this crate has a v3 comment reader at all rather than reusing the surviving
//! v2 [`get_issue_comments`](crate::AtlassianClient::get_issue_comments).
//!
//! # Pagination here is the mirror image of enhanced search
//!
//! `GET /rest/api/3/issue/{key}/comment` is offset-paginated: `startAt`,
//! `maxResults`, `total`. It has no page token, which inverts one of the
//! [`search`](crate::search) module's rules. There, an empty page with a token
//! **continues** iteration. Here, an empty page **ends** it -- there is no token
//! to advance, so re-requesting the same offset would spin forever. See
//! [`V3CommentPage::next_start_at`], which is the one place that rule is
//! written down.

use std::collections::{BTreeMap, HashMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::model::V3User;
use crate::adf::{AdfDocument, RichText};
use crate::error::{AtlassianError, Result};

/// What [`V3AddCommentRequest::into_wire`] fails with on an empty body.
///
/// Jira answers an empty comment body with a 400, so refusing it locally costs
/// the caller a round trip rather than a rejection. The message names the rule
/// and never the body, which is rendered from caller data.
const EMPTY_BODY: &str = "a v3 comment body cannot be empty; a caller that means \
                          'post nothing' posts nothing";

/// A comment as `GET`/`POST /rest/api/3/issue/{key}/comment` returns it.
///
/// [`id`](Self::id) is required because Jira returns it on every comment it
/// serves and it is the only handle a later call can address the comment by.
/// Everything else is optional, and anything this crate does not model lands in
/// [`other`](Self::other) rather than being dropped -- comment properties,
/// `visibility`, `jsdPublic`, and whatever Atlassian adds next.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3Comment {
    /// Numeric comment id, as a string.
    pub id: String,
    /// API URL of the comment.
    #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
    pub self_url: Option<String>,
    /// The comment body.
    ///
    /// Normally [`RichText::Adf`]. A comment last written through v2 still
    /// answers with a bare string, which reads back as [`RichText::Text`];
    /// anything else survives as [`RichText::Unknown`] rather than failing the
    /// whole page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<RichText>,
    /// Who wrote the comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<V3User>,
    /// Who last edited the comment.
    #[serde(
        rename = "updateAuthor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub update_author: Option<V3User>,
    /// Creation timestamp, ISO 8601.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Last-edited timestamp, ISO 8601.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    /// Every member this crate does not model, preserved verbatim.
    ///
    /// A [`BTreeMap`] rather than a [`HashMap`] so that re-serializing a comment
    /// read from Jira is byte-stable, which is what makes a golden snapshot of a
    /// response worth asserting on.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// One page of `GET /rest/api/3/issue/{key}/comment`.
///
/// Offset pagination, so unlike [`SearchPage`](crate::search::SearchPage) there
/// is a `total` and there is no page token. Advance with
/// [`next_start_at`](Self::next_start_at) rather than by adding
/// `maxResults` to the previous offset: Jira may return fewer comments than were
/// asked for, and an offset computed from the request rather than from the
/// response then skips the difference.
///
/// ```
/// use threatflux_atlassian_sdk::v3::V3CommentPage;
///
/// let page: V3CommentPage = serde_json::from_str(
///     r#"{"comments":[{"id":"1"},{"id":"2"}],"startAt":0,"maxResults":2,"total":5}"#,
/// )?;
///
/// assert_eq!(page.next_start_at(), Some(2));
/// assert!(!page.total_disagrees());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct V3CommentPage {
    /// The comments on this page, in the order Jira returned them.
    #[serde(default)]
    pub comments: Vec<V3Comment>,
    /// The offset this page starts at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_at: Option<u64>,
    /// The page size Jira actually applied, which can be smaller than the one
    /// requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u64>,
    /// How many comments the issue has in total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

impl V3CommentPage {
    /// The offset of the next page, or `None` when iteration is over.
    ///
    /// Three termination rules, in force in this order:
    ///
    /// 1. **An empty page ends the iteration.** This is the opposite of the
    ///    enhanced-search rule, and the difference is structural rather than a
    ///    matter of taste: search advances by an opaque token that Jira hands
    ///    back even on an empty page, whereas this endpoint advances by an
    ///    offset that only the returned comments can move. Continuing on an
    ///    empty page would re-request the same offset forever.
    /// 2. **`total` stops it.** Once `startAt` plus the comments read reaches
    ///    `total`, there is nothing after this page.
    /// 3. **Without a `total`, iteration runs until a page comes back empty.**
    ///    That costs exactly one extra request and cannot loop.
    ///
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::v3::V3GetCommentsOptions;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let mut options = V3GetCommentsOptions::new();
    /// let mut all = Vec::new();
    /// loop {
    ///     let page = client.v3().get_comments("KAN-77", &options).await.unwrap();
    ///     let next = page.next_start_at();
    ///     all.extend(page.comments);
    ///     match next {
    ///         Some(start_at) => options = options.with_start_at(start_at),
    ///         None => break,
    ///     }
    /// }
    /// # });
    /// ```
    pub fn next_start_at(&self) -> Option<u64> {
        if self.comments.is_empty() {
            return None;
        }

        let consumed = self.consumed();
        match self.total {
            Some(total) if consumed >= total => None,
            _ => Some(consumed),
        }
    }

    /// Whether another page is expected after this one.
    pub fn has_more(&self) -> bool {
        self.next_start_at().is_some()
    }

    /// Whether `total` contradicts the comments on this page.
    ///
    /// True when Jira claims more comments than it has served yet answers this
    /// offset with none, or when it serves past its own declared total. Worth
    /// logging, never worth acting on: [`next_start_at`](Self::next_start_at)
    /// terminates either way, because a wrong answer that ends is better than a
    /// right answer that never does.
    pub fn total_disagrees(&self) -> bool {
        let Some(total) = self.total else {
            return false;
        };

        (self.comments.is_empty() && self.start_at.unwrap_or(0) < total) || self.consumed() > total
    }

    /// How many comments have been read once this page is consumed.
    fn consumed(&self) -> u64 {
        self.start_at
            .unwrap_or(0)
            .saturating_add(u64::try_from(self.comments.len()).unwrap_or(u64::MAX))
    }
}

/// The order `GET /rest/api/3/issue/{key}/comment` returns comments in.
///
/// Typed rather than a free string because `orderBy` is the one query parameter
/// of this endpoint that Jira validates against a closed set, and a caller who
/// misspells it gets a 400 rather than a default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum V3CommentOrder {
    /// Oldest first. Jira's own default, and what a marker scan wants: the
    /// first matching comment is then the original rather than the latest edit.
    #[default]
    Created,
    /// Newest first.
    CreatedDescending,
}

impl V3CommentOrder {
    /// The `orderBy` value Jira expects.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::CreatedDescending => "-created",
        }
    }
}

/// What a comment read may narrow or expand.
///
/// The default asks for nothing at all, which is Jira's own default: the first
/// page at Jira's page size, oldest first, no expansions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct V3GetCommentsOptions {
    /// Offset of the first comment to return.
    pub start_at: Option<u64>,
    /// Most comments to return on one page. Jira caps this at its own maximum.
    pub max_results: Option<u32>,
    /// The order to return comments in.
    pub order_by: Option<V3CommentOrder>,
    /// `expand` values, such as `renderedBody`.
    pub expand: Vec<String>,
}

impl V3GetCommentsOptions {
    /// Options that narrow nothing and expand nothing.
    pub const fn new() -> Self {
        Self {
            start_at: None,
            max_results: None,
            order_by: None,
            expand: Vec::new(),
        }
    }

    /// Reads from this offset.
    #[must_use]
    pub const fn with_start_at(mut self, start_at: u64) -> Self {
        self.start_at = Some(start_at);
        self
    }

    /// Asks for at most this many comments per page.
    #[must_use]
    pub const fn with_max_results(mut self, max_results: u32) -> Self {
        self.max_results = Some(max_results);
        self
    }

    /// Asks for this order.
    #[must_use]
    pub const fn with_order(mut self, order_by: V3CommentOrder) -> Self {
        self.order_by = Some(order_by);
        self
    }

    /// Requests these expansions, replacing any already requested.
    #[must_use]
    pub fn with_expand(mut self, expand: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.expand = expand.into_iter().map(Into::into).collect();
        self
    }

    /// The query parameters these options describe.
    ///
    /// An unset option contributes no parameter at all, so a default read is
    /// byte-identical on the wire to one that never mentioned options.
    pub(crate) fn query(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(start_at) = self.start_at {
            params.insert("startAt".to_string(), start_at.to_string());
        }
        if let Some(max_results) = self.max_results {
            params.insert("maxResults".to_string(), max_results.to_string());
        }
        if let Some(order_by) = self.order_by {
            params.insert("orderBy".to_string(), order_by.as_str().to_string());
        }
        if !self.expand.is_empty() {
            params.insert("expand".to_string(), self.expand.join(","));
        }
        params
    }
}

/// A `POST /rest/api/3/issue/{key}/comment` request.
///
/// A struct rather than a bare body argument so that a member Atlassian adds
/// later -- comment properties, a visibility restriction -- is an additive
/// change instead of a new method. Build one from anything a
/// [`RichText`] is built from:
///
/// ```
/// use threatflux_atlassian_sdk::adf::{AdfBlock, AdfDocument};
/// use threatflux_atlassian_sdk::v3::V3AddCommentRequest;
///
/// let from_text = V3AddCommentRequest::new("see the advisory");
/// let from_adf = V3AddCommentRequest::new(AdfDocument::new([AdfBlock::paragraph_text("built")]));
/// let from_str: V3AddCommentRequest = "see the advisory".into();
///
/// assert_eq!(from_text, from_str);
/// assert_ne!(from_text, from_adf);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3AddCommentRequest {
    /// The comment body.
    ///
    /// Held as a [`RichText`] and normalized to ADF on the way out, so a caller
    /// may pass a `&str` and still never send a plain string to a v3 endpoint.
    pub body: RichText,
}

impl V3AddCommentRequest {
    /// A comment carrying `body`.
    pub fn new(body: impl Into<RichText>) -> Self {
        Self { body: body.into() }
    }

    /// Normalizes the body into the one v3 wire form.
    ///
    /// A [`RichText::Text`] body is upgraded to ADF, a [`RichText::Adf`] one is
    /// validated, and a [`RichText::Unknown`] one is refused -- see
    /// [`RichText::into_wire`]. An empty document is refused too: Jira answers
    /// one with a 400, and a write that cannot succeed should not consume a
    /// round trip.
    pub(crate) fn into_wire(self) -> Result<Self> {
        let body = self.body.into_wire()?;
        if body.is_empty() {
            return Err(AtlassianError::validation(EMPTY_BODY));
        }

        Ok(Self {
            body: RichText::Adf(body),
        })
    }
}

impl From<RichText> for V3AddCommentRequest {
    fn from(body: RichText) -> Self {
        Self { body }
    }
}

impl From<AdfDocument> for V3AddCommentRequest {
    fn from(body: AdfDocument) -> Self {
        Self::new(body)
    }
}

impl From<String> for V3AddCommentRequest {
    fn from(body: String) -> Self {
        Self::new(body)
    }
}

impl From<&str> for V3AddCommentRequest {
    fn from(body: &str) -> Self {
        Self::new(body)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        V3AddCommentRequest, V3Comment, V3CommentOrder, V3CommentPage, V3GetCommentsOptions,
    };
    use crate::adf::{AdfBlock, AdfDocument, RichText};
    use crate::error::AtlassianError;
    use serde_json::json;

    fn page(comments: usize, start_at: Option<u64>, total: Option<u64>) -> V3CommentPage {
        V3CommentPage {
            comments: (0..comments)
                .map(|index| V3Comment {
                    id: index.to_string(),
                    ..V3Comment::default()
                })
                .collect(),
            start_at,
            max_results: None,
            total,
        }
    }

    #[test]
    fn a_v2_era_string_body_reads_back_as_text() {
        // The compatibility case that justifies a v3 comment reader existing at
        // all: a comment written years ago through v2 is stored as a string, and
        // reading it through a `String`-typed model would fail on today's ADF
        // comments while an ADF-typed one fails on this.
        let comment: V3Comment = serde_json::from_value(json!({
            "id": "10100",
            "body": "written through v2"
        }))
        .expect("parses");

        assert_eq!(
            comment.body,
            Some(RichText::Text("written through v2".to_string()))
        );
    }

    #[test]
    fn an_adf_body_reads_back_as_adf() {
        let comment: V3Comment = serde_json::from_value(json!({
            "id": "10100",
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": "hi"}]}]
            }
        }))
        .expect("parses");

        assert!(matches!(comment.body, Some(RichText::Adf(_))));
    }

    #[test]
    fn an_unmodelled_body_shape_survives_instead_of_failing_the_page() {
        let comment: V3Comment =
            serde_json::from_value(json!({"id": "10100", "body": {"type": "richTextV4"}}))
                .expect("parses");

        assert!(comment.body.expect("a body").is_unknown());
    }

    #[test]
    fn unmodelled_members_survive_a_round_trip() {
        let raw = json!({
            "id": "10100",
            "self": "https://example.atlassian.net/rest/api/3/issue/10077/comment/10100",
            "body": "hi",
            "author": {"accountId": "account-123"},
            "updateAuthor": {"accountId": "account-456"},
            "created": "2026-01-01T00:00:00.000+0000",
            "updated": "2026-01-02T00:00:00.000+0000",
            "visibility": {"type": "role", "value": "Administrators"},
            "jsdPublic": true
        });

        let comment: V3Comment = serde_json::from_value(raw.clone()).expect("parses");
        assert_eq!(
            comment.other.get("visibility"),
            Some(&json!({"type": "role", "value": "Administrators"}))
        );
        assert_eq!(
            serde_json::to_value(&comment).expect("serializes"),
            raw,
            "a member this crate does not model was dropped or rewritten"
        );
    }

    #[test]
    fn a_comment_with_only_an_id_parses() {
        let comment: V3Comment = serde_json::from_value(json!({"id": "10100"})).expect("parses");
        assert_eq!(comment.id, "10100");
        assert!(comment.body.is_none());
    }

    #[test]
    fn an_empty_page_ends_the_iteration_rather_than_repeating_the_offset() {
        // The mirror image of the enhanced-search rule. There, an empty page
        // with a token continues; here there is no token, so the only thing that
        // could move the offset is the comments, and there are none. Continuing
        // would re-request this exact offset forever.
        assert_eq!(page(0, Some(0), Some(5)).next_start_at(), None);
        assert_eq!(page(0, None, None).next_start_at(), None);
        assert!(!page(0, Some(0), Some(5)).has_more());
    }

    #[test]
    fn the_offset_advances_by_what_was_returned_not_by_what_was_asked_for() {
        // Jira may serve fewer comments than `maxResults`. An offset computed
        // from the request would then skip the difference silently.
        let short = V3CommentPage {
            max_results: Some(50),
            ..page(2, Some(10), Some(100))
        };
        assert_eq!(short.next_start_at(), Some(12));
    }

    #[test]
    fn the_total_stops_the_iteration() {
        assert_eq!(page(2, Some(3), Some(5)).next_start_at(), None);
        assert_eq!(page(2, Some(2), Some(5)).next_start_at(), Some(4));
    }

    #[test]
    fn a_page_with_no_total_runs_until_a_page_comes_back_empty() {
        let first = page(2, Some(0), None);
        assert_eq!(first.next_start_at(), Some(2));
        assert_eq!(page(0, Some(2), None).next_start_at(), None);
    }

    #[test]
    fn a_disagreeing_total_is_reported_and_still_terminates() {
        // Jira says five comments exist and serves none at offset zero.
        let starved = page(0, Some(0), Some(5));
        assert!(starved.total_disagrees());
        assert_eq!(
            starved.next_start_at(),
            None,
            "a wrong answer that ends beats a right answer that never does"
        );

        // ... and the other direction: more served than declared.
        let overflowing = page(3, Some(4), Some(5));
        assert!(overflowing.total_disagrees());

        assert!(!page(2, Some(0), Some(5)).total_disagrees());
        assert!(!page(0, Some(5), Some(5)).total_disagrees());
        assert!(!page(2, Some(0), None).total_disagrees());
    }

    #[test]
    fn a_page_missing_every_optional_member_parses() {
        let page: V3CommentPage = serde_json::from_value(json!({})).expect("parses");
        assert_eq!(page, V3CommentPage::default());
        assert!(!page.has_more());
    }

    #[test]
    fn default_read_options_ask_for_nothing() {
        assert!(V3GetCommentsOptions::new().query().is_empty());
        assert_eq!(V3GetCommentsOptions::default(), V3GetCommentsOptions::new());
    }

    #[test]
    fn read_options_render_every_parameter_jira_names() {
        let query = V3GetCommentsOptions::new()
            .with_start_at(25)
            .with_max_results(50)
            .with_order(V3CommentOrder::CreatedDescending)
            .with_expand(["renderedBody"])
            .query();

        assert_eq!(query.get("startAt").map(String::as_str), Some("25"));
        assert_eq!(query.get("maxResults").map(String::as_str), Some("50"));
        assert_eq!(query.get("orderBy").map(String::as_str), Some("-created"));
        assert_eq!(
            query.get("expand").map(String::as_str),
            Some("renderedBody")
        );
    }

    #[test]
    fn the_default_order_is_oldest_first() {
        assert_eq!(V3CommentOrder::default(), V3CommentOrder::Created);
        assert_eq!(V3CommentOrder::Created.as_str(), "created");
        assert_eq!(V3CommentOrder::CreatedDescending.as_str(), "-created");
    }

    #[test]
    fn a_plain_text_body_becomes_adf_on_the_wire() {
        let request = V3AddCommentRequest::new("first line\nsecond line")
            .into_wire()
            .expect("plain text is always writable");

        assert_eq!(
            serde_json::to_value(&request).expect("serializes"),
            json!({"body": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "first line"},
                        {"type": "hardBreak"},
                        {"type": "text", "text": "second line"}
                    ]
                }]
            }}),
            "a v3 comment must never carry a bare string body"
        );
    }

    #[test]
    fn an_unwritable_body_is_refused_before_a_body_exists() {
        let body: RichText = serde_json::from_value(json!({"type": "richTextV4"})).expect("parses");
        let error = V3AddCommentRequest::new(body)
            .into_wire()
            .expect_err("an `Unknown` body must not be writable");

        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );
    }

    #[test]
    fn an_empty_body_is_refused() {
        // Only text that upgrades to *no* blocks at all. A whitespace-only line
        // is content -- see the test below.
        for empty in ["", "\n", "\n\n\n", "\r\n\r\n"] {
            let error = V3AddCommentRequest::new(empty)
                .into_wire()
                .expect_err("an empty comment must not be sent");
            assert!(
                matches!(error, AtlassianError::Validation { .. }),
                "{empty:?} produced {error:?}"
            );
        }

        let error = V3AddCommentRequest::new(AdfDocument::empty())
            .into_wire()
            .expect_err("an empty document must not be sent");
        assert!(matches!(error, AtlassianError::Validation { .. }));
    }

    #[test]
    fn a_whitespace_only_line_is_content_and_is_not_refused() {
        // `"   "` is not empty text: it upgrades to a paragraph holding one
        // `text` node, so the emptiness gate must not swallow it.
        let request = V3AddCommentRequest::new("   ")
            .into_wire()
            .expect("whitespace is content");
        assert!(matches!(request.body, RichText::Adf(_)));
    }

    #[test]
    fn the_from_impls_cover_the_ways_a_caller_holds_a_body() {
        let owned = "owned".to_string();
        let document = AdfDocument::new([AdfBlock::paragraph_text("built")]);

        assert_eq!(
            V3AddCommentRequest::from("borrowed"),
            V3AddCommentRequest::new("borrowed")
        );
        assert_eq!(
            V3AddCommentRequest::from(owned.clone()),
            V3AddCommentRequest::new(owned)
        );
        assert_eq!(
            V3AddCommentRequest::from(document.clone()),
            V3AddCommentRequest::new(document.clone())
        );
        assert_eq!(
            V3AddCommentRequest::from(RichText::Adf(document.clone())),
            V3AddCommentRequest::new(document)
        );
    }

    #[test]
    fn a_body_is_the_only_member_on_the_wire() {
        assert_eq!(
            serde_json::to_value(V3AddCommentRequest::new("hi")).expect("serializes"),
            json!({"body": "hi"}),
            "the request must contribute no member of its own"
        );
    }
}
