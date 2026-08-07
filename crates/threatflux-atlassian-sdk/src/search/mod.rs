//! Typed models for Jira's enhanced search.
//!
//! Enhanced search is `POST /rest/api/3/search/jql`, the replacement for the
//! `GET /rest/api/2/search` route Atlassian is removing. It is a different
//! endpoint rather than a new spelling of the old one, and the two differ in
//! ways a caller cannot paper over:
//!
//! | | Legacy search | Enhanced search |
//! |---|---|---|
//! | Pagination | `startAt` offset | opaque `nextPageToken` |
//! | Result size | `total` in every response | not returned at all |
//! | Query transport | URL query string | request body |
//! | Default fields | a navigable set | ids only |
//!
//! # Pagination is by token
//!
//! [`SearchPage`] carries a [`nextPageToken`](SearchPage::next_page_token) and
//! no `startAt`, because the endpoint has no concept of an offset: page *n* is
//! reachable only by having asked for page *n − 1*. A caller keeping an offset
//! counter is not merely doing it the slow way, it is doing something the
//! server cannot honour. [`SearchPage::next_token`] is the one authority on
//! whether another page exists — including on a page whose `issues` array is
//! empty, which is a legitimate intermediate page and not the end.
//!
//! [`SearchCursor`] is what follows those tokens for a caller who wants more
//! than one page: it owns the six-clause termination contract, refuses to hand
//! back a partial result set when a [`SearchLimits`] cap stops it, and reports an
//! expired page token as [`AtlassianError::PageTokenExpired`] rather than as an
//! indistinguishable 400.
//!
//! [`AtlassianError::PageTokenExpired`]: crate::error::AtlassianError::PageTokenExpired
//!
//! # There is no total
//!
//! Nothing here reports how many issues match. Enhanced search does not count
//! the result set; an approximate count is a separate endpoint, and it is
//! approximate as named. Reconciliation logic that wants "is there exactly one
//! of these" has to look at the issues it actually received.
//!
//! # Reads are tolerant
//!
//! The field set is chosen per request, so every field on
//! [`SearchIssueFields`] is optional and a narrowed `fields` list is a normal
//! response rather than a parse error. Fields this crate does not model —
//! custom fields above all — are preserved in
//! [`SearchIssueFields::other`](SearchIssueFields::other) and re-serialize
//! exactly as they arrived, so a read-modify-write does not quietly discard
//! them. [`RawSearchPage`] goes further and leaves each issue as raw JSON.
//!
//! # Writes are checked
//!
//! [`SearchRequest::validate`] is the gate on the way out: it rejects a blank
//! query, an empty field list, a page size outside the endpoint's range, and a
//! blank page token — the last because Jira reads one as "no token" and answers
//! with the first page, which turns a lost token into an infinite loop over
//! page one rather than an error.
//!
//! ```
//! use threatflux_atlassian_sdk::search::{SearchPage, SearchRequest};
//!
//! let request = SearchRequest::new(r#"project = "KAN" AND labels = "gh-901234-77""#)
//!     .with_fields(["summary", "labels", "status"])
//!     .with_max_results(50);
//! request.validate()?;
//!
//! // What one page of the answer looks like coming back.
//! let page: SearchPage = serde_json::from_str(
//!     r#"{"issues":[{"id":"10042","key":"KAN-42",
//!                    "fields":{"summary":"Bump openssl","labels":["gh-901234-77"]}}],
//!         "nextPageToken":"eyJ0IjoxfQ==","isLast":false}"#,
//! )?;
//!
//! assert_eq!(page.issues[0].key, "KAN-42");
//! assert!(page.issues[0].fields.has_label("gh-901234-77"));
//!
//! // Ask for the next page by echoing the token, never by advancing an offset.
//! let next = page
//!     .next_token()
//!     .map(|token| request.clone().with_next_page_token(token));
//! assert!(next.is_some());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The methods that send these models —
//! [`search_jql`](crate::AtlassianClient::search_jql),
//! [`search_jql_raw`](crate::AtlassianClient::search_jql_raw),
//! [`approximate_issue_count`](crate::AtlassianClient::approximate_issue_count)
//! and [`find_issue_by_jql`](crate::AtlassianClient::find_issue_by_jql) — hang
//! off the Jira client rather than off a handle of their own, and every request
//! they build goes through the same transport, credentials, host policy and
//! diagnostics policy as the rest of the crate.

mod api;
mod cursor;
mod limits;
mod page;
mod project;
mod request;

pub use cursor::{SearchCursor, TerminationReason, MAX_REMEMBERED_PAGE_TOKENS};
pub use limits::{SearchLimits, DEFAULT_MAX_ISSUES, DEFAULT_MAX_PAGES};
pub use page::{
    RawSearchPage, SearchIssue, SearchIssueFields, SearchNamedRef, SearchPage, SearchStatus,
    SearchStatusCategory, SearchUser,
};
pub use project::{ProjectSearchPage, ProjectSearchQuery, SearchProject};
pub use request::{
    SearchRequest, SearchRequestError, ALL_FIELDS, DEFAULT_FIELDS, DEFAULT_MAX_RESULTS,
    MAX_PROPERTIES, MAX_RECONCILE_ISSUES, MAX_RESULTS_CEILING,
};
