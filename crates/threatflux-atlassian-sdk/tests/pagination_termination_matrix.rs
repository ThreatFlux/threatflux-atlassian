//! One case per clause of the enhanced-search termination contract, driven from
//! outside the crate and asserted from the request journal.
//!
//! # Why a second suite over the same six clauses
//!
//! `SearchCursor` carries per-clause unit tests beside its own source. Those
//! assert the cursor's *decisions* -- what it returned, what it recorded as a
//! termination reason. These assert the cursor's *requests*: how many were sent,
//! and which page token each one carried. The two failures that matter here are
//! invisible to the first kind of test and caught by the second:
//!
//! - A cursor that stops one page early returns a short result set that looks
//!   exactly like a complete one. In a dedupe check that reads "no such issue"
//!   and mints a duplicate.
//! - A cursor that re-sends a token it has already spent, or that sends none
//!   when it holds one, asks Jira a different question than the caller thinks it
//!   asked -- and Jira answers it, so the return value is well-formed and wrong.
//!
//! Every case below therefore ends in [`sent_tokens`], which is the sequence of
//! `nextPageToken` values the server actually received. A cursor that produced
//! the right issues by asking the wrong questions fails on that sequence.
//!
//! The suite also runs against the published surface only, which is its second
//! job: `SearchCursor`, `TerminationReason`, `SearchLimits` and
//! `AtlassianError::PageTokenExpired` all have to be reachable and usable from a
//! downstream crate for the contract to be a contract at all.
//!
//! # The six clauses
//!
//! 1. The token is the sole authority on whether to continue.
//! 2. `isLast` is advisory and never decides.
//! 3. An empty page with a token is an ordinary intermediate page.
//! 4. A repeated token is a hard error rather than a spin.
//! 5. A cap is a refusal, not a shorter answer.
//! 6. An expired page token ends the iteration and is never resumed.

use serde_json::{json, Value};
use threatflux_atlassian_sdk::search::{
    SearchCursor, SearchIssue, SearchLimits, SearchRequest, TerminationReason,
};
use threatflux_atlassian_sdk::{AtlassianClient, AtlassianConfig, AtlassianError, HostPolicy};
use threatflux_atlassian_testkit::jira_mock::{JiraMock, Step};

/// `POST /rest/api/3/search/jql`.
const SEARCH: &str = "/rest/api/3/search/jql";

/// A client pointed at a loopback mock.
fn client_for(mock: &JiraMock) -> AtlassianClient {
    let config = AtlassianConfig::builder()
        .base_url(mock.uri())
        .username("test@example.com")
        .api_token("test-token")
        .host_policy(HostPolicy::Loopback)
        .build()
        .expect("a loopback configuration builds");
    AtlassianClient::new(config).expect("a client builds")
}

/// The query every case runs: a dedupe lookup by canonical label.
fn request() -> SearchRequest {
    SearchRequest::new(r#"labels = "jira-automation-gh-901234-77""#)
}

/// One issue, in the shape enhanced search returns.
fn issue(id: &str, key: &str) -> Value {
    json!({"id": id, "key": key, "fields": {"summary": "Bump openssl"}})
}

/// A page carrying `issues`, and `nextPageToken` when a token is given.
///
/// `isLast` agrees with the token here. The two clause-2 cases build their pages
/// by hand precisely so they can disagree.
fn page(issues: &[Value], token: Option<&str>) -> Value {
    let mut body = json!({"issues": issues, "isLast": token.is_none()});
    if let Some(token) = token {
        body["nextPageToken"] = json!(token);
    }
    body
}

/// Mounts `steps` as the successive answers of the search endpoint.
async fn script(mock: &JiraMock, steps: Vec<Step>) {
    mock.script("POST", SEARCH, steps).await;
}

/// The `nextPageToken` each recorded request carried, in order.
///
/// The heart of this suite. `None` is the first request of an iteration, and
/// every entry after it must be the token the previous response handed back --
/// so this sequence states both how far the walk went and whether it walked
/// forward.
async fn sent_tokens(mock: &JiraMock) -> Vec<Option<String>> {
    mock.journal()
        .await
        .iter()
        .map(|recorded| {
            recorded
                .body_json()
                .and_then(|body| body.get("nextPageToken").cloned())
                .and_then(|token| token.as_str().map(str::to_owned))
        })
        .collect()
}

/// `tokens` in the shape [`sent_tokens`] returns.
fn tokens(tokens: &[Option<&str>]) -> Vec<Option<String>> {
    tokens
        .iter()
        .map(|token| token.map(ToOwned::to_owned))
        .collect()
}

/// The keys of `issues`, in order.
fn keys(issues: &[SearchIssue]) -> Vec<&str> {
    issues.iter().map(|issue| issue.key.as_str()).collect()
}

// ---------------------------------------------------------------------------
// Clause 1 -- the page token is the sole authority.
// ---------------------------------------------------------------------------

/// A page with no token is the last page.
#[tokio::test]
async fn clause_1_a_page_without_a_token_is_the_last_request() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![Step::json(200, &page(&[issue("10042", "KAN-42")], None))],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());
    let collected = cursor.try_collect().await.expect("the walk succeeds");

    assert_eq!(keys(&collected), ["KAN-42"]);
    assert_eq!(
        cursor.terminated_reason(),
        Some(TerminationReason::Exhausted)
    );
    assert!(!cursor.truncated());
    assert_eq!(sent_tokens(&mock).await, tokens(&[None]));
}

/// An empty-string token is no token, and must not be echoed back.
///
/// Jira reads a blank token as "no token" and answers with page one, so a cursor
/// that honoured one would fetch the first page forever and hand the caller the
/// same issues over and over. The journal is what proves it did not: a second
/// request carrying `""` is the whole bug.
#[tokio::test]
async fn clause_1_an_empty_token_is_not_echoed_back() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![Step::json(
            200,
            &json!({
                "issues": [issue("10042", "KAN-42")],
                "nextPageToken": "",
                "isLast": false
            }),
        )],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());
    let collected = cursor.try_collect().await.expect("the walk succeeds");

    assert_eq!(keys(&collected), ["KAN-42"]);
    assert_eq!(
        cursor.terminated_reason(),
        Some(TerminationReason::Exhausted)
    );
    assert_eq!(sent_tokens(&mock).await, tokens(&[None]));
}

// ---------------------------------------------------------------------------
// Clause 2 -- `isLast` is advisory.
// ---------------------------------------------------------------------------

/// `isLast: true` alongside a token does not stop the walk.
#[tokio::test]
async fn clause_2_an_is_last_that_claims_the_end_does_not_stop_a_tokened_page() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(
                200,
                &json!({
                    "issues": [issue("10042", "KAN-42")],
                    "nextPageToken": "page-2",
                    "isLast": true
                }),
            ),
            Step::json(200, &page(&[issue("10043", "KAN-43")], None)),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());
    let collected = cursor.try_collect().await.expect("the walk succeeds");

    assert_eq!(keys(&collected), ["KAN-42", "KAN-43"]);
    assert_eq!(sent_tokens(&mock).await, tokens(&[None, Some("page-2")]));
}

/// `isLast: false` with no token does not extend the walk.
///
/// The other half of the same clause, and the one a "trust `isLast` when it says
/// there is more" implementation gets wrong: with no token there is nothing to
/// ask with, so a second request could only repeat page one.
#[tokio::test]
async fn clause_2_an_is_last_that_promises_more_does_not_extend_a_tokenless_page() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![Step::json(
            200,
            &json!({"issues": [issue("10042", "KAN-42")], "isLast": false}),
        )],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());
    let collected = cursor.try_collect().await.expect("the walk succeeds");

    assert_eq!(keys(&collected), ["KAN-42"]);
    assert_eq!(
        cursor.terminated_reason(),
        Some(TerminationReason::Exhausted)
    );
    assert_eq!(sent_tokens(&mock).await, tokens(&[None]));
}

// ---------------------------------------------------------------------------
// Clause 3 -- an empty page is not the end.
// ---------------------------------------------------------------------------

/// An empty page carrying a token is an ordinary intermediate page.
///
/// This is the classic `/search/jql` migration bug, and it is the one with a
/// duplicate issue at the end of it: the reconciliation lookup reads the empty
/// first page as "nothing matched", creates a second Jira issue, and the issue
/// it was looking for was one page further on the whole time.
#[tokio::test]
async fn clause_3_an_empty_page_with_a_token_does_not_end_the_walk() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(200, &page(&[], Some("page-2"))),
            Step::json(200, &page(&[], Some("page-3"))),
            Step::json(200, &page(&[issue("10042", "KAN-42")], None)),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());
    let collected = cursor.try_collect().await.expect("the walk succeeds");

    assert_eq!(keys(&collected), ["KAN-42"]);
    assert_eq!(
        sent_tokens(&mock).await,
        tokens(&[None, Some("page-2"), Some("page-3")])
    );
}

/// `find_first` walks past empty pages and stops at the first issue.
///
/// It stops as soon as it has an answer, which is the property that keeps a
/// dedupe lookup from walking a large result set: the fourth page below is never
/// requested.
#[tokio::test]
async fn clause_3_find_first_walks_past_empty_pages_and_no_further() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(200, &page(&[], Some("page-2"))),
            Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-3"))),
            Step::json(200, &page(&[issue("10043", "KAN-43")], None)),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());
    let found = cursor.find_first().await.expect("the walk succeeds");

    assert_eq!(found.map(|issue| issue.key), Some("KAN-42".to_string()));
    assert_eq!(sent_tokens(&mock).await, tokens(&[None, Some("page-2")]));
}

// ---------------------------------------------------------------------------
// Clause 4 -- a repeated token is a hard error.
// ---------------------------------------------------------------------------

/// A token Jira hands back unchanged would ask the identical question forever.
///
/// The cursor refuses, and the refusal is terminal: the second call repeats it
/// without sending anything. Without the terminal half, a caller looping on
/// `next_page` would turn a server-side quirk into an unbounded request storm.
#[tokio::test]
async fn clause_4_a_repeated_token_is_a_terminal_error_and_sends_nothing_more() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(200, &page(&[issue("10042", "KAN-42")], Some("stuck"))),
            Step::json(200, &page(&[issue("10043", "KAN-43")], Some("stuck"))),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());

    cursor
        .next_page()
        .await
        .expect("the first page arrives")
        .expect("a page");
    let error = cursor
        .next_page()
        .await
        .expect_err("a page that echoes its own token is refused");
    assert!(
        error
            .to_string()
            .contains("page token it had just been given"),
        "error was: {error}"
    );

    let repeated = cursor
        .next_page()
        .await
        .expect_err("the refusal is terminal");
    assert_eq!(repeated.to_string(), error.to_string());

    assert_eq!(sent_tokens(&mock).await, tokens(&[None, Some("stuck")]));
}

// ---------------------------------------------------------------------------
// Clause 5 -- a cap is a refusal, not a shorter answer.
// ---------------------------------------------------------------------------

/// A page cap stops the walk, sets `truncated`, and fails the collect.
///
/// The failure is the point. A bulk caller reads the returned `Vec` as *the* set
/// of matching issues, so handing back the first page of several would answer a
/// question nobody asked -- and the caller most likely to hit a cap is the one
/// deciding whether an issue already exists, which a partial answer misleads
/// worst.
#[tokio::test]
async fn clause_5_a_page_cap_fails_the_collect_rather_than_truncating_it() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
            Step::json(200, &page(&[issue("10043", "KAN-43")], None)),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client
        .search_cursor(&request())
        .with_limits(SearchLimits::default().with_max_pages(Some(1)));
    let error = cursor
        .try_collect()
        .await
        .expect_err("a capped walk is not an answer");

    assert!(
        error.to_string().contains("page cap of 1"),
        "error was: {error}"
    );
    assert!(cursor.truncated());
    assert_eq!(cursor.terminated_reason(), Some(TerminationReason::Capped));
    assert_eq!(
        sent_tokens(&mock).await,
        tokens(&[None]),
        "the cap is checked between pages, so the page past it is never requested"
    );
}

/// An issue cap stops the walk at the next page boundary.
///
/// Caps are checked between pages rather than mid-page, so the assertion is that
/// the *next* page was not requested -- not that the last page was trimmed.
#[tokio::test]
async fn clause_5_an_issue_cap_stops_at_the_next_page_boundary() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(
                200,
                &page(
                    &[issue("10042", "KAN-42"), issue("10043", "KAN-43")],
                    Some("page-2"),
                ),
            ),
            Step::json(200, &page(&[issue("10044", "KAN-44")], None)),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client
        .search_cursor(&request())
        .with_limits(SearchLimits::default().with_max_issues(Some(1)));

    let first = cursor
        .next_page()
        .await
        .expect("the first page arrives")
        .expect("a page");
    assert_eq!(keys(&first.issues), ["KAN-42", "KAN-43"]);

    assert!(cursor
        .next_page()
        .await
        .expect("the cap ends the walk cleanly")
        .is_none());
    assert!(cursor.truncated());
    assert_eq!(sent_tokens(&mock).await, tokens(&[None]));
}

// ---------------------------------------------------------------------------
// Clause 6 -- an expired page token is terminal and is never resumed.
// ---------------------------------------------------------------------------

/// A 400 on a page the cursor was issued a token for is an expiry.
///
/// The classification is structural -- page index above zero -- and reads
/// nothing out of the response body, so it neither depends on Atlassian's error
/// wording nor lets that wording into an error message. The mock answers with a
/// body that says nothing about tokens, which is what makes the point.
#[tokio::test]
async fn clause_6_a_400_after_the_first_page_is_reported_as_an_expired_token() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
            Step::json(
                400,
                &json!({"errorMessages": ["Bad Request"], "errors": {}}),
            ),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());

    cursor
        .next_page()
        .await
        .expect("the first page arrives")
        .expect("a page");
    let error = cursor
        .next_page()
        .await
        .expect_err("the second page is refused");

    assert!(
        matches!(error, AtlassianError::PageTokenExpired { page_index: 1 }),
        "expected an expiry at page 1, got {error:?}"
    );
    assert_eq!(
        cursor.terminated_reason(),
        Some(TerminationReason::PageTokenExpired)
    );
    assert!(
        !cursor.truncated(),
        "an expiry is not a cap; a caller must not read it as a complete-but-trimmed answer"
    );
}

/// An expired token is never retried and never silently restarted.
///
/// Both halves matter and only the journal separates them. Retrying would send
/// the dead token again; restarting would send `None` and walk a result set that
/// has been changing underneath the iteration, stitching two instants into a set
/// that was never the answer at either.
#[tokio::test]
async fn clause_6_an_expired_token_is_neither_retried_nor_restarted() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
            Step::json(
                400,
                &json!({"errorMessages": ["Bad Request"], "errors": {}}),
            ),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());

    cursor
        .next_page()
        .await
        .expect("the first page arrives")
        .expect("a page");
    let first = cursor.next_page().await.expect_err("the token is refused");

    for _ in 0..3 {
        let repeated = cursor
            .next_page()
            .await
            .expect_err("the refusal is terminal");
        assert_eq!(repeated.to_string(), first.to_string());
    }
    let collected = cursor
        .try_collect()
        .await
        .expect_err("a collect over a finished cursor repeats the refusal");
    assert_eq!(collected.to_string(), first.to_string());

    assert_eq!(
        sent_tokens(&mock).await,
        tokens(&[None, Some("page-2")]),
        "a stopped cursor sends nothing further, by either token or restart"
    );
}

/// A 400 on the first request is a query error, not an expiry.
///
/// The two demand opposite responses -- fix the query, or start the search
/// again -- so conflating them hands the caller advice that cannot work. The
/// first request of an iteration carries no Jira-issued token, so there is
/// nothing that could have expired.
#[tokio::test]
async fn clause_6_a_400_on_the_first_page_is_a_query_error() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![Step::json(
            400,
            &json!({"errorMessages": ["Error in the JQL Query"], "errors": {}}),
        )],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());
    let error = cursor.next_page().await.expect_err("the query is refused");

    assert!(
        !matches!(error, AtlassianError::PageTokenExpired { .. }),
        "a first-page 400 must not be reported as an expiry: {error:?}"
    );
    assert_eq!(cursor.terminated_reason(), None);
    assert_eq!(sent_tokens(&mock).await, tokens(&[None]));
}

/// A failure that is not a 400 leaves the cursor on its unspent token.
///
/// The cursor is not a retry loop, but it must not consume a token it never got
/// an answer for either: re-requesting the same page after a 503 is a legitimate
/// thing for a caller to do, and the token it needs is the one it already sent.
#[tokio::test]
async fn clause_6_a_transient_failure_leaves_the_token_unspent() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![
            Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
            Step::status(503),
            Step::json(200, &page(&[issue("10043", "KAN-43")], None)),
        ],
    )
    .await;

    let client = client_for(&mock);
    let mut cursor = client.search_cursor(&request());

    cursor
        .next_page()
        .await
        .expect("the first page arrives")
        .expect("a page");
    let error = cursor.next_page().await.expect_err("the 503 surfaces");
    assert!(
        !matches!(error, AtlassianError::PageTokenExpired { .. }),
        "a 503 is not an expiry: {error:?}"
    );
    assert_eq!(cursor.terminated_reason(), None);

    let retried = cursor
        .next_page()
        .await
        .expect("the same page can be asked for again")
        .expect("a page");
    assert_eq!(keys(&retried.issues), ["KAN-43"]);
    assert_eq!(
        sent_tokens(&mock).await,
        tokens(&[None, Some("page-2"), Some("page-2")]),
        "the retry asks for the page that failed, not the one after it"
    );
}

// ---------------------------------------------------------------------------
// The cursor is reachable and usable from outside the crate.
// ---------------------------------------------------------------------------

/// The published surface a downstream caller needs to drive an iteration.
///
/// A compile-time assertion: if `SearchCursor` stopped being nameable, or its
/// borrow of the client stopped working through a re-export, this suite would
/// fail to build rather than fail at runtime.
#[tokio::test]
async fn a_cursor_can_be_named_and_driven_by_a_downstream_caller() {
    let mock = JiraMock::start().await;
    script(
        &mock,
        vec![Step::json(200, &page(&[issue("10042", "KAN-42")], None))],
    )
    .await;

    let client = client_for(&mock);
    let request = request();
    let mut cursor: SearchCursor<'_> = client
        .search_cursor(&request)
        .with_limits(SearchLimits::default().with_max_issues(Some(10)));

    let mut seen = Vec::new();
    while let Some(page) = cursor.next_page().await.expect("the walk succeeds") {
        seen.extend(page.issues.into_iter().map(|issue| issue.key));
    }

    assert_eq!(seen, ["KAN-42"]);
    assert_eq!(
        cursor.terminated_reason(),
        Some(TerminationReason::Exhausted)
    );
}
