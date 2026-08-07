//! The enhanced-search endpoints, hung off [`AtlassianClient`].
//!
//! The models live beside this file; this is the part that talks to Jira. Every
//! call here is a **POST**, including the two that are plainly reads, for two
//! reasons that are properties of the endpoint rather than preferences:
//!
//! - A JQL query is unbounded caller text. A reconciliation query naming a
//!   dedupe label is short, but one carrying a `summary ~` term built from an
//!   event body is not, and a query long enough to be useful is regularly long
//!   enough to exceed what proxies and gateways accept in a URL. Enhanced search
//!   takes it in the body, where there is no such ceiling.
//! - `reconcileIssues` has no query-string spelling at all. It is body-only, so
//!   the one request field that forces index consistency is unreachable from a
//!   GET.
//!
//! Both are tagged [`Idempotency::Safe`] regardless: the method is POST but the
//! effect is a read, and a replayed search converges on the same server state.
//! Tagging them by HTTP method instead would tell the retry work that a search
//! must not be replayed, which is exactly backwards.
//!
//! `/search/approximate-count` is a deliberate addition rather than part of the
//! endpoint set the v2 migration replaces. It is here because enhanced search
//! reports no `total` at all, and walking pages to count is the expensive answer
//! to a question that has a cheap one.

use reqwest::{Method, Response};
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, warn};

use super::{
    RawSearchPage, SearchIssue, SearchPage, SearchRequest, SearchRequestError, DEFAULT_MAX_PAGES,
};
use crate::client::{preview, AtlassianClient, Idempotency, TransportRequest};
use crate::error::{AtlassianError, Result};

/// `POST /rest/api/3/search/jql`, as path segments.
const SEARCH_SEGMENTS: &[&str] = &["rest", "api", "3", "search", "jql"];

/// `POST /rest/api/3/search/approximate-count`, as path segments.
const COUNT_SEGMENTS: &[&str] = &["rest", "api", "3", "search", "approximate-count"];

/// The body of `POST /rest/api/3/search/approximate-count`.
///
/// One field, required. A response this crate cannot read is an error rather
/// than a defaulted zero: "no issues match" and "the count did not arrive" lead
/// to opposite decisions, and a default would render them identical.
#[derive(Debug, Deserialize)]
struct ApproximateCountResponse {
    /// Jira's estimate of how many issues match.
    count: u64,
}

impl AtlassianClient {
    /// Runs `request` against `POST /rest/api/3/search/jql` and returns one page.
    ///
    /// The request is [validated](SearchRequest::validate) before anything is
    /// sent, so a blank query, an empty field list or a blank page token costs no
    /// round trip.
    ///
    /// # One page, and the token decides whether there is another
    ///
    /// This returns exactly the page Jira answered with. It does not follow
    /// [`next_page_token`](SearchPage::next_page_token), and a caller that wants
    /// the rest of the result set echoes that token into
    /// [`SearchRequest::with_next_page_token`] — never into a `startAt` counter,
    /// which this endpoint does not have.
    ///
    /// A page whose [`issues`](SearchPage::issues) are empty **is not** proof
    /// that nothing matched: Jira may answer with no issues and a token, and the
    /// matches sit on a later page. Use [`find_issue_by_jql`](Self::find_issue_by_jql)
    /// rather than reading `page.issues.is_empty()` as "no such issue".
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::search::SearchRequest;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let request = SearchRequest::new(r#"project = "KAN" AND labels = "gh-901234-77""#)
    ///     .with_fields(["summary", "labels"]);
    ///
    /// let page = client.search_jql(&request).await.unwrap();
    /// for issue in &page.issues {
    ///     println!("{}", issue.key);
    /// }
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if `request` is not sendable, before any
    /// request is made. Otherwise whatever the transport returns, plus a parse
    /// error if the page cannot be read.
    pub async fn search_jql(&self, request: &SearchRequest) -> Result<SearchPage> {
        let response = self.send_search(request).await?;
        let page: SearchPage = response.json().await?;

        report_page(
            page.issues.len(),
            page.next_token(),
            page.is_last_disagrees(),
        );

        Ok(page)
    }

    /// Runs `request` against `POST /rest/api/3/search/jql` and returns the page
    /// with its issues left as raw JSON.
    ///
    /// [`SearchPage`] models the fields this crate reads and keeps the rest in a
    /// map; this returns [`RawSearchPage`], which models none of them. It exists
    /// for the caller whose field set is mostly custom fields — a report over
    /// twenty `customfield_*` ids, a schema probe, a field this crate has no
    /// type for — and who would rather read the JSON directly than reach through
    /// [`SearchIssueFields::field`](super::SearchIssueFields::field) for every
    /// one of them.
    ///
    /// Pagination, validation and idempotency are identical to
    /// [`search_jql`](Self::search_jql); only the decoding differs.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::search::SearchRequest;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let request = SearchRequest::new(r#"project = "KAN""#)
    ///     .with_fields(["customfield_10001", "customfield_10002"]);
    ///
    /// let page = client.search_jql_raw(&request).await.unwrap();
    /// for issue in &page.issues {
    ///     println!("{issue}");
    /// }
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// As [`search_jql`](Self::search_jql).
    pub async fn search_jql_raw(&self, request: &SearchRequest) -> Result<RawSearchPage> {
        let response = self.send_search(request).await?;
        let page: RawSearchPage = response.json().await?;

        report_page(
            page.issues.len(),
            page.next_token(),
            page.is_last_disagrees(),
        );

        Ok(page)
    }

    /// Asks Jira roughly how many issues match `jql`, with
    /// `POST /rest/api/3/search/approximate-count`.
    ///
    /// # It is cheap, which is the reason it exists
    ///
    /// One round trip, no issues, no fields, no pagination: Jira answers from
    /// its index without materializing a result set. Enhanced search reports no
    /// `total`, so the alternative to this call is walking every page and
    /// counting what arrives — a request per page and a payload per issue, to
    /// learn a single number. Reach for this instead whenever the number is all
    /// that is wanted.
    ///
    /// # It is approximate, and that word is load-bearing
    ///
    /// The answer is an estimate drawn from the index, not a count of rows a
    /// permission check has been applied to, and it can be wrong in either
    /// direction. So it may inform — a dashboard, a log line, a decision about
    /// whether a query is worth paginating — and it may never decide. In
    /// particular, nothing should suppress a create on `count > 0` or perform
    /// one on `count == 0`: that is a decision about specific issues, and it
    /// needs the issues themselves. [`find_issue_by_jql`](Self::find_issue_by_jql)
    /// is what answers that question.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let roughly = client
    ///     .approximate_issue_count(r#"project = "KAN" AND statusCategory != Done"#)
    ///     .await
    ///     .unwrap();
    /// println!("about {roughly} open issues");
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if `jql` is blank, before any request is
    /// made — a blank query would match every issue in the instance. Otherwise
    /// whatever the transport returns, plus a parse error if the count cannot be
    /// read.
    pub async fn approximate_issue_count(&self, jql: &str) -> Result<u64> {
        if jql.trim().is_empty() {
            return Err(SearchRequestError::BlankJql.into());
        }

        info!(
            "Asking for an approximate issue count over a {}-character JQL query",
            jql.len()
        );
        debug!("JQL query: {}", preview(jql));

        let body = json!({ "jql": jql });
        let response = self
            .transport()
            .send(
                TransportRequest::new(Method::POST, COUNT_SEGMENTS, Idempotency::Safe).json(&body),
            )
            .await?;

        let counted: ApproximateCountResponse = response.json().await?;
        debug!("Approximate issue count: {}", counted.count);

        Ok(counted.count)
    }

    /// Returns the first issue `request` matches, or `None` when it matches
    /// nothing.
    ///
    /// This is the single-result convenience reconciliation leans on: "is there
    /// already a Jira issue carrying this dedupe label" is the question that
    /// decides whether a create happens, and getting it wrong mints a duplicate.
    ///
    /// # Why this is not `search_jql(..).issues.first()`
    ///
    /// Enhanced search may answer with an **empty page and a page token**, with
    /// the matches on a later page. Reading `issues.first()` off one page would
    /// report `None` for an issue that exists, so this walks *past empty pages*
    /// until it finds an issue or the token runs out.
    ///
    /// It never walks past a page that carried an issue. At most one page of
    /// issues is ever fetched and only its first issue is read, so this stays a
    /// single-result call rather than a quiet iteration: a caller that wants
    /// every match, or that needs to rank duplicates against each other, pages
    /// deliberately with [`search_jql`](Self::search_jql).
    ///
    /// Which issue "first" is is Jira's ordering, so a caller that means
    /// "oldest" or "most recently updated" says so in the query's `ORDER BY`
    /// rather than relying on the default.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::search::SearchRequest;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let request = SearchRequest::new(r#"labels = "gh-901234-77" ORDER BY created ASC"#)
    ///     .with_fields(["summary", "labels", "status"]);
    ///
    /// match client.find_issue_by_jql(&request).await.unwrap() {
    ///     Some(issue) => println!("already tracked as {}", issue.key),
    ///     None => println!("nothing tracks this yet"),
    /// }
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// As [`search_jql`](Self::search_jql), plus [`AtlassianError::JiraApi`] for
    /// the two ways the endpoint can fail to make progress: it repeats the page
    /// token it had just issued, or it answers with empty pages past the page
    /// budget in [`DEFAULT_MAX_PAGES`]. Both are refusals to answer rather than
    /// a `None`, because a `None` here is read as "no such issue" and would be a
    /// silent wrong answer.
    pub async fn find_issue_by_jql(&self, request: &SearchRequest) -> Result<Option<SearchIssue>> {
        let mut request = request.clone();
        let mut previous_token: Option<String> = None;

        for _ in 0..DEFAULT_MAX_PAGES {
            let page = self.search_jql(&request).await?;

            // Read the token before the issues, which are moved out below.
            let token = page.next_token().map(str::to_owned);

            if let Some(issue) = page.issues.into_iter().next() {
                return Ok(Some(issue));
            }

            let Some(token) = token else {
                return Ok(None);
            };

            if previous_token.as_deref() == Some(token.as_str()) {
                return Err(AtlassianError::jira_api(
                    "enhanced search answered an empty page with the page token it had just issued, so another request would ask the same question again",
                    None,
                ));
            }

            debug!("Enhanced search answered an empty page; following its token");
            request.set_next_page_token(Some(token.clone()));
            previous_token = Some(token);
        }

        Err(AtlassianError::jira_api(
            format!(
                "enhanced search answered {DEFAULT_MAX_PAGES} empty pages without exhausting the result set; narrow the query rather than walking further"
            ),
            None,
        ))
    }

    /// Validates `request`, then sends it to `POST /rest/api/3/search/jql`.
    ///
    /// Shared by the typed and raw readers so there is one request shape, one
    /// idempotency tag and one logging policy between them.
    async fn send_search(&self, request: &SearchRequest) -> Result<Response> {
        request.validate()?;

        // The query is not this crate's text. A dedupe query carries the
        // caller's label scheme and a `summary ~` term carries whatever the
        // event that produced it did, so the whole of it is exactly what must
        // not land in an `info` log a workflow publishes. The page token is
        // Jira's own opaque blob and is no more loggable.
        info!(
            "Running an enhanced search with a {}-character JQL query over {} field(s)",
            request.jql().len(),
            request.fields().len()
        );
        debug!("JQL query: {}", preview(request.jql()));

        let body = serde_json::to_value(request)?;
        self.transport()
            .send(
                TransportRequest::new(Method::POST, SEARCH_SEGMENTS, Idempotency::Safe).json(&body),
            )
            .await
    }
}

/// Logs what a page carried, and flags a self-contradicting one.
///
/// `isLast` is advisory and the token decides, so a disagreement changes
/// nothing — but it is the signal that Atlassian's pagination contract moved
/// under this crate, and it is worthless if nobody can see it.
fn report_page(issue_count: usize, next_token: Option<&str>, is_last_disagrees: bool) {
    debug!(
        "Enhanced search returned {} issue(s); another page: {}",
        issue_count,
        next_token.is_some()
    );

    if is_last_disagrees {
        warn!(
            "Enhanced search returned an isLast that contradicts its page token; the token decides"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{ApproximateCountResponse, DEFAULT_MAX_PAGES};
    use crate::config::{AtlassianConfig, HostPolicy};
    use crate::error::AtlassianError;
    use crate::search::{SearchPage, SearchRequest};
    use crate::AtlassianClient;
    use serde_json::{json, Value};
    use std::future::Future;
    use threatflux_atlassian_testkit::jira_mock::{JiraMock, RecordedRequest, Step};
    use threatflux_atlassian_testkit::logs;

    const SEARCH: &str = "/rest/api/3/search/jql";
    const COUNT: &str = "/rest/api/3/search/approximate-count";

    /// A client pointed at a loopback mock.
    ///
    /// `HostPolicy::Loopback` is what admits the `http://` scheme; it is set by
    /// a code call because the environment deliberately cannot reach it.
    fn client_for(mock: &JiraMock) -> AtlassianClient {
        let config = AtlassianConfig::builder()
            .base_url(mock.uri())
            .username("test@example.com")
            .api_token("test-token")
            .host_policy(HostPolicy::Loopback)
            .build()
            .expect("a loopback config builds");
        AtlassianClient::new(config).expect("a client builds")
    }

    fn issue(id: &str, key: &str) -> Value {
        json!({"id": id, "key": key, "fields": {"summary": "Bump openssl"}})
    }

    /// A page carrying `issues`, and a token when one is given.
    fn page(issues: &[Value], token: Option<&str>) -> Value {
        let mut body = json!({"issues": issues, "isLast": token.is_none()});
        if let Some(token) = token {
            body["nextPageToken"] = json!(token);
        }
        body
    }

    async fn only_request(mock: &JiraMock) -> RecordedRequest {
        let mut journal = mock.journal().await;
        assert_eq!(
            journal.len(),
            1,
            "expected exactly one request: {journal:?}"
        );
        journal.remove(0)
    }

    /// Runs `body` on a current-thread runtime with every `tracing` event captured.
    ///
    /// The subscriber `logs::capture` installs is thread-local, so the future has
    /// to be driven on the thread that installed it rather than on a worker pool.
    fn capture_async<T>(body: impl Future<Output = T>) -> (T, String) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime should build");
        logs::capture(|| runtime.block_on(body))
    }

    #[tokio::test]
    async fn a_search_posts_its_body_to_the_v3_route_and_carries_no_query_string() {
        // POST rather than GET is the whole shape of enhanced search: the query
        // is unbounded caller text, and `reconcileIssues` has no query-string
        // spelling at all.
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
            .await;

        let request = SearchRequest::new(r#"project = "KAN""#)
            .with_fields(["summary"])
            .with_max_results(25)
            .with_reconcile_issues([10_042]);
        client_for(&mock)
            .search_jql(&request)
            .await
            .expect("the search succeeds");

        let recorded = only_request(&mock).await;
        assert_eq!(recorded.method, "POST");
        assert_eq!(recorded.path, SEARCH);
        assert_eq!(
            recorded.query, None,
            "the query belongs in the body, not the URL"
        );
        assert_eq!(
            recorded.body_json(),
            Some(json!({
                "jql": r#"project = "KAN""#,
                "fields": ["summary"],
                "maxResults": 25,
                "reconcileIssues": [10_042]
            }))
        );
    }

    #[tokio::test]
    async fn a_search_reads_the_page_and_its_token() {
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            SEARCH,
            Step::json(
                200,
                &page(&[issue("10042", "KAN-42")], Some("eyJ0IjoxfQ==")),
            ),
        )
        .await;

        let page = client_for(&mock)
            .search_jql(&SearchRequest::new(r#"project = "KAN""#))
            .await
            .expect("the search succeeds");

        assert_eq!(page.issues.len(), 1);
        assert_eq!(page.issues[0].key, "KAN-42");
        assert_eq!(page.issues[0].numeric_id(), Some(10_042));
        assert_eq!(page.next_token(), Some("eyJ0IjoxfQ=="));
    }

    #[tokio::test]
    async fn a_search_echoes_a_page_token_into_the_body() {
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
            .await;

        let request = SearchRequest::new(r#"project = "KAN""#).with_next_page_token("token-2");
        client_for(&mock)
            .search_jql(&request)
            .await
            .expect("the search succeeds");

        let body = only_request(&mock).await.body_json().expect("a JSON body");
        assert_eq!(body.get("nextPageToken"), Some(&json!("token-2")));
        assert!(
            body.get("startAt").is_none(),
            "enhanced search has no offset pagination"
        );
    }

    #[tokio::test]
    async fn an_unsendable_request_is_refused_without_a_round_trip() {
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
            .await;

        let error = client_for(&mock)
            .search_jql(&SearchRequest::new("   "))
            .await
            .expect_err("a blank query is refused");

        assert!(
            matches!(error, AtlassianError::Validation { ref message } if message.contains("blank")),
            "unexpected error {error:?}"
        );
        assert!(
            mock.journal().await.is_empty(),
            "a refused request must cost no round trip"
        );
    }

    #[test]
    fn a_search_is_tagged_replay_safe_despite_being_a_post() {
        // The retry work reads the tag, not the method. A search tagged from its
        // POST would be treated as an unsafe write and refused a replay.
        let (result, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
                .await;
            client_for(&mock)
                .search_jql(&SearchRequest::new(r#"project = "KAN""#))
                .await
        });

        assert!(result.is_ok());
        assert!(log.contains("Safe"), "log was: {log}");
        assert!(!log.contains("UnsafeWrite"), "log was: {log}");
    }

    #[test]
    fn a_search_does_not_log_the_query_it_sends() {
        // A dedupe query carries the caller's label scheme, and a reconciliation
        // query can carry summary text taken from an event body. Neither belongs
        // in a log that a workflow publishes.
        const TAIL: &str = "trailing-term-that-must-not-reach-a-log";
        let jql = format!(r#"project = "KAN" AND labels = "prefix-{TAIL}""#);

        let (result, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
                .await;
            client_for(&mock)
                .search_jql(&SearchRequest::new(&jql))
                .await
        });

        assert!(result.is_ok());
        assert!(!log.contains(TAIL), "log was: {log}");
        assert!(!log.contains(&jql), "log was: {log}");
        assert!(
            log.contains(&format!("{}-character JQL query", jql.len())),
            "log was: {log}"
        );
        assert!(log.contains("(truncated)"), "log was: {log}");
    }

    #[test]
    fn a_contradicted_is_last_is_warned_about_and_the_token_still_decides() {
        let (page, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub(
                "POST",
                SEARCH,
                Step::json(
                    200,
                    &json!({"issues": [], "nextPageToken": "more", "isLast": true}),
                ),
            )
            .await;
            client_for(&mock)
                .search_jql(&SearchRequest::new(r#"project = "KAN""#))
                .await
        });

        let page = page.expect("the search succeeds");
        assert_eq!(page.next_token(), Some("more"));
        assert!(log.contains("contradicts its page token"), "log was: {log}");
    }

    #[tokio::test]
    async fn a_raw_search_leaves_every_issue_as_it_arrived() {
        let mock = JiraMock::start().await;
        let body = json!({
            "issues": [{"id": "10042", "key": "KAN-42",
                        "fields": {"customfield_10001": [1, 2, 3]}}],
            "nextPageToken": "more"
        });
        mock.stub("POST", SEARCH, Step::json(200, &body)).await;

        let raw = client_for(&mock)
            .search_jql_raw(&SearchRequest::new(r#"project = "KAN""#).with_all_fields())
            .await
            .expect("the search succeeds");

        assert_eq!(
            raw.issues,
            body["issues"].as_array().expect("an array").clone(),
            "a raw page must not decode the issues it carries"
        );
        assert_eq!(raw.next_token(), Some("more"));
        assert_eq!(only_request(&mock).await.path, SEARCH);
    }

    #[tokio::test]
    async fn a_raw_search_validates_its_request_too() {
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
            .await;

        let error = client_for(&mock)
            .search_jql_raw(
                &SearchRequest::new(r#"project = "KAN""#).with_fields(Vec::<String>::new()),
            )
            .await
            .expect_err("an empty field list is refused");

        assert!(matches!(error, AtlassianError::Validation { .. }));
        assert!(mock.journal().await.is_empty());
    }

    #[tokio::test]
    async fn an_approximate_count_posts_only_the_query_and_reads_the_number() {
        let mock = JiraMock::start().await;
        mock.stub("POST", COUNT, Step::json(200, &json!({"count": 1234})))
            .await;

        let count = client_for(&mock)
            .approximate_issue_count(r#"project = "KAN""#)
            .await
            .expect("the count succeeds");

        assert_eq!(count, 1234);

        let recorded = only_request(&mock).await;
        assert_eq!(recorded.method, "POST");
        assert_eq!(recorded.path, COUNT);
        assert_eq!(recorded.query, None);
        assert_eq!(
            recorded.body_json(),
            Some(json!({"jql": r#"project = "KAN""#})),
            "the count endpoint takes the query and nothing else"
        );
    }

    #[tokio::test]
    async fn an_approximate_count_refuses_a_blank_query_without_a_round_trip() {
        let mock = JiraMock::start().await;
        mock.stub("POST", COUNT, Step::json(200, &json!({"count": 0})))
            .await;

        let error = client_for(&mock)
            .approximate_issue_count(" \t ")
            .await
            .expect_err("a blank query is refused");

        assert!(
            matches!(error, AtlassianError::Validation { ref message } if message.contains("blank")),
            "unexpected error {error:?}"
        );
        assert!(mock.journal().await.is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_count_is_an_error_rather_than_a_zero() {
        let mock = JiraMock::start().await;
        mock.stub("POST", COUNT, Step::json(200, &json!({"isLast": true})))
            .await;

        client_for(&mock)
            .approximate_issue_count(r#"project = "KAN""#)
            .await
            .expect_err("a missing count must not read as zero");
    }

    #[test]
    fn a_count_response_needs_its_count() {
        let read: ApproximateCountResponse =
            serde_json::from_value(json!({"count": 7})).expect("deserializes");
        assert_eq!(read.count, 7);

        assert!(serde_json::from_value::<ApproximateCountResponse>(json!({})).is_err());
    }

    #[tokio::test]
    async fn finding_one_issue_reads_the_first_of_the_page_in_a_single_request() {
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            SEARCH,
            Step::json(
                200,
                &page(&[issue("10042", "KAN-42"), issue("10043", "KAN-43")], None),
            ),
        )
        .await;

        let found = client_for(&mock)
            .find_issue_by_jql(&SearchRequest::new(r#"labels = "gh-1-2""#))
            .await
            .expect("the search succeeds");

        assert_eq!(found.map(|issue| issue.key), Some("KAN-42".to_string()));
        mock.assert_call_count("POST", SEARCH, 1).await;
    }

    #[tokio::test]
    async fn finding_one_issue_reports_none_when_the_result_set_is_exhausted() {
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
            .await;

        let found = client_for(&mock)
            .find_issue_by_jql(&SearchRequest::new(r#"labels = "gh-1-2""#))
            .await
            .expect("the search succeeds");

        assert!(found.is_none());
        mock.assert_call_count("POST", SEARCH, 1).await;
    }

    #[tokio::test]
    async fn finding_one_issue_walks_past_an_empty_page_that_carries_a_token() {
        // The classic `/search/jql` migration bug: an empty page is not the end
        // of the result set, and reading it as "no such issue" mints a duplicate.
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[], Some("page-2"))),
                Step::json(200, &page(&[issue("10042", "KAN-42")], None)),
            ],
        )
        .await;

        let found = client_for(&mock)
            .find_issue_by_jql(&SearchRequest::new(r#"labels = "gh-1-2""#))
            .await
            .expect("the search succeeds");

        assert_eq!(found.map(|issue| issue.key), Some("KAN-42".to_string()));

        let journal = mock.journal().await;
        assert_eq!(journal.len(), 2);
        assert!(
            journal[0]
                .body_json()
                .and_then(|body| body.get("nextPageToken").cloned())
                .is_none(),
            "the first request must not carry a token"
        );
        assert_eq!(
            journal[1]
                .body_json()
                .and_then(|body| body.get("nextPageToken").cloned()),
            Some(json!("page-2")),
            "the second request must echo the token the first was given"
        );
    }

    #[tokio::test]
    async fn finding_one_issue_never_walks_past_a_page_that_carried_an_issue() {
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
                Step::json(200, &page(&[issue("10043", "KAN-43")], None)),
            ],
        )
        .await;

        let found = client_for(&mock)
            .find_issue_by_jql(&SearchRequest::new(r#"labels = "gh-1-2""#))
            .await
            .expect("the search succeeds");

        assert_eq!(found.map(|issue| issue.key), Some("KAN-42".to_string()));
        mock.assert_call_count("POST", SEARCH, 1).await;
    }

    #[tokio::test]
    async fn finding_one_issue_refuses_a_page_token_the_server_just_issued() {
        // A repeated token cannot make progress, so asking again is a spin. Fail
        // on the second sighting rather than on the hundredth.
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], Some("stuck"))))
            .await;

        let error = client_for(&mock)
            .find_issue_by_jql(&SearchRequest::new(r#"labels = "gh-1-2""#))
            .await
            .expect_err("a repeated token is a hard error");

        assert!(
            matches!(error, AtlassianError::JiraApi { ref message, .. } if message.contains("just issued")),
            "unexpected error {error:?}"
        );
        mock.assert_call_count("POST", SEARCH, 2).await;
    }

    #[tokio::test]
    async fn finding_one_issue_stops_at_the_page_budget_rather_than_walking_forever() {
        let mock = JiraMock::start().await;
        let steps = (0..DEFAULT_MAX_PAGES)
            .map(|index| Step::json(200, &page(&[], Some(&format!("page-{index}")))))
            .collect();
        mock.script("POST", SEARCH, steps).await;

        let error = client_for(&mock)
            .find_issue_by_jql(&SearchRequest::new(r#"labels = "gh-1-2""#))
            .await
            .expect_err("an unending run of empty pages is refused");

        assert!(
            matches!(error, AtlassianError::JiraApi { ref message, .. } if message.contains("empty pages")),
            "unexpected error {error:?}"
        );
        mock.assert_call_count("POST", SEARCH, DEFAULT_MAX_PAGES)
            .await;
    }

    #[tokio::test]
    async fn a_failing_search_keeps_the_response_body_out_of_the_error() {
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            SEARCH,
            Step::json(
                400,
                &json!({"errorMessages": ["The value 'nope' does not exist for the field 'project'"]}),
            ),
        )
        .await;

        let error = client_for(&mock)
            .search_jql(&SearchRequest::new(r#"project = "nope""#))
            .await
            .expect_err("a 400 is an error");

        assert!(
            !error.to_string().contains("does not exist for the field"),
            "the default diagnostics policy must keep the body out: {error}"
        );
    }

    #[tokio::test]
    async fn a_page_that_cannot_be_decoded_typed_can_still_be_read_raw() {
        // The reason `search_jql_raw` exists: a caller whose field set this
        // crate does not model gets the JSON rather than a lossy struct.
        let mock = JiraMock::start().await;
        let body = json!({
            "issues": [{"id": "10042", "key": "KAN-42",
                        "fields": {"summary": "kept", "customfield_10001": {"value": "High"}}}]
        });
        mock.stub("POST", SEARCH, Step::json(200, &body)).await;

        let raw = client_for(&mock)
            .search_jql_raw(&SearchRequest::new(r#"project = "KAN""#))
            .await
            .expect("the search succeeds");

        assert_eq!(
            raw.issues[0]["fields"]["customfield_10001"],
            json!({"value": "High"})
        );

        // And the typed reader is not lossy either: the same field survives in
        // `other`, which is why `search_jql_raw` is a convenience and not a
        // correctness requirement.
        let typed: SearchPage = serde_json::from_value(body).expect("deserializes");
        assert_eq!(
            typed.issues[0].fields.field("customfield_10001"),
            Some(&json!({"value": "High"}))
        );
    }
}
