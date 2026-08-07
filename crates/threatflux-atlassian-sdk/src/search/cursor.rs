//! Iteration over an enhanced-search result set, one page token at a time.
//!
//! [`SearchCursor`] is the only thing in this crate that follows a
//! `nextPageToken`. Everything else — [`search_jql`](AtlassianClient::search_jql),
//! [`search_jql_raw`](AtlassianClient::search_jql_raw) — hands back the single
//! page Jira answered with and stops there.
//!
//! This module is private and re-exported by name, so the six-clause termination
//! contract is documented on [`SearchCursor`] itself rather than here: a module
//! page that rustdoc never renders is the wrong home for the part of this
//! milestone a caller most needs to read.

use std::collections::VecDeque;
use std::hash::{DefaultHasher, Hasher};

use tracing::debug;

use super::{SearchIssue, SearchLimits, SearchPage, SearchRequest};
use crate::client::AtlassianClient;
use crate::error::{AtlassianError, Result};

/// Page tokens a [`SearchCursor`] remembers when deciding clause 4.
///
/// Clause 4 has to compare a token against the ones the walk already followed,
/// not merely against the previous one, or a server cycling `A, B, A, B, ...`
/// walks without end. Remembering *every* token would make the cursor's memory a
/// function of how many pages a server chooses to serve, so the window is fixed:
/// the oldest entry is dropped once it is full.
///
/// A thousand pages is an order of magnitude past
/// [`DEFAULT_MAX_PAGES`](super::DEFAULT_MAX_PAGES), so under the default caps the
/// window can never fill and clause 4 is exact. A cycle whose period is longer
/// than this is left to the caps — and [`SearchLimits::unlimited`] removes those,
/// which is the one combination that can walk forever.
pub const MAX_REMEMBERED_PAGE_TOKENS: usize = 1_024;

/// Salts for the two halves of a [`TokenFingerprint`]. Arbitrary, and only
/// required to differ, so that the halves fail independently.
const FINGERPRINT_SALTS: (u64, u64) = (0x9e37_79b9_7f4a_7c15, 0xc2b2_ae3d_27d4_eb4f);

/// A fixed-size stand-in for a page token.
///
/// Jira's token is opaque and of a length the server chooses, so a window of
/// tokens is a window of unbounded size. A fingerprint costs sixteen bytes
/// whatever the token, which is what makes [`MAX_REMEMBERED_PAGE_TOKENS`] a
/// memory bound rather than a count.
///
/// Two independently salted 64-bit halves rather than one, because a collision
/// here does not merely miss a cycle: it *invents* one, and turns a healthy walk
/// into a hard error. At 128 bits that cannot happen by accident, and a page
/// token is not an adversary's to choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TokenFingerprint(u64, u64);

impl TokenFingerprint {
    /// The fingerprint of `token`.
    fn of(token: &str) -> Self {
        Self(
            hash_salted(FINGERPRINT_SALTS.0, token),
            hash_salted(FINGERPRINT_SALTS.1, token),
        )
    }
}

/// One salted 64-bit hash of `token`.
///
/// The length is written after the bytes so that no two distinct tokens share a
/// byte stream — the ordinary framing problem a bare `write` would leave open.
fn hash_salted(salt: u64, token: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write_u64(salt);
    hasher.write(token.as_bytes());
    hasher.write_usize(token.len());
    hasher.finish()
}

/// Records `token` in `seen`, dropping the oldest entry once the window is full.
///
/// A token already in the window is not recorded twice. Re-requesting a page
/// after a 503 sends the same token again, and a caller retrying in a loop would
/// otherwise fill the window with one fingerprint and evict the history clause 4
/// decides against.
///
/// The scan is linear in the window, which is a thousand sixteen-byte
/// comparisons against a network round trip.
fn remember(seen: &mut VecDeque<TokenFingerprint>, token: &str) {
    let fingerprint = TokenFingerprint::of(token);
    if seen.contains(&fingerprint) {
        return;
    }
    if seen.len() >= MAX_REMEMBERED_PAGE_TOKENS {
        seen.pop_front();
    }
    seen.push_back(fingerprint);
}

/// Why a [`SearchCursor`] stopped.
///
/// Reported by [`SearchCursor::terminated_reason`] for a caller driving the
/// cursor by hand. A caller that only holds the `Result` of a failed
/// [`next_page`](SearchCursor::next_page) does not need this: the two failure
/// modes it would want to tell apart are already distinct error variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TerminationReason {
    /// Jira answered with no further page token: the result set was walked to
    /// its end.
    Exhausted,

    /// A [`SearchLimits`] cap stopped the walk with pages still to fetch. The
    /// issues delivered so far are a prefix of the answer, not the answer.
    Capped,

    /// A page token was rejected mid-iteration.
    ///
    /// The iteration is over and cannot be continued. See
    /// [`SearchCursor`](SearchCursor#expired-page-tokens) for why resuming in
    /// place is not offered.
    PageTokenExpired,
}

/// How a cursor stopped, including the two ways that are failures.
///
/// [`TerminationReason`] is the caller-facing half of this; the extra state here
/// is what lets a stopped cursor keep answering the same way rather than
/// quietly restarting or reporting a refusal as a clean end of iteration.
#[derive(Debug)]
enum Stop {
    /// Iteration finished. Further calls report no more pages.
    Ended(TerminationReason),

    /// A Jira-issued page token was rejected. Further calls repeat the refusal.
    Expired {
        /// Index of the page the rejected token asked for.
        page_index: usize,
    },

    /// The endpoint could not make progress. Further calls repeat the refusal.
    Refused(Box<AtlassianError>),
}

/// Walks an enhanced-search result set page by page.
///
/// Built from a client and a [`SearchRequest`] with
/// [`AtlassianClient::search_cursor`], and borrows the client for as long as it
/// lives. The request is validated on the first
/// [`next_page`](Self::next_page) rather than at construction, so building a
/// cursor costs nothing and cannot fail.
///
/// # The termination contract
///
/// When iteration stops, and why, is the whole of this type. Six clauses, each
/// of which is a way a caller can silently get a wrong answer if it is left
/// implicit:
///
/// 1. **The token is the sole authority.** Iteration stops when, and only when,
///    a page carries no `nextPageToken` — an absent token, or an empty-string
///    one, which Jira reads as "no token" and answers with page one.
/// 2. **`isLast` is advisory.** A page that claims to be last while handing back
///    a token is followed anyway, with a warning; so is the reverse.
///    [`SearchPage::is_last`](super::SearchPage::is_last) never decides.
/// 3. **An empty page is not the end.** A page with no issues and a token is an
///    ordinary intermediate page. Stopping there is the classic `/search/jql`
///    migration bug: it reports "nothing matched" for a result set whose matches
///    are one page further on, and in a dedupe check that mints a duplicate.
/// 4. **A token the walk has already followed is a hard error.** A token handed
///    straight back means the next request would ask the identical question. A
///    token from further back means the walk is going round a ring: `A, B, A,
///    B, ...` never repeats a token *immediately*, so a check against the
///    previous request alone would follow it until something else stopped it.
///    Both are refused rather than spun on. The comparison covers the last
///    [`MAX_REMEMBERED_PAGE_TOKENS`] tokens the cursor sent, which is an order of
///    magnitude past [`DEFAULT_MAX_PAGES`](super::DEFAULT_MAX_PAGES); a ring
///    longer than that is left to the caps of clause 5, and
///    [`SearchLimits::unlimited`] removes those, which is the one combination
///    under which a cursor can walk without end.
/// 5. **A cap is a refusal, not a shorter answer.** Hitting a [`SearchLimits`]
///    cap sets [`truncated`](Self::truncated), and makes
///    [`try_collect`](Self::try_collect) and [`find_first`](Self::find_first)
///    fail rather than hand back a partial result set that reads like a
///    complete one.
/// 6. **An expired page token ends the iteration and is never resumed.** Page
///    tokens are time-limited; see below.
///
/// # Expired page tokens
///
/// A `/search/jql` page token has a lifetime measured in minutes, so a long
/// [`try_collect`](Self::try_collect) or a consumer that does slow work between
/// pages can take a 400 *part-way through* an iteration that began healthily.
/// That 400 and a malformed-JQL 400 demand opposite responses — one says
/// restart the search, the other says fix the query — so the cursor
/// distinguishes them and reports the first as
/// [`AtlassianError::PageTokenExpired`].
///
/// The classification is **structural rather than message-matching**: a 400 is
/// an expired token only when the failing request carried a token *Jira itself
/// issued to this cursor*, which is to say on the second page or later. A 400 on
/// the first request is always a query error, including when the caller seeded
/// the cursor with a token of its own — that token was not issued to this
/// iteration, so the cursor will not claim to know why Jira rejected it. Nothing
/// here reads Atlassian's error text, so nothing here breaks when Atlassian
/// rewords it.
///
/// A cursor that has taken an expired token is finished. It does not re-request
/// the page, and it does not silently start over: restarting an iteration walks
/// a result set that has been changing underneath it, so the pages already
/// delivered and the pages still to come would answer the query as it stood at
/// two different instants. Stitching them together produces a set that was never
/// the answer at any instant — rows shifting between pages are counted twice or
/// missed entirely — and a caller reconciling over it acts on it believing it is
/// complete. Recovery is the caller's deliberate act: build a fresh cursor,
/// discard what the abandoned one delivered, and walk again from page one.
///
/// # What it is not
///
/// It is not a [`Stream`](https://docs.rs/futures-core), deliberately: an
/// async iterator borrowing its client needs a self-referential boxed future and
/// a dependency this workspace does not otherwise carry, to deliver what
/// `while let Some(page) = cursor.next_page().await?` already delivers. Adding
/// the impl later is additive.
///
/// It is also not a retry loop. A failure that is neither a repeated token nor
/// an expired one — a 503, a timeout — leaves the cursor exactly where it was,
/// on the same unspent token, so a caller that wants to re-request that page
/// calls [`next_page`](Self::next_page) again. The two failures the cursor does
/// treat as terminal are terminal because retrying them cannot work: a repeated
/// token asks the identical question forever, and an expired token is expired
/// for good.
///
/// # Example
/// ```rust,no_run
/// use threatflux_atlassian_sdk::AtlassianClient;
/// use threatflux_atlassian_sdk::error::AtlassianError;
/// use threatflux_atlassian_sdk::search::SearchRequest;
///
/// # tokio_test::block_on(async {
/// # let client = AtlassianClient::from_env().unwrap();
/// let request = SearchRequest::new(r#"project = "KAN" ORDER BY created ASC"#)
///     .with_fields(["summary", "labels"]);
/// let mut cursor = client.search_cursor(&request);
///
/// loop {
///     match cursor.next_page().await {
///         Ok(Some(page)) => {
///             for issue in &page.issues {
///                 println!("{}", issue.key);
///             }
///         }
///         Ok(None) => break,
///         // The token ran out of time. Start a fresh cursor and walk again;
///         // do not carry the pages already delivered into the new walk.
///         Err(AtlassianError::PageTokenExpired { page_index }) => {
///             println!("page token expired at page {page_index}; restart from page one");
///             break;
///         }
///         Err(error) => panic!("the search failed: {error}"),
///     }
/// }
/// # });
/// ```
#[derive(Debug)]
pub struct SearchCursor<'a> {
    /// The client every page is fetched through.
    client: &'a AtlassianClient,

    /// The request, with its page token replaced before each fetch after the
    /// first.
    request: SearchRequest,

    /// How far the walk may go.
    limits: SearchLimits,

    /// Pages successfully fetched, which is also the index of the next one.
    pages_fetched: usize,

    /// Issues delivered so far, across every page.
    issues_seen: usize,

    /// Fingerprints of the last [`MAX_REMEMBERED_PAGE_TOKENS`] tokens this
    /// cursor sent, oldest first. Clause 4 is decided against this.
    followed_tokens: VecDeque<TokenFingerprint>,

    /// Set once the cursor has stopped, and never cleared.
    stop: Option<Stop>,
}

impl AtlassianClient {
    /// Builds a [`SearchCursor`] that walks every page `request` matches.
    ///
    /// The cursor starts from `request` exactly as given, page token included:
    /// seeding one with a token resumes an iteration a previous cursor reported,
    /// with the caveat in
    /// [Expired page tokens](SearchCursor#expired-page-tokens).
    ///
    /// Caps come from [`SearchLimits::default`]; change them with
    /// [`SearchCursor::with_limits`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::search::{SearchLimits, SearchRequest};
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let request = SearchRequest::new(r#"labels = "gh-901234-77""#);
    /// let issues = client
    ///     .search_cursor(&request)
    ///     .with_limits(SearchLimits::default().with_max_issues(Some(200)))
    ///     .try_collect()
    ///     .await
    ///     .unwrap();
    ///
    /// println!("{} issue(s)", issues.len());
    /// # });
    /// ```
    pub fn search_cursor(&self, request: &SearchRequest) -> SearchCursor<'_> {
        SearchCursor {
            client: self,
            request: request.clone(),
            limits: SearchLimits::default(),
            pages_fetched: 0,
            issues_seen: 0,
            followed_tokens: VecDeque::new(),
            stop: None,
        }
    }
}

impl SearchCursor<'_> {
    /// Replaces the caps this cursor walks under.
    ///
    /// Applies from the next fetch on, so raising a cap a cursor has already
    /// stopped at does not restart it — build a new cursor for that.
    #[must_use]
    pub const fn with_limits(mut self, limits: SearchLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Fetches the next page, or reports that there is not one.
    ///
    /// `Ok(None)` means iteration is over; ask
    /// [`terminated_reason`](Self::terminated_reason) whether that was the end
    /// of the result set or a cap. Every clause of the
    /// [termination contract](Self#the-termination-contract) is decided here.
    ///
    /// # Errors
    ///
    /// [`AtlassianError::PageTokenExpired`] when a token this cursor was issued
    /// is rejected: the iteration is finished, and every later call repeats this
    /// error rather than resuming or restarting.
    ///
    /// [`AtlassianError::JiraApi`] when Jira answers with a page token this
    /// iteration has already followed — the one it was just given, or an earlier
    /// one within the [`MAX_REMEMBERED_PAGE_TOKENS`] window — which no further
    /// request could make progress against. That refusal is also terminal and is
    /// likewise repeated.
    ///
    /// Otherwise whatever [`search_jql`](AtlassianClient::search_jql) returns —
    /// including [`AtlassianError::Validation`] on the first call if the request
    /// is not sendable — leaving the cursor on the same token and free to try
    /// the page again.
    pub async fn next_page(&mut self) -> Result<Option<SearchPage>> {
        if let Some(stop) = &self.stop {
            return match stop {
                Stop::Ended(_) => Ok(None),
                Stop::Expired { page_index } => Err(AtlassianError::PageTokenExpired {
                    page_index: *page_index,
                }),
                Stop::Refused(error) => Err((**error).clone()),
            };
        }

        // Clause 5: the caps are checked between pages, so reaching one is
        // always "there is more, and this cursor will not go and get it".
        if self.limits.page_cap_reached(self.pages_fetched)
            || self.limits.issue_cap_reached(self.issues_seen)
        {
            debug!(
                "Enhanced-search iteration stopped at a cap after {} page(s) and {} issue(s)",
                self.pages_fetched, self.issues_seen
            );
            self.stop = Some(Stop::Ended(TerminationReason::Capped));
            return Ok(None);
        }

        let page_index = self.pages_fetched;
        // Kept so a page that echoes it can be recognised. It is Jira's opaque
        // blob and never reaches a log or an error message.
        let sent_token = self.request.next_page_token().map(str::to_owned);
        // Recorded before the fetch, so a token the walk followed is remembered
        // whether the answer to it is a page or a failure.
        if let Some(token) = sent_token.as_deref() {
            remember(&mut self.followed_tokens, token);
        }

        let page = match self.client.search_jql(&self.request).await {
            Ok(page) => page,
            Err(error) => return Err(self.classify_failure(page_index, error)),
        };

        self.pages_fetched += 1;
        self.issues_seen += page.issues.len();

        // Clause 1: the token decides. Clause 2 needs no code — `search_jql`
        // warns about a contradicting `isLast` and nothing reads it. Clause 3 is
        // the absence of an `issues.is_empty()` test here.
        match page.next_token() {
            None => {
                debug!(
                    "Enhanced-search iteration reached the end of the result set after {} page(s) and {} issue(s)",
                    self.pages_fetched, self.issues_seen
                );
                self.stop = Some(Stop::Ended(TerminationReason::Exhausted));
            }
            // Clause 4, the immediate case. Compared exactly rather than by
            // fingerprint, because this is the one the contract names first and
            // the token is still to hand.
            Some(token) if sent_token.as_deref() == Some(token) => {
                let error = AtlassianError::jira_api(
                    format!(
                        "enhanced search answered page {page_index} with the page token it had just been given, so another request would ask the same question again"
                    ),
                    None,
                );
                self.stop = Some(Stop::Refused(Box::new(error.clone())));
                return Err(error);
            }
            // Clause 4, the ring. Nothing about the token itself reaches the
            // message: the page index says where the walk closed on itself, and
            // that is all a caller can act on anyway.
            Some(token) if self.followed_tokens.contains(&TokenFingerprint::of(token)) => {
                let error = AtlassianError::jira_api(
                    format!(
                        "enhanced search answered page {page_index} with a page token this iteration has already followed, so the walk is going round a cycle rather than advancing"
                    ),
                    None,
                );
                self.stop = Some(Stop::Refused(Box::new(error.clone())));
                return Err(error);
            }
            Some(token) => {
                let token = token.to_owned();
                self.request.set_next_page_token(Some(token));
            }
        }

        Ok(Some(page))
    }

    /// Walks every remaining page and returns the issues on them.
    ///
    /// # A cap fails rather than truncating
    ///
    /// Clause 5 of the contract, and the reason this is `try_collect` rather
    /// than `collect`: a bulk caller reads the returned `Vec` as *the* set of
    /// matching issues. Handing back the first 5 000 of 12 000 would answer a
    /// question nobody asked, and the caller most likely to hit a cap — one
    /// deciding whether an issue already exists — is the one a partial answer
    /// misleads worst.
    ///
    /// Collection starts from wherever the cursor is, so calling this after
    /// [`next_page`](Self::next_page) returns the *rest* of the result set.
    ///
    /// # Errors
    ///
    /// [`AtlassianError::JiraApi`] if a cap stopped the walk with pages left, and
    /// whatever [`next_page`](Self::next_page) returns otherwise.
    pub async fn try_collect(&mut self) -> Result<Vec<SearchIssue>> {
        let mut collected = Vec::new();

        while let Some(page) = self.next_page().await? {
            collected.extend(page.issues);
        }

        self.refuse_if_capped()?;
        Ok(collected)
    }

    /// Returns the first issue in the result set, or `None` when there is none.
    ///
    /// Walks *past empty pages* — clause 3 — because an empty page with a token
    /// is not proof that nothing matched, and never walks past a page that
    /// carried an issue.
    ///
    /// Which issue is first is Jira's ordering, so a caller that means "oldest"
    /// or "most recently updated" says so in the query's `ORDER BY`.
    ///
    /// # Errors
    ///
    /// [`AtlassianError::JiraApi`] if a cap stopped the walk before an issue was
    /// found: `None` here reads as "no such issue", and a cap is not evidence of
    /// that. Otherwise whatever [`next_page`](Self::next_page) returns.
    pub async fn find_first(&mut self) -> Result<Option<SearchIssue>> {
        while let Some(page) = self.next_page().await? {
            if let Some(issue) = page.issues.into_iter().next() {
                return Ok(Some(issue));
            }
        }

        self.refuse_if_capped()?;
        Ok(None)
    }

    /// Whether iteration stopped at a cap with pages still to fetch.
    ///
    /// True only for [`TerminationReason::Capped`]. A cursor that walked the
    /// result set to its end reports `false` even if it delivered more issues
    /// than [`SearchLimits::max_issues`] allowed — the caps are checked between
    /// pages, and an answer that is complete is not truncated.
    pub const fn truncated(&self) -> bool {
        matches!(self.stop, Some(Stop::Ended(TerminationReason::Capped)))
    }

    /// Why iteration stopped, or `None` while it is still going.
    ///
    /// Also `None` for a cursor stopped by a refusal that is not a token
    /// expiry — the repeated-token error of clause 4 — because that refusal was
    /// already returned to the caller as an `Err`, and a
    /// [`TerminationReason`] would be a second, weaker copy of it.
    pub const fn terminated_reason(&self) -> Option<TerminationReason> {
        match &self.stop {
            Some(Stop::Ended(reason)) => Some(*reason),
            Some(Stop::Expired { .. }) => Some(TerminationReason::PageTokenExpired),
            Some(Stop::Refused(_)) | None => None,
        }
    }

    /// Records a failed fetch and returns the error the caller should see.
    ///
    /// Clause 6 lives here. The test is structural — a 400 on any page after the
    /// first carried a token Jira issued to this cursor — and reads nothing out
    /// of the response body, so it neither depends on Atlassian's error wording
    /// nor lets that wording into an error message.
    fn classify_failure(&mut self, page_index: usize, error: AtlassianError) -> AtlassianError {
        if page_index > 0 && response_status(&error) == Some(400) {
            debug!(
                "Enhanced-search page token rejected at page {page_index}; the iteration cannot be resumed"
            );
            self.stop = Some(Stop::Expired { page_index });
            return AtlassianError::PageTokenExpired { page_index };
        }

        // Anything else leaves the cursor usable: the token was not spent, and
        // re-requesting the same page is a legitimate response to a 503.
        error
    }

    /// Fails when the walk stopped at a cap, and does nothing otherwise.
    fn refuse_if_capped(&self) -> Result<()> {
        if !self.truncated() {
            return Ok(());
        }

        let cap = if self.limits.page_cap_reached(self.pages_fetched) {
            self.limits
                .max_pages()
                .map_or_else(|| "page cap".to_owned(), |cap| format!("page cap of {cap}"))
        } else {
            self.limits.max_issues().map_or_else(
                || "issue cap".to_owned(),
                |cap| format!("issue cap of {cap}"),
            )
        };

        Err(AtlassianError::jira_api(
            format!(
                "enhanced search stopped at its {cap} after {} page(s) and {} issue(s), with the result set unfinished; a partial answer is not an answer, so narrow the query or raise the cap deliberately",
                self.pages_fetched, self.issues_seen
            ),
            None,
        ))
    }
}

/// The HTTP status behind `error`, when it came from a response.
///
/// Reads the diagnostics record first because it is populated under every
/// [`DiagnosticsPolicy`](crate::error::DiagnosticsPolicy), the default one
/// included, and falls back to the status each variant carries in its own shape
/// so an error built by hand classifies the same way as one built from a
/// response.
fn response_status(error: &AtlassianError) -> Option<u16> {
    if let Some(status) = error
        .diagnostics()
        .and_then(|diagnostics| diagnostics.status)
    {
        return Some(status);
    }

    match error {
        AtlassianError::Http { status_code, .. } => *status_code,
        AtlassianError::JiraApi { code, .. } => code.and_then(|code| u16::try_from(code).ok()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        remember, SearchCursor, TerminationReason, TokenFingerprint, MAX_REMEMBERED_PAGE_TOKENS,
    };
    use crate::config::{AtlassianConfig, HostPolicy};
    use crate::error::AtlassianError;
    use crate::search::{SearchLimits, SearchRequest};
    use crate::AtlassianClient;
    use serde_json::{json, Value};
    use std::collections::VecDeque;
    use std::future::Future;
    use threatflux_atlassian_testkit::jira_mock::{JiraMock, Step};
    use threatflux_atlassian_testkit::logs;

    const SEARCH: &str = "/rest/api/3/search/jql";

    /// A client pointed at a loopback mock.
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

    fn request() -> SearchRequest {
        SearchRequest::new(r#"labels = "gh-901234-77""#)
    }

    fn issue(id: &str, key: &str) -> Value {
        json!({"id": id, "key": key, "fields": {"summary": "Bump openssl"}})
    }

    /// A page carrying `issues`, and a token when one is given.
    ///
    /// `isLast` agrees with the token here; a test that wants them to disagree
    /// builds its page by hand.
    fn page(issues: &[Value], token: Option<&str>) -> Value {
        let mut body = json!({"issues": issues, "isLast": token.is_none()});
        if let Some(token) = token {
            body["nextPageToken"] = json!(token);
        }
        body
    }

    /// The keys of `issues`, in order.
    fn keys(issues: &[crate::search::SearchIssue]) -> Vec<&str> {
        issues.iter().map(|issue| issue.key.as_str()).collect()
    }

    /// The `nextPageToken` each recorded request carried, in order.
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

    /// Runs `body` on a current-thread runtime with every `tracing` event captured.
    ///
    /// The subscriber `logs::capture` installs is thread-local, so the future has
    /// to be driven on the thread that installed it.
    fn capture_async<T>(body: impl Future<Output = T>) -> (T, String) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime should build");
        logs::capture(|| runtime.block_on(body))
    }

    // ------------------------------------------------------------------
    // Clause 1 — the page token is the sole authority on whether to go on.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn clause_1_an_absent_token_ends_the_iteration() {
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            SEARCH,
            Step::json(200, &page(&[issue("10042", "KAN-42")], None)),
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&request());

        let first = cursor.next_page().await.expect("the first page arrives");
        assert_eq!(first.expect("a page").issues.len(), 1);
        assert!(
            cursor.next_page().await.expect("iteration ends").is_none(),
            "a page with no token is the last page"
        );
        assert_eq!(
            cursor.terminated_reason(),
            Some(TerminationReason::Exhausted)
        );
        assert!(!cursor.truncated());
        mock.assert_call_count("POST", SEARCH, 1).await;
    }

    #[tokio::test]
    async fn clause_1_an_empty_token_ends_the_iteration_rather_than_restarting_it() {
        // Jira reads a blank token as "no token" and answers with page one, so
        // honouring one would walk the first page forever.
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            SEARCH,
            Step::json(
                200,
                &json!({"issues": [issue("10042", "KAN-42")], "nextPageToken": "", "isLast": false}),
            ),
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&request());
        let collected = cursor.try_collect().await.expect("the walk succeeds");

        assert_eq!(collected.len(), 1);
        assert_eq!(
            cursor.terminated_reason(),
            Some(TerminationReason::Exhausted)
        );
        mock.assert_call_count("POST", SEARCH, 1).await;
    }

    // ------------------------------------------------------------------
    // Clause 2 — `isLast` is advisory; a disagreement is logged, not obeyed.
    // ------------------------------------------------------------------

    #[test]
    fn clause_2_an_is_last_that_contradicts_the_token_is_warned_about_and_ignored() {
        let ((collected, reason), log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.script(
                "POST",
                SEARCH,
                vec![
                    // "Last page" — and here is a token for the next one.
                    Step::json(
                        200,
                        &json!({"issues": [issue("10042", "KAN-42")],
                                "nextPageToken": "page-2", "isLast": true}),
                    ),
                    // "Not the last page" — and no token to reach another.
                    Step::json(
                        200,
                        &json!({"issues": [issue("10043", "KAN-43")], "isLast": false}),
                    ),
                ],
            )
            .await;

            let client = client_for(&mock);
            let mut cursor = client.search_cursor(&request());
            let collected = cursor.try_collect().await.expect("the walk succeeds");
            let reason = cursor.terminated_reason();
            mock.assert_call_count("POST", SEARCH, 2).await;
            (collected, reason)
        });

        assert_eq!(
            keys(&collected),
            vec!["KAN-42", "KAN-43"],
            "the token decides in both directions"
        );
        assert_eq!(reason, Some(TerminationReason::Exhausted));
        assert!(log.contains("contradicts its page token"), "log was: {log}");
    }

    // ------------------------------------------------------------------
    // Clause 3 — an empty page carrying a token is an intermediate page.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn clause_3_an_empty_page_with_a_token_does_not_end_the_iteration() {
        // The classic `/search/jql` migration bug. Reading an empty page as "no
        // matches" reports nothing tracked for an issue that is tracked, and the
        // caller mints a duplicate.
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
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

        assert_eq!(keys(&collected), vec!["KAN-42"]);
        assert_eq!(
            cursor.terminated_reason(),
            Some(TerminationReason::Exhausted)
        );
        assert_eq!(
            sent_tokens(&mock).await,
            vec![None, Some("page-2".to_owned()), Some("page-3".to_owned())],
            "each request must echo the token the page before it carried"
        );
    }

    #[tokio::test]
    async fn clause_3_find_first_walks_past_empty_pages_and_stops_at_the_first_issue() {
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
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

        assert_eq!(found.map(|issue| issue.key), Some("KAN-42".to_owned()));
        mock.assert_call_count("POST", SEARCH, 2).await;
    }

    #[tokio::test]
    async fn find_first_reports_none_only_when_the_result_set_was_walked_out() {
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
            .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&request());

        assert!(cursor
            .find_first()
            .await
            .expect("the walk succeeds")
            .is_none());
        assert_eq!(
            cursor.terminated_reason(),
            Some(TerminationReason::Exhausted)
        );
    }

    // ------------------------------------------------------------------
    // Clause 4 — a repeated token is a refusal, not a spin.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn clause_4_a_repeated_page_token_is_a_hard_error_and_is_terminal() {
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            SEARCH,
            Step::json(200, &page(&[issue("10042", "KAN-42")], Some("stuck"))),
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
            .expect_err("a token Jira just issued cannot be followed again");

        assert!(
            matches!(error, AtlassianError::JiraApi { ref message, .. }
                if message.contains("just been given")),
            "unexpected error {error:?}"
        );
        assert_eq!(
            cursor.terminated_reason(),
            None,
            "a refusal is not a termination reason; the caller already holds the error"
        );
        assert!(!cursor.truncated());

        // Terminal: the refusal repeats and costs no further round trip.
        let again = cursor.next_page().await.expect_err("the refusal repeats");
        assert!(matches!(again, AtlassianError::JiraApi { .. }));
        mock.assert_call_count("POST", SEARCH, 2).await;
    }

    #[tokio::test]
    async fn clause_4_a_two_token_cycle_is_a_hard_error_too() {
        // `A, B, A, B, ...` never repeats a token *immediately*, so a check
        // against the previous request alone walks it to the page cap — or, under
        // `SearchLimits::unlimited`, forever.
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-a"))),
                Step::json(200, &page(&[issue("10043", "KAN-43")], Some("page-b"))),
                Step::json(200, &page(&[issue("10044", "KAN-44")], Some("page-a"))),
                // Never reached: the cycle is recognised on the third answer.
                Step::json(200, &page(&[issue("10045", "KAN-45")], Some("page-b"))),
            ],
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&request());
        let error = cursor
            .try_collect()
            .await
            .expect_err("a walk going round a cycle cannot be collected");

        assert!(
            matches!(error, AtlassianError::JiraApi { ref message, .. }
                if message.contains("already followed")),
            "unexpected error {error:?}"
        );
        assert!(!cursor.truncated(), "a cycle is a refusal, not a cap");
        mock.assert_call_count("POST", SEARCH, 3).await;

        // Terminal, exactly like the immediate repeat, and costing no round trip.
        let again = cursor.next_page().await.expect_err("the refusal repeats");
        assert_eq!(again.to_string(), error.to_string());
        mock.assert_call_count("POST", SEARCH, 3).await;
    }

    #[tokio::test]
    async fn clause_4_a_long_cycle_is_caught_up_to_the_remembered_window() {
        // A cycle whose period is inside the window is caught by the token check
        // rather than by a cap, which is what makes the refusal survive
        // `SearchLimits::unlimited`.
        let period = 8;
        let mut steps: Vec<Step> = (0..period)
            .map(|index| {
                Step::json(
                    200,
                    &page(&[issue("10042", "KAN-42")], Some(&format!("page-{index}"))),
                )
            })
            .collect();
        // Back to the first token: the walk is a ring.
        steps.push(Step::json(
            200,
            &page(&[issue("10042", "KAN-42")], Some("page-0")),
        ));
        assert!(period < MAX_REMEMBERED_PAGE_TOKENS);

        let mock = JiraMock::start().await;
        mock.script("POST", SEARCH, steps).await;

        let client = client_for(&mock);
        let mut cursor = client
            .search_cursor(&request())
            .with_limits(SearchLimits::unlimited());
        let error = cursor.try_collect().await.expect_err("the ring is refused");

        assert!(
            matches!(error, AtlassianError::JiraApi { ref message, .. }
                if message.contains("already followed")),
            "unexpected error {error:?}"
        );
        mock.assert_call_count("POST", SEARCH, period + 1).await;
    }

    #[tokio::test]
    async fn clause_4_a_walk_of_distinct_tokens_past_the_window_is_not_refused() {
        // The window is a bound on memory, not a bound on the walk: a healthy
        // iteration longer than it must not be mistaken for a cycle.
        let pages = 12;
        let mut steps: Vec<Step> = (0..pages)
            .map(|index| {
                Step::json(
                    200,
                    &page(&[issue("10042", "KAN-42")], Some(&format!("page-{index}"))),
                )
            })
            .collect();
        steps.push(Step::json(200, &page(&[issue("10043", "KAN-43")], None)));

        let mock = JiraMock::start().await;
        mock.script("POST", SEARCH, steps).await;

        let client = client_for(&mock);
        let mut cursor = client
            .search_cursor(&request())
            .with_limits(SearchLimits::unlimited());
        let collected = cursor.try_collect().await.expect("the walk succeeds");

        assert_eq!(collected.len(), pages + 1);
        assert_eq!(
            cursor.terminated_reason(),
            Some(TerminationReason::Exhausted)
        );
    }

    #[test]
    fn a_token_fingerprint_separates_tokens_that_differ_anywhere() {
        // The fingerprint is what stands in for the token, so a pair the hash
        // cannot tell apart would be a cycle reported on a healthy walk.
        let tokens = [
            "", "a", "b", "ab", "a\0b", "ab\0", "\0ab", "page-1", "page-10", "page-2",
        ];
        for (index, left) in tokens.iter().enumerate() {
            for right in &tokens[index + 1..] {
                assert_ne!(
                    TokenFingerprint::of(left),
                    TokenFingerprint::of(right),
                    "{left:?} and {right:?} fingerprint alike"
                );
            }
            assert_eq!(TokenFingerprint::of(left), TokenFingerprint::of(left));
        }
    }

    #[test]
    fn the_remembered_window_is_bounded() {
        let mut seen: VecDeque<TokenFingerprint> = VecDeque::new();
        for index in 0..MAX_REMEMBERED_PAGE_TOKENS * 3 {
            remember(&mut seen, &format!("page-{index}"));
            assert!(seen.len() <= MAX_REMEMBERED_PAGE_TOKENS);
        }

        assert_eq!(seen.len(), MAX_REMEMBERED_PAGE_TOKENS);
        assert!(
            !seen.contains(&TokenFingerprint::of("page-0")),
            "the oldest fingerprint must have been evicted"
        );

        // A token re-sent after a retryable failure must not cost a slot, or a
        // caller retrying in a loop would evict the history clause 4 needs.
        let resent = format!("page-{}", MAX_REMEMBERED_PAGE_TOKENS * 3 - 1);
        assert!(seen.contains(&TokenFingerprint::of(&resent)));
        let oldest = seen.front().copied().expect("the window is not empty");
        for _ in 0..MAX_REMEMBERED_PAGE_TOKENS {
            remember(&mut seen, &resent);
        }
        assert_eq!(seen.len(), MAX_REMEMBERED_PAGE_TOKENS);
        assert_eq!(seen.front().copied(), Some(oldest));
    }

    // ------------------------------------------------------------------
    // Clause 5 — a cap is a refusal to answer, not a shorter answer.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn clause_5_a_page_cap_sets_truncated_and_fails_a_collect() {
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
                Step::json(200, &page(&[issue("10043", "KAN-43")], Some("page-3"))),
                Step::json(200, &page(&[issue("10044", "KAN-44")], None)),
            ],
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client
            .search_cursor(&request())
            .with_limits(SearchLimits::default().with_max_pages(Some(2)));

        let error = cursor
            .try_collect()
            .await
            .expect_err("a capped walk must not hand back a prefix as the answer");

        assert!(
            matches!(error, AtlassianError::JiraApi { ref message, .. }
                if message.contains("page cap of 2")),
            "unexpected error {error:?}"
        );
        assert!(cursor.truncated());
        assert_eq!(cursor.terminated_reason(), Some(TerminationReason::Capped));
        mock.assert_call_count("POST", SEARCH, 2).await;
    }

    #[tokio::test]
    async fn clause_5_a_cap_fails_a_find_rather_than_reporting_no_such_issue() {
        // `find_first` returning `None` at a cap would read as "no such issue",
        // which is the wrong answer a cap must never be allowed to produce.
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[], Some("page-2"))),
                Step::json(200, &page(&[], Some("page-3"))),
            ],
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client
            .search_cursor(&request())
            .with_limits(SearchLimits::unlimited().with_max_pages(Some(2)));

        let error = cursor
            .find_first()
            .await
            .expect_err("a cap is not a `None`");

        assert!(
            matches!(error, AtlassianError::JiraApi { ref message, .. }
                if message.contains("page cap of 2")),
            "unexpected error {error:?}"
        );
        assert!(cursor.truncated());
    }

    #[tokio::test]
    async fn clause_5_an_issue_cap_stops_the_walk_at_the_next_page_boundary() {
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
                Step::json(200, &page(&[issue("10043", "KAN-43")], Some("page-3"))),
            ],
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client
            .search_cursor(&request())
            .with_limits(SearchLimits::unlimited().with_max_issues(Some(1)));

        let error = cursor.try_collect().await.expect_err("the cap refuses");

        assert!(
            matches!(error, AtlassianError::JiraApi { ref message, .. }
                if message.contains("issue cap of 1")),
            "unexpected error {error:?}"
        );
        assert!(cursor.truncated());
        mock.assert_call_count("POST", SEARCH, 1).await;
    }

    #[tokio::test]
    async fn clause_5_a_walk_that_ends_exactly_at_its_cap_is_not_truncated() {
        // A cap reached at the same moment the result set ran out is a complete
        // answer, and reporting it as truncated would fail a correct walk.
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

        let client = client_for(&mock);
        let mut cursor = client
            .search_cursor(&request())
            .with_limits(SearchLimits::default().with_max_pages(Some(2)));

        let collected = cursor.try_collect().await.expect("the walk succeeds");

        assert_eq!(keys(&collected), vec!["KAN-42", "KAN-43"]);
        assert!(!cursor.truncated());
        assert_eq!(
            cursor.terminated_reason(),
            Some(TerminationReason::Exhausted)
        );
    }

    #[tokio::test]
    async fn clause_5_a_zero_page_cap_stops_before_any_request() {
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
            .await;

        let client = client_for(&mock);
        let mut cursor = client
            .search_cursor(&request())
            .with_limits(SearchLimits::default().with_max_pages(Some(0)));

        assert!(cursor.next_page().await.expect("no page is due").is_none());
        assert!(cursor.truncated());
        assert!(mock.journal().await.is_empty());
    }

    // ------------------------------------------------------------------
    // Clause 6 — an expired page token ends the walk and is never resumed.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn clause_6_a_400_on_a_later_page_is_reported_as_an_expired_token() {
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
                Step::json(
                    400,
                    &json!({"errorMessages": ["The page token is invalid or has expired"]}),
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
        let error = cursor.next_page().await.expect_err("the token is rejected");

        assert!(
            matches!(error, AtlassianError::PageTokenExpired { page_index: 1 }),
            "unexpected error {error:?}"
        );
        assert_eq!(
            cursor.terminated_reason(),
            Some(TerminationReason::PageTokenExpired)
        );
        assert!(!cursor.truncated());
    }

    #[tokio::test]
    async fn clause_6_an_expired_token_is_never_retried_or_resumed() {
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
                Step::json(400, &json!({"errorMessages": ["token expired"]})),
                // Never reached. If the cursor re-requested the page or started
                // over, this step would make the failure look survivable.
                Step::json(200, &page(&[issue("10043", "KAN-43")], None)),
            ],
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&request());

        cursor.next_page().await.expect("the first page arrives");
        cursor.next_page().await.expect_err("the token is rejected");

        for _ in 0..3 {
            let again = cursor
                .next_page()
                .await
                .expect_err("a finished cursor stays finished");
            assert!(
                matches!(again, AtlassianError::PageTokenExpired { page_index: 1 }),
                "unexpected error {again:?}"
            );
        }

        assert!(
            cursor
                .try_collect()
                .await
                .expect_err("a collect on a finished cursor fails too")
                .to_string()
                .contains("start the search again from its first page"),
            "the error must say how to recover"
        );
        mock.assert_call_count("POST", SEARCH, 2).await;
    }

    #[tokio::test]
    async fn clause_6_the_expiry_is_visible_to_a_caller_holding_only_the_result() {
        // The point of the variant: "your token expired, walk again from page
        // one" and "your JQL is wrong, fix the query" arrive as the same HTTP
        // 400 and call for opposite responses. A caller that never touches the
        // cursor still has to be able to tell them apart.
        async fn walk(steps: Vec<Step>) -> Result<Vec<String>, AtlassianError> {
            let mock = JiraMock::start().await;
            mock.script("POST", SEARCH, steps).await;
            let client = client_for(&mock);
            client
                .search_cursor(&request())
                .try_collect()
                .await
                .map(|issues| issues.into_iter().map(|issue| issue.key).collect())
        }

        let expired = walk(vec![
            Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
            Step::json(400, &json!({"errorMessages": ["token expired"]})),
        ])
        .await
        .expect_err("the second page fails");

        let bad_jql = walk(vec![Step::json(
            400,
            &json!({"errorMessages": ["Field 'nope' does not exist"]}),
        )])
        .await
        .expect_err("the first page fails");

        assert!(
            matches!(expired, AtlassianError::PageTokenExpired { page_index: 1 }),
            "unexpected error {expired:?}"
        );
        assert!(
            matches!(
                bad_jql,
                AtlassianError::JiraApi {
                    code: Some(400),
                    ..
                }
            ),
            "unexpected error {bad_jql:?}"
        );
    }

    #[tokio::test]
    async fn clause_6_a_400_on_the_first_page_is_a_query_error_not_an_expiry() {
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            SEARCH,
            Step::json(
                400,
                &json!({"errorMessages": ["Field 'nope' does not exist"]}),
            ),
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&request());
        let error = cursor.next_page().await.expect_err("the query is rejected");

        assert!(
            matches!(
                error,
                AtlassianError::JiraApi {
                    code: Some(400),
                    ..
                }
            ),
            "unexpected error {error:?}"
        );
        assert_eq!(cursor.terminated_reason(), None);
    }

    #[tokio::test]
    async fn clause_6_a_400_on_a_caller_supplied_first_token_is_a_query_error() {
        // The classification is structural: only a token *this* cursor was
        // issued proves the walk was healthy a page ago. A token the caller
        // seeded the request with was issued to somebody else, possibly long
        // ago, so the cursor does not claim to know why Jira refused it.
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            SEARCH,
            Step::json(
                400,
                &json!({"errorMessages": ["The page token is invalid"]}),
            ),
        )
        .await;

        let client = client_for(&mock);
        let seeded = request().with_next_page_token("token-from-an-earlier-run");
        let mut cursor = client.search_cursor(&seeded);
        let error = cursor.next_page().await.expect_err("the token is rejected");

        assert!(
            matches!(
                error,
                AtlassianError::JiraApi {
                    code: Some(400),
                    ..
                }
            ),
            "unexpected error {error:?}"
        );
        assert_eq!(cursor.terminated_reason(), None);
    }

    #[tokio::test]
    async fn clause_6_only_a_400_is_an_expiry_and_other_failures_leave_the_cursor_usable() {
        // A 503 mid-walk says nothing about the token, so the cursor keeps it
        // and the caller is free to ask for the same page again.
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
                Step::json(503, &json!({"errorMessages": ["Service Unavailable"]})),
                Step::json(200, &page(&[issue("10043", "KAN-43")], None)),
            ],
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&request());

        cursor.next_page().await.expect("the first page arrives");
        let error = cursor.next_page().await.expect_err("the second page fails");

        assert!(
            matches!(
                error,
                AtlassianError::JiraApi {
                    code: Some(503),
                    ..
                }
            ),
            "unexpected error {error:?}"
        );
        assert_eq!(cursor.terminated_reason(), None);

        let recovered = cursor
            .next_page()
            .await
            .expect("the same page can be asked for again")
            .expect("a page");
        assert_eq!(recovered.issues[0].key, "KAN-43");
        assert_eq!(
            sent_tokens(&mock).await,
            vec![None, Some("page-2".to_owned()), Some("page-2".to_owned())],
            "the unspent token must be re-sent rather than dropped"
        );
    }

    // ------------------------------------------------------------------
    // House rules that hold across every clause.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn a_collect_gathers_every_page_in_order() {
        let mock = JiraMock::start().await;
        mock.script(
            "POST",
            SEARCH,
            vec![
                Step::json(200, &page(&[issue("10042", "KAN-42")], Some("page-2"))),
                Step::json(
                    200,
                    &page(&[issue("10043", "KAN-43"), issue("10044", "KAN-44")], None),
                ),
            ],
        )
        .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&request());
        let collected = cursor.try_collect().await.expect("the walk succeeds");

        assert_eq!(keys(&collected), vec!["KAN-42", "KAN-43", "KAN-44"]);
    }

    #[tokio::test]
    async fn an_unsendable_request_is_refused_on_the_first_page_without_a_round_trip() {
        let mock = JiraMock::start().await;
        mock.stub("POST", SEARCH, Step::json(200, &page(&[], None)))
            .await;

        let client = client_for(&mock);
        let mut cursor = client.search_cursor(&SearchRequest::new("   "));
        let error = cursor
            .next_page()
            .await
            .expect_err("a blank query is refused");

        assert!(matches!(error, AtlassianError::Validation { .. }));
        assert!(mock.journal().await.is_empty());
    }

    #[test]
    fn iteration_never_logs_a_page_token() {
        // Jira's token is opaque and unbounded, and the iteration's own debug
        // lines are published by the Action; counts and page indexes are all
        // they may carry.
        const TOKEN: &str = "TOKEN-canary-8f21c7a3";

        let (collected, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.script(
                "POST",
                SEARCH,
                vec![
                    Step::json(200, &page(&[], Some(TOKEN))),
                    Step::json(200, &page(&[issue("10042", "KAN-42")], None)),
                ],
            )
            .await;
            let client = client_for(&mock);
            client.search_cursor(&request()).try_collect().await
        });

        assert_eq!(collected.expect("the walk succeeds").len(), 1);
        assert!(!log.contains(TOKEN), "log was: {log}");
    }

    #[test]
    fn a_cursor_and_its_reason_are_debug() {
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<SearchCursor<'_>>();
        assert_debug::<TerminationReason>();
    }
}
