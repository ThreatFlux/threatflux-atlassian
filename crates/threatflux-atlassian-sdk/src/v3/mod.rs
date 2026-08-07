//! Jira Cloud REST API v3.
//!
//! v2 and v3 are the same REST API with one structural difference: every
//! rich-text field -- an issue description, a comment body -- is a wiki-markup
//! string under v2 and an [ADF](crate::adf) object under v3. Everything else --
//! the routes, the field ids, the error shapes -- is shared.
//!
//! # Why this is a second module and not a version switch
//!
//! Reaching v3 through a runtime `ApiVersion` on the client would only work if
//! every return type became a union of its two shapes, because the difference
//! is not confined to rich text: `POST /search/jql` shares no member with
//! `GET /search`. Flipping [`crate::types`] over in place instead would break
//! [`IssueFields`](crate::types::IssueFields),
//! [`IssueSearchResult`](crate::types::IssueSearchResult), the CLI, both
//! examples and the remote client, for a wire benefit that a parallel model
//! delivers without touching any of them.
//!
//! So this module is purely additive. `types.rs` is frozen, every existing
//! caller keeps compiling, and a caller that wants v3 asks for it:
//!
//! ```rust,no_run
//! use threatflux_atlassian_sdk::AtlassianClient;
//! use threatflux_atlassian_sdk::v3::{V3CreateIssueFields, V3NamedRef, V3ProjectRef};
//!
//! # tokio_test::block_on(async {
//! let client = AtlassianClient::from_env().unwrap();
//!
//! let created = client
//!     .v3()
//!     .create_issue(
//!         V3CreateIssueFields::new(
//!             V3ProjectRef::by_key("KAN"),
//!             "Upgrade openssl",
//!             V3NamedRef::by_name("Task"),
//!         )
//!         .with_description("first line\nsecond line")
//!         .into(),
//!     )
//!     .await
//!     .unwrap();
//!
//! println!("{} ({})", created.key, created.id);
//! # });
//! ```
//!
//! # A create is one round trip
//!
//! [`JiraV3::create_issue`] returns what Jira answered the `POST` with and stops
//! there. It deliberately does not read the issue back, because a `POST` that
//! succeeded followed by a `GET` that failed returns an error for an issue that
//! exists -- and a caller that treats that error as "nothing was created"
//! creates a second one. The v2
//! [`create_issue`](crate::AtlassianClient::create_issue) has that shape and
//! [`create_issue_key`](crate::AtlassianClient::create_issue_key) exists to work
//! around it; v3 does not inherit the problem. A caller that wants the stored
//! issue asks for it with [`JiraV3::get_issue`], having already banked the key.
//!
//! # Reads are tolerant, writes are strict
//!
//! [`V3IssueFields`] is entirely optional, so a narrowed `fields=` read parses,
//! and unmodelled fields are preserved rather than dropped. Writes go the other
//! way: rich text is normalized to ADF and validated before a request body
//! exists, so a document this crate could read but could not have built is
//! refused locally instead of by Jira.
//!
//! Three methods carry rich text, and
//! [`AdfDocument::validate`](crate::adf::AdfDocument::validate) gates all three
//! -- [`JiraV3::create_issue`]'s description, [`JiraV3::add_comment`]'s body and
//! [`JiraV3::update_issue_description`]. A gate that holds on two of them is not
//! a gate: an `Unknown` node exists precisely so an unmodelled `table` or
//! `mediaSingle` survives a *read*, and letting one back out through whichever
//! write path was added last would serialize an arbitrary caller-supplied value
//! into a request body as JSON structure.
//!
//! [`JiraV3::update_issue`] is the exception that proves the rule and is
//! documented as such: its field map holds raw `serde_json::Value`s, so setting
//! `description` through it bypasses the gate. That is what
//! [`JiraV3::update_issue_description`] exists for.
//!
//! It is the *only* exception, and the one that had to be closed to keep that
//! sentence true is worth naming:
//! [`V3CreateIssueFields::custom_fields`] is flattened into the same JSON object
//! as the modelled members, so a custom field id of `description` would have
//! been emitted beside the validated one and won, carrying an arbitrary value
//! onto the wire through a path with no gate on it at all. A custom field id
//! that collides with a modelled member is therefore refused -- where it is set,
//! and again where the request body is built.
//!
//! # Comments go in both directions
//!
//! [`JiraV3::add_comment`] and [`JiraV3::get_comments`] both type the body as
//! [`RichText`]. The read side is the one that has to be
//! argued for, and it is why this module has a comment *reader* at all rather
//! than leaving reads to the surviving v2
//! [`get_issue_comments`](crate::AtlassianClient::get_issue_comments): a real
//! project holds ADF comments written this year next to string comments written
//! through v2 years ago, and reading the first kind with a v2 string reader --
//! or the second with an ADF reader -- fails the page. See [`V3CommentPage`]
//! for the pagination contract, which is the mirror image of the one in
//! [`search`](crate::search).
//!
//! # Issue properties are where identity is stored
//!
//! [`JiraV3::get_property`], [`set_property`](JiraV3::set_property),
//! [`delete_property`](JiraV3::delete_property) and
//! [`list_properties`](JiraV3::list_properties) read and write arbitrary JSON
//! hung off an issue under an [`IssuePropertyKey`]. Two rules carry the design:
//! a missing property is `Ok(None)` rather than an error, because it is the
//! state every first write starts from; and a write reports whether it *created*
//! the property, which is the only thing Jira offers a caller racing another run
//! for the same key. Properties are storage and not an index -- they are not
//! JQL-searchable for a plain API-token integration, so discovery stays
//! label-based.

mod comment;
mod model;
mod property;

pub use comment::{
    V3AddCommentRequest, V3Comment, V3CommentOrder, V3CommentPage, V3GetCommentsOptions,
};
pub use model::{
    V3CreateIssueFields, V3CreateIssueRequest, V3CreatedIssue, V3GetIssueOptions, V3Issue,
    V3IssueFields, V3IssueRef, V3NamedRef, V3ProjectRef, V3Status, V3StatusCategory,
    V3UpdateIssueRequest, V3User,
};
pub use property::{
    IssueProperty, IssuePropertyKey, IssuePropertyKeys, IssuePropertyRef, IssuePropertyWrite,
    MAX_PROPERTY_KEY_CHARS,
};

use reqwest::Method;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::adf::RichText;
use crate::client::{preview, Idempotency, Transport, TransportRequest};
use crate::error::{AtlassianError, Result};

/// The Jira field id of an issue description.
///
/// Named rather than spelled inline so that the one write path that sets it
/// through the generic update body is greppable next to the two that set it
/// through a typed request.
const DESCRIPTION_FIELD: &str = "description";

/// The Jira Cloud v3 endpoints, borrowed from an
/// [`AtlassianClient`](crate::AtlassianClient).
///
/// Obtained from [`AtlassianClient::v3`](crate::AtlassianClient::v3). It holds
/// no state of its own: the credentials, the host policy, the diagnostics policy
/// and the HTTP client all belong to the client it came from, so a v3 call is
/// subject to exactly the same destination checks and error redaction as a v2
/// one.
#[derive(Debug, Clone, Copy)]
pub struct JiraV3<'a> {
    transport: &'a Transport,
}

impl<'a> JiraV3<'a> {
    /// Borrows `transport` for the duration of a v3 call.
    pub(crate) const fn new(transport: &'a Transport) -> Self {
        Self { transport }
    }

    /// Creates an issue with `POST /rest/api/3/issue`.
    ///
    /// Returns the id, key and API URL Jira answered with. There is no second
    /// round trip: see the [module documentation](self) for why reading the
    /// issue back would make a successful create indistinguishable from a failed
    /// one.
    ///
    /// A [`description`](V3CreateIssueFields::description) is normalized to ADF
    /// before the body is built -- plain text is upgraded, an
    /// [`AdfDocument`](crate::adf::AdfDocument) is validated, and a
    /// [`RichText::Unknown`] is refused. That
    /// happens before anything is sent, so a rejected description costs no
    /// request. A
    /// [custom field](V3CreateIssueFields::custom_fields) whose id collides with
    /// a modelled member is refused at the same point and for a related reason:
    /// flattening would let it override the member it collides with.
    ///
    /// # The one failure this cannot report cleanly
    ///
    /// Jira answers the `POST`, and then the response body is read. If that read
    /// fails -- a truncated body, a shape this crate cannot parse, a connection
    /// dropped after the status line -- **the issue exists and this returns
    /// `Err`.** What is lost is the whole of [`V3CreatedIssue`]: the key, the id
    /// and the API URL of an issue that is now in the project with nothing
    /// pointing at it. The error carries no marker distinguishing it from a
    /// create that never happened, so:
    ///
    /// - **Do not retry this call on an error.** A retry after a lost response
    ///   creates a second issue. This is the narrow residue of the v2
    ///   POST-then-GET shape rather than a return of it: the only way in is a
    ///   success whose body will not parse, where the v2 path landed in the same
    ///   state whenever a perfectly ordinary follow-up `GET` failed.
    /// - **Recover by searching, not by re-creating.** A caller that put a
    ///   dedupe label in [`labels`](V3CreateIssueFields::labels) finds the issue
    ///   by that label; one that did not has only the `ERROR` line this logs,
    ///   which is why the label is worth setting on every automated create.
    /// - A caller that must not lose outputs -- a workflow step that publishes
    ///   the key -- has to write out what it knows *before* propagating this
    ///   error, because this method cannot do it for you.
    ///
    /// A future release is expected to make this case identifiable from the
    /// error value itself. Until it does, an error from this method means
    /// *unknown*, not *nothing happened*.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::v3::{
    ///     V3CreateIssueFields, V3CreateIssueRequest, V3NamedRef, V3ProjectRef,
    /// };
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let fields = V3CreateIssueFields::new(
    ///     V3ProjectRef::by_key("KAN"),
    ///     "Upgrade openssl",
    ///     V3NamedRef::by_name("Task"),
    /// )
    /// .with_labels(["jira-automation-gh-42-7"]);
    ///
    /// let created = client
    ///     .v3()
    ///     .create_issue(V3CreateIssueRequest::new(fields))
    ///     .await
    ///     .unwrap();
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if the description cannot be written, or
    /// if a custom field id collides with a modelled member -- both before any
    /// request is made, so neither costs a request. Otherwise whatever the
    /// transport returns. A rejected create made no issue; a 2xx whose body
    /// cannot be read did make one, and returns an error indistinguishable from
    /// the first kind. See *the one failure this cannot report cleanly* above:
    /// the key is gone, the `ERROR` line is the only record, and a retry
    /// duplicates the issue.
    pub async fn create_issue(&self, request: V3CreateIssueRequest) -> Result<V3CreatedIssue> {
        let request = request.into_wire()?;

        info!("Creating a Jira v3 issue");
        debug!("New v3 issue summary: {}", preview(&request.fields.summary));

        let body = serde_json::to_value(request)?;
        let response = self
            .transport
            .send(
                TransportRequest::new(
                    Method::POST,
                    &["rest", "api", "3", "issue"],
                    Idempotency::UnsafeWrite,
                )
                .json(&body),
            )
            .await?;

        let created: V3CreatedIssue = response.json().await.inspect_err(|error| {
            error!("Jira accepted the v3 create but its response could not be read, so the created issue has no key here: {error}");
        })?;
        info!("Created Jira v3 issue {}", preview(&created.key));

        Ok(created)
    }

    /// Updates an issue with `PUT /rest/api/3/issue/{key}`.
    ///
    /// Jira answers a successful update with 204 and no body, so there is
    /// nothing to return. The request's own
    /// [`idempotency`](V3UpdateIssueRequest) decides the replay tag this call
    /// records: setting fields converges on a replay, applying operations may
    /// not.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::v3::V3UpdateIssueRequest;
    /// use serde_json::json;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// client
    ///     .v3()
    ///     .update_issue(
    ///         "KAN-77",
    ///         V3UpdateIssueRequest::new()
    ///             .with_field("summary", "Upgrade openssl to 3.5.4")
    ///             .with_update("labels", json!([{"add": "jira-automation-gh-42-7"}])),
    ///     )
    ///     .await
    ///     .unwrap();
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if the request would change nothing, in
    /// which case no request is made. Otherwise whatever the transport returns.
    pub async fn update_issue(&self, issue_key: &str, request: V3UpdateIssueRequest) -> Result<()> {
        if request.is_empty() {
            return Err(AtlassianError::validation(
                "a v3 issue update must set at least one field or one update operation",
            ));
        }

        let idempotency = request.idempotency();
        info!(
            "Updating a Jira v3 issue: {} field(s), {} operation(s)",
            request.fields.len(),
            request.update.len()
        );
        debug!("v3 update target: {}", preview(issue_key));

        let body = serde_json::to_value(request)?;
        let segments = ["rest", "api", "3", "issue", issue_key];
        let response = self
            .transport
            .send(TransportRequest::new(Method::PUT, &segments, idempotency).json(&body))
            .await?;

        debug!("v3 update answered {}", response.status());
        Ok(())
    }

    /// Replaces an issue's description with `PUT /rest/api/3/issue/{key}`.
    ///
    /// The description is normalized to ADF before the body is built -- plain
    /// text is upgraded, an [`AdfDocument`](crate::adf::AdfDocument) is
    /// validated, and a [`RichText::Unknown`] is
    /// refused. That is the same gate
    /// [`create_issue`](Self::create_issue) and [`add_comment`](Self::add_comment)
    /// apply, and applying it here is the whole reason this method exists rather
    /// than a line of documentation pointing at
    /// [`update_issue`](Self::update_issue): that method's field map holds a
    /// `serde_json::Value`, so setting `description` through it puts an arbitrary
    /// caller-supplied value on the wire as JSON structure with nothing
    /// inspecting it. Every typed write path in this module runs
    /// [`AdfDocument::validate`](crate::adf::AdfDocument::validate); a gate that
    /// holds on two paths out of three is not a gate.
    ///
    /// **An empty document is a write, not a refusal.**
    /// `{"type":"doc","version":1,"content":[]}` is legal ADF and is how a
    /// description is cleared, so it is sent. That is the one place this path
    /// deliberately differs from [`add_comment`](Self::add_comment), which
    /// refuses an empty body because Jira answers one with a 400 and "post
    /// nothing" is expressed by posting nothing. A caller that means "leave the
    /// description alone" does not call this at all.
    ///
    /// The body is a `fields`-only update, so it carries the safe replay tag: a
    /// replay sets the same description and converges.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::adf::{AdfBlock, AdfDocument};
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// // Plain text is upgraded on the way out ...
    /// client
    ///     .v3()
    ///     .update_issue_description("KAN-77", "first line\nsecond line")
    ///     .await
    ///     .unwrap();
    ///
    /// // ... and a built document is validated on the way out.
    /// client
    ///     .v3()
    ///     .update_issue_description(
    ///         "KAN-77",
    ///         AdfDocument::new([AdfBlock::paragraph_text("see the advisory")]),
    ///     )
    ///     .await
    ///     .unwrap();
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if the description cannot be written,
    /// before any request is made. Otherwise whatever the transport returns.
    pub async fn update_issue_description(
        &self,
        issue_key: &str,
        description: impl Into<RichText> + Send,
    ) -> Result<()> {
        let document = description.into().into_wire()?;
        let field = serde_json::to_value(document)?;

        info!("Replacing a Jira v3 issue description");
        self.update_issue(
            issue_key,
            V3UpdateIssueRequest::new().with_field(DESCRIPTION_FIELD, field),
        )
        .await
    }

    /// Reads an issue with `GET /rest/api/3/issue/{key}`.
    ///
    /// Requests Jira's default field set. Use
    /// [`get_issue_with`](Self::get_issue_with) to narrow it.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let issue = client.v3().get_issue("KAN-77").await.unwrap();
    /// println!("{:?}", issue.fields.summary);
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever the transport returns.
    pub async fn get_issue(&self, issue_key: &str) -> Result<V3Issue> {
        self.get_issue_with(issue_key, &V3GetIssueOptions::new())
            .await
    }

    /// Reads an issue with `GET /rest/api/3/issue/{key}`, narrowing or expanding
    /// what comes back.
    ///
    /// Narrowing is the reason [`V3IssueFields`] has no required member: a
    /// `fields=summary` response carries no `issuetype`, and the v2 model fails
    /// such a response with `missing field`. A field that was not requested
    /// reads back as `None`, which is not the same as empty.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::v3::V3GetIssueOptions;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let options = V3GetIssueOptions::new().with_fields(["summary", "labels"]);
    /// let issue = client.v3().get_issue_with("KAN-77", &options).await.unwrap();
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever the transport returns.
    pub async fn get_issue_with(
        &self,
        issue_key: &str,
        options: &V3GetIssueOptions,
    ) -> Result<V3Issue> {
        debug!("Reading v3 issue: {}", preview(issue_key));

        let segments = ["rest", "api", "3", "issue", issue_key];
        let params = options.query();
        let mut request = TransportRequest::new(Method::GET, &segments, Idempotency::Safe);
        if !params.is_empty() {
            request = request.query(&params);
        }

        let response = self.transport.send(request).await?;
        Ok(response.json().await?)
    }

    /// Adds a comment with `POST /rest/api/3/issue/{key}/comment`.
    ///
    /// The body is normalized to ADF before the request exists -- plain text is
    /// upgraded, an [`AdfDocument`](crate::adf::AdfDocument) is validated, a
    /// [`RichText::Unknown`] is refused, and so
    /// is an empty document. Returns the comment Jira stored, whose `id` is the
    /// only handle a later call can address it by.
    ///
    /// Tagged as an unsafe write: a replay posts a second comment.
    ///
    /// # The one failure this cannot report cleanly
    ///
    /// The same residue as [`create_issue`](Self::create_issue), one size
    /// smaller. Jira answers the `POST`, and then the response body is read; if
    /// that read fails, **the comment is on the issue and this returns `Err`**,
    /// having lost the [`V3Comment`] -- the `id` included, which is the only
    /// handle any later call can address the comment by. The error does not say
    /// which side of the write it happened on, so **do not retry**: a retry
    /// posts the comment twice, and unlike an issue there is no label to find it
    /// by afterwards. A caller that needs to recognize its own comment on a
    /// later pass puts a deterministic marker in the body and scans the comment
    /// list with [`get_comments`](Self::get_comments) rather than trusting this
    /// return value.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let comment = client
    ///     .v3()
    ///     .add_comment("KAN-77", "tracked by gh-42-7")
    ///     .await
    ///     .unwrap();
    ///
    /// println!("{}", comment.id);
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if the body cannot be written, before any
    /// request is made. Otherwise whatever the transport returns. A rejected
    /// request posted nothing; a 2xx whose body cannot be read did post, and
    /// returns an error indistinguishable from the first kind. See *the one
    /// failure this cannot report cleanly* above: the comment id is gone, the
    /// `ERROR` line is the only record, and a retry posts a duplicate.
    pub async fn add_comment(
        &self,
        issue_key: &str,
        comment: impl Into<V3AddCommentRequest> + Send,
    ) -> Result<V3Comment> {
        let request = comment.into().into_wire()?;

        info!("Adding a comment to a Jira v3 issue");
        debug!("v3 comment target: {}", preview(issue_key));

        let body = serde_json::to_value(request)?;
        let segments = ["rest", "api", "3", "issue", issue_key, "comment"];
        let response = self
            .transport
            .send(
                TransportRequest::new(Method::POST, &segments, Idempotency::UnsafeWrite)
                    .json(&body),
            )
            .await?;

        let created: V3Comment = response.json().await.inspect_err(|error| {
            error!("Jira accepted the v3 comment but its response could not be read, so the posted comment has no id here: {error}");
        })?;
        debug!("Added Jira v3 comment {}", preview(&created.id));

        Ok(created)
    }

    /// Reads one page of comments with `GET /rest/api/3/issue/{key}/comment`.
    ///
    /// Bodies come back as [`RichText`], so a comment
    /// written years ago through v2 -- still stored as a plain string -- reads
    /// back beside today's ADF ones instead of failing the page. That tolerance
    /// is the reason this exists rather than the surviving v2
    /// [`get_issue_comments`](crate::AtlassianClient::get_issue_comments),
    /// which would parse a v3 ADF body with a v2 string reader.
    ///
    /// One page. Advance with
    /// [`V3CommentPage::next_start_at`], which owns the termination contract --
    /// note in particular that an empty page **ends** the iteration here,
    /// unlike in [`search`](crate::search).
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::v3::{V3CommentOrder, V3GetCommentsOptions};
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let options = V3GetCommentsOptions::new()
    ///     .with_max_results(50)
    ///     .with_order(V3CommentOrder::Created);
    /// let page = client.v3().get_comments("KAN-77", &options).await.unwrap();
    ///
    /// println!("{} of {:?}", page.comments.len(), page.total);
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever the transport returns.
    pub async fn get_comments(
        &self,
        issue_key: &str,
        options: &V3GetCommentsOptions,
    ) -> Result<V3CommentPage> {
        debug!("Reading v3 comments for: {}", preview(issue_key));

        let segments = ["rest", "api", "3", "issue", issue_key, "comment"];
        let params = options.query();
        let mut request = TransportRequest::new(Method::GET, &segments, Idempotency::Safe);
        if !params.is_empty() {
            request = request.query(&params);
        }

        let page: V3CommentPage = self.transport.send(request).await?.json().await?;
        if page.total_disagrees() {
            warn!(
                comments = page.comments.len(),
                start_at = ?page.start_at,
                total = ?page.total,
                "Jira's comment total disagrees with the page it served; iteration follows the page"
            );
        }

        Ok(page)
    }

    /// Reads an issue property with
    /// `GET /rest/api/3/issue/{key}/properties/{property}`.
    ///
    /// **A 404 is `Ok(None)`, not an error.** A property that has never been
    /// written is the state every first write starts from, so treating its
    /// absence as a failure would make the ordinary path the error path and
    /// force every caller to match on an error variant to discover "not set
    /// yet".
    ///
    /// The one thing that costs: Jira answers 404 both for a property that does
    /// not exist and for an issue that does not exist or is not visible, and
    /// the two are only distinguishable from the response body, which the
    /// default [`DiagnosticsPolicy`](crate::DiagnosticsPolicy) withholds. A
    /// caller that needs to tell them apart reads the issue.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::v3::IssuePropertyKey;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let key = IssuePropertyKey::new("threatflux.source-event").unwrap();
    ///
    /// match client.v3().get_property("KAN-77", &key).await.unwrap() {
    ///     Some(property) => println!("{}", property.value),
    ///     None => println!("not tracked yet"),
    /// }
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever the transport returns, except a 404.
    pub async fn get_property(
        &self,
        issue_key: &str,
        property: &IssuePropertyKey,
    ) -> Result<Option<IssueProperty>> {
        debug!(
            "Reading v3 issue property {} on: {}",
            preview(property.as_str()),
            preview(issue_key)
        );

        let segments = [
            "rest",
            "api",
            "3",
            "issue",
            issue_key,
            "properties",
            property.as_str(),
        ];
        let request = TransportRequest::new(Method::GET, &segments, Idempotency::Safe);

        match self.transport.send(request).await {
            Ok(response) => Ok(Some(response.json().await?)),
            Err(AtlassianError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Writes an issue property with
    /// `PUT /rest/api/3/issue/{key}/properties/{property}`.
    ///
    /// The request body is `value` itself: a property is stored whole, so this
    /// replaces any document already under the key rather than merging into it.
    ///
    /// Returns whether the property was [`Created`](IssuePropertyWrite::Created)
    /// (Jira answered 201) or [`Updated`](IssuePropertyWrite::Updated) (200).
    /// That is the only signal a caller racing another run for the same key
    /// gets: both writers succeed, and exactly one is told it created.
    ///
    /// Tagged as a safe write, and the returned outcome does not
    /// contradict that: the tag is about *server state*, which a replay of this
    /// `PUT` converges on, and the created/updated answer is a report about the
    /// state that was found rather than a second effect.
    ///
    /// # Example
    /// ```rust,no_run
    /// use threatflux_atlassian_sdk::AtlassianClient;
    /// use threatflux_atlassian_sdk::v3::IssuePropertyKey;
    /// use serde_json::json;
    ///
    /// # tokio_test::block_on(async {
    /// # let client = AtlassianClient::from_env().unwrap();
    /// let key = IssuePropertyKey::new("threatflux.source-event").unwrap();
    /// let outcome = client
    ///     .v3()
    ///     .set_property("KAN-77", &key, &json!({"schema": 1, "issue": 7}))
    ///     .await
    ///     .unwrap();
    ///
    /// if outcome.is_created() {
    ///     println!("this run claimed the issue");
    /// }
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever the transport returns.
    pub async fn set_property(
        &self,
        issue_key: &str,
        property: &IssuePropertyKey,
        value: &Value,
    ) -> Result<IssuePropertyWrite> {
        info!("Writing a Jira v3 issue property");
        debug!(
            "v3 property write target: {} on {}",
            preview(property.as_str()),
            preview(issue_key)
        );

        let segments = [
            "rest",
            "api",
            "3",
            "issue",
            issue_key,
            "properties",
            property.as_str(),
        ];
        let response = self
            .transport
            .send(TransportRequest::new(Method::PUT, &segments, Idempotency::Safe).json(value))
            .await?;

        let status = response.status().as_u16();
        let outcome = match status {
            201 => IssuePropertyWrite::Created,
            200 => IssuePropertyWrite::Updated,
            other => {
                warn!(
                    status = other,
                    "Jira answered a v3 property write with an unexpected success status; \
                     reporting it as an update"
                );
                IssuePropertyWrite::Updated
            }
        };

        debug!("v3 property write answered {status} ({outcome:?})");
        Ok(outcome)
    }

    /// Removes an issue property with
    /// `DELETE /rest/api/3/issue/{key}/properties/{property}`.
    ///
    /// Returns `true` when a property was removed and `false` when there was
    /// nothing under the key. A 404 is the second case rather than an error, for
    /// the same reason it is on [`get_property`](Self::get_property) and for one
    /// more: a delete whose response was lost and is replayed answers 404 the
    /// second time, and reporting a failure for an operation that succeeded is
    /// exactly the shape of bug the reconciliation work exists to remove.
    ///
    /// The same caveat applies: Jira answers 404 for an unknown issue as well as
    /// an unknown property, and the response body that would distinguish them is
    /// withheld by the default
    /// [`DiagnosticsPolicy`](crate::DiagnosticsPolicy).
    ///
    /// # Errors
    ///
    /// Whatever the transport returns, except a 404.
    pub async fn delete_property(
        &self,
        issue_key: &str,
        property: &IssuePropertyKey,
    ) -> Result<bool> {
        info!("Removing a Jira v3 issue property");
        debug!(
            "v3 property delete target: {} on {}",
            preview(property.as_str()),
            preview(issue_key)
        );

        let segments = [
            "rest",
            "api",
            "3",
            "issue",
            issue_key,
            "properties",
            property.as_str(),
        ];
        let request = TransportRequest::new(Method::DELETE, &segments, Idempotency::Safe);

        match self.transport.send(request).await {
            Ok(_) => Ok(true),
            Err(AtlassianError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Lists the property keys set on an issue with
    /// `GET /rest/api/3/issue/{key}/properties`.
    ///
    /// Keys only: a listing carries no values, so finding out that a property
    /// exists and reading it are two calls.
    ///
    /// # Errors
    ///
    /// Whatever the transport returns.
    pub async fn list_properties(&self, issue_key: &str) -> Result<IssuePropertyKeys> {
        debug!("Listing v3 issue properties on: {}", preview(issue_key));

        let segments = ["rest", "api", "3", "issue", issue_key, "properties"];
        let response = self
            .transport
            .send(TransportRequest::new(
                Method::GET,
                &segments,
                Idempotency::Safe,
            ))
            .await?;

        Ok(response.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IssuePropertyKey, IssuePropertyWrite, JiraV3, V3AddCommentRequest, V3CommentOrder,
        V3CreateIssueFields, V3CreateIssueRequest, V3GetCommentsOptions, V3GetIssueOptions,
        V3NamedRef, V3ProjectRef, V3UpdateIssueRequest,
    };
    use crate::adf::{AdfBlock, AdfDocument, AdfValidationError, RichText};
    use crate::config::{AtlassianConfig, HostPolicy};
    use crate::error::AtlassianError;
    use crate::AtlassianClient;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::future::Future;
    use threatflux_atlassian_testkit::jira_mock::{JiraMock, RecordedRequest, Step};
    use threatflux_atlassian_testkit::logs;

    const CREATE: &str = "/rest/api/3/issue";
    const ISSUE: &str = "/rest/api/3/issue/KAN-77";
    const COMMENT: &str = "/rest/api/3/issue/KAN-77/comment";
    const PROPERTIES: &str = "/rest/api/3/issue/KAN-77/properties";
    const PROPERTY: &str = "/rest/api/3/issue/KAN-77/properties/threatflux.source-event";

    /// The key `PROPERTY` addresses.
    fn property_key() -> IssuePropertyKey {
        IssuePropertyKey::new("threatflux.source-event").expect("a legal key")
    }

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

    fn minimal_request() -> V3CreateIssueRequest {
        V3CreateIssueFields::new(
            V3ProjectRef::by_key("KAN"),
            "Upgrade openssl",
            V3NamedRef::by_name("Task"),
        )
        .into()
    }

    fn created_body() -> Value {
        json!({
            "id": "10077",
            "key": "KAN-77",
            "self": "https://example.atlassian.net/rest/api/3/issue/10077"
        })
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

    /// Drives every v3 write path that carries rich text and asserts each one
    /// refused `body` locally, without sending anything.
    ///
    /// The three paths are the whole of this module's rich-text write surface: a
    /// create description, a comment body and a description replacement. They are
    /// asserted together rather than one per test because the property under test
    /// is not "this path rejects" but "no path is the one that forgot" -- a
    /// fourth write path added later fails this helper until it is added here.
    ///
    /// Every route is stubbed with a *success*, so a request that escaped the
    /// gate would be answered `Ok` and would show up in the journal rather than
    /// as an incidental failure.
    async fn every_write_path_refuses(body: &RichText) {
        let mock = JiraMock::start().await;
        mock.stub("POST", CREATE, Step::json(201, &created_body()))
            .await;
        mock.stub("POST", COMMENT, Step::json(201, &json!({"id": "10100"})))
            .await;
        mock.stub("PUT", ISSUE, Step::status(204)).await;
        let client = client_for(&mock);

        let create = client
            .v3()
            .create_issue(V3CreateIssueRequest::new(
                V3CreateIssueFields::new(
                    V3ProjectRef::by_key("KAN"),
                    "Upgrade openssl",
                    V3NamedRef::by_name("Task"),
                )
                .with_description(body.clone()),
            ))
            .await
            .expect_err("a create description must be refused");
        let comment = client
            .v3()
            .add_comment("KAN-77", V3AddCommentRequest::new(body.clone()))
            .await
            .expect_err("a comment body must be refused");
        let update = client
            .v3()
            .update_issue_description("KAN-77", body.clone())
            .await
            .expect_err("a description replacement must be refused");

        for (path, error) in [
            ("create_issue", create),
            ("add_comment", comment),
            ("update_issue_description", update),
        ] {
            assert!(
                matches!(error, AtlassianError::Validation { .. }),
                "{path} answered {error:?} instead of a validation error"
            );
        }
        assert!(
            mock.journal().await.is_empty(),
            "rich text the write gate refuses still reached the network"
        );
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
    async fn create_issue_posts_to_the_v3_route_and_never_reads_the_issue_back() {
        // The whole point of the v3 create: one round trip. A POST that
        // succeeded followed by a GET that failed returns an error for an issue
        // that exists, and a caller that retries on that error creates a second
        // one.
        let mock = JiraMock::start().await;
        mock.stub("POST", CREATE, Step::json(201, &created_body()))
            .await;

        let created = client_for(&mock)
            .v3()
            .create_issue(minimal_request())
            .await
            .expect("the create succeeds");

        assert_eq!(created.key, "KAN-77");
        assert_eq!(created.id, "10077");
        assert_eq!(
            created.self_url.as_deref(),
            Some("https://example.atlassian.net/rest/api/3/issue/10077")
        );
        mock.assert_call_count("POST", CREATE, 1).await;
        mock.assert_call_count("GET", ISSUE, 0).await;
    }

    #[tokio::test]
    async fn a_create_body_carries_no_null_for_an_unset_optional() {
        let mock = JiraMock::start().await;
        mock.stub("POST", CREATE, Step::json(201, &created_body()))
            .await;

        client_for(&mock)
            .v3()
            .create_issue(minimal_request())
            .await
            .expect("the create succeeds");

        let request = only_request(&mock).await;
        assert_eq!(request.path, CREATE, "the v2 route must not be used");
        assert_eq!(
            request.body_json().expect("a JSON body"),
            json!({"fields": {
                "project": {"key": "KAN"},
                "summary": "Upgrade openssl",
                "issuetype": {"name": "Task"}
            }})
        );
        assert!(
            !request.body_text().contains("null"),
            "an unset optional reached the wire as a null: {}",
            request.body_text()
        );
    }

    #[tokio::test]
    async fn a_plain_text_description_reaches_the_wire_as_adf() {
        let mock = JiraMock::start().await;
        mock.stub("POST", CREATE, Step::json(201, &created_body()))
            .await;

        let request = V3CreateIssueRequest::new(
            V3CreateIssueFields::new(
                V3ProjectRef::by_key("KAN"),
                "Upgrade openssl",
                V3NamedRef::by_name("Task"),
            )
            .with_description("first line\nsecond line"),
        );
        client_for(&mock)
            .v3()
            .create_issue(request)
            .await
            .expect("the create succeeds");

        let body = only_request(&mock).await.body_json().expect("a JSON body");
        assert_eq!(
            body["fields"]["description"],
            json!({
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
            }),
            "a v3 write must never carry a bare string description"
        );
    }

    #[tokio::test]
    async fn an_unwritable_description_costs_no_request() {
        // `RichText::Unknown` is a read-tolerance escape hatch. Serializing one
        // into a request body would put an arbitrary caller-supplied value on
        // the wire as JSON structure, so it is refused -- and refused before
        // anything is sent, not after Jira answers 400.
        let mock = JiraMock::start().await;
        mock.stub("POST", CREATE, Step::json(201, &created_body()))
            .await;

        let description: RichText =
            serde_json::from_value(json!({"type": "richTextV4"})).expect("parses");
        let request = V3CreateIssueRequest::new(
            V3CreateIssueFields::new(
                V3ProjectRef::by_key("KAN"),
                "Upgrade openssl",
                V3NamedRef::by_name("Task"),
            )
            .with_description(description),
        );

        let error = client_for(&mock)
            .v3()
            .create_issue(request)
            .await
            .expect_err("an unwritable description must not be sent");

        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );
        assert!(
            mock.journal().await.is_empty(),
            "a refused request still reached the network"
        );
    }

    // ------------------------------------------------- the write gate, per path

    /// A document this crate could never have built: `version` 9, and a
    /// `mediaSingle` node it deliberately does not model.
    ///
    /// [`AdfDocument::validate`] rejects both, so no typed write path can emit
    /// it -- which is what makes it the right probe for a hole *around* the
    /// gate.
    fn unwritable_document() -> Value {
        json!({
            "type": "doc",
            "version": 9,
            "content": [{"type": "mediaSingle", "attrs": {"x": 1}}]
        })
    }

    #[tokio::test]
    async fn a_custom_field_cannot_smuggle_a_document_past_the_write_gate() {
        // `custom_fields` is flattened into the same JSON object as the modelled
        // members, and `serde_json::Map` keeps the last write, so an id that
        // collides with a modelled member *wins* on the wire. Planted straight
        // into the public map rather than through the builder, because the field
        // is public and both doors have to be shut.
        let mock = JiraMock::start().await;
        mock.stub("POST", CREATE, Step::json(201, &created_body()))
            .await;

        let mut fields = V3CreateIssueFields::new(
            V3ProjectRef::by_key("KAN"),
            "Upgrade openssl",
            V3NamedRef::by_name("Task"),
        )
        .with_description("legitimate text");
        fields
            .custom_fields
            .insert(super::DESCRIPTION_FIELD.to_string(), unwritable_document());

        let error = client_for(&mock)
            .v3()
            .create_issue(V3CreateIssueRequest::new(fields))
            .await
            .expect_err("a custom field that shadows a modelled member must be refused");

        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );
        assert!(
            mock.journal().await.is_empty(),
            "an unvalidated document reached the network through a custom field"
        );
    }

    #[tokio::test]
    async fn a_rich_text_unknown_is_refused_on_every_v3_write_path() {
        // The read-tolerance escape hatch, checked across the whole write
        // surface rather than on whichever path happened to be written first.
        let body: RichText = serde_json::from_value(json!({"type": "richTextV4"})).expect("parses");
        assert!(body.is_unknown());

        every_write_path_refuses(&body).await;
    }

    #[tokio::test]
    async fn an_unmodelled_adf_node_is_refused_on_every_v3_write_path() {
        // `mediaSingle` is one of the node types this crate deliberately does
        // not model, so that a human-edited description survives a read intact.
        // The document below therefore *parses*, which is the point -- and it is
        // exactly what must never reach a request body, because emitting it
        // serializes an arbitrary caller-supplied value as JSON structure.
        let document: AdfDocument = serde_json::from_value(json!({
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": "see the advisory"}]},
                {"type": "mediaSingle", "attrs": {"layout": "center"}}
            ]
        }))
        .expect("an unmodelled node is read, not rejected");
        assert!(
            matches!(
                document.validate(),
                Err(AdfValidationError::UnknownNode { .. })
            ),
            "the gate this test relies on stopped rejecting unmodelled nodes"
        );

        every_write_path_refuses(&RichText::Adf(document)).await;
    }

    #[tokio::test]
    async fn a_malformed_known_adf_node_is_refused_on_every_v3_write_path() {
        // Not an `Unknown` node: a `heading` this crate models fully, built
        // through this crate's own constructor at a level ADF does not allow.
        // `validate()` is the only thing between it and a Jira 400, so every
        // write path has to run it -- structural validity is not the same
        // property as "no unmodelled nodes", and passing one test does not
        // imply the other.
        let document = AdfDocument::new([AdfBlock::heading_text(0, "level zero")]);
        assert!(
            matches!(
                document.validate(),
                Err(AdfValidationError::InvalidHeadingLevel { level: 0, .. })
            ),
            "the gate this test relies on stopped rejecting malformed headings"
        );

        every_write_path_refuses(&RichText::Adf(document)).await;
    }

    #[test]
    fn create_issue_does_not_log_the_whole_summary() {
        // The summary is rendered from a template over event fields, so its tail
        // is caller data and does not belong in a log a workflow publishes.
        const TAIL: &str = "trailing-summary-text-that-must-not-reach-a-log";
        let summary = format!("Upgrade openssl -- {TAIL}");

        let (result, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub("POST", CREATE, Step::json(201, &created_body()))
                .await;
            client_for(&mock)
                .v3()
                .create_issue(
                    V3CreateIssueFields::new(
                        V3ProjectRef::by_key("KAN"),
                        summary.clone(),
                        V3NamedRef::by_name("Task"),
                    )
                    .into(),
                )
                .await
        });

        assert_eq!(result.expect("the create succeeds").key, "KAN-77");
        assert!(!log.contains(TAIL), "log was: {log}");
        assert!(log.contains("(truncated)"), "log was: {log}");
    }

    #[tokio::test]
    async fn a_failing_create_does_not_carry_the_response_body_into_the_error() {
        // v3 goes through the same error seam as v2, so the default
        // diagnostics policy applies here too and a Jira error document -- which
        // echoes the request that produced it -- stays out of the error value.
        const ECHOED: &str = "field-value-echoed-back-by-jira";
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            CREATE,
            Step::json(400, &json!({"errorMessages": [ECHOED], "errors": {}})),
        )
        .await;

        let error = client_for(&mock)
            .v3()
            .create_issue(minimal_request())
            .await
            .expect_err("a 400 is an error");

        assert!(
            !error.to_string().contains(ECHOED),
            "the response body leaked into the error: {error}"
        );
    }

    // --------------------------------------- the residual an error cannot name

    #[test]
    fn a_create_whose_response_cannot_be_read_leaves_an_issue_nothing_can_name() {
        // The documented residual, pinned as behaviour: the POST succeeded, so
        // the issue exists, and its key went with the response. Nothing goes
        // looking for it -- a recovering GET here would be the v2 shape this
        // module exists to avoid -- so the `ERROR` line is the only record, and
        // the returned error is indistinguishable from a create that never
        // happened. Every "do not retry, recover by label" sentence in the
        // rustdoc is only true while all three of those hold.
        const ECHOED: &str = "field-value-echoed-back-by-jira";

        let (result, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub(
                "POST",
                CREATE,
                Step::json(201, &json!({"id": "10077", "note": ECHOED})),
            )
            .await;

            let outcome = client_for(&mock).v3().create_issue(minimal_request()).await;
            mock.assert_call_count("POST", CREATE, 1).await;
            mock.assert_call_count("GET", ISSUE, 0).await;
            outcome
        });

        let error = result.expect_err("a create response with no key cannot be read");
        assert!(
            !error.to_string().contains(ECHOED),
            "the unreadable response leaked into the error: {error}"
        );
        assert!(
            log.contains("the created issue has no key here"),
            "the only record of the lost key is missing: {log}"
        );
        assert!(!log.contains(ECHOED), "log was: {log}");
    }

    #[test]
    fn a_comment_whose_response_cannot_be_read_leaves_a_comment_nothing_can_name() {
        // The same residual one size smaller, and worse in one respect: an issue
        // can be found again by its dedupe label, a comment only by a marker the
        // caller put in the body itself.
        const ECHOED: &str = "comment-text-echoed-back-by-jira";

        let (result, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub("POST", COMMENT, Step::json(201, &json!({"note": ECHOED})))
                .await;

            let outcome = client_for(&mock)
                .v3()
                .add_comment("KAN-77", "tracked by gh-42-7")
                .await;
            mock.assert_call_count("POST", COMMENT, 1).await;
            outcome
        });

        let error = result.expect_err("a comment response with no id cannot be read");
        assert!(
            !error.to_string().contains(ECHOED),
            "the unreadable response leaked into the error: {error}"
        );
        assert!(
            log.contains("the posted comment has no id here"),
            "the only record of the lost comment id is missing: {log}"
        );
        assert!(!log.contains(ECHOED), "log was: {log}");
    }

    #[tokio::test]
    async fn update_issue_puts_the_body_to_the_v3_route() {
        let mock = JiraMock::start().await;
        mock.stub("PUT", ISSUE, Step::status(204)).await;

        client_for(&mock)
            .v3()
            .update_issue(
                "KAN-77",
                V3UpdateIssueRequest::new()
                    .with_field("summary", "Upgrade openssl to 3.5.4")
                    .with_update("labels", json!([{"add": "jira-automation-gh-42-7"}])),
            )
            .await
            .expect("a 204 is a successful update");

        let request = only_request(&mock).await;
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, ISSUE);
        assert_eq!(
            request.body_json().expect("a JSON body"),
            json!({
                "fields": {"summary": "Upgrade openssl to 3.5.4"},
                "update": {"labels": [{"add": "jira-automation-gh-42-7"}]}
            })
        );
    }

    #[tokio::test]
    async fn an_empty_update_costs_no_request() {
        let mock = JiraMock::start().await;
        mock.stub("PUT", ISSUE, Step::status(204)).await;

        let error = client_for(&mock)
            .v3()
            .update_issue("KAN-77", V3UpdateIssueRequest::new())
            .await
            .expect_err("an update that changes nothing is refused");

        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );
        assert!(
            mock.journal().await.is_empty(),
            "a refused update still reached the network"
        );
    }

    #[tokio::test]
    async fn update_issue_description_puts_adf_to_the_v3_route() {
        let mock = JiraMock::start().await;
        mock.stub("PUT", ISSUE, Step::status(204)).await;

        client_for(&mock)
            .v3()
            .update_issue_description("KAN-77", "first line\nsecond line")
            .await
            .expect("a 204 is a successful update");

        let request = only_request(&mock).await;
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, ISSUE, "the v2 route must not be used");
        assert_eq!(
            request.body_json().expect("a JSON body"),
            json!({"fields": {"description": {
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
            }}}),
            "a v3 write must never carry a bare string description"
        );
    }

    #[tokio::test]
    async fn update_issue_description_sets_the_field_and_stages_no_operation() {
        // A `fields`-only body, which is what earns the safe replay tag: a
        // replay sets the same description and converges. Staging this as a
        // `update` operation instead would tag every description change as an
        // unsafe write for no gain.
        let mock = JiraMock::start().await;
        mock.stub("PUT", ISSUE, Step::status(204)).await;

        client_for(&mock)
            .v3()
            .update_issue_description(
                "KAN-77",
                AdfDocument::new([AdfBlock::paragraph_text("see the advisory")]),
            )
            .await
            .expect("the update succeeds");

        let body = only_request(&mock).await.body_json().expect("a JSON body");
        assert!(
            body.get("update").is_none(),
            "a description replacement staged a field operation: {body}"
        );
        assert_eq!(
            body["fields"]["description"]["content"][0]["content"][0]["text"],
            json!("see the advisory")
        );
    }

    #[tokio::test]
    async fn an_empty_description_document_clears_the_field_rather_than_being_refused() {
        // The one place this path deliberately differs from `add_comment`:
        // `{"type":"doc","version":1,"content":[]}` is legal ADF and is how a
        // description is cleared, so it goes out. An empty *comment* is refused,
        // because Jira answers one with a 400 and "post nothing" is expressed by
        // posting nothing.
        let mock = JiraMock::start().await;
        mock.stub("PUT", ISSUE, Step::status(204)).await;

        client_for(&mock)
            .v3()
            .update_issue_description("KAN-77", AdfDocument::empty())
            .await
            .expect("an empty document is legal ADF");

        assert_eq!(
            only_request(&mock).await.body_json().expect("a JSON body"),
            json!({"fields": {"description": {"type": "doc", "version": 1, "content": []}}}),
            "clearing a description is a write, not a refusal"
        );
    }

    #[test]
    fn update_issue_description_does_not_log_the_description() {
        // A description is rendered from a template over event fields, so it is
        // caller data end to end and does not belong in a log a workflow
        // publishes.
        const TAIL: &str = "trailing-description-text-that-must-not-reach-a-log";

        let (result, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub("PUT", ISSUE, Step::status(204)).await;
            client_for(&mock)
                .v3()
                .update_issue_description("KAN-77", format!("see the advisory -- {TAIL}"))
                .await
        });

        result.expect("the update succeeds");
        assert!(!log.contains(TAIL), "log was: {log}");
        assert!(
            log.contains("Replacing a Jira v3 issue description"),
            "log was: {log}"
        );
    }

    #[tokio::test]
    async fn get_issue_sends_no_query_when_nothing_is_narrowed() {
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            ISSUE,
            Step::json(
                200,
                &json!({"id": "10077", "key": "KAN-77", "fields": {"summary": "Upgrade openssl"}}),
            ),
        )
        .await;

        let issue = client_for(&mock)
            .v3()
            .get_issue("KAN-77")
            .await
            .expect("the read succeeds");

        assert_eq!(issue.key, "KAN-77");
        assert_eq!(issue.fields.summary.as_deref(), Some("Upgrade openssl"));
        assert_eq!(
            only_request(&mock).await.query,
            None,
            "a default read must be byte-identical to a bare GET"
        );
    }

    #[tokio::test]
    async fn get_issue_with_narrows_the_fields_and_still_parses() {
        // The response carries `summary` alone: no `issuetype`, no `status`, no
        // `project`. The v2 model fails this outright with `missing field`.
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            ISSUE,
            Step::json(
                200,
                &json!({
                    "id": "10077",
                    "key": "KAN-77",
                    "fields": {"summary": "Upgrade openssl", "customfield_10010": 7}
                }),
            ),
        )
        .await;

        let options = V3GetIssueOptions::new()
            .with_fields(["summary", "customfield_10010"])
            .with_expand(["renderedFields"]);
        let issue = client_for(&mock)
            .v3()
            .get_issue_with("KAN-77", &options)
            .await
            .expect("a narrowed read succeeds");

        assert_eq!(issue.fields.summary.as_deref(), Some("Upgrade openssl"));
        assert!(issue.fields.issue_type.is_none());
        assert_eq!(issue.fields.other.get("customfield_10010"), Some(&json!(7)));

        let query = only_request(&mock).await.query.expect("a query string");
        let pairs: BTreeMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(
            pairs.get("fields").map(String::as_str),
            Some("summary,customfield_10010")
        );
        assert_eq!(
            pairs.get("expand").map(String::as_str),
            Some("renderedFields")
        );
    }

    #[tokio::test]
    async fn get_issue_reads_a_v2_era_string_description() {
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            ISSUE,
            Step::json(
                200,
                &json!({
                    "id": "10077",
                    "key": "KAN-77",
                    "fields": {"description": "written through v2"}
                }),
            ),
        )
        .await;

        let issue = client_for(&mock)
            .v3()
            .get_issue("KAN-77")
            .await
            .expect("the read succeeds");

        assert_eq!(
            issue.fields.description,
            Some(RichText::Text("written through v2".to_string())),
            "a v2-era string body must not fail a v3 read"
        );
    }

    #[test]
    fn the_accessor_hands_out_the_client_s_own_transport() {
        // `JiraV3` holds no state: the credentials, the host policy and the
        // diagnostics policy all stay with the client, so a v3 call cannot be
        // pointed somewhere a v2 call could not.
        let config = AtlassianConfig::builder()
            .base_url("https://test.atlassian.net")
            .username("test@example.com")
            .api_token("test-token")
            .build()
            .expect("a config builds");
        let client = AtlassianClient::new(config).expect("a client builds");

        let v3: JiraV3<'_> = client.v3();
        assert!(
            std::ptr::eq(v3.transport, client.v3().transport),
            "every accessor call must borrow the same transport"
        );
    }

    // ---------------------------------------------------------------- comments

    #[tokio::test]
    async fn add_comment_posts_adf_to_the_v3_comment_route() {
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            COMMENT,
            Step::json(201, &json!({"id": "10100", "body": "ignored"})),
        )
        .await;

        let comment = client_for(&mock)
            .v3()
            .add_comment("KAN-77", "first line\nsecond line")
            .await
            .expect("the comment posts");

        assert_eq!(comment.id, "10100");

        let request = only_request(&mock).await;
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, COMMENT, "the v2 route must not be used");
        assert_eq!(
            request.body_json().expect("a JSON body"),
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

    #[tokio::test]
    async fn an_unwritable_comment_body_costs_no_request() {
        let mock = JiraMock::start().await;
        mock.stub("POST", COMMENT, Step::json(201, &json!({"id": "10100"})))
            .await;

        let body: RichText = serde_json::from_value(json!({"type": "richTextV4"})).expect("parses");
        let error = client_for(&mock)
            .v3()
            .add_comment("KAN-77", V3AddCommentRequest::new(body))
            .await
            .expect_err("an unwritable body must not be sent");

        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );
        assert!(
            mock.journal().await.is_empty(),
            "a refused comment still reached the network"
        );
    }

    #[test]
    fn add_comment_does_not_log_the_body() {
        // A comment body is rendered from a template over event fields, so it is
        // caller data end to end and does not belong in a log a workflow
        // publishes.
        const TAIL: &str = "trailing-comment-text-that-must-not-reach-a-log";

        let (result, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub("POST", COMMENT, Step::json(201, &json!({"id": "10100"})))
                .await;
            client_for(&mock)
                .v3()
                .add_comment("KAN-77", format!("tracked by gh-42-7 -- {TAIL}"))
                .await
        });

        assert_eq!(result.expect("the comment posts").id, "10100");
        assert!(!log.contains(TAIL), "log was: {log}");
        assert!(
            log.contains("Adding a comment to a Jira v3 issue"),
            "log was: {log}"
        );
    }

    #[tokio::test]
    async fn get_comments_reads_v2_string_bodies_beside_v3_adf_bodies() {
        // The reason this method exists rather than the surviving v2
        // `get_issue_comments`: one page can hold both shapes at once, and a
        // reader typed for either one alone fails the whole page.
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            COMMENT,
            Step::json(
                200,
                &json!({
                    "startAt": 0,
                    "maxResults": 2,
                    "total": 2,
                    "comments": [
                        {"id": "10100", "body": "written through v2"},
                        {
                            "id": "10101",
                            "author": {"accountId": "account-123"},
                            "body": {
                                "type": "doc",
                                "version": 1,
                                "content": [{
                                    "type": "paragraph",
                                    "content": [{"type": "text", "text": "written through v3"}]
                                }]
                            }
                        }
                    ]
                }),
            ),
        )
        .await;

        let page = client_for(&mock)
            .v3()
            .get_comments("KAN-77", &V3GetCommentsOptions::new())
            .await
            .expect("the read succeeds");

        assert_eq!(page.comments.len(), 2);
        assert_eq!(
            page.comments[0].body,
            Some(RichText::Text("written through v2".to_string())),
            "a v2-era string body must not fail a v3 comment read"
        );
        assert!(matches!(page.comments[1].body, Some(RichText::Adf(_))));
        assert_eq!(
            page.comments[1]
                .author
                .as_ref()
                .and_then(|author| author.account_id.as_deref()),
            Some("account-123")
        );
        assert_eq!(page.next_start_at(), None);

        assert_eq!(
            only_request(&mock).await.query,
            None,
            "a default read must be byte-identical to a bare GET"
        );
    }

    #[tokio::test]
    async fn get_comments_renders_every_pagination_parameter() {
        let mock = JiraMock::start().await;
        mock.stub("GET", COMMENT, Step::json(200, &json!({"comments": []})))
            .await;

        let options = V3GetCommentsOptions::new()
            .with_start_at(25)
            .with_max_results(50)
            .with_order(V3CommentOrder::CreatedDescending)
            .with_expand(["renderedBody"]);
        client_for(&mock)
            .v3()
            .get_comments("KAN-77", &options)
            .await
            .expect("the read succeeds");

        let query = only_request(&mock).await.query.expect("a query string");
        let pairs: BTreeMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(pairs.get("startAt").map(String::as_str), Some("25"));
        assert_eq!(pairs.get("maxResults").map(String::as_str), Some("50"));
        assert_eq!(pairs.get("orderBy").map(String::as_str), Some("-created"));
        assert_eq!(
            pairs.get("expand").map(String::as_str),
            Some("renderedBody")
        );
    }

    #[tokio::test]
    async fn a_comment_list_is_walked_by_the_offset_the_page_reports() {
        let mock = JiraMock::start().await;
        mock.script(
            "GET",
            COMMENT,
            vec![
                Step::json(
                    200,
                    &json!({
                        "startAt": 0,
                        "maxResults": 2,
                        "total": 3,
                        "comments": [{"id": "1"}, {"id": "2"}]
                    }),
                ),
                Step::json(
                    200,
                    &json!({
                        "startAt": 2,
                        "maxResults": 2,
                        "total": 3,
                        "comments": [{"id": "3"}]
                    }),
                ),
            ],
        )
        .await;

        let client = client_for(&mock);
        let mut options = V3GetCommentsOptions::new().with_max_results(2);
        let mut ids = Vec::new();
        loop {
            let page = client
                .v3()
                .get_comments("KAN-77", &options)
                .await
                .expect("the read succeeds");
            let next = page.next_start_at();
            ids.extend(page.comments.into_iter().map(|comment| comment.id));
            match next {
                Some(start_at) => options = options.with_start_at(start_at),
                None => break,
            }
        }

        assert_eq!(ids, ["1", "2", "3"]);
        mock.assert_call_count("GET", COMMENT, 2).await;
    }

    #[test]
    fn a_comment_total_that_contradicts_the_page_is_reported_and_still_terminates() {
        let (page, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub(
                "GET",
                COMMENT,
                Step::json(200, &json!({"startAt": 0, "total": 5, "comments": []})),
            )
            .await;
            client_for(&mock)
                .v3()
                .get_comments("KAN-77", &V3GetCommentsOptions::new())
                .await
        });

        let page = page.expect("the read succeeds");
        assert_eq!(
            page.next_start_at(),
            None,
            "a starved page must end the walk rather than re-request the offset"
        );
        assert!(
            log.contains("disagrees with the page it served"),
            "log was: {log}"
        );
    }

    // -------------------------------------------------------------- properties

    #[tokio::test]
    async fn a_missing_property_reads_as_none_rather_than_an_error() {
        // The single most important detail of this surface: a property that has
        // never been written is the state every first write starts from, so a
        // 404 is the ordinary answer and not a failure.
        let mock = JiraMock::start().await;
        mock.stub("GET", PROPERTY, Step::status(404)).await;

        let property = client_for(&mock)
            .v3()
            .get_property("KAN-77", &property_key())
            .await
            .expect("a 404 is not an error here");

        assert!(property.is_none());
        mock.assert_call_count("GET", PROPERTY, 1).await;
    }

    #[tokio::test]
    async fn a_present_property_reads_back_whole() {
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            PROPERTY,
            Step::json(
                200,
                &json!({
                    "key": "threatflux.source-event",
                    "value": {"schema": 1, "repository_id": 42, "issue_number": 7}
                }),
            ),
        )
        .await;

        let property = client_for(&mock)
            .v3()
            .get_property("KAN-77", &property_key())
            .await
            .expect("the read succeeds")
            .expect("the property exists");

        assert_eq!(property.key, "threatflux.source-event");
        assert_eq!(property.value["repository_id"], json!(42));
    }

    #[tokio::test]
    async fn the_404_tolerance_is_narrow_and_covers_nothing_else() {
        // Only "not there" is absorbed. A permission failure is a real failure,
        // and reporting it as an absent property would make a misconfigured
        // token look like a fresh issue and mint a duplicate.
        for (status, expect_permission_denied) in [(403_u16, true), (500, false)] {
            let mock = JiraMock::start().await;
            mock.stub("GET", PROPERTY, Step::status(status)).await;

            let error = client_for(&mock)
                .v3()
                .get_property("KAN-77", &property_key())
                .await
                .expect_err("only a 404 is absorbed");

            if expect_permission_denied {
                assert!(
                    matches!(error, AtlassianError::PermissionDenied { .. }),
                    "expected a permission error, got {error:?}"
                );
            } else {
                assert!(
                    matches!(error, AtlassianError::JiraApi { .. }),
                    "expected a Jira API error, got {error:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_property_write_puts_the_value_itself_and_names_the_race_winner() {
        // 201 means this call created the property, which is the only signal a
        // caller racing another run for the same key gets. 200 means it replaced
        // a value somebody else had already written.
        let mock = JiraMock::start().await;
        mock.script("PUT", PROPERTY, vec![Step::status(201), Step::status(200)])
            .await;

        let client = client_for(&mock);
        let value = json!({"schema": 1, "repository_id": 42, "issue_number": 7});

        let first = client
            .v3()
            .set_property("KAN-77", &property_key(), &value)
            .await
            .expect("the write succeeds");
        assert_eq!(first, IssuePropertyWrite::Created);
        assert!(first.is_created());

        let second = client
            .v3()
            .set_property("KAN-77", &property_key(), &value)
            .await
            .expect("the write succeeds");
        assert_eq!(second, IssuePropertyWrite::Updated);
        assert!(!second.is_created());

        let journal = mock.journal().await;
        assert_eq!(journal.len(), 2);
        assert_eq!(journal[0].method, "PUT");
        assert_eq!(journal[0].path, PROPERTY);
        assert_eq!(
            journal[0].body_json().expect("a JSON body"),
            value,
            "a property is stored whole: the body is the value, with no wrapper"
        );
    }

    #[tokio::test]
    async fn a_property_key_is_percent_encoded_and_cannot_open_a_path_boundary() {
        // The key is caller data in a URL path. `Transport` encodes each segment
        // on its own, so a key that looks like a traversal addresses a property
        // with a strange name rather than a different endpoint. Nothing is
        // stubbed, so the mock answers 404 -- which this call absorbs.
        let mock = JiraMock::start().await;
        let hostile = IssuePropertyKey::new("../../admin").expect("a slash is legal in a key");

        let property = client_for(&mock)
            .v3()
            .get_property("KAN-77", &hostile)
            .await
            .expect("an unmatched path answers 404, which reads as absent");

        assert!(property.is_none());
        assert_eq!(
            only_request(&mock).await.path,
            "/rest/api/3/issue/KAN-77/properties/..%2F..%2Fadmin",
            "a key escaped the properties path"
        );
    }

    #[tokio::test]
    async fn a_property_delete_reports_whether_anything_was_removed() {
        let mock = JiraMock::start().await;
        mock.script(
            "DELETE",
            PROPERTY,
            vec![Step::status(204), Step::status(404)],
        )
        .await;

        let client = client_for(&mock);

        assert!(
            client
                .v3()
                .delete_property("KAN-77", &property_key())
                .await
                .expect("the delete succeeds"),
            "the first delete removed a property"
        );
        assert!(
            !client
                .v3()
                .delete_property("KAN-77", &property_key())
                .await
                .expect("a replayed delete is not a failure"),
            "a replayed delete must converge rather than report a failure for work that succeeded"
        );

        mock.assert_call_count("DELETE", PROPERTY, 2).await;
    }

    #[tokio::test]
    async fn a_property_listing_names_the_keys_and_nothing_else() {
        let mock = JiraMock::start().await;
        mock.stub(
            "GET",
            PROPERTIES,
            Step::json(
                200,
                &json!({"keys": [
                    {
                        "self": "https://example.atlassian.net/rest/api/3/issue/10077/properties/threatflux.source-event",
                        "key": "threatflux.source-event"
                    },
                    {"self": "https://example.atlassian.net/rest/api/3/issue/10077/properties/other", "key": "other"}
                ]}),
            ),
        )
        .await;

        let keys = client_for(&mock)
            .v3()
            .list_properties("KAN-77")
            .await
            .expect("the listing succeeds");

        assert_eq!(keys.len(), 2);
        assert!(keys.contains("threatflux.source-event"));
        assert!(!keys.contains("threatflux.reconcile"));
        assert_eq!(only_request(&mock).await.path, PROPERTIES);
    }

    #[test]
    fn a_property_value_never_reaches_a_log() {
        // A property carries the source-event identity and the reconciliation
        // hashes, which are derived from an event payload. None of it belongs in
        // a workflow log.
        const CANARY: &str = "CANARY-property-value-9f13c7";

        let (result, log) = capture_async(async {
            let mock = JiraMock::start().await;
            mock.stub("PUT", PROPERTY, Step::status(201)).await;
            client_for(&mock)
                .v3()
                .set_property("KAN-77", &property_key(), &json!({"marker": CANARY}))
                .await
        });

        assert_eq!(
            result.expect("the write succeeds"),
            IssuePropertyWrite::Created
        );
        assert!(!log.contains(CANARY), "log was: {log}");
        assert!(
            log.contains("Writing a Jira v3 issue property"),
            "log was: {log}"
        );
    }
}
