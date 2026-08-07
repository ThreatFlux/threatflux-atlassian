//! Every SDK endpoint that talks HTTP, asserted from the mock's request journal.
//!
//! # Why these live here and not in `client.rs`
//!
//! These suites were five inline `#[cfg(test)]` tests inside `client.rs`. They
//! were never unit tests: each one starts a real server, sends a real request
//! over loopback and reads a real response, so the only thing the inline
//! position bought was access to private items -- which none of them used. Out
//! here they are compiled against the crate's *published* surface, so a method
//! that stops being `pub`, a type that stops being constructible from outside,
//! or a re-export that goes missing fails this binary instead of passing a test
//! that reached around the wall.
//!
//! # Why the journal replaces `.expect(1)`
//!
//! The originals mounted `Mock::given(...).and(body_json(...)).expect(1)`. That
//! shape asserts a count of requests *that matched*, and a request that does not
//! match is not counted at all -- it falls through to wiremock's 404 and shows up
//! as some unrelated failure downstream, or as nothing. Worse, the count says
//! nothing about what arrived: it cannot distinguish "the body was right" from
//! "the body was wrong in a way the matcher did not look at", because the
//! matcher *is* the assertion, and every field it does not name is unchecked.
//!
//! So every case here mounts an unconditional response and then asserts on what
//! the server actually received: method, path, query parameters, headers and
//! body, plus an exact call count from the same journal. A request built wrong
//! still reaches the mount, is still answered, and is still caught -- and the
//! failure names the field rather than a count.
//!
//! # What is retargeted at v3, and what is not
//!
//! v3 is additive (see [`v3`](threatflux_atlassian_sdk::v3)), so it does not
//! cover all of v2. Where a v3 seam exists -- creating an issue, writing and
//! reading a comment, updating fields -- there is a v3 case below, and it asserts
//! the thing the v2 shape gets wrong: a v3 create is *one* round trip, and a v3
//! comment body is an ADF object rather than a bare string.
//!
//! Where no v3 seam exists -- assignment, user search, changelog, issue links,
//! attachments -- the v2 case stays v2. Retargeting those would mean adding
//! production methods, which this suite is not the place for; each is marked
//! below so the gap is a recorded fact rather than an oversight.
//!
//! The v2 cases are kept in full rather than replaced by their v3 counterparts.
//! `create_issue`, `add_issue_comment` and `get_issue_comments` are published and
//! still supported, and deleting their only end-to-end coverage because a newer
//! path exists would leave the shipped one untested.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};
use threatflux_atlassian_sdk::adf::RichText;
use threatflux_atlassian_sdk::v3::{
    V3AddCommentRequest, V3CommentOrder, V3CreateIssueFields, V3GetCommentsOptions,
    V3GetIssueOptions, V3NamedRef, V3ProjectRef, V3UpdateIssueRequest,
};
use threatflux_atlassian_sdk::{
    AtlassianClient, AtlassianConfig, CreateIssueFields, CreateIssueRequest, HostPolicy,
    IssueTypeReference, ProjectReference,
};
use threatflux_atlassian_testkit::fixtures;
use threatflux_atlassian_testkit::golden::assert_json_eq;
use threatflux_atlassian_testkit::jira_mock::{JiraMock, RecordedRequest, Step};

/// A client pointed at a loopback mock.
///
/// `HostPolicy::Loopback` is what admits the `http://127.0.0.1:PORT` base URL.
/// The `verify_ssl(false)` this replaced never did anything here -- reqwest
/// negotiates no TLS on an `http://` URL -- and is now a hard error on a
/// cleartext destination, so a code call naming the policy is the only way in.
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

/// The requests the mock received for `http_method` and `path`, in order.
async fn recorded(mock: &JiraMock, http_method: &str, path: &str) -> Vec<RecordedRequest> {
    mock.journal()
        .await
        .into_iter()
        .filter(|request| request.method.eq_ignore_ascii_case(http_method) && request.path == path)
        .collect()
}

/// Exactly one recorded request for `http_method` and `path`.
///
/// # Panics
///
/// Panics naming the actual count, because "the endpoint was called twice" is
/// the failure these suites exist to catch and it deserves to be said outright.
async fn only_request(mock: &JiraMock, http_method: &str, path: &str) -> RecordedRequest {
    let mut requests = recorded(mock, http_method, path).await;
    assert_eq!(
        requests.len(),
        1,
        "{http_method} {path} was called {} time(s), expected exactly 1",
        requests.len()
    );
    requests.remove(0)
}

/// The query string of a recorded request, as name/value pairs.
///
/// The client builds query parameters out of a `HashMap`, so their order on the
/// wire is whatever that map iterated in. Comparing the raw string would be a
/// coin flip; comparing the pairs is the assertion that was meant.
fn query_pairs(request: &RecordedRequest) -> BTreeMap<String, String> {
    request
        .query
        .as_deref()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

/// `entries` in the shape [`query_pairs`] returns.
fn pairs(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// The JSON body of a recorded request.
///
/// # Panics
///
/// Panics if the body is not JSON, which for these endpoints means the request
/// was built with the wrong content type.
fn body_of(request: &RecordedRequest) -> Value {
    request
        .body_json()
        .unwrap_or_else(|| panic!("{} {} carried no JSON body", request.method, request.path))
}

/// A v2 issue as `GET /rest/api/2/issue/{key}` returns it.
///
/// `IssueFields` requires `issuetype`, `status` and `project`, so a narrowed
/// response does not parse -- which is the v2 limitation `V3IssueFields` exists
/// to lift, and the reason this literal is as long as it is.
fn v2_issue_body(self_url: &str) -> Value {
    json!({
        "id": "10001",
        "key": "TEST-123",
        "self": self_url,
        "fields": {
            "summary": "Created issue",
            "description": "Test description",
            "issuetype": {
                "id": "10000",
                "name": "Task",
                "description": "Task issue",
                "iconUrl": null,
                "subtask": false
            },
            "status": {
                "id": "1",
                "name": "To Do",
                "description": "Pending work",
                "category": {
                    "id": 2,
                    "key": "new",
                    "name": "To Do",
                    "colorName": "blue-gray"
                }
            },
            "priority": null,
            "assignee": null,
            "reporter": null,
            "project": {
                "id": "10000",
                "key": "TEST",
                "name": "Test Project",
                "description": null,
                "projectTypeKey": "software",
                "avatarUrls": null
            },
            "created": null,
            "updated": null,
            "resolutiondate": null,
            "labels": [],
            "components": []
        }
    })
}

/// A v2 create request for `TEST`, with every optional member unset.
fn v2_create_request(description: Option<&str>) -> CreateIssueRequest {
    CreateIssueRequest {
        fields: CreateIssueFields {
            project: ProjectReference::by_key("TEST"),
            summary: "Created issue".to_string(),
            issue_type: IssueTypeReference::by_name("Task"),
            description: description.map(ToString::to_string),
            assignee: None,
            priority: None,
            labels: None,
            components: None,
            parent: None,
            custom_fields: HashMap::new(),
        },
    }
}

/// A temporary file holding `contents`, named after `label` and this process.
fn temp_file(label: &str, contents: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "threatflux-atlassian-{label}-{}.txt",
        std::process::id()
    ));
    fs::write(&path, contents).expect("the attachment fixture is writable");
    path
}

// ---------------------------------------------------------------------------
// v2 -- the endpoints that are still the only way to reach these operations.
// ---------------------------------------------------------------------------

/// `create_issue` POSTs and then reads the issue back, which is two requests.
///
/// The second request is the shape `create_issue_key` and the whole v3 create
/// path exist to avoid: an issue that was created and then could not be read
/// back returns `Err` for an issue that exists. Pinned here rather than
/// described, so that a change to it is a test result.
#[tokio::test]
async fn v2_create_issue_posts_then_reads_the_issue_back() {
    let mock = JiraMock::start().await;
    let self_url = format!("{}/rest/api/2/issue/10001", mock.uri());
    mock.stub(
        "POST",
        "/rest/api/2/issue",
        Step::json(
            201,
            &json!({"id": "10001", "key": "TEST-123", "self": self_url}),
        ),
    )
    .await;
    mock.stub(
        "GET",
        "/rest/api/2/issue/TEST-123",
        Step::json(200, &v2_issue_body(&self_url)),
    )
    .await;

    let issue = client_for(&mock)
        .create_issue(v2_create_request(Some("Test description")))
        .await
        .expect("the create succeeds");

    assert_eq!(issue.key, "TEST-123");
    assert_eq!(issue.fields.summary, "Created issue");

    // The nested `"id": null`s are the v2 wire form as it ships today.
    // `skip_serializing_if` was applied to `CreateIssueFields`' own optional
    // members -- `parent` above all, which Jira rejects as an explicit null on a
    // non-subtask type -- but not inside `ProjectReference` and
    // `IssueTypeReference`, whose members are both `Option` and both always
    // emitted. `types.rs` is frozen, so this is pinned rather than fixed: a v3
    // create emits neither null (see the v3 case below), and a change to the v2
    // shape should have to come past this assertion.
    let posted = only_request(&mock, "POST", "/rest/api/2/issue").await;
    assert_json_eq(
        &body_of(&posted),
        &json!({
            "fields": {
                "project": {"key": "TEST", "id": null},
                "summary": "Created issue",
                "issuetype": {"name": "Task", "id": null},
                "description": "Test description"
            }
        }),
    );

    let read_back = only_request(&mock, "GET", "/rest/api/2/issue/TEST-123").await;
    assert_eq!(read_back.query, None);
    assert_eq!(
        mock.journal().await.len(),
        2,
        "the v2 create is exactly one POST and one GET"
    );
}

/// The v2 comment write and read, with the wire shapes both directions.
///
/// The POST body is a **bare string**, which is the v2 contract and the reason
/// `JiraV3::add_comment` exists rather than this method growing an ADF mode.
#[tokio::test]
async fn v2_comment_write_and_read_carry_a_plain_string_body() {
    let mock = JiraMock::start().await;
    mock.stub(
        "POST",
        "/rest/api/2/issue/TEST-123/comment",
        Step::json(201, &json!({"id": "10001", "body": "Review evidence"})),
    )
    .await;
    mock.stub(
        "GET",
        "/rest/api/2/issue/TEST-123/comment",
        Step::json(
            200,
            &json!({"startAt": 5, "maxResults": 10, "total": 0, "comments": []}),
        ),
    )
    .await;

    let client = client_for(&mock);
    // The padding pins the trimming: the body on the wire is the trimmed text.
    let comment = client
        .add_issue_comment("TEST-123", "  Review evidence  ")
        .await
        .expect("the comment posts");
    let page = client
        .get_issue_comments("TEST-123", 5, 10)
        .await
        .expect("the comment page reads");

    assert_eq!(comment["id"], "10001");
    assert_eq!(page["startAt"], 5);

    let posted = only_request(&mock, "POST", "/rest/api/2/issue/TEST-123/comment").await;
    assert_json_eq(&body_of(&posted), &json!({"body": "Review evidence"}));

    let read = only_request(&mock, "GET", "/rest/api/2/issue/TEST-123/comment").await;
    assert_eq!(
        query_pairs(&read),
        pairs(&[("startAt", "5"), ("maxResults", "10")])
    );
}

/// Assignment stays v2: this crate models no `PUT /rest/api/3/issue/{key}/assignee`.
///
/// Both directions are asserted, because unassigning is `{"accountId": null}`
/// rather than an absent member and the two are different requests.
#[tokio::test]
async fn v2_assignment_sends_an_account_id_or_an_explicit_null() {
    let mock = JiraMock::start().await;
    mock.stub(
        "PUT",
        "/rest/api/2/issue/TEST-123/assignee",
        Step::status(204),
    )
    .await;

    let client = client_for(&mock);
    client
        .assign_issue("TEST-123", Some("account-123"))
        .await
        .expect("the assignment succeeds");
    client
        .assign_issue("TEST-123", None)
        .await
        .expect("the unassignment succeeds");

    let requests = recorded(&mock, "PUT", "/rest/api/2/issue/TEST-123/assignee").await;
    assert_eq!(requests.len(), 2);
    assert_json_eq(&body_of(&requests[0]), &json!({"accountId": "account-123"}));
    assert_json_eq(&body_of(&requests[1]), &json!({"accountId": null}));
}

/// User search and changelog stay v2: neither has a v3 method in this crate.
///
/// Both are pure query-parameter endpoints, so the journal's query string is the
/// whole assertion -- and the search term is asserted trimmed.
#[tokio::test]
async fn v2_user_search_and_changelog_send_their_pagination_parameters() {
    let mock = JiraMock::start().await;
    mock.stub(
        "GET",
        "/rest/api/2/user/search",
        Step::json(
            200,
            &json!([{"accountId": "account-123", "displayName": "Allen Example", "active": true}]),
        ),
    )
    .await;
    mock.stub(
        "GET",
        "/rest/api/2/issue/TEST-123/changelog",
        Step::json(
            200,
            &json!({"startAt": 1, "maxResults": 2, "total": 1, "values": []}),
        ),
    )
    .await;

    let client = client_for(&mock);
    let users = client
        .search_users(" Allen ", 0, 25)
        .await
        .expect("the user search succeeds");
    let changelog = client
        .get_issue_changelog("TEST-123", 1, 2)
        .await
        .expect("the changelog reads");

    assert_eq!(users[0].account_id.as_deref(), Some("account-123"));
    assert_eq!(changelog["maxResults"], 2);

    let searched = only_request(&mock, "GET", "/rest/api/2/user/search").await;
    assert_eq!(
        query_pairs(&searched),
        pairs(&[("query", "Allen"), ("startAt", "0"), ("maxResults", "25")])
    );

    let read = only_request(&mock, "GET", "/rest/api/2/issue/TEST-123/changelog").await;
    assert_eq!(
        query_pairs(&read),
        pairs(&[("startAt", "1"), ("maxResults", "2")])
    );
}

/// Issue links stay v2: this crate models no v3 link endpoint.
#[tokio::test]
async fn v2_issue_links_are_created_by_body_and_deleted_by_path() {
    let mock = JiraMock::start().await;
    mock.stub("POST", "/rest/api/2/issueLink", Step::status(201))
        .await;
    mock.stub("DELETE", "/rest/api/2/issueLink/10001", Step::status(204))
        .await;

    let client = client_for(&mock);
    client
        .create_issue_link("Blocks", "TEST-123", "TEST-456")
        .await
        .expect("the link is created");
    client
        .delete_issue_link("10001")
        .await
        .expect("the link is deleted");

    let created = only_request(&mock, "POST", "/rest/api/2/issueLink").await;
    assert_json_eq(
        &body_of(&created),
        &json!({
            "type": {"name": "Blocks"},
            "inwardIssue": {"key": "TEST-123"},
            "outwardIssue": {"key": "TEST-456"}
        }),
    );

    // The id is a path segment, so the only assertion available is that it
    // reached the path rather than a query parameter or a body.
    let deleted = only_request(&mock, "DELETE", "/rest/api/2/issueLink/10001").await;
    assert_eq!(deleted.query, None);
    assert!(deleted.body.is_empty());
}

/// The attachment upload stays v2, and is the one request that is not JSON.
///
/// It is also the one that used to bypass the shared request path, so the
/// header assertion is load-bearing: without `X-Atlassian-Token: no-check` Jira
/// rejects the upload as XSRF, and a matcher-based test that stopped naming the
/// header would go on passing.
#[tokio::test]
async fn v2_attachment_upload_is_multipart_and_carries_the_xsrf_header() {
    let mock = JiraMock::start().await;
    let attachment = temp_file("journal-attachment", b"review evidence");
    let file_name = attachment
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the attachment has a UTF-8 file name")
        .to_owned();
    mock.stub(
        "POST",
        "/rest/api/2/issue/TEST-123/attachments",
        Step::json(200, &json!([{"id": "10001", "filename": file_name}])),
    )
    .await;

    let response = client_for(&mock)
        .add_issue_attachment("TEST-123", &attachment)
        .await
        .expect("the upload succeeds");
    fs::remove_file(&attachment).expect("the attachment fixture is removable");

    assert_eq!(response[0]["id"], "10001");

    let uploaded = only_request(&mock, "POST", "/rest/api/2/issue/TEST-123/attachments").await;
    assert_eq!(
        uploaded
            .headers
            .get("x-atlassian-token")
            .map(String::as_str),
        Some("no-check")
    );
    assert!(
        uploaded
            .headers
            .get("content-type")
            .is_some_and(|value| value.starts_with("multipart/form-data")),
        "content type was {:?}",
        uploaded.headers.get("content-type")
    );

    let body = uploaded.body_text();
    assert!(body.contains("review evidence"), "body was: {body}");
    assert!(body.contains(&file_name), "body was: {body}");
}

// ---------------------------------------------------------------------------
// v3 -- the same operations through the seam that has one.
// ---------------------------------------------------------------------------

/// A v3 create is one request, and the key comes back from it.
///
/// The counterpart of `v2_create_issue_posts_then_reads_the_issue_back`, and the
/// reason both are here: the assertion that matters is the difference between
/// them, and a difference is only observable if both sides are measured. A `GET`
/// mount is deliberately absent, so a re-GET would 404 rather than passing
/// quietly -- but the journal count is what actually decides it.
#[tokio::test]
async fn v3_create_issue_is_one_round_trip_and_never_reads_the_issue_back() {
    let mock = JiraMock::start().await;
    mock.stub(
        "POST",
        "/rest/api/3/issue",
        Step::json_str(201, fixtures::jira_body("create-issue-response")),
    )
    .await;

    let created = client_for(&mock)
        .v3()
        .create_issue(
            V3CreateIssueFields::new(
                V3ProjectRef::by_key("KAN"),
                "Upgrade openssl",
                V3NamedRef::by_name("Task"),
            )
            .with_labels(["jira-automation-gh-901234-77"])
            .into(),
        )
        .await
        .expect("the create succeeds");

    assert_eq!(created.key, "KAN-77");
    assert_eq!(created.id, "10077");
    assert_eq!(
        created.self_url.as_deref(),
        Some("https://example.atlassian.net/rest/api/3/issue/10077"),
        "the v3 create response keeps the id and the API URL the v2 one discards"
    );

    let posted = only_request(&mock, "POST", "/rest/api/3/issue").await;
    assert_json_eq(
        &body_of(&posted),
        &json!({
            "fields": {
                "project": {"key": "KAN"},
                "summary": "Upgrade openssl",
                "issuetype": {"name": "Task"},
                "labels": ["jira-automation-gh-901234-77"]
            }
        }),
    );
    assert_eq!(
        mock.journal().await.len(),
        1,
        "a v3 create that reads the issue back would return Err for an issue that exists"
    );
}

/// Reading the created issue back is a second call the caller decides to make.
///
/// The read is narrowed, which is the v3 tolerance the v2 model has not got: a
/// `fields=summary,labels` response carries no `issuetype`, and `IssueFields`
/// fails it with `missing field`.
#[tokio::test]
async fn v3_get_issue_reads_a_narrowed_field_set_back() {
    let mock = JiraMock::start().await;
    mock.stub(
        "GET",
        "/rest/api/3/issue/KAN-77",
        Step::json(
            200,
            &json!({
                "id": "10077",
                "key": "KAN-77",
                "fields": {
                    "summary": "Upgrade openssl",
                    "labels": ["jira-automation-gh-901234-77"]
                }
            }),
        ),
    )
    .await;

    let options = V3GetIssueOptions::new().with_fields(["summary", "labels"]);
    let issue = client_for(&mock)
        .v3()
        .get_issue_with("KAN-77", &options)
        .await
        .expect("the narrowed read succeeds");

    assert_eq!(issue.fields.summary.as_deref(), Some("Upgrade openssl"));
    assert_eq!(
        issue.fields.labels.as_deref(),
        Some(["jira-automation-gh-901234-77".to_string()].as_slice())
    );
    assert!(
        issue.fields.issue_type.is_none(),
        "a field that was not requested reads back as None, not as an error"
    );

    let read = only_request(&mock, "GET", "/rest/api/3/issue/KAN-77").await;
    assert_eq!(query_pairs(&read), pairs(&[("fields", "summary%2Clabels")]));
}

/// A v3 comment goes out as ADF and comes back tolerant of both wire forms.
///
/// The write half is the assertion the v2 comment test cannot make: the body is
/// an ADF *object*, and the plain string the caller passed was upgraded on the
/// way out rather than sent as-is.
///
/// The read half is why `get_comments` exists at all rather than leaving reads
/// to the v2 method. The page below holds one ADF body and one v2-era string
/// body, which is what a real project that has been running for years looks
/// like; a reader that insisted on either shape would fail the whole page.
#[tokio::test]
async fn v3_comment_writes_adf_and_reads_both_wire_forms() {
    let mock = JiraMock::start().await;
    mock.stub(
        "POST",
        "/rest/api/3/issue/KAN-77/comment",
        Step::json(
            201,
            &json!({
                "id": "10100",
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": "tracked by gh-901234-77"}]
                    }]
                }
            }),
        ),
    )
    .await;
    mock.stub(
        "GET",
        "/rest/api/3/issue/KAN-77/comment",
        Step::json(
            200,
            &json!({
                "startAt": 0,
                "maxResults": 50,
                "total": 2,
                "comments": [
                    {"id": "10100", "body": "written through v2, years ago"},
                    {
                        "id": "10101",
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

    let client = client_for(&mock);
    let posted = client
        .v3()
        .add_comment(
            "KAN-77",
            V3AddCommentRequest::new("tracked by gh-901234-77"),
        )
        .await
        .expect("the comment posts");
    let options = V3GetCommentsOptions::new()
        .with_max_results(50)
        .with_order(V3CommentOrder::Created);
    let page = client
        .v3()
        .get_comments("KAN-77", &options)
        .await
        .expect("the comment page reads");

    assert_eq!(posted.id, "10100");
    assert_eq!(page.comments.len(), 2);
    assert!(
        matches!(page.comments[0].body, Some(RichText::Text(_))),
        "a v2-era string body reads back as text: {:?}",
        page.comments[0].body
    );
    assert!(
        matches!(page.comments[1].body, Some(RichText::Adf(_))),
        "a v3 body reads back as ADF: {:?}",
        page.comments[1].body
    );

    let request = only_request(&mock, "POST", "/rest/api/3/issue/KAN-77/comment").await;
    assert_json_eq(
        &body_of(&request),
        &json!({
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "tracked by gh-901234-77"}]
                }]
            }
        }),
    );

    let read = only_request(&mock, "GET", "/rest/api/3/issue/KAN-77/comment").await;
    assert_eq!(
        query_pairs(&read),
        pairs(&[("maxResults", "50"), ("orderBy", "created")])
    );
}

/// A v3 field update is a `fields` map, and a v2 one is the same shape at v2.
///
/// Both are asserted in one case because the interesting property is that the
/// bodies are identical and only the route differs: `update_issue` is the one
/// operation where the v2 and v3 wire forms genuinely agree, since a field map
/// of scalars carries no rich text to convert.
#[tokio::test]
async fn field_updates_send_the_same_body_on_both_routes() {
    let mock = JiraMock::start().await;
    mock.stub("PUT", "/rest/api/3/issue/TEST-123", Step::status(204))
        .await;
    mock.stub("PUT", "/rest/api/2/issue/TEST-123", Step::status(204))
        .await;

    let client = client_for(&mock);
    client
        .v3()
        .update_issue(
            "TEST-123",
            V3UpdateIssueRequest::new()
                .with_field("summary", "Updated summary")
                .with_field("labels", json!(["reviewed"])),
        )
        .await
        .expect("the v3 update succeeds");
    client
        .update_issue(
            "TEST-123",
            HashMap::from([
                (
                    "summary".to_string(),
                    Value::String("Updated summary".to_string()),
                ),
                ("labels".to_string(), json!(["reviewed"])),
            ]),
        )
        .await
        .expect("the v2 update succeeds");

    let expected = json!({"fields": {"summary": "Updated summary", "labels": ["reviewed"]}});
    let v3 = only_request(&mock, "PUT", "/rest/api/3/issue/TEST-123").await;
    let v2 = only_request(&mock, "PUT", "/rest/api/2/issue/TEST-123").await;
    assert_json_eq(&body_of(&v3), &expected);
    assert_json_eq(&body_of(&v2), &expected);
}

/// An update that would change nothing costs no request.
///
/// The refusal is local, so the journal is the only place the saving is visible.
#[tokio::test]
async fn an_empty_v3_update_sends_no_request() {
    let mock = JiraMock::start().await;
    mock.stub("PUT", "/rest/api/3/issue/TEST-123", Step::status(204))
        .await;

    let error = client_for(&mock)
        .v3()
        .update_issue("TEST-123", V3UpdateIssueRequest::new())
        .await
        .expect_err("an update that sets nothing is refused");

    assert!(
        error.to_string().contains("at least one field"),
        "error was: {error}"
    );
    assert!(mock.journal().await.is_empty());
}
