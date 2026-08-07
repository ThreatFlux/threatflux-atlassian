//! Four named ADF goldens, asserted against the bytes that reach the server.
//!
//! An ADF document is a tree, and every interesting property of it -- whether a
//! line break became a `hardBreak` or a paragraph split, whether an empty
//! description became an absent key or a null one, whether a `table` survived a
//! read -- is a property of the *shape*. A test that checks the return value of a
//! conversion checks the shape this crate believes it built; only a snapshot of
//! the request body checks the shape Jira would receive.
//!
//! So each golden below is a whole JSON document, compared against what the mock
//! recorded, semantically rather than byte-wise: `reqwest` serializes a struct in
//! field-declaration order and `serde_json::Map` is sorted, so two payloads that
//! differ only in key order are the same request and a byte comparison would
//! fail on a refactor that changed nothing.
//!
//! | Golden | Pins |
//! |---|---|
//! | [`golden_multiline_hard_breaks`] | A single newline inside a paragraph is a `hardBreak` node, and `\r\n` never reaches the wire |
//! | [`golden_multi_paragraph`] | A run of blank lines is one paragraph break, and every write path normalizes identically |
//! | [`golden_absent_description`] | `None` emits **no `description` key at all** -- never `"description": null`, and never an empty document |
//! | [`golden_unknown_round_trip`] | `to_value(from_value(x)) == x` over `table` and `mediaSingle`, and that such a document is refused on every write |
//!
//! # What is not asserted here
//!
//! No golden interprets markup. `**bold**` is eight characters of text in every
//! one of these documents, because the input side of this conversion is a
//! template rendered over an outside author's issue body and the guarantee worth
//! having is that such text never re-enters a parser. That negative contract has
//! its own unit tests on `text_to_adf`; what these add is that the same text
//! survives the trip to the wire.

use serde_json::{json, Value};
use threatflux_atlassian_sdk::adf::{AdfBlock, AdfDocument, AdfInline, RichText};
use threatflux_atlassian_sdk::v3::{
    V3AddCommentRequest, V3CreateIssueFields, V3NamedRef, V3ProjectRef,
};
use threatflux_atlassian_sdk::{AtlassianClient, AtlassianConfig, AtlassianError, HostPolicy};
use threatflux_atlassian_testkit::fixtures;
use threatflux_atlassian_testkit::golden::assert_json_eq;
use threatflux_atlassian_testkit::jira_mock::{JiraMock, RecordedRequest, Step};

/// The issue every case here writes to.
const ISSUE: &str = "KAN-77";

/// `POST /rest/api/3/issue`.
const CREATE_PATH: &str = "/rest/api/3/issue";

/// `PUT /rest/api/3/issue/KAN-77`.
const UPDATE_PATH: &str = "/rest/api/3/issue/KAN-77";

/// `POST /rest/api/3/issue/KAN-77/comment`.
const COMMENT_PATH: &str = "/rest/api/3/issue/KAN-77/comment";

// ---------------------------------------------------------------------------
// The goldens.
// ---------------------------------------------------------------------------

/// **Golden 1** -- a multiline description, as hard breaks inside one paragraph.
///
/// Three source lines, two of them separated by `\r\n` and `\n` respectively, so
/// the same golden proves both line-ending conventions normalize to the same
/// tree. A single newline is a break *within* a paragraph and not a new one:
/// getting that wrong turns every wrapped description into a wall of one-line
/// paragraphs, which renders differently and is invisible to any test that only
/// counts characters.
fn golden_multiline_hard_breaks() -> Value {
    json!({
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "paragraph",
            "content": [
                {"type": "text", "text": "Severity: high"},
                {"type": "hardBreak"},
                {"type": "text", "text": "Package: openssl"},
                {"type": "hardBreak"},
                {"type": "text", "text": "Advisory: GHSA-0000-1111-2222"}
            ]
        }]
    })
}

/// **Golden 2** -- a multi-paragraph description.
///
/// A run of one *or more* blank lines is a single paragraph break, which is why
/// the source below uses three: a conversion that emitted one empty paragraph
/// per blank line would produce a document that validates, renders as a column
/// of gaps, and passes every assertion that looks only at the text.
fn golden_multi_paragraph() -> Value {
    json!({
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Dependabot raised this."},
                    {"type": "hardBreak"},
                    {"type": "text", "text": "It affects the release build."}
                ]
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": "See the advisory for the fixed version."}]
            }
        ]
    })
}

/// **Golden 3** -- a create with no description at all.
///
/// The whole request body, not a fragment, because the property is the *absence*
/// of a key: a fragment assertion on `fields.description` cannot tell "the key is
/// missing" from "the key is there and null", and Jira reads those two
/// differently -- a null description on a create is a rejected request on some
/// field configurations and an explicit clear on others.
fn golden_absent_description() -> Value {
    json!({
        "fields": {
            "project": {"key": "KAN"},
            "summary": "Upgrade openssl",
            "issuetype": {"name": "Task"}
        }
    })
}

/// **Golden 4** -- a real Jira description this crate models only in part.
///
/// `table` and `mediaSingle` have no variant here and never will have one for
/// every node Atlassian ships, so they are parsed into the `Unknown` escape
/// hatch and re-emitted verbatim. The paragraph either side of them is modelled,
/// which is the case that matters: a document is a *mixture*, and a round trip
/// that preserved the unmodelled nodes by refusing to parse the modelled ones
/// would be useless.
///
/// Every shape here is one Jira actually emits. In particular there is no empty
/// `content` array and no empty `marks` array on a modelled node -- those two are
/// documented normalizations (`{"type":"paragraph","content":[]}` re-emits as
/// `{"type":"paragraph"}`), so including one would fail this golden for a reason
/// that has nothing to do with `Unknown`.
fn golden_unknown_round_trip() -> Value {
    json!({
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": "Impact"}]
            },
            {
                "type": "table",
                "attrs": {"isNumberColumnEnabled": false, "layout": "default", "localId": "t-1"},
                "content": [{
                    "type": "tableRow",
                    "content": [
                        {
                            "type": "tableHeader",
                            "attrs": {"colspan": 1, "rowspan": 1},
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": "Package"}]
                            }]
                        },
                        {
                            "type": "tableCell",
                            "attrs": {"colspan": 1, "rowspan": 1, "colwidth": [220]},
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": "openssl"}]
                            }]
                        }
                    ]
                }]
            },
            {
                "type": "mediaSingle",
                "attrs": {"layout": "center", "width": 62.5},
                "content": [{
                    "type": "media",
                    "attrs": {
                        "id": "b1c2d3e4",
                        "type": "file",
                        "collection": "contentId-10077",
                        "width": 1200,
                        "height": 630
                    }
                }]
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "see "},
                    {
                        "type": "text",
                        "text": "the advisory",
                        "marks": [{
                            "type": "link",
                            "attrs": {"href": "https://example.test/advisories/GHSA-0000-1111-2222"}
                        }]
                    }
                ]
            }
        ]
    })
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

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

/// Exactly one recorded request for `http_method` and `path`.
///
/// # Panics
///
/// Panics naming the actual count.
async fn only_request(mock: &JiraMock, http_method: &str, path: &str) -> RecordedRequest {
    let mut requests: Vec<RecordedRequest> = mock
        .journal()
        .await
        .into_iter()
        .filter(|request| request.method.eq_ignore_ascii_case(http_method) && request.path == path)
        .collect();
    assert_eq!(
        requests.len(),
        1,
        "{http_method} {path} was called {} time(s), expected exactly 1",
        requests.len()
    );
    requests.remove(0)
}

/// The JSON body of a recorded request.
///
/// # Panics
///
/// Panics if the body is not JSON.
fn body_of(request: &RecordedRequest) -> Value {
    request
        .body_json()
        .unwrap_or_else(|| panic!("{} {} carried no JSON body", request.method, request.path))
}

/// Mounts the create endpoint and returns a client for it.
async fn mock_create(mock: &JiraMock) -> AtlassianClient {
    mock.stub(
        "POST",
        CREATE_PATH,
        Step::json_str(201, fixtures::jira_body("create-issue-response")),
    )
    .await;
    client_for(mock)
}

/// The fields of a create for `KAN`, with no description set.
fn create_fields() -> V3CreateIssueFields {
    V3CreateIssueFields::new(
        V3ProjectRef::by_key("KAN"),
        "Upgrade openssl",
        V3NamedRef::by_name("Task"),
    )
}

// ---------------------------------------------------------------------------
// Golden 1 -- hard breaks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_multiline_description_reaches_the_wire_as_hard_breaks() {
    let mock = JiraMock::start().await;
    let client = mock_create(&mock).await;

    client
        .v3()
        .create_issue(
            create_fields()
                .with_description(
                    "Severity: high\r\nPackage: openssl\nAdvisory: GHSA-0000-1111-2222",
                )
                .into(),
        )
        .await
        .expect("the create succeeds");

    let posted = only_request(&mock, "POST", CREATE_PATH).await;
    assert_json_eq(
        &body_of(&posted)["fields"]["description"],
        &golden_multiline_hard_breaks(),
    );

    // The tree above cannot hold a carriage return, but the assertion is worth
    // making on the raw bytes as well: a `\r` that survived normalization would
    // sit inside a `text` node, where the golden would catch it -- and a `\r`
    // introduced anywhere else in the body would not.
    let raw = posted.body_text();
    assert!(!raw.contains('\r'), "a carriage return reached the wire");
}

// ---------------------------------------------------------------------------
// Golden 2 -- paragraphs, on every write path.
// ---------------------------------------------------------------------------

/// One golden, three write paths.
///
/// Normalization lives in `RichText::into_wire`, which all three call, but
/// "they all call it" is exactly the kind of claim that stops being true when a
/// fourth path is added. Asserting the identical document on a create, an update
/// and a comment makes the shared normalization a property of the wire rather
/// than of the call graph.
#[tokio::test]
async fn a_multi_paragraph_description_normalizes_identically_on_every_write_path() {
    const SOURCE: &str =
        "Dependabot raised this.\nIt affects the release build.\n\n\nSee the advisory for the fixed version.";

    let mock = JiraMock::start().await;
    mock.stub(
        "POST",
        CREATE_PATH,
        Step::json_str(201, fixtures::jira_body("create-issue-response")),
    )
    .await;
    mock.stub("PUT", UPDATE_PATH, Step::status(204)).await;
    mock.stub(
        "POST",
        COMMENT_PATH,
        Step::json(201, &json!({"id": "10100"})),
    )
    .await;

    let client = client_for(&mock);
    client
        .v3()
        .create_issue(create_fields().with_description(SOURCE).into())
        .await
        .expect("the create succeeds");
    client
        .v3()
        .update_issue_description(ISSUE, SOURCE)
        .await
        .expect("the description update succeeds");
    client
        .v3()
        .add_comment(ISSUE, V3AddCommentRequest::new(SOURCE))
        .await
        .expect("the comment posts");

    let golden = golden_multi_paragraph();
    let created = only_request(&mock, "POST", CREATE_PATH).await;
    let updated = only_request(&mock, "PUT", UPDATE_PATH).await;
    let commented = only_request(&mock, "POST", COMMENT_PATH).await;

    assert_json_eq(&body_of(&created)["fields"]["description"], &golden);
    assert_json_eq(&body_of(&updated)["fields"]["description"], &golden);
    assert_json_eq(&body_of(&commented)["body"], &golden);
}

// ---------------------------------------------------------------------------
// Golden 3 -- the empty description, in both directions.
// ---------------------------------------------------------------------------

/// No description means no `description` key -- not a null one.
///
/// The whole body is compared, so `assert_json_eq` reports an appearing key as
/// `unexpected key (null)` rather than passing a fragment assertion that never
/// looked.
#[tokio::test]
async fn an_absent_description_puts_no_description_key_on_the_wire() {
    let mock = JiraMock::start().await;
    let client = mock_create(&mock).await;

    client
        .v3()
        .create_issue(create_fields().into())
        .await
        .expect("the create succeeds");

    let posted = only_request(&mock, "POST", CREATE_PATH).await;
    let body = body_of(&posted);
    assert_json_eq(&body, &golden_absent_description());

    // Said twice, on purpose. The comparison above would catch a null, but only
    // as one line of a whole-document diff; this states the property the golden
    // exists for in the form a reader will look for it.
    let fields = body["fields"]
        .as_object()
        .expect("the create body carries a fields object");
    assert!(
        !fields.contains_key("description"),
        "an unset description must not appear on the wire at all, as null or otherwise"
    );
}

/// The read direction: an absent key comes back as `None`, not as empty text.
///
/// The two are not interchangeable. `None` means *not set or not requested*, and
/// a caller reconciling a description has to be able to tell it from a
/// description that was deliberately cleared.
#[tokio::test]
async fn an_absent_description_reads_back_as_none() {
    let mock = JiraMock::start().await;
    mock.stub(
        "GET",
        UPDATE_PATH,
        Step::json(
            200,
            &json!({"id": "10077", "key": ISSUE, "fields": {"summary": "Upgrade openssl"}}),
        ),
    )
    .await;

    let issue = client_for(&mock)
        .v3()
        .get_issue(ISSUE)
        .await
        .expect("the read succeeds");

    assert!(
        issue.fields.description.is_none(),
        "description was {:?}",
        issue.fields.description
    );
}

/// Where the "whitespace-only means no description" decision has to be taken.
///
/// Not here. This crate does not interpret text: `""` converts to a legal empty
/// document and `"   \n  "` converts to a paragraph holding that whitespace, and
/// both of them put a `description` key on the wire. Deciding that a
/// whitespace-only rendered template means "no description" is a policy about
/// templates, and it belongs to the caller that rendered one -- which is why the
/// Action maps it to `None` before it ever reaches a request.
///
/// Pinned rather than described, because the failure it guards against is
/// silent: an empty document is valid ADF, Jira accepts it, and the issue simply
/// ends up with its description cleared.
#[tokio::test]
async fn an_empty_or_whitespace_description_is_still_a_description_here() {
    let mock = JiraMock::start().await;
    let client = mock_create(&mock).await;

    client
        .v3()
        .create_issue(create_fields().with_description("").into())
        .await
        .expect("the create succeeds");
    client
        .v3()
        .create_issue(create_fields().with_description("   \n  ").into())
        .await
        .expect("the create succeeds");

    let requests: Vec<RecordedRequest> = mock.journal().await;
    assert_eq!(requests.len(), 2);

    assert_json_eq(
        &body_of(&requests[0])["fields"]["description"],
        &json!({"type": "doc", "version": 1, "content": []}),
    );
    assert_json_eq(
        &body_of(&requests[1])["fields"]["description"],
        &json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "   "},
                    {"type": "hardBreak"},
                    {"type": "text", "text": "  "}
                ]
            }]
        }),
    );
}

// ---------------------------------------------------------------------------
// Golden 4 -- the lossless `Unknown` round trip.
// ---------------------------------------------------------------------------

/// `to_value(from_value(x)) == x` over a document holding `table` and
/// `mediaSingle`.
///
/// This is the property that makes a read-modify-write safe. Without it, reading
/// an issue whose description contains a table, changing one paragraph and
/// writing it back destroys the table -- and nothing in the process reports an
/// error, because a closed enum that rejected the node would have failed the
/// read instead, and a catch-all that re-emitted `{"type":"unsupported"}` would
/// have succeeded at writing rubbish.
#[test]
fn an_unmodelled_node_survives_a_parse_and_re_emit_unchanged() {
    let original = golden_unknown_round_trip();

    let parsed: AdfDocument =
        serde_json::from_value(original.clone()).expect("a document with unmodelled nodes parses");
    let re_emitted = serde_json::to_value(&parsed).expect("the parsed document serializes");

    assert_json_eq(&re_emitted, &original);
    assert_eq!(
        re_emitted, original,
        "the round trip is exact, not merely semantically equal"
    );

    // The mixture is the point: the modelled paragraphs did not become `Unknown`
    // just because their neighbours did.
    assert_eq!(parsed.content.len(), 4);
    assert!(matches!(parsed.content[0], AdfBlock::Paragraph { .. }));
    assert!(matches!(parsed.content[1], AdfBlock::Unknown(_)));
    assert!(matches!(parsed.content[2], AdfBlock::Unknown(_)));
    assert!(matches!(parsed.content[3], AdfBlock::Paragraph { .. }));
}

/// The same document round-trips through `RichText`, which is how it arrives.
///
/// A description is read as a `RichText`, not as an `AdfDocument`, and the
/// untagged variant order decides which arm it lands in. An ADF document that
/// resolved to `RichText::Unknown` would still round-trip byte-for-byte and
/// would be unwritable for the wrong reason, so the variant is asserted as well
/// as the bytes.
#[test]
fn an_unmodelled_node_round_trips_through_rich_text_as_adf() {
    let original = golden_unknown_round_trip();

    let parsed: RichText =
        serde_json::from_value(original.clone()).expect("the description parses as rich text");

    assert!(
        matches!(parsed, RichText::Adf(_)),
        "a document is ADF even when some of its nodes are not modelled: {parsed:?}"
    );
    assert_eq!(
        serde_json::to_value(&parsed).expect("the rich text serializes"),
        original
    );
}

/// Read tolerance is not a write primitive: every v3 write refuses the document.
///
/// Three paths, and the journal is empty at the end of all three. A gate that
/// holds on two paths out of three is not a gate, and the one it did not hold on
/// would serialize an arbitrary caller-supplied value into a request body as
/// JSON *structure* -- sibling keys, a replaced root, forged node types.
#[tokio::test]
async fn an_unmodelled_node_is_refused_on_every_v3_write_path() {
    let mock = JiraMock::start().await;
    // Mounted so that a request which does escape is answered rather than 404ed:
    // the assertion is the empty journal, and a mount makes a leak show up as a
    // failed count instead of a confusing transport error.
    mock.stub(
        "POST",
        CREATE_PATH,
        Step::json_str(201, fixtures::jira_body("create-issue-response")),
    )
    .await;
    mock.stub("PUT", UPDATE_PATH, Step::status(204)).await;
    mock.stub(
        "POST",
        COMMENT_PATH,
        Step::json(201, &json!({"id": "10100"})),
    )
    .await;

    let document: AdfDocument = serde_json::from_value(golden_unknown_round_trip())
        .expect("a document with unmodelled nodes parses");
    let client = client_for(&mock);

    let create = client
        .v3()
        .create_issue(create_fields().with_description(document.clone()).into())
        .await
        .expect_err("a create carrying an unmodelled node is refused");
    let update = client
        .v3()
        .update_issue_description(ISSUE, document.clone())
        .await
        .expect_err("a description update carrying an unmodelled node is refused");
    let comment = client
        .v3()
        .add_comment(ISSUE, V3AddCommentRequest::new(document))
        .await
        .expect_err("a comment carrying an unmodelled node is refused");

    for error in [create, update, comment] {
        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a local validation refusal, got {error:?}"
        );
    }
    assert!(
        mock.journal().await.is_empty(),
        "a refused write must cost no round trip"
    );
}

/// A document this crate *did* build is not refused by the same gate.
///
/// The control for the case above: without it, a validator that rejected every
/// document would pass it. `hardBreak`, `heading`, `bulletList`, `codeBlock` and
/// the `link` mark are all here, so the acceptance is over the modelled surface
/// rather than over a single paragraph.
#[tokio::test]
async fn a_fully_modelled_document_is_written_unchanged() {
    let mock = JiraMock::start().await;
    mock.stub("PUT", UPDATE_PATH, Step::status(204)).await;

    let document = AdfDocument::new([
        AdfBlock::heading_text(2, "Impact"),
        AdfBlock::paragraph([
            AdfInline::text("first line"),
            AdfInline::hard_break(),
            AdfInline::link("the advisory", "https://example.test/a"),
        ]),
        AdfBlock::bullet_list([
            threatflux_atlassian_sdk::adf::AdfListItem::text("openssl"),
            threatflux_atlassian_sdk::adf::AdfListItem::text("libssl"),
        ]),
        AdfBlock::code_block_with_language("shell", "cargo update -p openssl"),
    ]);

    client_for(&mock)
        .v3()
        .update_issue_description(ISSUE, document.clone())
        .await
        .expect("a modelled document is written");

    let updated = only_request(&mock, "PUT", UPDATE_PATH).await;
    assert_json_eq(
        &body_of(&updated)["fields"]["description"],
        &serde_json::to_value(&document).expect("the document serializes"),
    );
}
