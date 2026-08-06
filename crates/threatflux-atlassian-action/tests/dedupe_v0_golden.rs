//! Golden vector for the dedupe label the Action emits today, and the hostile
//! payload corpus that has to run through it without moving it.
//!
//! The label is written onto live Jira issues and queried back with
//! `project = "..." AND labels = "..."`, so it is a wire format: change it and
//! every issue an earlier release created stops matching, silently, and the next
//! delivery mints a duplicate. `tests/fixtures/dedupe-v0-golden.json` therefore
//! pins the exact label for every case, and the assertions here compare it
//! against both the production path and an independent SHA-256 oracle.
//!
//! Three layers, in that order: the golden table equals what the crate emits,
//! the golden table equals what a second SHA-256 implementation computes, and
//! the named relations between cases (which twins collide, which diverge) hold
//! over the table. Only the first layer runs the crate, so a failure there is a
//! behaviour change and a failure in the other two is an edited fixture.
//!
//! Several tests pin behaviour that is known to be wrong -- a title is a mutable
//! identity, two dedupe fields collide with one field containing the joiner, a
//! rendered summary can exceed Jira's 255-character cap. Each is named for what
//! it pins so the change that fixes the behaviour has to update the test on
//! purpose rather than discover it as a red build.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use threatflux_atlassian_action::config::{load_config_from_str, RuleConfig};
use threatflux_atlassian_action::github::{load_issue_event_from_str, GitHubIssueEvent};
use threatflux_atlassian_action::jira::{build_create_issue_request, build_dedupe_jql};
use threatflux_atlassian_action::output::{encode_output, OutputError};
use threatflux_atlassian_action::rules::evaluate_rule;
use threatflux_atlassian_testkit::env::EnvGuard;
use threatflux_atlassian_testkit::fixtures;
use threatflux_atlassian_testkit::gha::parse_github_output;
use threatflux_atlassian_testkit::golden::assert_json_eq;

const GOLDEN: &str = include_str!("fixtures/dedupe-v0-golden.json");

/// Deliveries this suite owns, resolved ahead of the shared testkit table.
///
/// The pair differs in `issue.id`, `issue.number`, `issue.node_id` and every URL
/// derived from the number, and agrees on everything else. It is the fixture the
/// identity change has to be visible in.
const LOCAL_EVENTS: &[(&str, &str)] = &[
    (
        "identity-pair-issue-101",
        include_str!("fixtures/github/identity-pair-issue-101.json"),
    ),
    (
        "identity-pair-issue-202",
        include_str!("fixtures/github/identity-pair-issue-202.json"),
    ),
];

/// Corpus members the golden table must never lose.
const REQUIRED_CASES: &[&str] = &[
    "shipped-dependabot-repository-and-title",
    "default-label-prefix-repository-and-title",
    "identity-pair-issue-101",
    "identity-pair-issue-202",
    "hostile-title-crlf",
    "hostile-title-lone-cr",
    "hostile-title-lf",
    "hostile-title-github-output-delimiter-literal",
    "hostile-title-env-expansion-marker",
    "hostile-title-jql-metacharacters",
    "hostile-title-astral-emoji",
    "hostile-title-trailing-whitespace-twin",
    "hostile-title-over-the-jira-summary-cap",
];

/// The documented scheme, read from the golden file rather than assumed.
struct Scheme {
    joiner: String,
    hex_chars: usize,
    default_prefix: String,
    project_key: String,
}

fn golden_document() -> Value {
    serde_json::from_str(GOLDEN).expect("the golden vector should be valid JSON")
}

fn golden_cases(document: &Value) -> &Vec<Value> {
    document["cases"]
        .as_array()
        .expect("the golden vector should carry a `cases` array")
}

fn golden_case<'a>(document: &'a Value, name: &str) -> &'a Value {
    golden_cases(document)
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("golden case '{name}' is missing"))
}

fn scheme(document: &Value) -> Scheme {
    let block = &document["scheme"];
    Scheme {
        joiner: text(&block["field_joiner"]),
        hex_chars: usize::try_from(
            block["hex_digest_prefix_chars"]
                .as_u64()
                .expect("hex_digest_prefix_chars should be a number"),
        )
        .expect("hex_digest_prefix_chars should fit a usize"),
        default_prefix: text(&block["default_label_prefix"]),
        project_key: text(&block["project_key"]),
    }
}

fn text(value: &Value) -> String {
    value
        .as_str()
        .unwrap_or_else(|| panic!("expected a string, got {value}"))
        .to_string()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected an array, got {value}"))
        .iter()
        .map(text)
        .collect()
}

/// The label the documented scheme produces, computed without the crate.
///
/// A second implementation is the point: production and the golden file can only
/// agree with this one by implementing the same algorithm.
fn oracle_label(scheme: &Scheme, label_prefix: &str, values: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(values.join(&scheme.joiner).as_bytes());

    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest, "{byte:02x}").expect("write to string");
    }
    format!("{label_prefix}-{}", &digest[..scheme.hex_chars])
}

fn event_payload(name: &str) -> &'static str {
    LOCAL_EVENTS
        .iter()
        .find_map(|(key, body)| (*key == name).then_some(*body))
        .unwrap_or_else(|| fixtures::github_event(name))
}

fn event_json(name: &str) -> Value {
    serde_json::from_str(event_payload(name))
        .unwrap_or_else(|error| panic!("event fixture '{name}' is not valid JSON: {error}"))
}

fn parse_event(payload: &Value) -> GitHubIssueEvent {
    load_issue_event_from_str("issues", &payload.to_string()).expect("event should parse")
}

/// Builds the delivery a golden case describes: a fixture, optionally with
/// `issue.title` or `issue.body` swapped.
fn event_from_spec(spec: &Value) -> GitHubIssueEvent {
    let mut payload = event_json(&text(&spec["fixture"]));
    for field in ["title", "body"] {
        if let Some(value) = spec.get(field) {
            payload["issue"][field] = value.clone();
        }
    }
    parse_event(&payload)
}

/// The base delivery with `issue.title` replaced.
fn event_titled(title: &str) -> GitHubIssueEvent {
    let mut payload = event_json("issues-opened-dependabot");
    payload["issue"]["title"] = Value::String(title.to_string());
    parse_event(&payload)
}

/// The base delivery with `issue.body` replaced.
fn event_bodied(body: &str) -> GitHubIssueEvent {
    let mut payload = event_json("issues-opened-dependabot");
    payload["issue"]["body"] = Value::String(body.to_string());
    parse_event(&payload)
}

/// The shipped Dependabot rule with the dedupe block a case asks for.
///
/// Everything else -- the actor gate, the severity regex, the summary and
/// description templates, the project key -- stays as shipped, so a case
/// exercises the configuration consumers actually run.
fn dedupe_rule(label_prefix: Option<&str>, fields: &[String]) -> RuleConfig {
    let mut config = load_config_from_str(fixtures::action_config("dependabot-high"))
        .expect("the shipped dependabot config should load");
    let mut rule = config.rules.remove(0);
    rule.jira.dedupe.label_prefix = label_prefix.map(str::to_string);
    rule.jira.dedupe.fields = fields.to_vec();
    rule
}

fn repo_and_title() -> Vec<String> {
    vec![
        "repository.full_name".to_string(),
        "issue.title".to_string(),
    ]
}

/// Mirrors `resolve_event_value`, which is crate-private.
fn field_value(path: &str, event: &GitHubIssueEvent) -> String {
    match path {
        "issue.title" => event.issue.title.clone(),
        "issue.body" => event.issue.body.clone().unwrap_or_default(),
        "issue.html_url" => event.issue.html_url.clone(),
        "issue.user.login" => event.issue.user.login.clone(),
        "repository.full_name" => event.repository.full_name.clone(),
        other => panic!("unsupported dedupe field '{other}'"),
    }
}

fn label_for(rule: &RuleConfig, event: &GitHubIssueEvent) -> String {
    evaluate_rule(rule, event)
        .expect("rule evaluation should succeed")
        .expect("the corpus deliveries all carry a matching severity line")
        .dedupe_label
}

fn label_for_title(title: &str) -> String {
    let rule = dedupe_rule(Some("dependabot-alert"), &repo_and_title());
    label_for(&rule, &event_titled(title))
}

fn rendered_summary(rule: &RuleConfig, event: &GitHubIssueEvent) -> String {
    let matched = evaluate_rule(rule, event)
        .expect("rule evaluation should succeed")
        .expect("the corpus deliveries all carry a matching severity line");
    build_create_issue_request(rule, event, &matched)
        .expect("the shipped rule should build a request")
        .fields
        .summary
}

#[test]
fn the_scheme_block_describes_the_algorithm_the_oracle_implements() {
    let document = golden_document();
    let block = &document["scheme"];

    assert_eq!(block["id"], "v0-sha256-12");
    assert_eq!(
        block["digest"], "sha256",
        "the oracle hashes with SHA-256; the file may not claim otherwise"
    );
    assert_eq!(block["hex_digest_prefix_chars"], 12);
    assert_eq!(block["field_joiner"], "\n");
    assert_eq!(block["default_label_prefix"], "jira-automation");
}

#[test]
fn dedupe_labels_and_queries_match_the_golden_vector() {
    let document = golden_document();
    let scheme = scheme(&document);
    let mut recomputed = Vec::new();

    for case in golden_cases(&document) {
        let fields = strings(&case["fields"]);
        let label_prefix = case["label_prefix"].as_str();
        let rule = dedupe_rule(label_prefix, &fields);
        assert_eq!(
            rule.jira.project_key, scheme.project_key,
            "case '{}' assumes the shipped project key",
            case["name"]
        );

        let event = event_from_spec(&case["event"]);
        let values: Vec<String> = fields
            .iter()
            .map(|field| field_value(field, &event))
            .collect();
        let label = label_for(&rule, &event);
        let jql = build_dedupe_jql(&rule, &label);

        let mut entry = case.clone();
        entry["values"] = Value::from(values);
        entry["label"] = Value::String(label);
        entry["jql"] = Value::String(jql);
        recomputed.push(entry);
    }

    assert_json_eq(&Value::Array(recomputed), &document["cases"]);
}

#[test]
fn every_golden_label_matches_an_independent_sha256_oracle() {
    let document = golden_document();
    let scheme = scheme(&document);

    for case in golden_cases(&document) {
        let label_prefix = case["label_prefix"]
            .as_str()
            .map_or_else(|| scheme.default_prefix.clone(), str::to_string);
        assert_eq!(
            text(&case["label"]),
            oracle_label(&scheme, &label_prefix, &strings(&case["values"])),
            "golden case '{}'",
            case["name"]
        );
    }
}

#[test]
fn the_golden_table_keeps_every_corpus_member_and_names_each_once() {
    let document = golden_document();
    let names: Vec<String> = golden_cases(&document)
        .iter()
        .map(|case| text(&case["name"]))
        .collect();
    let unique: BTreeSet<&String> = names.iter().collect();

    assert_eq!(unique.len(), names.len(), "case names must be unique");
    for required in REQUIRED_CASES {
        assert!(
            names.iter().any(|name| name == required),
            "the corpus lost '{required}'"
        );
    }
}

#[test]
fn identity_pair_differing_only_in_issue_number_shares_one_dedupe_label_today() {
    let first = event_json("identity-pair-issue-101");
    let second = event_json("identity-pair-issue-202");

    assert_eq!(first["repository"]["id"], second["repository"]["id"]);
    assert_eq!(
        first["repository"]["full_name"],
        second["repository"]["full_name"]
    );
    assert_eq!(first["issue"]["title"], second["issue"]["title"]);
    assert_ne!(first["issue"]["number"], second["issue"]["number"]);
    assert_ne!(first["issue"]["id"], second["issue"]["id"]);
    assert_ne!(first["issue"]["node_id"], second["issue"]["node_id"]);

    let document = golden_document();
    let one = text(&golden_case(&document, "identity-pair-issue-101")["label"]);
    let two = text(&golden_case(&document, "identity-pair-issue-202")["label"]);

    // Pins today's scheme, which hashes content and cannot see the issue number:
    // two distinct GitHub issues collapse onto one Jira issue. The identity work
    // in the D workstream replaces this with `{prefix}-gh-{repo_id}-{number}`,
    // at which point this assertion becomes `assert_ne!` -- deliberately, in the
    // same change, with the alert-volume increase in the release notes.
    assert_eq!(
        one, two,
        "today's content hash cannot distinguish two issues with one title"
    );
}

#[test]
fn identity_pair_diverges_today_only_when_a_dedupe_field_carries_the_issue_number() {
    let document = golden_document();
    let one = text(&golden_case(&document, "identity-pair-issue-101-with-html-url")["label"]);
    let two = text(&golden_case(&document, "identity-pair-issue-202-with-html-url")["label"]);

    assert_ne!(
        one, two,
        "issue.html_url embeds the issue number, so it is the only per-issue \
         identity a consumer can configure today"
    );
}

#[test]
fn retitling_one_issue_mints_a_second_dedupe_label_today() {
    let before = label_for_title("Bump openssl from 1.0 to 1.1");
    let after = label_for_title("Bump openssl from 1.0 to 1.1.1");

    assert_ne!(
        before, after,
        "a mutable field in the identity is what makes a retitle create a second \
         Jira issue"
    );
}

#[test]
fn crlf_lone_cr_and_lf_title_twins_produce_three_distinct_labels() {
    let document = golden_document();
    let labels: Vec<String> = [
        "hostile-title-crlf",
        "hostile-title-lone-cr",
        "hostile-title-lf",
    ]
    .iter()
    .map(|name| text(&golden_case(&document, name)["label"]))
    .collect();
    let unique: BTreeSet<&String> = labels.iter().collect();

    assert_eq!(
        unique.len(),
        3,
        "line terminators are hashed verbatim, so the three twins do not dedupe \
         against each other: {labels:?}"
    );
}

#[test]
fn a_trailing_space_in_the_title_produces_a_distinct_label() {
    let document = golden_document();

    assert_ne!(
        text(&golden_case(&document, "shipped-dependabot-repository-and-title")["label"]),
        text(&golden_case(&document, "hostile-title-trailing-whitespace-twin")["label"]),
        "dedupe fields are hashed untrimmed"
    );
}

#[test]
fn two_dedupe_fields_collide_with_one_field_carrying_the_joiner() {
    let document = golden_document();
    let two_fields =
        text(&golden_case(&document, "shipped-dependabot-repository-and-title")["label"]);
    let one_field =
        text(&golden_case(&document, "newline-in-one-field-collides-with-two-fields")["label"]);

    // The joiner is a bare newline and no field is escaped before joining, so a
    // title of "<repo>\n<title>" reaches the digest as the same byte string the
    // two-field configuration produces.
    assert_eq!(
        two_fields, one_field,
        "the newline joiner is not injective over the field values"
    );
}

#[test]
fn jql_metacharacters_in_the_title_cannot_reach_the_dedupe_query() {
    let document = golden_document();
    let case = golden_case(&document, "hostile-title-jql-metacharacters");
    let title = text(&case["event"]["title"]);
    let jql = text(&case["jql"]);

    assert_eq!(
        jql,
        format!(
            "project = \"KAN\" AND labels = \"{}\"",
            text(&case["label"])
        )
    );
    assert!(!jql.contains("ORDER BY created"), "query: {jql}");
    assert!(!jql.contains('\''), "query: {jql}");
    assert!(
        title.contains("ORDER BY created"),
        "the hostile title must still carry the metacharacters"
    );
}

#[test]
fn every_corpus_label_stays_an_ascii_jql_safe_token() {
    let document = golden_document();

    for case in golden_cases(&document) {
        let label = text(&case["label"]);
        assert!(label.len() <= 255, "case '{}': {label}", case["name"]);
        assert!(
            label
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '-')),
            "case '{}' produced a label event data could shape: {label}",
            case["name"]
        );
    }
}

#[test]
#[serial_test::serial]
fn an_env_expansion_marker_in_event_data_is_never_expanded() {
    const CANARY: &str = "ATATT-canary-must-never-appear";

    let mut guard = EnvGuard::new();
    guard.set("JIRA_API_TOKEN", CANARY);

    let rule = dedupe_rule(Some("dependabot-alert"), &repo_and_title());
    let event = event_titled("Bump ${JIRA_API_TOKEN} openssl");
    let matched = evaluate_rule(&rule, &event)
        .expect("rule evaluation should succeed")
        .expect("rule should match");
    let request = build_create_issue_request(&rule, &event, &matched)
        .expect("the shipped rule should build a request");
    let jql = build_dedupe_jql(&rule, &matched.dedupe_label);

    // `${...}` expansion walks the parsed config only. Event data reaches the
    // template renderer, which substitutes `{{ ... }}` and never re-scans its
    // own output, so the marker is inert text on every path.
    assert!(request.fields.summary.contains("${JIRA_API_TOKEN}"));
    for rendered in [
        &matched.dedupe_label,
        &request.fields.summary,
        request
            .fields
            .description
            .as_ref()
            .expect("the shipped rule renders a description"),
        &jql,
    ] {
        assert!(
            !rendered.contains(CANARY),
            "the token leaked into {rendered}"
        );
    }
}

#[test]
fn no_corpus_payload_can_forge_a_second_github_output_entry() {
    // No step output carries a rendered summary today; `results-json` is the
    // first output that will carry event-derived text, so the corpus is driven
    // through the encoder under that name rather than a name it already fills.
    const OUTPUT_NAME: &str = "results-json";

    let document = golden_document();

    for case in golden_cases(&document) {
        let name = text(&case["name"]);
        let rule = dedupe_rule(case["label_prefix"].as_str(), &strings(&case["fields"]));
        let summary = rendered_summary(&rule, &event_from_spec(&case["event"]));

        match encode_output(OUTPUT_NAME, &summary) {
            Ok(encoded) => {
                let entries =
                    parse_github_output(&encoded).expect("the runner should parse the entry");
                assert_eq!(
                    entries,
                    vec![(OUTPUT_NAME.to_string(), summary.replace("\r\n", "\n"))],
                    "case '{name}' forged an entry"
                );
            }
            Err(error) => assert!(
                matches!(error, OutputError::BareCarriageReturn { .. }),
                "case '{name}' was rejected for the wrong reason: {error}"
            ),
        }
    }
}

#[test]
fn a_lone_carriage_return_in_the_title_is_the_one_corpus_payload_the_encoder_refuses() {
    let rule = dedupe_rule(Some("dependabot-alert"), &repo_and_title());
    let summary = rendered_summary(&rule, &event_titled("Bump openssl\rfrom 1.0 to 1.1"));

    assert_eq!(
        encode_output("results-json", &summary),
        Err(OutputError::BareCarriageReturn {
            name: "results-json".to_string(),
        })
    );
}

#[test]
fn a_32_kib_issue_body_reaches_the_jira_description_unbounded_today() {
    const BODY_BYTES: usize = 32 * 1024;
    const SEVERITY_LINE: &str = "Severity: high\n";

    let body = format!(
        "{SEVERITY_LINE}{}",
        "A".repeat(BODY_BYTES - SEVERITY_LINE.len())
    );
    assert_eq!(body.len(), BODY_BYTES);

    let rule = dedupe_rule(Some("dependabot-alert"), &repo_and_title());
    let event = event_bodied(&body);
    let matched = evaluate_rule(&rule, &event)
        .expect("rule evaluation should succeed")
        .expect("rule should match");
    let request = build_create_issue_request(&rule, &event, &matched)
        .expect("the shipped rule should build a request");

    // Pins the absence of a bound. Jira's description limit is roughly 32,767
    // characters and a GitHub body reaches 65,536, so the output bounding the B
    // workstream owns has to land before ADF multiplies this by ~48 bytes a line.
    assert_eq!(
        request.fields.description.as_deref(),
        Some(body.as_str()),
        "the body is forwarded verbatim, with no cap and no ellipsis"
    );
}

#[test]
fn a_256_character_title_renders_a_summary_over_the_jira_255_character_cap() {
    const JIRA_SUMMARY_CAP: usize = 255;

    let document = golden_document();
    let title =
        text(&golden_case(&document, "hostile-title-over-the-jira-summary-cap")["event"]["title"]);
    assert_eq!(
        title.chars().count(),
        256,
        "GitHub accepts issue titles up to 256 characters"
    );

    let rule = dedupe_rule(Some("dependabot-alert"), &repo_and_title());
    let summary = rendered_summary(&rule, &event_titled(&title));

    // NF9: the shipped template prepends "[Dependabot][High] " to a title that
    // already reaches the GitHub maximum, so this is a Jira 400 today, with no
    // truncation anywhere in the crate to prevent it.
    assert!(
        summary.chars().count() > JIRA_SUMMARY_CAP,
        "summary is {} characters",
        summary.chars().count()
    );
    assert!(summary.ends_with(&title), "summary: {summary}");
}

#[test]
fn a_four_byte_emoji_can_straddle_the_byte_the_summary_cap_falls_on() {
    const JIRA_SUMMARY_CAP: usize = 255;
    const ROCKET: &str = "\u{1f680}";

    let rule = dedupe_rule(Some("dependabot-alert"), &repo_and_title());
    let template_bytes = rendered_summary(&rule, &event_titled("@")).len() - 1;
    let pad = JIRA_SUMMARY_CAP - 2 - template_bytes;
    let title = format!("{}{ROCKET} from 1.0 to 1.1", "x".repeat(pad));
    let summary = rendered_summary(&rule, &event_titled(&title));

    assert_eq!(summary.find(ROCKET), Some(JIRA_SUMMARY_CAP - 2));
    assert!(summary.len() > JIRA_SUMMARY_CAP);

    // A cap applied as `&summary[..255]` panics here. Truncation has to be
    // char-boundary safe, which is why the corpus carries an astral-plane
    // character rather than only accented Latin.
    assert!(
        !summary.is_char_boundary(JIRA_SUMMARY_CAP),
        "the emoji should span the cap byte"
    );
}
