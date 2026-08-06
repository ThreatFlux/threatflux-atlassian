//! `GITHUB_OUTPUT` encoding proven against the runner's own grammar.
//!
//! Every assertion re-parses the bytes the encoder produced with
//! `threatflux_atlassian_testkit::gha`, which implements both forms the runner
//! accepts -- `name=value` and `name<<DELIM` -- and ends a line on `\r\n`, `\n`
//! and a lone `\r`, as .NET line splitting does. Asserting on the parsed entry
//! list rather than on a substring is what makes a forged entry visible:
//! `raw.contains("severity=high")` also holds on a file that carries a
//! `created=true` smuggled out of a value.
//!
//! The severity capture is driven through a deliberately permissive `(?s)`
//! regex rather than the restrictive one the shipped configs use. Encoding
//! safety may not depend on a consumer's regex: a config capturing
//! `(high|critical)` cannot express a hostile token at all, so a suite built on
//! one would pass against an encoder that forges entries. The permissive regex
//! hands the encoder the whole attacker-controlled body, which is the input the
//! property has to hold for.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use threatflux_atlassian_action::config::load_config_from_str;
use threatflux_atlassian_action::github::load_issue_event_from_str;
use threatflux_atlassian_action::output::{
    encode_output, is_severity_token, OutputError, OutputWriter, DELIMITER_PREFIX,
    MAX_OUTPUT_VALUE_BYTES,
};
use threatflux_atlassian_action::rules::evaluate_rule;
use threatflux_atlassian_testkit::fixtures;
use threatflux_atlassian_testkit::gha::{github_output_map, parse_github_output};

/// A consumer config whose severity capture is deliberately unconstrained.
///
/// `(?s)` makes `.` match a newline, so capture group 1 is the entire body
/// between the markers, terminators included.
const PERMISSIVE_CONFIG: &str = r"
version: 1
rules:
  - id: permissive-severity-capture
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?s)<severity>(.*)</severity>'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
";

/// The shape of severity regex every shipped config uses.
const RESTRICTIVE_CONFIG: &str = r"
version: 1
rules:
  - id: restrictive-severity-capture
    when:
      event: issues
      action: opened
    extract:
      severity:
        from: issue.body
        regex: '(?mi)^severity:\s*(high|critical)\b'
    jira:
      project_key: KAN
      issue_type: Bug
      priority_by_severity:
        high: High
      summary: test
      description: test
      dedupe:
        strategy: sha256
        fields: [repository.full_name, issue.title]
";

/// A body carrying both a token the restrictive regex accepts and a forgery.
const FORGING_BODY: &str = "Severity: high\n<severity>high\ncreated=true\nmatched-rule-id=forged\njira-issue-key=EVIL-1</severity>\n";

/// One hostile payload and the value a consumer must read back for it.
struct Payload {
    case: &'static str,
    value: String,
    read_back: String,
}

/// A payload the encoder must carry through unchanged.
fn exact(case: &'static str, value: impl Into<String>) -> Payload {
    let value = value.into();
    Payload {
        case,
        read_back: value.clone(),
        value,
    }
}

/// A payload whose CRLF pairs the encoder normalizes before writing.
fn normalized(case: &'static str, value: &str, read_back: &str) -> Payload {
    Payload {
        case,
        value: value.to_string(),
        read_back: read_back.to_string(),
    }
}

/// Hostile values, every one of which must survive the round trip intact.
fn corpus() -> Vec<Payload> {
    // Every delimiter already in the file is public information: a later step in
    // the same job can read it. Replaying one is the cheapest forgery attempt.
    let stolen = delimiter_written_for("high");

    vec![
        exact("plain_token", "high"),
        exact("empty", ""),
        exact("forged_key_value_line", "high\ncreated=true"),
        exact(
            "forged_whole_output_set",
            "high\nmatched-rule-id=forged\ncreated=true\njira-issue-key=EVIL-1\ndeduped=true\nseverity=low",
        ),
        exact(
            "forged_heredoc_opener",
            "high\nresults-json<<X\n{\"forged\": true}\nX",
        ),
        exact("forged_empty_delimiter_opener", "high\nresults-json<<\n"),
        exact(
            "literal_delimiter_prefix",
            format!("high\n{DELIMITER_PREFIX}\ncreated=true"),
        ),
        exact(
            "delimiter_prefix_with_digest_shape",
            format!("high\n{DELIMITER_PREFIX}{}\ncreated=true", "0".repeat(64)),
        ),
        exact(
            "delimiter_stolen_from_another_value",
            format!("high\n{stolen}\ncreated=true"),
        ),
        exact(
            "delimiter_of_another_entry_in_the_same_file",
            format!("high\n{}\ncreated=true", delimiter_written_for("false")),
        ),
        exact(
            "delimiter_stolen_and_reopened",
            format!("{stolen}\nseverity<<{stolen}\nforged\n{stolen}"),
        ),
        normalized("crlf_forgery", "high\r\ncreated=true\r\n", "high\ncreated=true\n"),
        normalized("crlf_only", "\r\n\r\n", "\n\n"),
        exact("env_expansion_marker", "${JIRA_API_TOKEN}\ncreated=true"),
        exact(
            "jql_metacharacters",
            "high\" AND labels = \"x\" OR project = \"KAN\" -- \\ '\ncreated=true",
        ),
        exact("astral_emoji_around_a_forgery", "🚨\ncreated=true\n😀"),
        // The runner reads the file with .NET `ReadLine`, which ends a line on
        // CR, LF and CRLF and on nothing else -- NEL, LS and PS are ordinary
        // characters there. If that ever stops being true these are line
        // terminators the encoder does not normalize, and this case fails.
        exact(
            "unicode_line_separators",
            "high\u{2028}created=true\u{85}deduped=true\u{2029}jira-issue-key=EVIL-1",
        ),
        exact("trailing_whitespace_twin", "high "),
        exact("tab_indented_forgery", "high\n\tcreated=true"),
        exact("leading_and_trailing_newlines", "\n\nhigh\n\n"),
        exact("newlines_only", "\n\n\n"),
        exact("thirty_two_kib_of_forgeries", "created=true\n".repeat(2600)),
        exact("over_255_characters", format!("high\n{}", "h".repeat(300))),
    ]
}

/// Values the encoder must refuse outright, and the refusal each one draws.
fn rejected_corpus() -> Vec<(&'static str, String, OutputError)> {
    let name = "severity".to_string();

    vec![
        (
            "lone_carriage_return_forgery",
            "high\rcreated=true".to_string(),
            OutputError::BareCarriageReturn { name: name.clone() },
        ),
        (
            "trailing_lone_carriage_return",
            "high\r".to_string(),
            OutputError::BareCarriageReturn { name: name.clone() },
        ),
        (
            "carriage_return_before_a_crlf_pair",
            "high\r\r\ncreated=true".to_string(),
            OutputError::BareCarriageReturn { name: name.clone() },
        ),
        (
            "nul_byte",
            "high\0created=true".to_string(),
            OutputError::InteriorNul { name: name.clone() },
        ),
        (
            "oversize_value",
            "a".repeat(MAX_OUTPUT_VALUE_BYTES + 1),
            OutputError::ValueTooLarge {
                name,
                bytes: MAX_OUTPUT_VALUE_BYTES + 1,
                limit: MAX_OUTPUT_VALUE_BYTES,
            },
        ),
    ]
}

/// The delimiter an encoded entry opened with, read off the wire.
///
/// The delimiter mixes a per-entry nonce into its digest, so it cannot be
/// recomputed from the value; a test that needs one takes it from bytes the
/// encoder already wrote, which is exactly what a later step in the job can do.
fn delimiter_of(encoded: &str) -> String {
    encoded
        .split_once("<<")
        .and_then(|(_, rest)| rest.split_once('\n'))
        .map(|(delimiter, _)| delimiter.to_string())
        .expect("an encoded entry opens a heredoc")
}

/// A delimiter the encoder wrote for `value` in an earlier entry.
fn delimiter_written_for(value: &str) -> String {
    delimiter_of(&encode_output("severity", value).expect("value should encode"))
}

/// Every line of `value` that has the exact shape a delimiter has.
fn delimiter_shaped_digests(value: &str) -> Vec<&str> {
    value
        .split('\n')
        .filter_map(|line| line.strip_prefix(DELIMITER_PREFIX))
        .filter(|digest| digest.len() == 64 && digest.chars().all(|ch| ch.is_ascii_hexdigit()))
        .collect()
}

/// `DELIMITER_PREFIX` plus the unsalted hex SHA-256 of `value`.
///
/// The delimiter this encoder used to publish, kept as the shape the current one
/// must never reproduce: it is a confirmation oracle for a guessed value.
fn oracle_delimiter(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());

    let mut delimiter = DELIMITER_PREFIX.to_string();
    for byte in hasher.finalize() {
        write!(&mut delimiter, "{byte:02x}").expect("write to string");
    }
    delimiter
}

fn write_entries(entries: &[(&str, &str)]) -> String {
    let mut writer = OutputWriter::new(Vec::new());
    for (name, value) in entries {
        writer.write(name, value).expect("entry should encode");
    }
    String::from_utf8(writer.into_inner()).expect("output should be utf-8")
}

/// The Action's five outputs, with `severity` carrying `value`.
///
/// `write` rather than `write_severity`: the allowlist is a second gate, and
/// bypassing it here is what leaves the encoding alone under test.
fn outcome_file(severity: &str) -> String {
    let entries = outcome_entries(severity);
    let borrowed: Vec<(&str, &str)> = entries
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    write_entries(&borrowed)
}

/// The same five outputs in the form `write_outputs` used before the encoder:
/// one `name=value` line each, written with no encoding at all.
fn plain_key_value_outcome_file(severity: &str) -> String {
    let mut raw = String::new();
    for (name, value) in outcome_entries(severity) {
        writeln!(&mut raw, "{name}={value}").expect("write to string");
    }
    raw
}

/// The same five outputs in the heredoc form with a delimiter chosen without
/// reading the value, which is the shape a fixed-delimiter encoder takes.
fn fixed_delimiter_outcome_file(severity: &str, delimiter: &str) -> String {
    let mut raw = String::new();
    for (name, value) in outcome_entries(severity) {
        writeln!(&mut raw, "{name}<<{delimiter}\n{value}\n{delimiter}").expect("write to string");
    }
    raw
}

/// Names the cases for which `encode` produces a file that is not the five
/// intended entries -- a forged entry, an overwritten one, or an unparseable
/// file.
fn cases_reaching_a_different_file(
    corpus: &[Payload],
    encode: impl Fn(&str) -> String,
) -> Vec<&'static str> {
    corpus
        .iter()
        .filter(|payload| {
            parse_github_output(&encode(&payload.value)).ok()
                != Some(expected_entries(&payload.read_back))
        })
        .map(|payload| payload.case)
        .collect()
}

fn outcome_entries(severity: &str) -> [(&'static str, String); 5] {
    [
        ("matched-rule-id", "severity-capture".to_string()),
        ("created", "false".to_string()),
        ("jira-issue-key", String::new()),
        ("deduped", "false".to_string()),
        ("severity", severity.to_string()),
    ]
}

fn expected_entries(severity: &str) -> Vec<(String, String)> {
    outcome_entries(severity)
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect()
}

/// Runs `config` over the dependabot delivery with `body` swapped in.
fn extract_severity(config: &str, body: &str) -> Option<String> {
    let config = load_config_from_str(config).expect("config should load");
    let payload = fixtures::github_event_with_issue_body("issues-opened-dependabot", body);
    let event = load_issue_event_from_str("issues", &payload).expect("event should parse");

    evaluate_rule(&config.rules[0], &event)
        .expect("rule evaluation should succeed")
        .map(|matched| matched.severity)
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}"))
}

/// Runs the action binary in dry run over `body`, returning exit success and
/// the raw `GITHUB_OUTPUT` file.
fn run_action_binary(prefix: &str, body: &str) -> (bool, String) {
    let temp_root = unique_temp_dir(prefix);
    fs::create_dir_all(&temp_root).expect("temp dir should be created");

    let config_path = temp_root.join("jira-automation.yml");
    let event_path = temp_root.join("event.json");
    let output_path = temp_root.join("github-output.txt");

    fs::write(&config_path, PERMISSIVE_CONFIG).expect("config should be written");
    fs::write(
        &event_path,
        fixtures::github_event_with_issue_body("issues-opened-dependabot", body),
    )
    .expect("event should be written");

    let status = Command::new(env!("CARGO_BIN_EXE_threatflux-atlassian-action"))
        .env_remove("INPUT_CONFIG_PATH")
        .env_remove("INPUT_DRY_RUN")
        .env_remove("INPUT_EVENT_NAME")
        .env_remove("INPUT_EVENT_PATH")
        .env_remove("GITHUB_EVENT_NAME")
        .env_remove("GITHUB_EVENT_PATH")
        .env_remove("JIRA_BASE_URL")
        .env_remove("JIRA_URL")
        .env("INPUT_CONFIG-PATH", config_path.display().to_string())
        .env("INPUT_DRY-RUN", "true")
        .env("INPUT_EVENT-NAME", "issues")
        .env("INPUT_EVENT-PATH", event_path.display().to_string())
        .env("GITHUB_OUTPUT", output_path.display().to_string())
        .status()
        .expect("binary should execute");

    let raw = fs::read_to_string(&output_path).expect("github output should exist");
    (status.success(), raw)
}

#[test]
fn every_hostile_payload_round_trips_through_the_runner_grammar() {
    for payload in corpus() {
        let raw = write_entries(&[("severity", payload.value.as_str())]);
        let entries = parse_github_output(&raw).expect("the runner must parse the file");

        assert_eq!(
            entries,
            vec![("severity".to_string(), payload.read_back.clone())],
            "case {}",
            payload.case
        );
        assert!(
            !raw.contains('\r'),
            "case {}: a carriage return reaching the file ends the line for the runner",
            payload.case
        );
    }
}

#[test]
fn a_hostile_payload_cannot_forge_an_extra_output() {
    for payload in corpus() {
        let raw = outcome_file(&payload.value);
        let entries = parse_github_output(&raw).expect("the runner must parse the file");

        assert_eq!(
            entries,
            expected_entries(&payload.read_back),
            "case {}",
            payload.case
        );

        let map = github_output_map(&raw).expect("the runner must parse the file");
        assert_eq!(map.len(), 5, "case {}: exactly five outputs", payload.case);
        assert_eq!(
            map["created"], "false",
            "case {}: a value may not overwrite another output",
            payload.case
        );
        assert_eq!(
            map["jira-issue-key"], "",
            "case {}: a value may not overwrite another output",
            payload.case
        );
    }
}

#[test]
fn a_severity_captured_by_a_permissive_regex_cannot_forge_an_output() {
    for payload in corpus() {
        // An empty capture is dropped before any output is written, so there is
        // nothing to encode for it; the direct-encoder cases cover the value.
        if payload.value.is_empty() {
            continue;
        }

        let body = format!("<severity>{}</severity>", payload.value);
        let severity = extract_severity(PERMISSIVE_CONFIG, &body)
            .unwrap_or_else(|| panic!("case {}: the permissive regex must capture", payload.case));

        assert_eq!(
            severity,
            payload.value.to_lowercase(),
            "case {}: the capture must reach the writer verbatim",
            payload.case
        );

        let raw = outcome_file(&severity);
        let entries = parse_github_output(&raw).expect("the runner must parse the file");
        assert_eq!(
            entries,
            expected_entries(&payload.read_back.to_lowercase()),
            "case {}",
            payload.case
        );
    }
}

#[test]
fn the_restrictive_production_regex_would_have_masked_the_encoding() {
    let restrictive = extract_severity(RESTRICTIVE_CONFIG, FORGING_BODY)
        .expect("the restrictive regex should match the body");
    assert_eq!(
        restrictive, "high",
        "a shipped config can only ever yield a flat token"
    );
    assert!(is_severity_token(&restrictive));

    let permissive = extract_severity(PERMISSIVE_CONFIG, FORGING_BODY)
        .expect("the permissive regex should match the body");
    assert!(
        permissive.contains("created=true") && permissive.contains("jira-issue-key=evil-1"),
        "the permissive capture must carry the forgery: {permissive:?}"
    );
    assert!(
        !is_severity_token(&permissive),
        "the forgery must be outside the allowlist"
    );

    for severity in [restrictive, permissive] {
        let raw = outcome_file(&severity);
        let entries = parse_github_output(&raw).expect("the runner must parse the file");
        let map = github_output_map(&raw).expect("the runner must parse the file");

        assert_eq!(entries.len(), 5, "severity {severity:?}");
        assert_eq!(map["created"], "false", "severity {severity:?}");
        assert_eq!(map["jira-issue-key"], "", "severity {severity:?}");
        assert_eq!(map["severity"], severity);
    }
}

#[test]
fn the_encoding_holds_without_the_severity_allowlist() {
    // The severity path and the ordinary path have to reach the same file: the
    // token shape is a description of what shipped configs produce, not a gate,
    // because a severity is written after the Jira write it reports on.
    let hostile = "high\ncreated=true\nmatched-rule-id=forged";
    assert!(
        !is_severity_token(hostile),
        "the token must be outside the shipped shape"
    );

    let mut guarded = OutputWriter::new(Vec::new());
    guarded
        .write_severity("severity", Some(hostile))
        .expect("an unusual token is not a reason to fail the step");
    let guarded_raw = String::from_utf8(guarded.into_inner()).expect("output should be utf-8");
    let raw = write_entries(&[("severity", hostile)]);
    let expected = vec![("severity".to_string(), hostile.to_string())];

    assert_eq!(
        parse_github_output(&guarded_raw).expect("the runner must parse the file"),
        expected,
        "the severity path must reach the same one entry"
    );
    assert_eq!(
        parse_github_output(&raw).expect("the runner must parse the file"),
        expected,
        "the encoding, not the allowlist, is what keeps this to one entry"
    );
}

#[test]
fn no_hostile_payload_can_carry_its_own_delimiter() {
    for payload in corpus() {
        let encoded = encode_output("severity", &payload.value).expect("value should encode");
        let delimiter = delimiter_of(&encoded);

        assert!(
            delimiter.starts_with(DELIMITER_PREFIX)
                && delimiter.len() == DELIMITER_PREFIX.len() + 64,
            "case {}: unexpected delimiter shape {delimiter}",
            payload.case
        );
        assert!(
            !payload.read_back.contains(delimiter.as_str()),
            "case {}: the value carries its own delimiter",
            payload.case
        );

        assert_eq!(
            encoded,
            format!(
                "severity<<{delimiter}\n{}\n{delimiter}\n",
                payload.read_back
            ),
            "case {}",
            payload.case
        );
        assert_eq!(
            encoded.matches(delimiter.as_str()).count(),
            2,
            "case {}: the delimiter appears only as the opener and the closer",
            payload.case
        );
    }
}

#[test]
fn the_delimiter_cannot_confirm_a_guess_at_the_value_it_closes() {
    // The delimiter is written in cleartext next to the value. If it were
    // `sha256(value)`, anyone holding the file could test a guessed value
    // against it -- free today, a disclosure as soon as a masked value goes
    // through this encoder. Two encodings of one value must therefore differ,
    // and neither may be the unsalted digest.
    for payload in corpus() {
        let first = delimiter_of(&encode_output("severity", &payload.value).expect("encodes"));
        let second = delimiter_of(&encode_output("severity", &payload.value).expect("encodes"));

        assert_ne!(
            first, second,
            "case {}: the delimiter is a function of the value alone",
            payload.case
        );
        for delimiter in [&first, &second] {
            assert_ne!(
                *delimiter,
                oracle_delimiter(&payload.read_back),
                "case {}: the delimiter is the unsalted digest of the value",
                payload.case
            );
        }
    }
}

#[test]
fn a_rejected_payload_writes_nothing_and_leaves_the_file_parseable() {
    for (case, value, expected) in rejected_corpus() {
        let mut writer = OutputWriter::new(Vec::new());
        writer
            .write("created", "false")
            .expect("entry should encode");
        let error = writer
            .write("severity", &value)
            .expect_err("the value must be refused");

        assert_eq!(
            error.downcast_ref::<OutputError>(),
            Some(&expected),
            "case {case}"
        );

        let raw = String::from_utf8(writer.into_inner()).expect("output should be utf-8");
        assert_eq!(
            parse_github_output(&raw).expect("the runner must parse the file"),
            vec![("created".to_string(), "false".to_string())],
            "case {case}: only the accepted entry may reach the file"
        );
    }
}

#[test]
fn the_plain_key_value_form_is_the_forgery_the_encoder_removes() {
    // Both of these are what `writeln!(handle, "severity={value}")` -- the form
    // `write_outputs` used before the encoder existed -- puts on disk for a
    // hostile severity.
    for naive in [
        "severity=high\ncreated=true\n",
        "severity=high\rcreated=true\n",
    ] {
        let entries = parse_github_output(naive).expect("the runner must parse the file");
        assert_eq!(
            entries,
            vec![
                ("severity".to_string(), "high".to_string()),
                ("created".to_string(), "true".to_string()),
            ],
            "the plain form forges an entry for {naive:?}"
        );
    }

    let encoded = write_entries(&[("severity", "high\ncreated=true")]);
    assert_eq!(
        parse_github_output(&encoded).expect("the runner must parse the file"),
        vec![("severity".to_string(), "high\ncreated=true".to_string())]
    );
    assert!(encode_output("severity", "high\rcreated=true").is_err());
}

#[test]
fn the_corpus_forges_entries_against_the_encodings_this_one_replaces() {
    let corpus = corpus();

    let forged_by_plain = cases_reaching_a_different_file(&corpus, plain_key_value_outcome_file);
    assert!(
        forged_by_plain.contains(&"forged_key_value_line"),
        "the corpus must falsify the plain `name=value` form: {forged_by_plain:?}"
    );

    let forged_by_fixed = cases_reaching_a_different_file(&corpus, |severity| {
        fixed_delimiter_outcome_file(severity, DELIMITER_PREFIX)
    });
    assert!(
        forged_by_fixed.contains(&"literal_delimiter_prefix"),
        "the corpus must falsify a delimiter chosen without reading the value: {forged_by_fixed:?}"
    );

    let forged_by_encoder = cases_reaching_a_different_file(&corpus, outcome_file);
    assert!(
        forged_by_encoder.is_empty(),
        "the encoder under test must forge nothing: {forged_by_encoder:?}"
    );
}

#[test]
fn the_corpus_covers_the_shapes_the_encoding_has_to_survive() {
    let corpus = corpus();

    let mut cases: Vec<&str> = corpus.iter().map(|payload| payload.case).collect();
    cases.sort_unstable();
    let mut unique = cases.clone();
    unique.dedup();
    assert_eq!(cases, unique, "case names must be unique");

    let covers = |what: &str, found: bool| assert!(found, "the corpus lost its {what} case");
    let any = |predicate: fn(&Payload) -> bool| corpus.iter().any(predicate);

    covers(
        "newline + key=value forgery",
        any(|payload| payload.value.contains("\ncreated=true")),
    );
    covers("CRLF", any(|payload| payload.value.contains("\r\n")));
    covers(
        "literal delimiter prefix",
        any(|payload| payload.value.contains(DELIMITER_PREFIX)),
    );
    // A delimiter the encoder actually wrote cannot be recomputed from a value
    // any more, so the corpus is checked for the shape rather than for a
    // specific string: a `ghadelimiter_` line carrying a real 64-hex digest, as
    // opposed to the synthetic all-zero one the literal-shape case carries.
    covers(
        "stolen delimiter",
        corpus.iter().any(|payload| {
            delimiter_shaped_digests(&payload.value)
                .iter()
                .any(|digest| *digest != "0".repeat(64))
        }),
    );
    covers(
        "env expansion marker",
        any(|payload| payload.value.contains("${JIRA_API_TOKEN}")),
    );
    covers(
        "JQL metacharacter",
        any(|payload| payload.value.contains("\" AND labels = ")),
    );
    covers(
        "four-byte character",
        any(|payload| payload.value.chars().any(|c| c.len_utf8() == 4)),
    );
    covers(
        "32 KiB body",
        any(|payload| payload.value.len() > 32 * 1024),
    );
    covers(
        "over-255-character",
        any(|payload| payload.value.chars().count() > 255),
    );
    covers(
        "trailing whitespace",
        any(|payload| payload.value.ends_with(' ')),
    );
    covers(
        "unicode line separator",
        any(|payload| payload.value.contains('\u{2028}')),
    );
}

#[test]
fn the_action_binary_writes_a_permissively_captured_severity() {
    let (success, raw) = run_action_binary("g5-permissive-accepted", "<severity>high</severity>");
    assert!(success, "the run should succeed");

    let map = github_output_map(&raw).expect("the runner must parse the file");
    assert_eq!(map.len(), 5);
    assert_eq!(map["matched-rule-id"], "permissive-severity-capture");
    assert_eq!(map["severity"], "high");
    assert_eq!(map["created"], "false");
}

#[test]
fn the_action_binary_carries_a_forged_severity_without_forging_an_output() {
    let forgery = "high\ncreated=true\nmatched-rule-id=forged\njira-issue-key=EVIL-1";
    let (success, raw) = run_action_binary(
        "g5-permissive-forgery",
        &format!("<severity>{forgery}</severity>"),
    );

    // The step succeeds: the forgery is data, and the run it reports on -- a
    // Jira create or dedupe on a non-dry run -- has already happened by the time
    // this value is written. What has to hold is that the file still parses to
    // exactly the five declared outputs.
    assert!(success, "an unusual severity token must not fail the run");

    let entries = parse_github_output(&raw).expect("the runner must parse the file");
    assert_eq!(
        entries,
        vec![
            (
                "matched-rule-id".to_string(),
                "permissive-severity-capture".to_string()
            ),
            ("created".to_string(), "false".to_string()),
            ("jira-issue-key".to_string(), String::new()),
            ("deduped".to_string(), "false".to_string()),
            ("severity".to_string(), forgery.to_lowercase()),
        ],
        "the five declared outputs, with the forgery carried as one value"
    );

    let map = github_output_map(&raw).expect("the runner must parse the file");
    assert_eq!(map.len(), 5);
    assert_eq!(
        map["jira-issue-key"], "",
        "the forged key must not become the step's issue key"
    );
    assert_eq!(map["created"], "false");
    assert_eq!(map["matched-rule-id"], "permissive-severity-capture");
}
