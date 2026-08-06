//! Encoding of the Action's `GITHUB_OUTPUT` entries.
//!
//! The runner reads that file as a sequence of `name=value` lines and
//! `name<<DELIM` heredocs, and it splits lines on `\r\n`, `\n` **and a lone
//! `\r`**. So a value written in the `name=value` form forges a second entry as
//! soon as it carries any line terminator, and a value written into a heredoc
//! with a fixed delimiter forges one as soon as it carries a line equal to that
//! delimiter.
//!
//! Every value here is written as a heredoc whose delimiter is
//! [`DELIMITER_PREFIX`] followed by the hex SHA-256 of a per-entry nonce and the
//! exact bytes being written. Forging the closing line then requires a value
//! that contains a digest over a nonce it has never seen -- the nonce is drawn
//! after the value is fixed and is never written anywhere -- so the collision the
//! fixed-delimiter form allows stays unreachable. A value carrying the literal
//! `ghadelimiter_` prefix, or a delimiter copied from an earlier entry, is
//! ordinary text under that rule, and [`OutputError::DelimiterCollision`] is the
//! enforced check rather than an assumed property.
//!
//! The nonce is what keeps the delimiter from being a *confirmation oracle*.
//! An unsalted `sha256(value)` published in cleartext next to the value lets
//! anyone holding the file test a guess: compute the digest of the guess and
//! compare. That costs nothing while every value here is a public token, and
//! becomes a disclosure the moment a masked value is routed through this
//! encoder. Un-forgeability never needed the digest to be a function of the
//! value alone, so it is not.
//!
//! Every refusal here is a *value* this encoder will not misrepresent, never a
//! verdict on the run that produced it. The encoding runs before the sink is
//! touched and the nonce comes from a fallible OS read rather than a panicking
//! one (`draw_nonce`), so a refusal costs exactly one entry; deciding what to
//! do about it belongs to the caller, and `write_outcome` -- which runs after
//! the irreversible Jira write -- logs it and keeps writing.

use anyhow::Result;
use rand::rngs::SysRng;
use rand::TryRng as _;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fmt::Write as _;
use std::io::Write;
use std::sync::LazyLock;

/// Largest value, in bytes, that may be written as one output entry.
pub const MAX_OUTPUT_VALUE_BYTES: usize = 1 << 20;

/// Largest accepted output name, in bytes.
pub const MAX_OUTPUT_NAME_BYTES: usize = 128;

/// Size of the per-entry nonce mixed into a delimiter, in bytes.
///
/// 256 bits, drawn from the OS CSPRNG per entry: the delimiter has to be
/// unguessable to a value that was written before it was drawn, and a nonce a
/// forger could enumerate -- a clock reading, a counter -- would let a large
/// value simply list the candidate digests.
const DELIMITER_NONCE_BYTES: usize = 32;

/// Prefix carried by every generated heredoc delimiter.
///
/// Kept equal to the prefix the GitHub toolkit uses so a human reading the file
/// sees the form they expect; the collision resistance comes from the digest
/// that follows it, never from the prefix.
pub const DELIMITER_PREFIX: &str = "ghadelimiter_";

/// Accepted shape of a severity token.
static SEVERITY_TOKEN_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,31}$").expect("valid regex"));

/// Accepted shape of an output name.
static OUTPUT_NAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").expect("valid regex"));

/// A value or name that cannot be encoded safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputError {
    /// The output name is empty, over-long, or carries a character that would
    /// change how the runner parses the line.
    InvalidName {
        /// The rejected name.
        name: String,
    },
    /// The value carries a NUL byte.
    InteriorNul {
        /// Name the value was being written for.
        name: String,
    },
    /// The value carries a carriage return that is not part of a `\r\n` pair.
    ///
    /// The runner ends a line on a lone `\r`, so such a value forges an entry.
    BareCarriageReturn {
        /// Name the value was being written for.
        name: String,
    },
    /// The value exceeds [`MAX_OUTPUT_VALUE_BYTES`].
    ValueTooLarge {
        /// Name the value was being written for.
        name: String,
        /// Size of the value after newline normalization.
        bytes: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
    /// A line of the value equals the heredoc delimiter.
    ///
    /// Unreachable for a delimiter the value cannot predict, and checked anyway
    /// so that the property is enforced by the encoder rather than assumed by it.
    DelimiterCollision {
        /// Name the value was being written for.
        name: String,
        /// The delimiter the value collided with.
        delimiter: String,
    },
    /// The OS entropy source could not supply this entry's delimiter nonce.
    ///
    /// Reported rather than panicked: see this module's `draw_nonce`.
    EntropyUnavailable {
        /// Name the value was being written for.
        name: String,
    },
}

impl OutputError {
    /// The output name the refusal is about.
    ///
    /// Every variant carries it, so a caller that degrades a refusal into a
    /// logged skip can name the entry it lost without re-deriving it.
    pub const fn name(&self) -> &str {
        match self {
            Self::InvalidName { name }
            | Self::InteriorNul { name }
            | Self::BareCarriageReturn { name }
            | Self::ValueTooLarge { name, .. }
            | Self::DelimiterCollision { name, .. }
            | Self::EntropyUnavailable { name } => name.as_str(),
        }
    }
}

impl fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Previewed rather than echoed: a rejected name may be arbitrarily
            // long, and this message is logged as well as returned.
            Self::InvalidName { name } => write!(
                formatter,
                "output name {} is not a run of `[A-Za-z0-9._-]` of at most {MAX_OUTPUT_NAME_BYTES} bytes starting with an alphanumeric",
                preview(name)
            ),
            Self::InteriorNul { name } => write!(
                formatter,
                "output {name:?} carries a NUL byte and cannot be encoded"
            ),
            Self::BareCarriageReturn { name } => write!(
                formatter,
                "output {name:?} carries a carriage return that is not part of a CRLF pair; the runner would end the line there"
            ),
            Self::ValueTooLarge {
                name,
                bytes,
                limit,
            } => write!(
                formatter,
                "output {name:?} is {bytes} bytes, over the {limit} byte limit"
            ),
            Self::DelimiterCollision { name, delimiter } => write!(
                formatter,
                "output {name:?} carries a line equal to its heredoc delimiter {delimiter:?}"
            ),
            Self::EntropyUnavailable { name } => write!(
                formatter,
                "output {name:?} has no heredoc delimiter: the OS entropy source for its per-entry nonce could not be read"
            ),
        }
    }
}

impl std::error::Error for OutputError {}

/// Reports whether `value` has the shape a shipped config's severity produces.
///
/// This is a description, not a gate. The encoding is what makes a severity
/// safe to write -- `the_encoding_holds_without_the_severity_allowlist` proves
/// the same hostile token round-trips with this predicate bypassed -- and by the
/// time a severity is written the Jira create or dedupe has already happened, so
/// refusing an unusual token here would fail a step for a reconciliation that
/// succeeded. [`OutputWriter::write_severity`] logs on a mismatch instead.
pub fn is_severity_token(value: &str) -> bool {
    SEVERITY_TOKEN_PATTERN.is_match(value)
}

/// Encodes one `GITHUB_OUTPUT` entry, terminator included.
///
/// The returned string is appended to the file verbatim.
pub fn encode_output(name: &str, value: &str) -> Result<String, OutputError> {
    encode_output_with_nonce(name, value, draw_nonce)
}

/// [`encode_output`] against a caller-supplied nonce source.
///
/// Split out so the entropy-failure branch is reachable in a test: the OS source
/// cannot be made to fail from inside the process.
fn encode_output_with_nonce<N>(name: &str, value: &str, draw: N) -> Result<String, OutputError>
where
    N: FnOnce() -> Option<[u8; DELIMITER_NONCE_BYTES]>,
{
    if name.is_empty() || name.len() > MAX_OUTPUT_NAME_BYTES || !OUTPUT_NAME_PATTERN.is_match(name)
    {
        return Err(OutputError::InvalidName {
            name: name.to_string(),
        });
    }

    if value.contains('\0') {
        return Err(OutputError::InteriorNul {
            name: name.to_string(),
        });
    }

    if has_bare_carriage_return(value) {
        return Err(OutputError::BareCarriageReturn {
            name: name.to_string(),
        });
    }

    // Every remaining `\r` is the first byte of a CRLF pair, which the runner
    // consumes as part of the terminator. Normalizing here makes the bytes on
    // disk equal to the value a consumer reads back.
    let normalized = value.replace("\r\n", "\n");

    if normalized.len() > MAX_OUTPUT_VALUE_BYTES {
        return Err(OutputError::ValueTooLarge {
            name: name.to_string(),
            bytes: normalized.len(),
            limit: MAX_OUTPUT_VALUE_BYTES,
        });
    }

    let Some(nonce) = draw() else {
        return Err(OutputError::EntropyUnavailable {
            name: name.to_string(),
        });
    };

    let delimiter = derive_delimiter(&nonce, &normalized);
    encode_with_delimiter(name, &normalized, &delimiter)
}

/// Draws a per-entry nonce from the OS CSPRNG, or reports that it could not.
///
/// Deliberately not `rand::random()`. That draws from `ThreadRng`, which
/// *panics* when the OS entropy source cannot be read at seed or reseed time,
/// and this call sits inside [`OutputWriter::write`] -- that is, after the
/// irreversible Jira create or dedupe. The release profile sets
/// `panic = "abort"`, so a panic here would take the process down with no
/// outputs at all, which is exactly the failure the encoder and
/// `write_outcome`'s degradation exist to remove. The fallible source is read
/// instead and the failure travels back as an [`OutputError`], which the caller
/// turns into one skipped entry rather than a red step.
///
/// The nonce property is unchanged: this is still 256 bits of OS entropy drawn
/// after the value is fixed and never written anywhere.
fn draw_nonce() -> Option<[u8; DELIMITER_NONCE_BYTES]> {
    let mut nonce = [0u8; DELIMITER_NONCE_BYTES];
    match SysRng.try_fill_bytes(&mut nonce) {
        Ok(()) => Some(nonce),
        Err(error) => {
            tracing::warn!(
                %error,
                "the OS entropy source could not be read, so this output has no heredoc delimiter"
            );
            None
        }
    }
}

/// Encodes one entry against a caller-supplied delimiter.
///
/// Split out from [`encode_output`] so the collision guard is reachable in a
/// test: no delimiter the encoder itself derives can trip it.
fn encode_with_delimiter(name: &str, value: &str, delimiter: &str) -> Result<String, OutputError> {
    if value.split('\n').any(|line| line == delimiter) {
        return Err(OutputError::DelimiterCollision {
            name: name.to_string(),
            delimiter: delimiter.to_string(),
        });
    }

    let mut encoded = String::with_capacity(name.len() + value.len() + 2 * delimiter.len() + 5);
    encoded.push_str(name);
    encoded.push_str("<<");
    encoded.push_str(delimiter);
    encoded.push('\n');
    encoded.push_str(value);
    encoded.push('\n');
    encoded.push_str(delimiter);
    encoded.push('\n');
    Ok(encoded)
}

/// Returns the delimiter for `value`: the prefix plus the hex SHA-256 of
/// `nonce` followed by the value.
///
/// `nonce` is fresh per entry and never written, so the delimiter is neither
/// predictable from the value nor a check on a guess at it, while still being a
/// function of the value for the nonce in hand -- which is what makes a value
/// carrying its own delimiter unreachable.
fn derive_delimiter(nonce: &[u8; DELIMITER_NONCE_BYTES], value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(value.as_bytes());

    let mut delimiter = String::with_capacity(DELIMITER_PREFIX.len() + 64);
    delimiter.push_str(DELIMITER_PREFIX);
    for byte in hasher.finalize() {
        write!(&mut delimiter, "{byte:02x}").expect("write to string");
    }
    delimiter
}

/// Drops a trailing lone carriage return from a captured severity.
///
/// Rust's `regex` ends a `(?m)$` before a `\n` only, and `.` matches a `\r`, so
/// `(?mi)^severity:\s*(.+)$` over the CRLF-authored body
/// `"Severity: high\r\nPackage: foo"` captures `"high\r"`. That is an artifact
/// of an ordinary config meeting an ordinary body, not a value anyone wrote, and
/// the encoder has to refuse it -- the runner ends a line on a lone `\r`.
///
/// [`crate::rules::evaluate_rule`] applies this to the capture itself, which is
/// where the artifact is made and the only place a repair reaches every consumer
/// of the token -- the `priority_by_severity` lookup above all, which fails the
/// whole run when the key carries the stray byte. What is left for
/// [`OutputWriter::write_severity`] is a backstop over any severity that did not
/// come from that path.
///
/// Only a *trailing* one is removed. A `\r` anywhere else is not a line-ending
/// artifact and still reaches [`OutputError::BareCarriageReturn`]; the encoder
/// is not weakened, and the degradation in `write_outcome` is what covers every
/// value this does not repair.
pub(crate) fn strip_trailing_carriage_return(value: &str) -> &str {
    value.strip_suffix('\r').unwrap_or(value)
}

/// Reports whether `value` carries a `\r` that is not followed by a `\n`.
fn has_bare_carriage_return(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
}

/// A bounded, escaped preview of a rejected token.
pub(crate) fn preview(value: &str) -> String {
    const LIMIT: usize = 48;

    let truncated: String = value.chars().take(LIMIT).collect();
    if truncated.len() == value.len() {
        format!("{truncated:?}")
    } else {
        format!("{truncated:?} (truncated)")
    }
}

/// A bounded, escaped preview of a filesystem path.
///
/// Keeps the tail rather than the head: a path is identified by its final
/// components, and a Windows temp-directory prefix alone can exceed the budget
/// that [`preview`] allows a token.
pub(crate) fn preview_path(value: &str) -> String {
    const LIMIT: usize = 96;

    let count = value.chars().count();
    if count <= LIMIT {
        format!("{value:?}")
    } else {
        let tail: String = value.chars().skip(count - LIMIT).collect();
        format!("{tail:?} (truncated from the left)")
    }
}

/// Appends encoded entries to a `GITHUB_OUTPUT` sink.
#[derive(Debug)]
pub struct OutputWriter<W> {
    sink: W,
}

impl<W: Write> OutputWriter<W> {
    /// Wraps `sink`, which is appended to and never rewritten.
    pub const fn new(sink: W) -> Self {
        Self { sink }
    }

    /// Writes one entry.
    ///
    /// The two failures are distinguishable and mean different things, which is
    /// what lets a caller past the point of no return degrade one and not the
    /// other. An [`OutputError`] in the returned chain means this value could
    /// not be represented and *nothing* was written -- the encoding runs to
    /// completion before the sink is touched -- so the sink is still usable and
    /// the remaining entries can go out. Anything else is the sink itself
    /// failing, which may have left a partial entry behind and is not
    /// recoverable.
    pub fn write(&mut self, name: &str, value: &str) -> Result<()> {
        let encoded = encode_output(name, value)?;
        self.sink.write_all(encoded.as_bytes())?;
        Ok(())
    }

    /// Writes an optional entry, an unset value being the empty string.
    pub fn write_optional(&mut self, name: &str, value: Option<&str>) -> Result<()> {
        self.write(name, value.unwrap_or_default())
    }

    /// Writes a boolean entry.
    pub fn write_bool(&mut self, name: &str, value: bool) -> Result<()> {
        self.write(name, if value { "true" } else { "false" })
    }

    /// Writes a severity entry, logging a token of an unexpected shape.
    ///
    /// The hard errors are reserved for what the encoder genuinely cannot carry
    /// -- a NUL, a bare carriage return, an oversize value -- because those are
    /// the only values that could reach the runner as something other than one
    /// entry. A token that is merely unusual, which is what a permissive
    /// consumer regex produces, is written like any other value: the Jira create
    /// or dedupe has already happened at this point, and failing the step here
    /// would report a reconciliation that succeeded as a failure while its issue
    /// key is live in Jira.
    ///
    /// `None` is written as the empty string, which is how the Action reports
    /// that no rule matched; it is not a token and is not logged as one.
    ///
    /// A trailing lone carriage return is dropped first: see this module's
    /// `strip_trailing_carriage_return` for why that one byte is a capture
    /// artifact rather than a value. [`crate::rules::evaluate_rule`] already
    /// applies the same repair to the capture, so a severity that still carries
    /// one here did not come from a rule match; the repair is logged either way
    /// because it changes a value the step publishes, and at `warn!` because the
    /// default `log-level` input is `info` and a silent one-byte edit to a
    /// published output is exactly what an operator cannot reconstruct
    /// afterwards. A token of nothing but that byte is left as the empty string,
    /// which a workflow cannot tell from "no rule matched" -- the reason
    /// `evaluate_rule` refuses to match on it rather than passing it down here.
    pub fn write_severity(&mut self, name: &str, value: Option<&str>) -> Result<()> {
        if let Some(artifact) = value.filter(|token| token.ends_with('\r')) {
            tracing::warn!(
                severity = %preview(artifact),
                "severity ended in a lone carriage return, which a `$`-anchored capture over a CRLF-authored body yields; the published value is the token without it"
            );
        }

        let token = value.map(strip_trailing_carriage_return);
        if let Some(unusual) = token.filter(|token| !is_severity_token(token)) {
            tracing::warn!(
                severity = %preview(unusual),
                "severity is outside the shape a shipped config produces; writing it as one encoded entry"
            );
        }
        self.write(name, token.unwrap_or_default())
    }

    /// Returns the wrapped sink.
    pub fn into_inner(self) -> W {
        self.sink
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_delimiter, encode_output, encode_output_with_nonce, encode_with_delimiter,
        is_severity_token, OutputError, OutputWriter, DELIMITER_PREFIX, MAX_OUTPUT_NAME_BYTES,
        MAX_OUTPUT_VALUE_BYTES,
    };
    use threatflux_atlassian_testkit::gha::{github_output_map, parse_github_output};
    use threatflux_atlassian_testkit::logs;

    fn written(entries: &[(&str, &str)]) -> String {
        let mut writer = OutputWriter::new(Vec::new());
        for (name, value) in entries {
            writer.write(name, value).expect("entry should encode");
        }
        String::from_utf8(writer.into_inner()).expect("output should be utf-8")
    }

    /// The delimiter an encoded entry opened with, read back off the wire.
    ///
    /// The delimiter is no longer a function of the value alone, so a test that
    /// needs it has to take it from the bytes rather than recompute it.
    fn delimiter_of(encoded: &str) -> String {
        encoded
            .split_once("<<")
            .and_then(|(_, rest)| rest.split_once('\n'))
            .map(|(delimiter, _)| delimiter.to_string())
            .expect("an encoded entry opens a heredoc")
    }

    #[test]
    fn every_value_is_written_as_a_heredoc() {
        let encoded = encode_output("severity", "high").expect("should encode");
        let delimiter = delimiter_of(&encoded);

        assert_eq!(
            encoded,
            format!("severity<<{delimiter}\nhigh\n{delimiter}\n")
        );
        assert!(delimiter.starts_with(DELIMITER_PREFIX));
        assert_eq!(delimiter.len(), DELIMITER_PREFIX.len() + 64);
    }

    #[test]
    fn the_delimiter_is_not_a_digest_of_the_value_alone() {
        // An unsalted `sha256(value)` written in cleartext next to the value is
        // a confirmation oracle: anyone holding the file can test a guessed
        // value against it, which is a disclosure the moment a masked value is
        // routed through this encoder.
        const EMPTY_SHA256: &str =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let first = delimiter_of(&encode_output("severity", "high").expect("should encode"));
        let second = delimiter_of(&encode_output("severity", "high").expect("should encode"));
        let empty = delimiter_of(&encode_output("severity", "").expect("should encode"));

        assert_ne!(
            first, second,
            "two encodings of one value must not share a delimiter"
        );
        assert_ne!(empty, format!("{DELIMITER_PREFIX}{EMPTY_SHA256}"));
        for delimiter in [&first, &second, &empty] {
            assert!(delimiter.starts_with(DELIMITER_PREFIX));
            assert_eq!(delimiter.len(), DELIMITER_PREFIX.len() + 64);
        }
    }

    #[test]
    fn the_delimiter_still_binds_the_value_it_closes() {
        // Un-forgeability is unchanged: for one nonce the digest is a function
        // of the value, so a value cannot carry a delimiter it cannot predict.
        let nonce = [7u8; super::DELIMITER_NONCE_BYTES];

        assert_eq!(
            derive_delimiter(&nonce, "high"),
            derive_delimiter(&nonce, "high")
        );
        assert_ne!(
            derive_delimiter(&nonce, "high"),
            derive_delimiter(&nonce, "low")
        );
        assert_ne!(
            derive_delimiter(&nonce, "high"),
            derive_delimiter(&[8u8; super::DELIMITER_NONCE_BYTES], "high")
        );
    }

    #[test]
    fn round_trips_through_the_runner_grammar() {
        let raw = written(&[
            ("matched-rule-id", "dependabot-high-issues"),
            ("created", "true"),
            ("severity", "high"),
        ]);
        let map = github_output_map(&raw).expect("runner should parse the file");

        assert_eq!(map.len(), 3);
        assert_eq!(map["matched-rule-id"], "dependabot-high-issues");
        assert_eq!(map["created"], "true");
        assert_eq!(map["severity"], "high");
    }

    #[test]
    fn empty_values_round_trip_as_empty() {
        let raw = written(&[("matched-rule-id", ""), ("created", "false")]);
        let map = github_output_map(&raw).expect("runner should parse the file");

        assert_eq!(map["matched-rule-id"], "");
        assert_eq!(map["created"], "false");
    }

    #[test]
    fn multiline_values_round_trip_verbatim() {
        for value in ["one\ntwo", "\n", "trailing\n", "\nleading", "a\n\nb"] {
            let raw = written(&[("results-json", value)]);
            let map = github_output_map(&raw).expect("runner should parse the file");
            assert_eq!(map["results-json"], value, "value {value:?}");
        }
    }

    #[test]
    fn a_value_that_forges_a_key_value_line_stays_one_entry() {
        let raw = written(&[("severity", "high\ncreated=true\nmatched-rule-id=owned")]);
        let entries = parse_github_output(&raw).expect("runner should parse the file");

        assert_eq!(
            entries,
            vec![(
                "severity".to_string(),
                "high\ncreated=true\nmatched-rule-id=owned".to_string()
            )],
            "a newline in a value must not forge an entry"
        );
    }

    #[test]
    fn a_value_carrying_the_delimiter_prefix_is_ordinary_text() {
        let hostile = format!("high\n{DELIMITER_PREFIX}deadbeef\ncreated=true");
        let raw = written(&[("severity", hostile.as_str())]);
        let entries = parse_github_output(&raw).expect("runner should parse the file");

        assert_eq!(entries, vec![("severity".to_string(), hostile)]);
    }

    #[test]
    fn a_value_carrying_a_delimiter_from_an_earlier_entry_is_ordinary_text() {
        // Every delimiter already in the file is public information -- a later
        // step in the same job can read it. Replaying one must not close this
        // value's heredoc.
        let stolen = delimiter_of(&encode_output("severity", "high").expect("should encode"));
        let hostile = format!("high\n{stolen}\ncreated=true\nmatched-rule-id=owned");
        let raw = written(&[("severity", hostile.as_str())]);
        let entries = parse_github_output(&raw).expect("runner should parse the file");

        assert_eq!(entries, vec![("severity".to_string(), hostile)]);
    }

    #[test]
    fn a_value_cannot_carry_its_own_delimiter() {
        // Self-reference is the only forgery the heredoc form leaves, and it now
        // needs a 256-bit nonce the value was written before. The guard is
        // asserted directly instead, against a delimiter supplied by hand.
        let value = "high\nghadelimiter_forged";
        assert_eq!(
            encode_with_delimiter("severity", value, "ghadelimiter_forged"),
            Err(OutputError::DelimiterCollision {
                name: "severity".to_string(),
                delimiter: "ghadelimiter_forged".to_string(),
            })
        );
        assert!(
            encode_output("severity", value).is_ok(),
            "the derived delimiter must not collide with that same value"
        );
    }

    #[test]
    fn crlf_is_normalized_to_the_value_the_runner_reads_back() {
        let raw = written(&[("results-json", "one\r\ntwo\r\n")]);
        let map = github_output_map(&raw).expect("runner should parse the file");

        assert_eq!(map["results-json"], "one\ntwo\n");
        assert!(!raw.contains('\r'), "no carriage return may reach the file");
    }

    #[test]
    fn a_bare_carriage_return_is_rejected() {
        for value in ["high\rcreated=true", "high\r", "\r\r\n"] {
            assert_eq!(
                encode_output("severity", value),
                Err(OutputError::BareCarriageReturn {
                    name: "severity".to_string()
                }),
                "value {value:?}"
            );
        }
    }

    #[test]
    fn a_nul_byte_is_rejected() {
        assert_eq!(
            encode_output("severity", "high\0created=true"),
            Err(OutputError::InteriorNul {
                name: "severity".to_string()
            })
        );
    }

    #[test]
    fn an_oversize_value_is_rejected_and_the_limit_itself_is_not() {
        let at_limit = "a".repeat(MAX_OUTPUT_VALUE_BYTES);
        assert!(encode_output("results-json", &at_limit).is_ok());

        let over = "a".repeat(MAX_OUTPUT_VALUE_BYTES + 1);
        assert_eq!(
            encode_output("results-json", &over),
            Err(OutputError::ValueTooLarge {
                name: "results-json".to_string(),
                bytes: MAX_OUTPUT_VALUE_BYTES + 1,
                limit: MAX_OUTPUT_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn the_size_limit_applies_after_newline_normalization() {
        let value = "a\r\n".repeat(MAX_OUTPUT_VALUE_BYTES / 2);
        assert!(value.len() > MAX_OUTPUT_VALUE_BYTES);
        assert!(
            encode_output("results-json", &value).is_ok(),
            "the limit must bound the bytes actually written"
        );
    }

    #[test]
    fn an_unusable_name_is_rejected() {
        for name in [
            "",
            "created=x",
            "created<<EOF",
            "created\nsecond",
            "-leading-hyphen",
            "with space",
        ] {
            assert_eq!(
                encode_output(name, "value"),
                Err(OutputError::InvalidName {
                    name: name.to_string()
                }),
                "name {name:?}"
            );
        }

        let long = "a".repeat(MAX_OUTPUT_NAME_BYTES + 1);
        assert_eq!(
            encode_output(&long, "value"),
            Err(OutputError::InvalidName { name: long })
        );
    }

    #[test]
    fn severity_allowlist_accepts_the_tokens_configs_produce() {
        for token in ["high", "critical", "low", "0", "a", "cvss-9.8", "sev.1-b"] {
            assert!(is_severity_token(token), "token {token:?}");
        }
        assert!(is_severity_token(&"a".repeat(32)));
    }

    #[test]
    fn severity_allowlist_rejects_everything_else() {
        for token in [
            "",
            "High",
            "high\ncreated=true",
            "high ",
            " high",
            "high\n",
            "-high",
            ".high",
            "high;drop",
            "${JIRA_API_TOKEN}",
            "high\rcreated=true",
        ] {
            assert!(!is_severity_token(token), "token {token:?}");
        }
        assert!(!is_severity_token(&"a".repeat(33)));
    }

    #[test]
    fn write_severity_carries_a_token_outside_the_shipped_shape_as_one_entry() {
        // The Jira write is already done when this runs, so an unusual token is
        // logged and written rather than turned into a failed step; the encoding
        // is what keeps it from forging a second entry.
        let hostile = "high\ncreated=true";
        assert!(!is_severity_token(hostile));

        let mut writer = OutputWriter::new(Vec::new());
        writer
            .write_severity("severity", Some(hostile))
            .expect("an unusual severity must still be written");

        let raw = String::from_utf8(writer.into_inner()).expect("output should be utf-8");
        assert_eq!(
            parse_github_output(&raw).expect("the runner must parse the file"),
            vec![("severity".to_string(), hostile.to_string())]
        );
    }

    #[test]
    fn write_severity_still_refuses_what_the_encoder_cannot_carry() {
        for (value, expected) in [
            (
                "high\rcreated=true".to_string(),
                OutputError::BareCarriageReturn {
                    name: "severity".to_string(),
                },
            ),
            (
                "high\0created=true".to_string(),
                OutputError::InteriorNul {
                    name: "severity".to_string(),
                },
            ),
            (
                "a".repeat(MAX_OUTPUT_VALUE_BYTES + 1),
                OutputError::ValueTooLarge {
                    name: "severity".to_string(),
                    bytes: MAX_OUTPUT_VALUE_BYTES + 1,
                    limit: MAX_OUTPUT_VALUE_BYTES,
                },
            ),
        ] {
            let mut writer = OutputWriter::new(Vec::new());
            let error = writer
                .write_severity("severity", Some(&value))
                .expect_err("a value the encoder cannot carry must fail");

            assert_eq!(error.downcast_ref::<OutputError>(), Some(&expected));
            assert!(
                writer.into_inner().is_empty(),
                "a rejected severity must write nothing"
            );
        }
    }

    #[test]
    fn write_severity_writes_an_absent_severity_as_empty() {
        let mut writer = OutputWriter::new(Vec::new());
        writer
            .write_severity("severity", None)
            .expect("an absent severity should be written as empty");

        let raw = String::from_utf8(writer.into_inner()).expect("output should be utf-8");
        assert_eq!(
            github_output_map(&raw).expect("should parse")["severity"],
            ""
        );
    }

    #[test]
    fn write_bool_writes_the_lowercase_literals() {
        let mut writer = OutputWriter::new(Vec::new());
        writer.write_bool("created", true).expect("should write");
        writer.write_bool("deduped", false).expect("should write");

        let raw = String::from_utf8(writer.into_inner()).expect("output should be utf-8");
        let map = github_output_map(&raw).expect("should parse");
        assert_eq!(map["created"], "true");
        assert_eq!(map["deduped"], "false");
    }

    #[test]
    fn a_rejected_value_writes_nothing() {
        let mut writer = OutputWriter::new(Vec::new());
        writer.write("created", "true").expect("should write");
        writer
            .write("severity", "high\rforged")
            .expect_err("a bare CR must be rejected");

        let raw = String::from_utf8(writer.into_inner()).expect("output should be utf-8");
        let map = github_output_map(&raw).expect("should parse");
        assert_eq!(map.len(), 1, "only the accepted entry may reach the file");
    }

    #[test]
    fn errors_do_not_echo_the_whole_value() {
        let secret = "s".repeat(4096);
        let error = encode_output("severity", &format!("{secret}\rforged"))
            .expect_err("a bare carriage return must be rejected");
        let rendered = error.to_string();

        assert!(rendered.len() < 200, "rendered error: {rendered}");
        assert!(!rendered.contains(&secret), "rendered error: {rendered}");
    }

    #[test]
    fn an_unreadable_entropy_source_is_reported_rather_than_panicked() {
        // `rand::random()` draws from `ThreadRng`, which panics when the OS
        // source cannot be read. That call sits after the irreversible Jira
        // write and the release profile aborts on panic, so the process would
        // exit with no outputs at all. The fallible source is used instead and
        // the failure comes back as an ordinary refusal for the caller to
        // degrade.
        assert_eq!(
            encode_output_with_nonce("severity", "high", || None),
            Err(OutputError::EntropyUnavailable {
                name: "severity".to_string()
            })
        );

        // Nothing else about the entry is decided before the draw: the value is
        // fully validated first, so the refusal is still the one that fits.
        assert_eq!(
            encode_output_with_nonce("severity", "high\rforged", || None),
            Err(OutputError::BareCarriageReturn {
                name: "severity".to_string()
            })
        );
    }

    #[test]
    fn the_shipped_path_draws_its_nonce_through_that_same_fallible_source() {
        // The injected source above only stands for the real one if
        // `encode_output` goes through `draw_nonce`, whose `Option` is what makes
        // an unreadable OS source a value the encoder can report on. Both halves
        // are asserted here: the source reads, and the entry it feeds still gets
        // a fresh delimiter.
        let nonce = super::draw_nonce().expect("the OS entropy source should be readable");
        assert_eq!(nonce.len(), super::DELIMITER_NONCE_BYTES);
        assert_ne!(
            nonce,
            super::draw_nonce().expect("the OS entropy source should be readable"),
            "two draws must not agree"
        );

        let delimiter =
            delimiter_of(&encode_output("severity", "high").expect("the OS source is readable"));
        assert!(delimiter.starts_with(DELIMITER_PREFIX));
        assert_eq!(delimiter.len(), DELIMITER_PREFIX.len() + 64);
        assert_ne!(
            delimiter,
            delimiter_of(&encode_output("severity", "high").expect("should encode")),
            "the nonce must still be drawn per entry"
        );
    }

    #[test]
    fn every_refusal_names_the_output_it_is_about() {
        for value in [
            "high\0forged".to_string(),
            "high\rforged".to_string(),
            "a".repeat(MAX_OUTPUT_VALUE_BYTES + 1),
        ] {
            let error = encode_output("severity", &value).expect_err("value should be refused");
            assert_eq!(error.name(), "severity", "value class {:?}", &value[..4]);
        }

        assert_eq!(
            encode_output("with space", "high")
                .expect_err("name should be refused")
                .name(),
            "with space"
        );
        assert_eq!(
            encode_output_with_nonce("severity", "high", || None)
                .expect_err("entropy should be refused")
                .name(),
            "severity"
        );
        assert_eq!(
            encode_with_delimiter(
                "severity",
                "high\nghadelimiter_forged",
                "ghadelimiter_forged"
            )
            .expect_err("collision should be refused")
            .name(),
            "severity"
        );
    }

    #[test]
    fn write_severity_writes_a_crlf_capture_artifact_instead_of_losing_it() {
        // `(?mi)^severity:\s*(.+)$` over a CRLF-authored body captures "high\r":
        // `$` matches before the `\n` and `.` matches the `\r`. That one byte is
        // an artifact of the capture, not a value, and refusing it would cost
        // this run its `severity` output for nothing.
        let mut writer = OutputWriter::new(Vec::new());
        writer
            .write_severity("severity", Some("high\r"))
            .expect("a trailing lone carriage return must not cost the entry");

        let raw = String::from_utf8(writer.into_inner()).expect("output should be utf-8");
        assert_eq!(
            github_output_map(&raw).expect("the runner must parse the file")["severity"],
            "high"
        );
        assert!(!raw.contains('\r'), "no carriage return may reach the file");
    }

    #[test]
    fn the_repair_of_a_published_value_is_visible_at_the_default_log_level() {
        // The default `log-level` input is `info`, so a `debug!` here left a run
        // silently publishing a `severity` one byte different from the token the
        // capture produced, with nothing in the log to say so. The line is also
        // the only place the original token appears, so it carries a bounded
        // preview of it.
        let ((), log) = logs::capture(|| {
            OutputWriter::new(Vec::new())
                .write_severity("severity", Some("high\r"))
                .expect("a trailing lone carriage return must not cost the entry");
        });

        assert!(
            !log.contains("DEBUG"),
            "the repair may not be logged below the default level: {log}"
        );
        assert!(log.contains("WARN"), "log was: {log}");
        assert!(
            log.contains(r#""high\r""#),
            "the log did not preview the original token: {log}"
        );
    }

    #[test]
    fn write_severity_repairs_only_a_trailing_carriage_return() {
        // The repair is for the one shape a line-anchored capture produces. A
        // `\r` anywhere else is not that, and the encoder still refuses it --
        // the runner would end the line there and the value would forge an
        // entry.
        let mut writer = OutputWriter::new(Vec::new());
        let error = writer
            .write_severity("severity", Some("high\rcreated=true"))
            .expect_err("an interior carriage return must still be refused");

        assert_eq!(
            error.downcast_ref::<OutputError>(),
            Some(&OutputError::BareCarriageReturn {
                name: "severity".to_string()
            })
        );
        assert!(
            writer.into_inner().is_empty(),
            "a refused severity must write nothing"
        );
    }

    #[test]
    fn the_repaired_severity_is_the_token_the_shipped_shape_describes() {
        // The repair is what keeps a CRLF-authored body from logging a warning
        // about a token that is, once the artifact is gone, entirely ordinary.
        assert!(!is_severity_token("high\r"));
        assert!(is_severity_token(super::strip_trailing_carriage_return(
            "high\r"
        )));
        assert_eq!(super::strip_trailing_carriage_return("high\r\r"), "high\r");
        assert_eq!(super::strip_trailing_carriage_return("high"), "high");
        assert_eq!(
            super::strip_trailing_carriage_return("high\r\n"),
            "high\r\n"
        );
    }

    #[test]
    fn a_rejected_name_is_not_echoed_whole_either() {
        // This message is logged as well as returned, and a name is not bounded
        // before it is checked.
        let long = "n".repeat(4096);
        let rendered = encode_output(&long, "value")
            .expect_err("an over-long name must be rejected")
            .to_string();

        assert!(rendered.len() < 200, "rendered error: {rendered}");
        assert!(!rendered.contains(&long));
        assert!(rendered.contains("truncated"));
    }

    #[test]
    fn the_logged_preview_of_an_unusual_token_is_bounded() {
        let secret = "s".repeat(4096);
        let preview = super::preview(&secret);

        assert!(preview.len() < 200, "preview: {preview}");
        assert!(preview.contains("truncated"));
        assert!(!preview.contains(&secret));
    }

    #[test]
    fn a_previewed_path_keeps_the_end_that_identifies_it() {
        // A runner's temp prefix alone can outrun the token budget, so a
        // head-truncated path names nothing an operator can act on.
        let long = format!("{}/github-output.txt", "d".repeat(4096));
        let preview = super::preview_path(&long);

        assert!(preview.len() < 200, "preview: {preview}");
        assert!(preview.contains("github-output.txt"), "preview: {preview}");
        assert!(preview.contains("truncated"), "preview: {preview}");
    }

    #[test]
    fn a_previewed_path_that_fits_is_left_whole() {
        let preview = super::preview_path("/tmp/run/github-output.txt");

        assert!(preview.contains("/tmp/run/github-output.txt"));
        assert!(!preview.contains("truncated"), "preview: {preview}");
    }
}
