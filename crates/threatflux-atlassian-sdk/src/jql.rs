//! JQL construction with injection-safe escaping
//!
//! JQL has two escaping layers, and reaching for the wrong one is a query injection.
//! [`try_quote_string_literal`] renders a complete quoted token for the operators that
//! compare a field against a literal (`=`, `!=`, `IN`, `NOT IN`).
//! [`quote_text_operand`] renders a token for the text operators (`~`, `!~`), whose
//! operand Jira forwards to Lucene *after* the JQL literal has been decoded, so it
//! escapes the Lucene metacharacters first and the JQL ones second.
//!
//! Both functions include the surrounding double quotes in what they return, so a
//! caller cannot forget them.
//!
//! [`JqlBuilder`] composes validated terms and joins them with `AND`, which keeps
//! field names and operators out of caller-controlled strings entirely.
//!
//! ```
//! use threatflux_atlassian_sdk::jql::JqlBuilder;
//!
//! let jql = JqlBuilder::new()
//!     .eq("project", "KAN")?
//!     .in_list("labels", ["dedupe-a", "dedupe-b"])?
//!     .build()?;
//!
//! assert_eq!(jql, r#"project = "KAN" AND labels IN ("dedupe-a", "dedupe-b")"#);
//! # Ok::<(), threatflux_atlassian_sdk::jql::JqlError>(())
//! ```

use crate::error::AtlassianError;
use std::fmt::Write as _;

/// A custom field reference addresses a numeric id; nothing Jira issues needs more
/// digits than a `u64` holds.
const MAX_CUSTOM_FIELD_DIGITS: usize = 19;

/// Characters Lucene treats as query syntax. Taken from Lucene's own
/// `QueryParser::escape` set, which is what Jira's text operators parse with.
const LUCENE_METACHARACTERS: [char; 19] = [
    '\\', '+', '-', '!', '(', ')', ':', '^', '[', ']', '"', '{', '}', '~', '*', '?', '|', '&', '/',
];

/// Failure modes of JQL construction.
///
/// Converts into [`AtlassianError::Validation`]: a malformed term is a validation
/// failure, and the message already carries everything a caller could branch on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JqlError {
    /// A field name did not match an identifier or a custom field reference.
    #[error(
        "invalid JQL field name {field:?}: expected [A-Za-z][A-Za-z0-9_]* or a custom field reference such as cf[10001]"
    )]
    InvalidFieldName {
        /// The rejected field name.
        field: String,
    },

    /// A value contained U+0000, which no JQL escape sequence can represent.
    #[error("JQL string literal cannot contain a NUL character (at byte {index})")]
    NulCharacter {
        /// Byte offset of the NUL within the value the caller passed.
        index: usize,
    },

    /// An `IN` or `NOT IN` term was given no values.
    #[error("JQL term for field {field:?} needs at least one value")]
    EmptyValueList {
        /// The field the empty list was given for.
        field: String,
    },

    /// A raw term was blank, which would emit a syntactically broken query.
    #[error("raw JQL term cannot be blank")]
    BlankRawTerm,

    /// [`JqlBuilder::build`] was called with no terms, which would match every issue.
    #[error("JQL query needs at least one term")]
    EmptyQuery,
}

impl From<JqlError> for AtlassianError {
    fn from(err: JqlError) -> Self {
        Self::validation(err.to_string())
    }
}

/// Sort direction for an `ORDER BY` clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JqlOrder {
    /// `ASC`
    Ascending,
    /// `DESC`
    Descending,
}

impl JqlOrder {
    const fn keyword(self) -> &'static str {
        match self {
            Self::Ascending => "ASC",
            Self::Descending => "DESC",
        }
    }
}

/// Renders `value` as a quoted JQL string literal, escaping included.
///
/// The returned token carries its own surrounding `"` characters. The escape table is:
///
/// | Input | Output |
/// |---|---|
/// | `\` | `\\` |
/// | `"` | `\"` |
/// | `'` | `\'` |
/// | U+000A | `\n` |
/// | U+000D | `\r` |
/// | U+0009 | `\t` |
/// | any other control character (C0, U+007F, C1) | `\uXXXX` |
///
/// Everything else, including non-ASCII text, is emitted unchanged.
///
/// ```
/// use threatflux_atlassian_sdk::jql::try_quote_string_literal;
///
/// assert_eq!(try_quote_string_literal("KAN")?, r#""KAN""#);
/// assert_eq!(try_quote_string_literal(r#"a"b"#)?, r#""a\"b""#);
/// # Ok::<(), threatflux_atlassian_sdk::jql::JqlError>(())
/// ```
///
/// # Errors
///
/// Returns [`JqlError::NulCharacter`] when `value` contains U+0000. JQL has no escape
/// for it, and stripping it would send Jira a different value than the caller asked
/// for, so it is rejected instead.
pub fn try_quote_string_literal(value: &str) -> Result<String, JqlError> {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');

    // One pass, one output escape per input character: no rule can consume what
    // another rule emitted, which is the hazard of a chain of `str::replace` calls
    // (there, `\` -> `\\` must run before `"` -> `\"` or the quote escape is undone).
    for (index, ch) in value.char_indices() {
        match ch {
            '\0' => return Err(JqlError::NulCharacter { index }),
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other.is_control() => push_unicode_escape(&mut out, other),
            other => out.push(other),
        }
    }

    out.push('"');
    Ok(out)
}

/// Renders `value` as a quoted JQL string literal for the text operators (`~`, `!~`).
///
/// Jira decodes the JQL literal and then parses the result as a Lucene query, so an
/// unescaped `*`, `~` or `(` in the operand is still syntax at that second layer even
/// though the JQL layer is safe. The Lucene metacharacters are escaped first, then the
/// whole thing goes through [`try_quote_string_literal`], which doubles the backslashes
/// this step introduced so exactly one survives the JQL decode.
///
/// ```
/// use threatflux_atlassian_sdk::jql::quote_text_operand;
///
/// assert_eq!(quote_text_operand("cve-2026*")?, r#""cve\\-2026\\*""#);
/// # Ok::<(), threatflux_atlassian_sdk::jql::JqlError>(())
/// ```
///
/// # Errors
///
/// Returns [`JqlError::NulCharacter`] when `value` contains U+0000, with the byte
/// offset measured against `value` rather than the intermediate escaped form.
pub fn quote_text_operand(value: &str) -> Result<String, JqlError> {
    if let Some(index) = value.find('\0') {
        return Err(JqlError::NulCharacter { index });
    }

    let mut lucene = String::with_capacity(value.len());
    for ch in value.chars() {
        if LUCENE_METACHARACTERS.contains(&ch) {
            lucene.push('\\');
        }
        lucene.push(ch);
    }

    try_quote_string_literal(&lucene)
}

/// Builds a JQL query from validated terms joined with `AND`.
///
/// Every value is escaped by [`try_quote_string_literal`] (or, for
/// [`contains`](Self::contains), by [`quote_text_operand`]) and every field name is
/// validated, so a caller-supplied string can only ever land inside its own term.
/// [`raw_term`](Self::raw_term) is the one deliberate exception.
///
/// ```
/// use threatflux_atlassian_sdk::jql::{JqlBuilder, JqlOrder};
///
/// let jql = JqlBuilder::new()
///     .eq("project", "KAN")?
///     .not_eq("statusCategory", "Done")?
///     .order_by("created", JqlOrder::Descending)?
///     .build()?;
///
/// assert_eq!(
///     jql,
///     r#"project = "KAN" AND statusCategory != "Done" ORDER BY created DESC"#
/// );
/// # Ok::<(), threatflux_atlassian_sdk::jql::JqlError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct JqlBuilder {
    terms: Vec<String>,
    order_by: Vec<String>,
}

impl JqlBuilder {
    /// Creates an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `field = "value"`.
    ///
    /// # Errors
    ///
    /// [`JqlError::InvalidFieldName`] for an unacceptable field name, or
    /// [`JqlError::NulCharacter`] for a value containing U+0000.
    pub fn eq(self, field: &str, value: &str) -> Result<Self, JqlError> {
        self.comparison(field, "=", value, try_quote_string_literal)
    }

    /// Adds `field != "value"`.
    ///
    /// # Errors
    ///
    /// As [`eq`](Self::eq).
    pub fn not_eq(self, field: &str, value: &str) -> Result<Self, JqlError> {
        self.comparison(field, "!=", value, try_quote_string_literal)
    }

    /// Adds `field ~ "value"`, escaping `value` for the text operators.
    ///
    /// # Errors
    ///
    /// As [`eq`](Self::eq).
    pub fn contains(self, field: &str, value: &str) -> Result<Self, JqlError> {
        self.comparison(field, "~", value, quote_text_operand)
    }

    /// Adds `field !~ "value"`, escaping `value` for the text operators.
    ///
    /// # Errors
    ///
    /// As [`eq`](Self::eq).
    pub fn not_contains(self, field: &str, value: &str) -> Result<Self, JqlError> {
        self.comparison(field, "!~", value, quote_text_operand)
    }

    /// Adds `field IN ("a", "b")`.
    ///
    /// # Errors
    ///
    /// As [`eq`](Self::eq), plus [`JqlError::EmptyValueList`] when `values` is empty:
    /// `IN ()` is not valid JQL, and silently dropping the term would widen the query.
    pub fn in_list<I, S>(self, field: &str, values: I) -> Result<Self, JqlError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.membership(field, "IN", values)
    }

    /// Adds `field NOT IN ("a", "b")`.
    ///
    /// # Errors
    ///
    /// As [`in_list`](Self::in_list).
    pub fn not_in<I, S>(self, field: &str, values: I) -> Result<Self, JqlError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.membership(field, "NOT IN", values)
    }

    /// Adds `field IS EMPTY`.
    ///
    /// # Errors
    ///
    /// [`JqlError::InvalidFieldName`] for an unacceptable field name.
    pub fn field_is_empty(mut self, field: &str) -> Result<Self, JqlError> {
        validate_field_name(field)?;
        self.terms.push(format!("{field} IS EMPTY"));
        Ok(self)
    }

    /// Adds `field IS NOT EMPTY`.
    ///
    /// # Errors
    ///
    /// [`JqlError::InvalidFieldName`] for an unacceptable field name.
    pub fn field_is_not_empty(mut self, field: &str) -> Result<Self, JqlError> {
        validate_field_name(field)?;
        self.terms.push(format!("{field} IS NOT EMPTY"));
        Ok(self)
    }

    /// Adds a term verbatim, with **no escaping and no syntax checking**.
    ///
    /// This is the escape hatch for constructs the builder does not model: function
    /// operands (`assignee = currentUser()`), `WAS`/`CHANGED` history predicates, `OR`
    /// groups. Whatever is passed becomes JQL exactly as written, so it must be a
    /// literal or something assembled from [`try_quote_string_literal`] output. Passing
    /// caller-controlled text here reintroduces exactly the injection the rest of this
    /// module exists to prevent.
    ///
    /// # Errors
    ///
    /// [`JqlError::BlankRawTerm`] when `term` is empty or only whitespace, which is the
    /// one thing checked, because it would emit a dangling `AND`.
    pub fn raw_term(mut self, term: &str) -> Result<Self, JqlError> {
        if term.trim().is_empty() {
            return Err(JqlError::BlankRawTerm);
        }
        self.terms.push(term.to_owned());
        Ok(self)
    }

    /// Appends an `ORDER BY` key. Repeated calls order by each key in turn.
    ///
    /// # Errors
    ///
    /// [`JqlError::InvalidFieldName`] for an unacceptable field name.
    pub fn order_by(mut self, field: &str, order: JqlOrder) -> Result<Self, JqlError> {
        validate_field_name(field)?;
        self.order_by.push(format!("{field} {}", order.keyword()));
        Ok(self)
    }

    /// Reports whether any term has been added yet.
    pub const fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Renders the query.
    ///
    /// # Errors
    ///
    /// [`JqlError::EmptyQuery`] when no term was added. An empty query string matches
    /// every issue in the instance, so it is refused rather than returned.
    pub fn build(self) -> Result<String, JqlError> {
        if self.terms.is_empty() {
            return Err(JqlError::EmptyQuery);
        }

        let mut query = self.terms.join(" AND ");
        if !self.order_by.is_empty() {
            query.push_str(" ORDER BY ");
            query.push_str(&self.order_by.join(", "));
        }
        Ok(query)
    }

    fn comparison(
        mut self,
        field: &str,
        operator: &str,
        value: &str,
        quote: fn(&str) -> Result<String, JqlError>,
    ) -> Result<Self, JqlError> {
        validate_field_name(field)?;
        let operand = quote(value)?;
        self.terms.push(format!("{field} {operator} {operand}"));
        Ok(self)
    }

    fn membership<I, S>(mut self, field: &str, operator: &str, values: I) -> Result<Self, JqlError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        validate_field_name(field)?;

        let mut operands = Vec::new();
        for value in values {
            operands.push(try_quote_string_literal(value.as_ref())?);
        }
        if operands.is_empty() {
            return Err(JqlError::EmptyValueList {
                field: field.to_owned(),
            });
        }

        self.terms
            .push(format!("{field} {operator} ({})", operands.join(", ")));
        Ok(self)
    }
}

fn validate_field_name(field: &str) -> Result<(), JqlError> {
    if is_identifier(field) || is_custom_field_reference(field) {
        return Ok(());
    }
    Err(JqlError::InvalidFieldName {
        field: field.to_owned(),
    })
}

fn is_identifier(field: &str) -> bool {
    let mut chars = field.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {
            chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        }
        _ => false,
    }
}

fn is_custom_field_reference(field: &str) -> bool {
    let Some(prefix) = field.get(..3) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case("cf[") {
        return false;
    }
    // `get(..3)` succeeding proves byte 3 is a character boundary.
    let Some(digits) = field[3..].strip_suffix(']') else {
        return false;
    };
    !digits.is_empty()
        && digits.len() <= MAX_CUSTOM_FIELD_DIGITS
        && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn push_unicode_escape(out: &mut String, ch: char) {
    let code = u32::from(ch);
    debug_assert!(
        code <= 0xFFFF,
        "only control characters reach this path, all of which fit four hex digits"
    );
    // Writing into a `String` cannot fail.
    let _ = write!(out, "\\u{code:04x}");
}

#[cfg(test)]
mod tests {
    use super::{
        quote_text_operand, try_quote_string_literal, JqlBuilder, JqlError, JqlOrder,
        LUCENE_METACHARACTERS,
    };
    use crate::error::AtlassianError;

    /// Values a JQL escaper has to survive: quote/backslash games, term terminators,
    /// newlines, control characters, and non-ASCII text.
    const HOSTILE_VALUES: &[&str] = &[
        r#"KAN" OR project = "EVIL"#,
        r#"KAN\" OR project = "EVIL"#,
        r"\",
        r"\\",
        r#"""#,
        r#"\""#,
        "') OR ('a'='a",
        "x\" ORDER BY created DESC -- ",
        "a\nb",
        "a\rb",
        "a\r\nb",
        "a\tb",
        "a\u{1}b",
        "a\u{1f}b",
        "a\u{7f}b",
        "a\u{9b}b",
        "labels = \"x\" AND labels",
        "${JIRA_API_TOKEN}",
        "\u{201c}smart\u{201d} quotes",
        "emoji \u{1f680} tail",
        "",
    ];

    /// Reverses [`try_quote_string_literal`], returning the decoded value and whatever
    /// followed the literal's closing quote. A non-empty remainder means the value
    /// escaped its own token.
    fn scan_literal(token: &str) -> (String, &str) {
        let mut chars = token.char_indices();
        assert_eq!(
            chars.next().map(|(_, ch)| ch),
            Some('"'),
            "token must open with a quote: {token}"
        );

        let mut decoded = String::new();
        while let Some((index, ch)) = chars.next() {
            match ch {
                '"' => return (decoded, &token[index + 1..]),
                '\\' => {
                    let (_, escape) = chars.next().expect("dangling escape");
                    match escape {
                        '\\' => decoded.push('\\'),
                        '"' => decoded.push('"'),
                        '\'' => decoded.push('\''),
                        'n' => decoded.push('\n'),
                        'r' => decoded.push('\r'),
                        't' => decoded.push('\t'),
                        'u' => {
                            let hex: String = (0..4)
                                .map(|_| chars.next().expect("truncated \\u escape").1)
                                .collect();
                            let code = u32::from_str_radix(&hex, 16).expect("hex digits");
                            decoded.push(char::from_u32(code).expect("scalar value"));
                        }
                        other => panic!("unsupported escape sequence \\{other}"),
                    }
                }
                other => decoded.push(other),
            }
        }

        panic!("unterminated literal: {token}");
    }

    fn unescape_lucene(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                out.push(chars.next().expect("dangling Lucene escape"));
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn quotes_a_plain_value() {
        assert_eq!(try_quote_string_literal("KAN").unwrap(), r#""KAN""#);
        assert_eq!(try_quote_string_literal("").unwrap(), r#""""#);
        assert_eq!(
            try_quote_string_literal("with spaces").unwrap(),
            r#""with spaces""#
        );
    }

    #[test]
    fn applies_the_documented_escape_table() {
        assert_eq!(try_quote_string_literal(r"a\b").unwrap(), r#""a\\b""#);
        assert_eq!(try_quote_string_literal("a\"b").unwrap(), r#""a\"b""#);
        assert_eq!(try_quote_string_literal("a'b").unwrap(), r#""a\'b""#);
        assert_eq!(try_quote_string_literal("a\nb").unwrap(), r#""a\nb""#);
        assert_eq!(try_quote_string_literal("a\rb").unwrap(), r#""a\rb""#);
        assert_eq!(try_quote_string_literal("a\tb").unwrap(), r#""a\tb""#);
    }

    #[test]
    fn escapes_backslash_before_quote() {
        // Escaping quotes before backslashes turns this input into `"\\\\""`, where a
        // JQL reader sees two escaped backslashes and then an unescaped quote that
        // closes the literal a character early. Pinned: the ordering is the whole fix.
        assert_eq!(try_quote_string_literal("\\\"").unwrap(), r#""\\\"""#);
        assert_eq!(try_quote_string_literal("\\\\").unwrap(), r#""\\\\""#);
    }

    #[test]
    fn escapes_other_control_characters_as_unicode_escapes() {
        assert_eq!(
            try_quote_string_literal("a\u{1}b").unwrap(),
            r#""a\u0001b""#
        );
        assert_eq!(
            try_quote_string_literal("a\u{b}b").unwrap(),
            r#""a\u000bb""#
        );
        assert_eq!(
            try_quote_string_literal("a\u{1f}b").unwrap(),
            r#""a\u001fb""#
        );
        assert_eq!(
            try_quote_string_literal("a\u{7f}b").unwrap(),
            r#""a\u007fb""#
        );
        assert_eq!(
            try_quote_string_literal("a\u{9b}b").unwrap(),
            r#""a\u009bb""#
        );
    }

    #[test]
    fn leaves_non_ascii_text_alone() {
        assert_eq!(
            try_quote_string_literal("caf\u{e9} \u{1f680}").unwrap(),
            "\"caf\u{e9} \u{1f680}\""
        );
    }

    #[test]
    fn rejects_nul_in_a_string_literal() {
        assert_eq!(
            try_quote_string_literal("ab\0cd"),
            Err(JqlError::NulCharacter { index: 2 })
        );
        assert_eq!(
            try_quote_string_literal("\0"),
            Err(JqlError::NulCharacter { index: 0 })
        );
    }

    #[test]
    fn hostile_values_round_trip() {
        for value in HOSTILE_VALUES {
            let token = try_quote_string_literal(value).unwrap();
            let (decoded, rest) = scan_literal(&token);
            assert_eq!(&decoded, value, "round trip failed for {value:?}");
            assert!(
                rest.is_empty(),
                "value escaped its token: {value:?} -> {token}"
            );
        }
    }

    #[test]
    fn hostile_values_cannot_terminate_their_token() {
        for value in HOSTILE_VALUES {
            let token = try_quote_string_literal(value).unwrap();
            assert!(token.starts_with('"') && token.ends_with('"'));
            assert!(
                !token
                    .get(1..token.len() - 1)
                    .expect("token has both quotes")
                    .chars()
                    .any(char::is_control),
                "raw control character survived for {value:?}"
            );

            // The only structural exit is the closing quote, and it is the last byte.
            let (_, rest) = scan_literal(&token);
            assert!(rest.is_empty(), "trailing JQL after token: {token}");
        }
    }

    #[test]
    fn text_operand_escapes_lucene_metacharacters() {
        assert_eq!(
            quote_text_operand("cve-2026*").unwrap(),
            r#""cve\\-2026\\*""#
        );
        assert_eq!(quote_text_operand("a+b").unwrap(), r#""a\\+b""#);
        assert_eq!(quote_text_operand(r"a\b").unwrap(), r#""a\\\\b""#);
    }

    #[test]
    fn text_operand_escapes_every_metacharacter_in_the_set() {
        for meta in LUCENE_METACHARACTERS {
            let token = quote_text_operand(&meta.to_string()).unwrap();
            let (decoded, rest) = scan_literal(&token);
            assert!(rest.is_empty(), "operand escaped its token: {meta:?}");
            assert_eq!(
                decoded,
                format!("\\{meta}"),
                "metacharacter {meta:?} was not Lucene-escaped"
            );
        }
    }

    #[test]
    fn text_operand_round_trips_through_both_layers() {
        for value in HOSTILE_VALUES {
            let token = quote_text_operand(value).unwrap();
            let (lucene, rest) = scan_literal(&token);
            assert!(rest.is_empty(), "operand escaped its token: {value:?}");
            assert_eq!(
                &unescape_lucene(&lucene),
                value,
                "two-layer round trip failed for {value:?}"
            );
        }
    }

    #[test]
    fn text_operand_reports_nul_offsets_against_the_caller_value() {
        assert_eq!(
            quote_text_operand("a+b\0"),
            Err(JqlError::NulCharacter { index: 3 })
        );
    }

    #[test]
    fn builder_emits_the_dedupe_query_shape() {
        let jql = JqlBuilder::new()
            .eq("project", "KAN")
            .unwrap()
            .eq("labels", "jira-automation-abc123def456")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            jql,
            r#"project = "KAN" AND labels = "jira-automation-abc123def456""#
        );
    }

    #[test]
    fn builder_renders_membership_terms() {
        let jql = JqlBuilder::new()
            .in_list("labels", ["a", "b"])
            .unwrap()
            .not_in("status", vec!["Done".to_owned()])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(jql, r#"labels IN ("a", "b") AND status NOT IN ("Done")"#);
    }

    #[test]
    fn builder_renders_text_and_emptiness_terms() {
        let jql = JqlBuilder::new()
            .contains("summary", "cve-2026")
            .unwrap()
            .not_contains("description", "noise")
            .unwrap()
            .field_is_empty("resolution")
            .unwrap()
            .field_is_not_empty("assignee")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            jql,
            concat!(
                r#"summary ~ "cve\\-2026" AND description !~ "noise""#,
                " AND resolution IS EMPTY AND assignee IS NOT EMPTY"
            )
        );
    }

    #[test]
    fn builder_renders_order_by_keys_in_order() {
        let jql = JqlBuilder::new()
            .eq("project", "KAN")
            .unwrap()
            .order_by("created", JqlOrder::Descending)
            .unwrap()
            .order_by("key", JqlOrder::Ascending)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(jql, r#"project = "KAN" ORDER BY created DESC, key ASC"#);
    }

    #[test]
    fn builder_raw_term_is_verbatim() {
        let jql = JqlBuilder::new()
            .eq("project", "KAN")
            .unwrap()
            .raw_term("assignee = currentUser()")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(jql, r#"project = "KAN" AND assignee = currentUser()"#);
    }

    #[test]
    fn builder_rejects_a_blank_raw_term() {
        assert_eq!(
            JqlBuilder::new().raw_term("   ").unwrap_err(),
            JqlError::BlankRawTerm
        );
        assert_eq!(
            JqlBuilder::new().raw_term("").unwrap_err(),
            JqlError::BlankRawTerm
        );
    }

    #[test]
    fn builder_accepts_identifier_and_custom_field_names() {
        for field in [
            "project",
            "labels",
            "statusCategory",
            "Sprint_1",
            "a",
            "cf[10001]",
            "CF[10001]",
            "cf[1]",
        ] {
            assert!(
                JqlBuilder::new().eq(field, "x").is_ok(),
                "field {field:?} should be accepted"
            );
        }
    }

    #[test]
    fn builder_rejects_field_names_that_could_carry_syntax() {
        for field in [
            "",
            " project",
            "project ",
            "1project",
            "_project",
            "pro ject",
            "project = \"x\" OR labels",
            "labels\n",
            "cf[]",
            "cf[abc]",
            "cf[10001",
            "cf[10001]x",
            "cf[10001] OR labels",
            "cf[12345678901234567890]",
            "caf\u{e9}",
        ] {
            assert_eq!(
                JqlBuilder::new().eq(field, "x").unwrap_err(),
                JqlError::InvalidFieldName {
                    field: field.to_owned()
                },
                "field {field:?} should be rejected"
            );
        }
    }

    #[test]
    fn builder_validates_field_names_on_every_term_kind() {
        let bad = "project OR labels";
        assert!(JqlBuilder::new().not_eq(bad, "x").is_err());
        assert!(JqlBuilder::new().contains(bad, "x").is_err());
        assert!(JqlBuilder::new().not_contains(bad, "x").is_err());
        assert!(JqlBuilder::new().in_list(bad, ["x"]).is_err());
        assert!(JqlBuilder::new().not_in(bad, ["x"]).is_err());
        assert!(JqlBuilder::new().field_is_empty(bad).is_err());
        assert!(JqlBuilder::new().field_is_not_empty(bad).is_err());
        assert!(JqlBuilder::new()
            .order_by(bad, JqlOrder::Ascending)
            .is_err());
    }

    #[test]
    fn builder_rejects_an_empty_query() {
        assert!(JqlBuilder::new().is_empty());
        assert_eq!(JqlBuilder::new().build().unwrap_err(), JqlError::EmptyQuery);

        let ordered = JqlBuilder::new()
            .order_by("created", JqlOrder::Ascending)
            .unwrap();
        assert_eq!(ordered.build().unwrap_err(), JqlError::EmptyQuery);
    }

    #[test]
    fn builder_rejects_an_empty_value_list() {
        let empty: [&str; 0] = [];
        assert_eq!(
            JqlBuilder::new().in_list("labels", empty).unwrap_err(),
            JqlError::EmptyValueList {
                field: "labels".to_owned()
            }
        );
        assert_eq!(
            JqlBuilder::new().not_in("labels", empty).unwrap_err(),
            JqlError::EmptyValueList {
                field: "labels".to_owned()
            }
        );
    }

    #[test]
    fn builder_propagates_a_nul_value() {
        assert_eq!(
            JqlBuilder::new().eq("project", "K\0N").unwrap_err(),
            JqlError::NulCharacter { index: 1 }
        );
        assert_eq!(
            JqlBuilder::new()
                .in_list("labels", ["ok", "b\0d"])
                .unwrap_err(),
            JqlError::NulCharacter { index: 1 }
        );
    }

    #[test]
    fn hostile_values_stay_inside_their_builder_term() {
        for value in HOSTILE_VALUES {
            let jql = JqlBuilder::new()
                .eq("project", value)
                .unwrap()
                .eq("labels", "tail")
                .unwrap()
                .build()
                .unwrap();

            let after_operator = jql
                .strip_prefix("project = ")
                .expect("first term is the equality");
            let (decoded, rest) = scan_literal(after_operator);
            assert_eq!(&decoded, value);
            assert_eq!(
                rest, r#" AND labels = "tail""#,
                "value {value:?} altered the query structure"
            );
        }
    }

    #[test]
    fn hostile_values_stay_inside_their_membership_term() {
        let jql = JqlBuilder::new()
            .in_list("labels", [r#"a" OR labels = "b"#, "plain"])
            .unwrap()
            .build()
            .unwrap();

        let inner = jql
            .strip_prefix("labels IN (")
            .and_then(|rest| rest.strip_suffix(')'))
            .expect("membership term shape");
        let (first, rest) = scan_literal(inner);
        assert_eq!(first, r#"a" OR labels = "b"#);
        assert_eq!(rest, r#", "plain""#);
    }

    #[test]
    fn jql_error_converts_to_a_validation_error() {
        let err: AtlassianError = JqlError::EmptyQuery.into();
        assert!(matches!(err, AtlassianError::Validation { .. }));
        assert_eq!(
            err.to_string(),
            "Validation error: JQL query needs at least one term"
        );

        let err: AtlassianError = JqlError::NulCharacter { index: 4 }.into();
        assert_eq!(
            err.to_string(),
            "Validation error: JQL string literal cannot contain a NUL character (at byte 4)"
        );
    }

    #[test]
    fn invalid_field_name_message_does_not_break_a_log_line() {
        let err = JqlBuilder::new().eq("bad\nfield", "x").unwrap_err();
        assert!(!err.to_string().contains('\n'));
    }
}
