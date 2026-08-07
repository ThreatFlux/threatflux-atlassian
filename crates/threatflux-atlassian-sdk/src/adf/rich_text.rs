//! [`RichText`]: the wire type of every v3 rich-text field.
//!
//! Jira Cloud's v2 API carries an issue description and a comment body as a
//! plain string; v3 carries the same fields as an ADF object. Real deployments
//! hold both shapes at once -- an issue created through v2 last year and read
//! back through v3 today can still answer with a string -- so the field type has
//! to accept either, and it has to emit exactly one.
//!
//! [`RichText`] is that type. It is deliberately *not* a v2 type: `types.rs`
//! stays frozen and keeps `Option<String>`, because a v2 request may never carry
//! ADF and a v2 response never contains it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::node::AdfDocument;
use super::text::text_to_adf;
use crate::error::{AtlassianError, Result};

/// What [`RichText::into_wire`] fails with when handed an
/// [`Unknown`](RichText::Unknown) value.
///
/// A fixed string with no interpolation. The value that tripped it is Jira- or
/// caller-supplied and unbounded in both size and content, so none of it reaches
/// the message -- the house rule is that no caller-derived value reaches a log
/// or an error.
const UNKNOWN_ON_WRITE: &str = "rich text field holds a value that is neither an ADF document nor \
                                a plain string; such a value can be read back from Jira but never \
                                written to it";

/// The content of a v3 description or comment body, in any shape Jira may send.
///
/// # Reads take three shapes, writes take one
///
/// | Variant | Read from | Written as |
/// |---|---|---|
/// | [`Adf`](Self::Adf) | a v3 response, or a caller building a document | itself, after [`AdfDocument::validate`] |
/// | [`Text`](Self::Text) | a v2-era field Jira still answers with a string | an ADF document, one paragraph per blank-line-separated run |
/// | [`Unknown`](Self::Unknown) | anything else | **never** -- [`into_wire`](Self::into_wire) refuses |
///
/// Normalization happens at wire time, not at construction time. A
/// [`Text`](Self::Text) value stays a string in memory and *upgrades* to ADF on
/// emit; there is no downgrade in the other direction, and none will be added,
/// because an ADF-to-plain-text conversion would re-create the plain-text
/// fallback typed ADF exists to eliminate.
///
/// ```
/// use threatflux_atlassian_sdk::adf::RichText;
/// use serde_json::json;
///
/// // A v2-era string body still parses.
/// let body: RichText = serde_json::from_value(json!("see the advisory"))?;
/// assert_eq!(body, RichText::from("see the advisory"));
///
/// // ... and goes out as ADF, never as a string.
/// assert_eq!(
///     serde_json::to_value(body.into_wire()?)?,
///     json!({
///         "type": "doc",
///         "version": 1,
///         "content": [
///             {"type": "paragraph", "content": [{"type": "text", "text": "see the advisory"}]}
///         ]
///     })
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # `Unknown` is a read-tolerance escape hatch, not a write primitive
///
/// [`Unknown`](Self::Unknown) exists so that a shape which is neither an ADF
/// document nor a string -- a future Atlassian representation, or a `description`
/// that arrives damaged -- can be read without failing the whole response, and
/// echoed back byte-for-byte. It is refused on every write path with
/// [`AtlassianError::Validation`], mirroring [`AdfDocument::validate`]'s
/// rejection of an unmodelled node.
///
/// That refusal is the point of the variant's existence, not a detail of it.
/// Serializing an [`Unknown`](Self::Unknown) into a request body would put an
/// arbitrary caller-supplied `serde_json::Value` on the wire as JSON
/// *structure*, which is a JSON-structure-injection primitive: a caller who can
/// influence the value could add sibling keys, replace the document root, or
/// forge node types the rest of this crate refuses to build.
///
/// # Serialization is transparent
///
/// `#[serde(untagged)]` means the enum contributes no wrapper of its own: a
/// [`Text`](Self::Text) serializes as a bare JSON string and an
/// [`Adf`](Self::Adf) as a bare ADF object. That is what lets it stand in for a
/// `String` field without changing the shape of the surrounding request.
///
/// # The variant order is load-bearing
///
/// Untagged deserialization tries the variants **in declaration order** and
/// takes the first that succeeds. [`Unknown`](Self::Unknown) holds a
/// `serde_json::Value`, which matches *every* input, so it must be declared
/// last. Moving it above [`Text`](Self::Text) would make every string body an
/// `Unknown` -- and therefore unwritable; moving it to the top would do the same
/// to every ADF document, making the entire modelled surface unreachable and the
/// type a very expensive `serde_json::Value`. The order is pinned by
/// `unknown_is_the_last_variant_or_it_shadows_the_modelled_ones`.
///
/// [`Adf`](Self::Adf) before [`Text`](Self::Text) is not load-bearing in the same
/// way -- an object never parses as a `String` and vice versa -- but it is kept
/// in preference order so the listing reads as "the shape we want, the shape we
/// tolerate, the shape we only survive".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
#[non_exhaustive]
pub enum RichText {
    /// An ADF document -- what v3 sends and the only thing this crate writes.
    Adf(AdfDocument),

    /// A plain string, as a v2-era field still answers with.
    ///
    /// Legal on a read and on construction. On a write it is upgraded to ADF by
    /// [`into_wire`](Self::into_wire) rather than sent as-is.
    Text(String),

    /// Anything else, preserved verbatim. **Read-only.**
    ///
    /// Rejected by [`into_wire`](Self::into_wire) with
    /// [`AtlassianError::Validation`]. See the type-level documentation for why
    /// that is not negotiable.
    Unknown(serde_json::Value),
}

impl RichText {
    /// Normalizes this value into the one v3 wire form: an ADF document.
    ///
    /// - [`Adf`](Self::Adf) is validated and returned. Every rejection
    ///   [`AdfDocument::validate`] can raise surfaces here as
    ///   [`AtlassianError::Validation`].
    /// - [`Text`](Self::Text) is upgraded by [`text_to_adf`]: a `\r\n` or `\r`
    ///   line ending normalizes to `\n`, a run of one or more blank lines starts
    ///   a new paragraph, a single line break inside a paragraph becomes a
    ///   `hardBreak`, control characters other than `\n` and `\t` are stripped,
    ///   and the result is bounded by [`AdfLimits::DEFAULT`]. Text that is
    ///   empty, or consists only of line breaks, yields an empty document -- a
    ///   caller that means "no description at all" sends `None` rather than an
    ///   empty `RichText`.
    /// - [`Unknown`](Self::Unknown) is refused.
    ///
    /// There is deliberately one plain-text-to-ADF conversion in this crate and
    /// [`text_to_adf`] is it. A second one here would mean the same string
    /// became different documents depending on which door it came through, and
    /// the door every v3 write uses is this one -- so it is the door that has to
    /// carry the stripping and the bound. A caller that wants a different
    /// ceiling calls [`text_to_adf_bounded`](super::text_to_adf_bounded) itself
    /// and hands the result over as an [`Adf`](Self::Adf).
    ///
    /// The returned document always passes [`AdfDocument::validate`], so a
    /// caller that goes through here does not have to validate again.
    ///
    /// ```
    /// use threatflux_atlassian_sdk::adf::RichText;
    /// use threatflux_atlassian_sdk::AtlassianError;
    /// use serde_json::json;
    ///
    /// let two_paragraphs = RichText::from("first\nstill first\n\nsecond");
    /// assert_eq!(two_paragraphs.into_wire()?.content.len(), 2);
    ///
    /// let unreadable: RichText = serde_json::from_value(json!({"body": "?"}))?;
    /// assert!(matches!(
    ///     unreadable.into_wire(),
    ///     Err(AtlassianError::Validation { .. })
    /// ));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if this is an [`Unknown`](Self::Unknown),
    /// or if it is an [`Adf`](Self::Adf) whose document does not validate.
    ///
    /// [`AdfLimits::DEFAULT`]: super::AdfLimits::DEFAULT
    pub fn into_wire(self) -> Result<AdfDocument> {
        match self {
            Self::Adf(document) => {
                document.validate()?;
                Ok(document)
            }
            Self::Text(text) => Ok(text_to_adf(&text)),
            Self::Unknown(_) => Err(AtlassianError::validation(UNKNOWN_ON_WRITE)),
        }
    }

    /// Whether this is the read-only [`Unknown`](Self::Unknown) variant.
    ///
    /// Lets a caller find out that a field cannot be written back *before*
    /// assembling a request around it, which is the read-modify-write case:
    /// reading an issue, editing one field, and putting the rest back.
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }
}

impl From<AdfDocument> for RichText {
    fn from(document: AdfDocument) -> Self {
        Self::Adf(document)
    }
}

impl From<String> for RichText {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl From<&str> for RichText {
    fn from(text: &str) -> Self {
        Self::Text(text.to_owned())
    }
}

impl From<&String> for RichText {
    fn from(text: &String) -> Self {
        Self::Text(text.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adf::{AdfBlock, AdfLimits, ADF_VERSION};
    use serde_json::{json, Value};

    /// Stands in for the v3 request builders, which take `impl Into<RichText>`.
    fn accepts(value: impl Into<RichText>) -> RichText {
        value.into()
    }

    /// An ADF document as it arrives on the wire.
    fn adf_json() -> Value {
        json!({
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": "hello"}]}
            ]
        })
    }

    #[test]
    fn unknown_is_the_last_variant_or_it_shadows_the_modelled_ones() {
        // `#[serde(untagged)]` tries variants in declaration order and takes the
        // first that succeeds. `Unknown(serde_json::Value)` succeeds on *every*
        // input, so each assertion below fails the moment `Unknown` is moved
        // above the variant it is being distinguished from:
        //
        //   Unknown above `Adf`  -> the ADF case becomes Unknown
        //   Unknown above `Text` -> the string case becomes Unknown
        //
        // and both cases would then be unwritable, because `into_wire` refuses
        // `Unknown`. This test is the pin for that ordering.
        let from_adf: RichText = serde_json::from_value(adf_json()).expect("ADF parses");
        assert!(
            matches!(from_adf, RichText::Adf(_)),
            "an ADF object must resolve to `Adf`, not {from_adf:?}"
        );

        let from_string: RichText = serde_json::from_value(json!("plain")).expect("string parses");
        assert_eq!(
            from_string,
            RichText::Text("plain".to_string()),
            "a JSON string must resolve to `Text`"
        );

        // Only shapes no modelled variant accepts may land in `Unknown`.
        for shape in [
            json!({"type": "comment", "body": "not a doc"}),
            json!({"type": "doc"}), // no `version`: not an `AdfDocument`
            json!(7),
            json!([{"type": "paragraph"}]),
            json!(null),
        ] {
            let parsed: RichText =
                serde_json::from_value(shape.clone()).expect("every shape parses as something");
            assert!(
                parsed.is_unknown(),
                "{shape} should have resolved to `Unknown`, got {parsed:?}"
            );
        }
    }

    #[test]
    fn unknown_round_trips_on_read() {
        // The whole reason the variant exists: a shape this crate cannot model
        // survives a read and is re-emitted byte-for-byte, so a read-modify-write
        // of some *other* field cannot silently destroy this one.
        let original = json!({
            "type": "richTextV4",
            "blocks": [{"kind": "table", "rows": 3}],
            "meta": {"editor": "future"}
        });

        let parsed: RichText = serde_json::from_value(original.clone()).expect("parses");
        assert!(parsed.is_unknown());
        assert_eq!(
            serde_json::to_value(&parsed).expect("serializes"),
            original,
            "round trip changed an unmodelled value"
        );
    }

    #[test]
    fn unknown_is_rejected_on_write() {
        let parsed: RichText = serde_json::from_value(json!({
            "type": "richTextV4",
            "secretish": "s3cret-payload-that-must-not-be-logged"
        }))
        .expect("parses");

        let error = parsed
            .into_wire()
            .expect_err("`Unknown` must not be writable");
        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );

        // Bounded logging: the refusal names the problem, never the value.
        let rendered = error.to_string();
        assert!(
            !rendered.contains("s3cret-payload-that-must-not-be-logged"),
            "the rejected value leaked into the error message: {rendered}"
        );
        assert!(
            !rendered.contains("richTextV4"),
            "leaked message: {rendered}"
        );
    }

    #[test]
    fn serialization_is_transparent_so_the_field_shape_is_unchanged() {
        // Untagged means no wrapper: whatever the variant holds is what lands on
        // the wire. Without this a `description: RichText` field would serialize
        // as `{"Text": "..."}` and Jira would reject the request.
        assert_eq!(
            serde_json::to_value(RichText::from("plain")).expect("serializes"),
            json!("plain")
        );
        let document: AdfDocument = serde_json::from_value(adf_json()).expect("parses");
        assert_eq!(
            serde_json::to_value(RichText::from(document)).expect("serializes"),
            adf_json()
        );
        assert_eq!(
            serde_json::to_value(RichText::Unknown(json!({"a": 1}))).expect("serializes"),
            json!({"a": 1})
        );
    }

    #[test]
    fn text_upgrades_to_adf_rather_than_going_out_as_a_string() {
        let wire = RichText::from("first line\nsecond line\n\n\nnew paragraph")
            .into_wire()
            .expect("plain text is always writable");

        assert_eq!(
            serde_json::to_value(&wire).expect("serializes"),
            json!({
                "type": "doc",
                "version": ADF_VERSION,
                "content": [
                    {"type": "paragraph", "content": [
                        {"type": "text", "text": "first line"},
                        {"type": "hardBreak"},
                        {"type": "text", "text": "second line"}
                    ]},
                    {"type": "paragraph", "content": [
                        {"type": "text", "text": "new paragraph"}
                    ]}
                ]
            })
        );
    }

    #[test]
    fn text_upgrade_normalizes_both_line_ending_conventions() {
        let crlf = RichText::from("a\r\nb\r\n\r\nc")
            .into_wire()
            .expect("writable");
        let cr = RichText::from("a\rb\r\rc").into_wire().expect("writable");
        let lf = RichText::from("a\nb\n\nc").into_wire().expect("writable");

        assert_eq!(crlf, lf, "CRLF must read as LF");
        assert_eq!(cr, lf, "a lone CR must read as LF");
        assert_eq!(lf.content.len(), 2);
    }

    #[test]
    fn the_text_upgrade_is_text_to_adf_and_not_a_second_copy_of_it() {
        // There was briefly a private converter here that implemented three of
        // `text_to_adf`'s four clauses -- it normalized line endings, split on
        // blank-line runs and emitted hard breaks, but neither stripped control
        // characters nor bounded its output. That made the same string produce
        // two different documents depending on whether it reached Jira as a
        // `RichText::Text` or through `text_to_adf`, and every v3 write takes
        // the first door. This test is the pin that keeps the two from drifting
        // apart again: it must be the *same function*, not merely agree today.
        for sample in [
            "a\r\nb\r\n\r\nc",
            "one line",
            "tab\there\nand\ttabs",
            "\u{0}nul\u{7}bell",
            "",
            "   ",
        ] {
            assert_eq!(
                RichText::from(sample).into_wire().expect("writable"),
                text_to_adf(sample),
                "the upgrade of {sample:?} diverged from `text_to_adf`"
            );
        }
    }

    #[test]
    fn the_text_upgrade_strips_control_characters_and_bounds_its_output() {
        // The two clauses the removed private converter did not implement.
        // Both matter here specifically because this is the conversion every
        // v3 description and comment body goes through.
        let stripped = RichText::from("before\u{0}after\u{7}\n\tkept")
            .into_wire()
            .expect("writable");
        let rendered = serde_json::to_string(&stripped).expect("serializes");
        assert!(
            !rendered.contains("\\u0000") && !rendered.contains("\\u0007"),
            "a control character reached the wire: {rendered}"
        );
        assert!(
            rendered.contains("beforeafter"),
            "stripping removed more than the control characters: {rendered}"
        );
        assert!(
            rendered.contains("\\t"),
            "a tab must survive, it is legal text: {rendered}"
        );

        let huge = "x".repeat(AdfLimits::DEFAULT.max_chars * 2);
        let bounded = RichText::from(huge).into_wire().expect("writable");
        let chars: usize = serde_json::to_value(&bounded).expect("serializes")["content"]
            .as_array()
            .expect("blocks")
            .iter()
            .flat_map(|block| block["content"].as_array().cloned().unwrap_or_default())
            .filter_map(|node| node["text"].as_str().map(|text| text.chars().count()))
            .sum();
        assert!(
            chars <= AdfLimits::DEFAULT.max_chars,
            "an over-long body was written whole: {chars} characters"
        );
    }

    #[test]
    fn text_with_no_content_upgrades_to_an_empty_document() {
        // `None` is how a caller says "no description"; an empty `RichText` is a
        // description that is empty, and that is legal ADF.
        for empty in ["", "\n", "\n\n\n", "\r\n\r\n"] {
            let wire = RichText::from(empty).into_wire().expect("writable");
            assert!(
                wire.is_empty(),
                "{empty:?} should have produced an empty document, got {wire:?}"
            );
        }
    }

    #[test]
    fn the_upgraded_document_is_always_valid() {
        // `into_wire`'s postcondition: the caller never has to validate again.
        // A whitespace-only line is the interesting case -- it is not empty, so
        // it becomes a `text` node, and an *empty* `text` node is what ADF
        // rejects.
        for text in ["", "   ", "a\n \nb", "\t", "line\n\nline"] {
            let wire = RichText::from(text).into_wire().expect("writable");
            assert!(
                wire.validate().is_ok(),
                "{text:?} upgraded to a document that does not validate"
            );
        }
    }

    #[test]
    fn an_adf_value_is_validated_on_the_way_out() {
        // The document parses (reads are tolerant) and then fails the write gate,
        // because `table` is not a node this crate can emit.
        let with_unmodelled_node: RichText = serde_json::from_value(json!({
            "type": "doc",
            "version": 1,
            "content": [{"type": "table", "content": []}]
        }))
        .expect("parses");
        assert!(matches!(with_unmodelled_node, RichText::Adf(_)));

        let error = with_unmodelled_node
            .into_wire()
            .expect_err("an unmodelled node must not be writable");
        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );

        // A structurally sound document goes through untouched.
        let good: RichText = serde_json::from_value(adf_json()).expect("parses");
        let expected: AdfDocument = serde_json::from_value(adf_json()).expect("parses");
        assert_eq!(good.into_wire().expect("valid"), expected);
    }

    #[test]
    fn the_from_impls_cover_the_four_ways_a_caller_holds_content() {
        let owned = "owned".to_string();
        assert_eq!(
            RichText::from("borrowed"),
            RichText::Text("borrowed".into())
        );
        assert_eq!(
            RichText::from(owned.clone()),
            RichText::Text("owned".into())
        );
        assert_eq!(RichText::from(&owned), RichText::Text("owned".into()));

        let document = AdfDocument::new([AdfBlock::paragraph_text("built")]);
        assert_eq!(
            RichText::from(document.clone()),
            RichText::Adf(document.clone())
        );

        // `Into` is what the v3 request builders take, so each of the four has
        // to resolve through it without a turbofish.
        assert_eq!(accepts("borrowed"), RichText::Text("borrowed".into()));
        assert_eq!(accepts(owned.clone()), RichText::Text("owned".into()));
        assert_eq!(accepts(&owned), RichText::Text("owned".into()));
        assert_eq!(accepts(document.clone()), RichText::Adf(document));
    }

    #[test]
    fn a_v2_era_string_body_survives_a_read_unchanged() {
        // The compatibility case the v3 comment reader depends on: bodies
        // written through v2 are strings, and reading them back through a
        // `RichText` field must neither fail nor rewrite them.
        let raw = json!("plain body with \"quotes\" and a \u{1f600}");
        let parsed: RichText = serde_json::from_value(raw.clone()).expect("parses");
        assert!(matches!(parsed, RichText::Text(_)));
        assert_eq!(serde_json::to_value(&parsed).expect("serializes"), raw);
    }
}
