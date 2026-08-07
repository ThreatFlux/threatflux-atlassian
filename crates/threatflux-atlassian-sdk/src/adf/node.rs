//! The node model: [`AdfDocument`] and the block, inline, list-item and mark types.
//!
//! Every enum in this module is internally tagged on `type` and carries an
//! `Unknown` fallback variant. See the [module documentation](super) for the
//! representation rules and the round-trip contract.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Keys found on a node this crate models but has no field for, kept verbatim.
///
/// Every modelled node that ADF gives attributes to carries one of these, so an
/// attribute this crate does not know about survives a read-modify-write instead
/// of being stripped on the way back out. See the [module
/// documentation](super#unmodelled-keys-survive-too) for the whole of the rule
/// and for the nodes it does not apply to.
///
/// ```
/// use threatflux_atlassian_sdk::adf::{AdfBlock, AdfDocument};
///
/// let raw = r#"{"type":"doc","version":1,"content":[
///     {"type":"paragraph","attrs":{"localId":"abc"},
///      "content":[{"type":"text","text":"hi"}]}
/// ]}"#;
///
/// let parsed: AdfDocument = serde_json::from_str(raw)?;
/// let AdfBlock::Paragraph { other, .. } = &parsed.content[0] else {
///     panic!("a paragraph with an unmodelled attribute is still a paragraph");
/// };
/// assert_eq!(other["attrs"], serde_json::json!({"localId": "abc"}));
/// # Ok::<(), serde_json::Error>(())
/// ```
///
/// A `BTreeMap` rather than a [`serde_json::Map`](serde_json::Map) so the empty
/// one can be built in a `const fn`, which is what keeps constructors such as
/// [`AdfDocument::empty`] and [`AdfBlock::empty_paragraph`] `const`.
pub type AdfExtraKeys = BTreeMap<String, serde_json::Value>;

/// The ADF schema version this crate emits and the only version
/// [`AdfDocument::validate`] accepts on a write.
///
/// Atlassian has published exactly one document schema version. A document that
/// declares a different one still deserializes -- reads stay tolerant -- and is
/// rejected on the write path.
pub const ADF_VERSION: u32 = 1;

/// The `type` discriminator of the ADF root node.
///
/// Modelling the root tag as a field rather than as a struct-level
/// `#[serde(tag = "type")]` attribute is deliberate. A struct-level tag is
/// **write-only**: serde emits it and then ignores it on the way in, so
/// `{"type":"paragraph","version":1}` would deserialize into an [`AdfDocument`]
/// and re-serialize as `{"type":"doc",...}` -- a silent rewrite of somebody
/// else's node. This enum has one legal value and rejects everything else, which
/// makes the mis-typed root a parse error instead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AdfDocType {
    /// The literal `doc`.
    #[default]
    #[serde(rename = "doc")]
    Doc,
}

/// The `type` discriminator of a list item.
///
/// Exists for the same reason as [`AdfDocType`]: without it, any node sitting
/// inside a `bulletList` would be re-emitted as a `listItem` regardless of what
/// it actually was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AdfListItemType {
    /// The literal `listItem`.
    #[default]
    #[serde(rename = "listItem")]
    ListItem,
}

/// An Atlassian Document Format document -- the `doc` root node.
///
/// ```
/// use threatflux_atlassian_sdk::adf::{AdfBlock, AdfDocument};
/// use serde_json::json;
///
/// let doc = AdfDocument::new([AdfBlock::paragraph_text("hello")]);
/// assert_eq!(
///     serde_json::to_value(&doc)?,
///     json!({
///         "type": "doc",
///         "version": 1,
///         "content": [
///             {"type": "paragraph", "content": [{"type": "text", "text": "hello"}]}
///         ]
///     })
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
///
/// Prefer [`AdfDocument::new`], [`AdfDocument::empty`] or
/// [`AdfDocumentBuilder`](crate::adf::AdfDocumentBuilder) over a struct literal:
/// they set [`version`](Self::version) and [`node_type`](Self::node_type) for you.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdfDocument {
    /// Always [`AdfDocType::Doc`]. Serializes as `"type": "doc"`.
    #[serde(rename = "type")]
    pub node_type: AdfDocType,
    /// Schema version, always [`ADF_VERSION`] on anything this crate emits.
    pub version: u32,
    /// Top-level block nodes, in document order.
    ///
    /// Always serialized, including when empty: `content` is a required member of
    /// the root node, and `{"type":"doc","version":1,"content":[]}` is what Jira
    /// returns for a description that was cleared.
    #[serde(default)]
    pub content: Vec<AdfBlock>,
    /// Root-node keys this crate does not model, kept verbatim. See
    /// [`AdfExtraKeys`].
    #[serde(flatten)]
    pub other: AdfExtraKeys,
}

impl Default for AdfDocument {
    /// An empty document at [`ADF_VERSION`].
    fn default() -> Self {
        Self::empty()
    }
}

impl AdfDocument {
    /// An empty document at [`ADF_VERSION`].
    pub const fn empty() -> Self {
        Self {
            node_type: AdfDocType::Doc,
            version: ADF_VERSION,
            content: Vec::new(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A document at [`ADF_VERSION`] holding `content`.
    pub fn new(content: impl IntoIterator<Item = AdfBlock>) -> Self {
        Self {
            node_type: AdfDocType::Doc,
            version: ADF_VERSION,
            content: content.into_iter().collect(),
            other: AdfExtraKeys::new(),
        }
    }

    /// Appends a block, consuming and returning the document.
    #[must_use]
    pub fn with_block(mut self, block: AdfBlock) -> Self {
        self.content.push(block);
        self
    }

    /// Whether the document holds no block nodes.
    ///
    /// An empty document is legal ADF and is accepted by
    /// [`validate`](Self::validate); callers that mean "no description at all"
    /// should send `None` rather than an empty document.
    pub const fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

/// A block-level node.
///
/// Block nodes are the children of the document root, of a `listItem` and of a
/// `blockquote`. Splitting them from [`AdfInline`] is what makes an invalid tree
/// -- a `hardBreak` at document top level, a `paragraph` inside a `paragraph` --
/// unrepresentable rather than merely invalid.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum AdfBlock {
    /// `paragraph` -- a run of inline content.
    ///
    /// The only block ADF permits to be empty. An empty paragraph is emitted as
    /// the bare `{"type":"paragraph"}`, which is the form Jira itself returns.
    Paragraph {
        /// Inline children, in document order.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        content: Vec<AdfInline>,
        /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
        #[serde(flatten)]
        other: AdfExtraKeys,
    },

    /// `heading` -- inline content at a level between 1 and 6.
    Heading {
        /// Carries the required `level`.
        attrs: AdfHeadingAttrs,
        /// Inline children, in document order.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        content: Vec<AdfInline>,
        /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
        #[serde(flatten)]
        other: AdfExtraKeys,
    },

    /// `bulletList` -- an unordered list of `listItem` nodes.
    BulletList {
        /// List items. ADF requires at least one.
        content: Vec<AdfListItem>,
        /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
        #[serde(flatten)]
        other: AdfExtraKeys,
    },

    /// `orderedList` -- a numbered list of `listItem` nodes.
    OrderedList {
        /// Optional `order` (the number the list starts at).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attrs: Option<AdfOrderedListAttrs>,
        /// List items. ADF requires at least one.
        content: Vec<AdfListItem>,
        /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
        #[serde(flatten)]
        other: AdfExtraKeys,
    },

    /// `codeBlock` -- preformatted text.
    ///
    /// Its children are `text` nodes only, and they may not carry marks. Line
    /// breaks inside a code block are `\n` characters within the text, never
    /// `hardBreak` nodes.
    CodeBlock {
        /// Optional `language` hint for syntax highlighting.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attrs: Option<AdfCodeBlockAttrs>,
        /// Text children, in document order.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        content: Vec<AdfInline>,
        /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
        #[serde(flatten)]
        other: AdfExtraKeys,
    },

    /// `blockquote` -- block content set off as a quotation.
    ///
    /// ADF does not permit a `blockquote` inside a `blockquote`; the nesting is
    /// representable and is rejected by [`AdfDocument::validate`].
    Blockquote {
        /// Block children, in document order.
        content: Vec<Self>,
        /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
        #[serde(flatten)]
        other: AdfExtraKeys,
    },

    /// `rule` -- a horizontal rule.
    ///
    /// A unit variant: ADF gives a `rule` neither content nor attributes, so
    /// there is nothing for an [`AdfExtraKeys`] map to hold. A key that turns up
    /// on one anyway is dropped -- see the [module
    /// documentation](super#unmodelled-keys-survive-too).
    Rule,

    /// A block node type this crate does not model, preserved verbatim.
    ///
    /// This is what makes a read/write round trip lossless over the node types
    /// real Jira descriptions contain but this crate has no variant for --
    /// `table`, `panel`, `mediaSingle`, `expand`, and anything Atlassian adds
    /// later. It also catches a *malformed* known node (a `heading` with no
    /// `level`), which is the deliberate trade-off for that tolerance.
    ///
    /// [`AdfDocument::validate`] rejects it, so an unmodelled node can be read
    /// and echoed back but never assembled into a write by this crate.
    #[serde(untagged)]
    Unknown(serde_json::Value),
}

impl AdfBlock {
    /// A `paragraph` holding `content`.
    pub fn paragraph(content: impl IntoIterator<Item = AdfInline>) -> Self {
        Self::Paragraph {
            content: content.into_iter().collect(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `paragraph` holding a single `text` node.
    pub fn paragraph_text(text: impl Into<String>) -> Self {
        Self::Paragraph {
            content: vec![AdfInline::text(text)],
            other: AdfExtraKeys::new(),
        }
    }

    /// An empty `paragraph`, which serializes as `{"type":"paragraph"}`.
    pub const fn empty_paragraph() -> Self {
        Self::Paragraph {
            content: Vec::new(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `heading` at `level` holding `content`.
    ///
    /// `level` is not checked here; [`AdfDocument::validate`] rejects a level
    /// outside 1..=6.
    pub fn heading(level: u8, content: impl IntoIterator<Item = AdfInline>) -> Self {
        Self::Heading {
            attrs: AdfHeadingAttrs::new(level),
            content: content.into_iter().collect(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `heading` at `level` holding a single `text` node.
    pub fn heading_text(level: u8, text: impl Into<String>) -> Self {
        Self::heading(level, [AdfInline::text(text)])
    }

    /// A `bulletList` holding `items`.
    pub fn bullet_list(items: impl IntoIterator<Item = AdfListItem>) -> Self {
        Self::BulletList {
            content: items.into_iter().collect(),
            other: AdfExtraKeys::new(),
        }
    }

    /// An `orderedList` holding `items`, numbered from 1.
    pub fn ordered_list(items: impl IntoIterator<Item = AdfListItem>) -> Self {
        Self::OrderedList {
            attrs: None,
            content: items.into_iter().collect(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `codeBlock` with no language hint.
    ///
    /// An empty `code` yields a code block with no children rather than an empty
    /// `text` node, which ADF does not allow.
    pub fn code_block(code: impl Into<String>) -> Self {
        Self::CodeBlock {
            attrs: None,
            content: Self::code_content(code.into()),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `codeBlock` tagged with a `language` hint.
    pub fn code_block_with_language(language: impl Into<String>, code: impl Into<String>) -> Self {
        Self::CodeBlock {
            attrs: Some(AdfCodeBlockAttrs {
                language: Some(language.into()),
                other: AdfExtraKeys::new(),
            }),
            content: Self::code_content(code.into()),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `blockquote` holding `content`.
    pub fn blockquote(content: impl IntoIterator<Item = Self>) -> Self {
        Self::Blockquote {
            content: content.into_iter().collect(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `rule`.
    pub const fn rule() -> Self {
        Self::Rule
    }

    fn code_content(code: String) -> Vec<AdfInline> {
        if code.is_empty() {
            Vec::new()
        } else {
            vec![AdfInline::text(code)]
        }
    }
}

/// An inline node: the content of a `paragraph`, a `heading` or a `codeBlock`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum AdfInline {
    /// `text` -- a run of characters, optionally marked.
    ///
    /// ADF requires the string to be non-empty; [`AdfDocument::validate`]
    /// rejects an empty one, because Jira answers such a document with a 400.
    Text {
        /// The characters themselves.
        text: String,
        /// Marks applied to this run. Omitted from the wire when empty.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        marks: Vec<AdfMark>,
        /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
        #[serde(flatten)]
        other: AdfExtraKeys,
    },

    /// `hardBreak` -- a line break inside a paragraph.
    ///
    /// A unit variant on purpose. A hard break has no children, and a variant
    /// with a content field would put `"content": []` on the wire, which Jira
    /// rejects. The consequence is that the optional `attrs` Atlassian's schema
    /// allows on a hard break (whose only member is the fixed literal
    /// `{"text":"\n"}`) is dropped rather than echoed back.
    HardBreak,

    /// An inline node type this crate does not model (`emoji`, `mention`,
    /// `inlineCard`, `date`, `status`, ...), preserved verbatim.
    ///
    /// Rejected by [`AdfDocument::validate`], exactly like
    /// [`AdfBlock::Unknown`].
    #[serde(untagged)]
    Unknown(serde_json::Value),
}

impl AdfInline {
    /// An unmarked `text` node.
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text {
            text: text.into(),
            marks: Vec::new(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `text` node carrying `marks`.
    pub fn text_with_marks(
        text: impl Into<String>,
        marks: impl IntoIterator<Item = AdfMark>,
    ) -> Self {
        Self::Text {
            text: text.into(),
            marks: marks.into_iter().collect(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `text` node carrying a single `link` mark -- the usual way to write a
    /// hyperlink in ADF.
    pub fn link(text: impl Into<String>, href: impl Into<String>) -> Self {
        Self::text_with_marks(text, [AdfMark::link(href)])
    }

    /// A `hardBreak`.
    pub const fn hard_break() -> Self {
        Self::HardBreak
    }
}

/// A `listItem`: the only legal child of a `bulletList` or an `orderedList`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdfListItem {
    /// Always [`AdfListItemType::ListItem`]. Serializes as `"type": "listItem"`.
    #[serde(rename = "type")]
    pub node_type: AdfListItemType,
    /// Block children. ADF requires at least one.
    pub content: Vec<AdfBlock>,
    /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
    #[serde(flatten)]
    pub other: AdfExtraKeys,
}

impl AdfListItem {
    /// A list item holding `content`.
    pub fn new(content: impl IntoIterator<Item = AdfBlock>) -> Self {
        Self {
            node_type: AdfListItemType::ListItem,
            content: content.into_iter().collect(),
            other: AdfExtraKeys::new(),
        }
    }

    /// A list item holding a single paragraph of `text`.
    pub fn text(text: impl Into<String>) -> Self {
        Self::new([AdfBlock::paragraph_text(text)])
    }
}

/// A mark: formatting applied to a run of [`AdfInline::Text`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum AdfMark {
    /// `link` -- turns the marked run into a hyperlink.
    Link {
        /// Carries the required `href`.
        attrs: AdfLinkAttrs,
        /// Keys this crate does not model, kept verbatim. See [`AdfExtraKeys`].
        #[serde(flatten)]
        other: AdfExtraKeys,
    },
    /// `strong` -- bold.
    ///
    /// A unit variant: ADF gives it no attributes, as for the four below. See
    /// the [module documentation](super#unmodelled-keys-survive-too).
    Strong,
    /// `em` -- italic.
    Em,
    /// `code` -- inline monospace.
    Code,
    /// `strike` -- struck through.
    Strike,
    /// `underline` -- underlined.
    Underline,
    /// A mark type this crate does not model (`textColor`, `subsup`,
    /// `backgroundColor`, ...), preserved verbatim.
    ///
    /// Rejected by [`AdfDocument::validate`], exactly like
    /// [`AdfBlock::Unknown`]. Keeping the fallback at mark level rather than
    /// letting an unmodelled mark demote its whole `text` node is what keeps a
    /// coloured run readable as typed text on the read path.
    #[serde(untagged)]
    Unknown(serde_json::Value),
}

impl AdfMark {
    /// A `link` mark pointing at `href`.
    pub fn link(href: impl Into<String>) -> Self {
        Self::Link {
            attrs: AdfLinkAttrs::new(href),
            other: AdfExtraKeys::new(),
        }
    }

    /// A `link` mark pointing at `href` with a hover `title`.
    pub fn link_with_title(href: impl Into<String>, title: impl Into<String>) -> Self {
        Self::Link {
            attrs: AdfLinkAttrs {
                title: Some(title.into()),
                ..AdfLinkAttrs::new(href)
            },
            other: AdfExtraKeys::new(),
        }
    }
}

/// `attrs` of a `heading`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdfHeadingAttrs {
    /// Heading level, 1 through 6.
    pub level: u8,
    /// Attributes this crate does not model, kept verbatim. See
    /// [`AdfExtraKeys`].
    #[serde(flatten)]
    pub other: AdfExtraKeys,
}

impl AdfHeadingAttrs {
    /// Heading attributes at `level`, with no unmodelled attributes.
    ///
    /// `level` is not checked here; [`AdfDocument::validate`] rejects a level
    /// outside 1..=6.
    pub const fn new(level: u8) -> Self {
        Self {
            level,
            other: AdfExtraKeys::new(),
        }
    }
}

/// `attrs` of an `orderedList`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdfOrderedListAttrs {
    /// The number the list starts at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<u32>,
    /// Attributes this crate does not model, kept verbatim. See
    /// [`AdfExtraKeys`].
    #[serde(flatten)]
    pub other: AdfExtraKeys,
}

/// `attrs` of a `codeBlock`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdfCodeBlockAttrs {
    /// Syntax highlighting hint, such as `rust` or `json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Attributes this crate does not model, kept verbatim. See
    /// [`AdfExtraKeys`].
    #[serde(flatten)]
    pub other: AdfExtraKeys,
}

/// `attrs` of a `link` mark.
///
/// Atlassian's schema also allows `id`, `collection` and `occurrenceKey` on a
/// link. They are not modelled as fields, and a link carrying them keeps them in
/// [`other`](Self::other) -- see the [module
/// documentation](super#unmodelled-keys-survive-too).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdfLinkAttrs {
    /// Link target.
    pub href: String,
    /// Optional hover title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Attributes this crate does not model, kept verbatim. See
    /// [`AdfExtraKeys`].
    #[serde(flatten)]
    pub other: AdfExtraKeys,
}

impl AdfLinkAttrs {
    /// Link attributes pointing at `href`, with no title and no unmodelled
    /// attributes.
    pub fn new(href: impl Into<String>) -> Self {
        Self {
            href: href.into(),
            title: None,
            other: AdfExtraKeys::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// Parses `raw` as a document and asserts the re-serialized form is byte-for-byte
    /// the JSON it came from. Every acceptance test below goes through here, so a
    /// representation that only serializes correctly -- or only parses correctly --
    /// cannot pass.
    fn round_trip(raw: &str) -> AdfDocument {
        let original: Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let parsed: AdfDocument =
            serde_json::from_value(original.clone()).expect("fixture parses as a document");
        let reserialized = serde_json::to_value(&parsed).expect("document serializes");
        assert_eq!(reserialized, original, "round trip changed the document");
        parsed
    }

    /// Wraps `blocks` in the root node, so a test can name only the node it is about.
    fn doc_with(blocks: &Value) -> String {
        json!({"type": "doc", "version": 1, "content": blocks}).to_string()
    }

    // --- The eight node types the issue names, one test each. ---

    #[test]
    fn doc_node_round_trips() {
        let parsed = round_trip(&doc_with(&json!([])));
        assert_eq!(parsed.node_type, AdfDocType::Doc);
        assert_eq!(parsed.version, ADF_VERSION);
        assert!(parsed.is_empty());
    }

    #[test]
    fn doc_node_rejects_a_root_that_is_not_a_doc() {
        // A struct-level `#[serde(tag = "type")]` would accept this and re-emit it
        // as `{"type":"doc",...}`, rewriting somebody else's node. `AdfDocType` is
        // what makes it a parse error instead.
        let wrong_root = r#"{"type":"paragraph","version":1,"content":[]}"#;
        assert!(serde_json::from_str::<AdfDocument>(wrong_root).is_err());
    }

    #[test]
    fn paragraph_node_round_trips() {
        let parsed = round_trip(&doc_with(&json!([
            {"type": "paragraph", "content": [{"type": "text", "text": "hello"}]}
        ])));
        assert_eq!(
            parsed.content,
            vec![AdfBlock::paragraph_text("hello")],
            "paragraph did not parse into the modelled variant"
        );
    }

    #[test]
    fn text_node_round_trips() {
        let parsed = round_trip(&doc_with(&json!([
            {"type": "paragraph", "content": [{"type": "text", "text": "plain run"}]}
        ])));
        let AdfBlock::Paragraph { content, .. } = &parsed.content[0] else {
            panic!("expected a paragraph, got {:?}", parsed.content[0]);
        };
        assert_eq!(content, &vec![AdfInline::text("plain run")]);
    }

    #[test]
    fn hard_break_node_round_trips() {
        let parsed = round_trip(&doc_with(&json!([{
            "type": "paragraph",
            "content": [
                {"type": "text", "text": "first"},
                {"type": "hardBreak"},
                {"type": "text", "text": "second"}
            ]
        }])));
        assert_eq!(
            parsed.content,
            vec![AdfBlock::paragraph([
                AdfInline::text("first"),
                AdfInline::hard_break(),
                AdfInline::text("second"),
            ])]
        );
    }

    #[test]
    fn hard_break_carries_no_content_key_on_the_wire() {
        // The reason `HardBreak` is a unit variant: a variant with a content field
        // puts `"content": []` on the wire, and Jira rejects that.
        let wire = serde_json::to_value(AdfInline::hard_break()).expect("serializes");
        assert_eq!(wire, json!({"type": "hardBreak"}));
        let object = wire.as_object().expect("hard break is an object");
        assert_eq!(object.len(), 1, "hard break emitted keys beyond `type`");
    }

    #[test]
    fn heading_node_round_trips() {
        let parsed = round_trip(&doc_with(&json!([{
            "type": "heading",
            "attrs": {"level": 3},
            "content": [{"type": "text", "text": "Impact"}]
        }])));
        assert_eq!(parsed.content, vec![AdfBlock::heading_text(3, "Impact")]);
    }

    #[test]
    fn bullet_list_node_round_trips() {
        let parsed = round_trip(&doc_with(&json!([{
            "type": "bulletList",
            "content": [
                {"type": "listItem", "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": "one"}]}
                ]},
                {"type": "listItem", "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": "two"}]}
                ]}
            ]
        }])));
        assert_eq!(
            parsed.content,
            vec![AdfBlock::bullet_list([
                AdfListItem::text("one"),
                AdfListItem::text("two"),
            ])]
        );
    }

    #[test]
    fn code_block_node_round_trips() {
        let parsed = round_trip(&doc_with(&json!([{
            "type": "codeBlock",
            "attrs": {"language": "rust"},
            "content": [{"type": "text", "text": "let x = 1;\nlet y = 2;"}]
        }])));
        assert_eq!(
            parsed.content,
            vec![AdfBlock::code_block_with_language(
                "rust",
                "let x = 1;\nlet y = 2;"
            )]
        );
    }

    #[test]
    fn link_mark_round_trips() {
        let parsed = round_trip(&doc_with(&json!([{
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": "advisory",
                "marks": [{"type": "link", "attrs": {"href": "https://example.test/a"}}]
            }]
        }])));
        assert_eq!(
            parsed.content,
            vec![AdfBlock::paragraph([AdfInline::link(
                "advisory",
                "https://example.test/a"
            )])]
        );
    }

    #[test]
    fn link_mark_keeps_its_optional_title() {
        let parsed = round_trip(&doc_with(&json!([{
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": "advisory",
                "marks": [{"type": "link", "attrs": {
                    "href": "https://example.test/a", "title": "CVE-2026-0001"
                }}]
            }]
        }])));
        assert_eq!(
            parsed.content,
            vec![AdfBlock::paragraph([AdfInline::text_with_marks(
                "advisory",
                [AdfMark::link_with_title(
                    "https://example.test/a",
                    "CVE-2026-0001"
                )]
            )])]
        );
    }

    // --- Unmodelled nodes. ---

    #[test]
    fn unmodelled_block_nodes_round_trip_losslessly() {
        // The document a later task asserts `to_value(parse(x)) == x` over: node
        // types this crate has no variant for, one of them nested.
        let raw = doc_with(&json!([
            {"type": "paragraph", "content": [{"type": "text", "text": "before"}]},
            {"type": "table", "attrs": {"isNumberColumnEnabled": false, "layout": "default"},
             "content": [{"type": "tableRow", "content": [
                 {"type": "tableHeader", "attrs": {}, "content": [
                     {"type": "paragraph", "content": [{"type": "text", "text": "h"}]}
                 ]}
             ]}]},
            {"type": "mediaSingle", "attrs": {"layout": "center"}, "content": [
                {"type": "media", "attrs": {"id": "abc", "type": "file", "collection": "c"}}
            ]},
            {"type": "panel", "attrs": {"panelType": "info"}, "content": [
                {"type": "panel", "attrs": {"panelType": "note"}, "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": "nested"}]}
                ]}
            ]},
            {"type": "paragraph", "content": [{"type": "text", "text": "after"}]}
        ]));

        let parsed = round_trip(&raw);
        assert_eq!(parsed.content.len(), 5);
        assert!(matches!(parsed.content[1], AdfBlock::Unknown(_)));
        assert!(matches!(parsed.content[2], AdfBlock::Unknown(_)));
        assert!(matches!(parsed.content[3], AdfBlock::Unknown(_)));
        assert!(
            matches!(parsed.content[0], AdfBlock::Paragraph { .. }),
            "modelled nodes must stay modelled when unmodelled ones are present"
        );
    }

    #[test]
    fn unmodelled_inline_nodes_round_trip_losslessly() {
        let parsed = round_trip(&doc_with(&json!([{
            "type": "paragraph",
            "content": [
                {"type": "text", "text": "hi "},
                {"type": "mention", "attrs": {"id": "557058:x", "text": "@dev"}},
                {"type": "emoji", "attrs": {"shortName": ":wave:", "id": "1f44b"}}
            ]
        }])));
        let AdfBlock::Paragraph { content, .. } = &parsed.content[0] else {
            panic!("expected a paragraph");
        };
        assert!(matches!(content[0], AdfInline::Text { .. }));
        assert!(matches!(content[1], AdfInline::Unknown(_)));
        assert!(matches!(content[2], AdfInline::Unknown(_)));
    }

    #[test]
    fn unmodelled_marks_round_trip_without_demoting_their_text_node() {
        let raw = doc_with(&json!([{
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": "coloured",
                "marks": [
                    {"type": "strong"},
                    {"type": "textColor", "attrs": {"color": "#ff5630"}}
                ]
            }]
        }]));
        let parsed = round_trip(&raw);
        let AdfBlock::Paragraph { content, .. } = &parsed.content[0] else {
            panic!("expected a paragraph");
        };
        let AdfInline::Text { text, marks, .. } = &content[0] else {
            panic!("an unmodelled mark must not demote its text node to Unknown");
        };
        assert_eq!(text, "coloured");
        assert_eq!(marks[0], AdfMark::Strong);
        assert!(matches!(marks[1], AdfMark::Unknown(_)));
    }

    #[test]
    fn malformed_known_node_degrades_to_unknown_rather_than_failing_the_parse() {
        // A heading with no level cannot be modelled, and erroring would make a
        // single damaged node fail the whole read.
        let parsed = round_trip(&doc_with(&json!([{"type": "heading", "attrs": {}}])));
        assert!(matches!(parsed.content[0], AdfBlock::Unknown(_)));
    }

    #[test]
    fn a_list_child_that_is_not_a_list_item_demotes_the_list_rather_than_being_rewritten() {
        // Without `AdfListItemType` this would parse as a `listItem` and be
        // re-emitted as one, silently changing the node's type.
        let parsed = round_trip(&doc_with(&json!([{
            "type": "bulletList",
            "content": [{"type": "taskItem", "content": []}]
        }])));
        assert!(matches!(parsed.content[0], AdfBlock::Unknown(_)));
    }

    #[test]
    fn a_node_that_is_not_an_object_is_preserved_rather_than_rejected() {
        let parsed = round_trip(&doc_with(&json!(["stray string"])));
        assert!(matches!(parsed.content[0], AdfBlock::Unknown(_)));
    }

    // --- Unmodelled keys on modelled nodes. ---

    #[test]
    fn an_unmodelled_key_on_a_modelled_node_survives_the_round_trip() {
        // The read-modify-write case an `Unknown` variant does nothing for: the
        // node types here are all modelled, so nothing degrades, and every key
        // below would be dropped by a model that only kept the fields it knows.
        let raw = json!({
            "type": "doc", "version": 1, "schema": "unreleased",
            "content": [
                {"type": "paragraph", "attrs": {"localId": "p-1"},
                 "content": [
                     {"type": "text", "text": "advisory", "annotationId": "a-1",
                      "marks": [{"type": "link", "attrs": {
                          "href": "https://example.test/a",
                          "id": "smart-1", "collection": "c", "occurrenceKey": "k-1"
                      }, "supported": true}]}
                 ]},
                {"type": "heading", "attrs": {"level": 2, "localId": "h-1"},
                 "content": [{"type": "text", "text": "Impact"}]},
                {"type": "orderedList", "attrs": {"order": 3, "localId": "ol-1"},
                 "content": [{"type": "listItem", "localId": "li-1", "content": [
                     {"type": "paragraph", "content": [{"type": "text", "text": "step"}]}
                 ]}]},
                {"type": "codeBlock", "attrs": {"language": "rust", "uniqueId": "cb-1"},
                 "content": [{"type": "text", "text": "fn main() {}"}]},
                {"type": "blockquote", "localId": "bq-1", "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": "quoted"}]}
                ]},
                {"type": "bulletList", "localId": "ul-1", "content": [
                    {"type": "listItem", "content": [
                        {"type": "paragraph", "content": [{"type": "text", "text": "item"}]}
                    ]}
                ]}
            ]
        })
        .to_string();

        let parsed = round_trip(&raw);

        assert_eq!(
            parsed.other["schema"],
            json!("unreleased"),
            "an unmodelled key on the root was dropped"
        );

        let AdfBlock::Paragraph { content, other } = &parsed.content[0] else {
            panic!("an unmodelled key must not demote a paragraph to Unknown");
        };
        assert_eq!(other["attrs"], json!({"localId": "p-1"}));

        let AdfInline::Text { marks, other, .. } = &content[0] else {
            panic!("an unmodelled key must not demote a text node");
        };
        assert_eq!(other["annotationId"], json!("a-1"));
        let AdfMark::Link { attrs, other } = &marks[0] else {
            panic!("an unmodelled key must not demote a link mark");
        };
        assert_eq!(attrs.href, "https://example.test/a");
        assert_eq!(attrs.other["occurrenceKey"], json!("k-1"));
        assert_eq!(other["supported"], json!(true));

        let AdfBlock::Heading { attrs, .. } = &parsed.content[1] else {
            panic!("expected a heading");
        };
        assert_eq!(attrs.level, 2);
        assert_eq!(attrs.other["localId"], json!("h-1"));

        let AdfBlock::OrderedList { attrs, content, .. } = &parsed.content[2] else {
            panic!("expected an ordered list");
        };
        assert_eq!(attrs.as_ref().expect("attrs are present").order, Some(3));
        assert_eq!(
            attrs.as_ref().expect("attrs are present").other["localId"],
            json!("ol-1")
        );
        assert_eq!(content[0].other["localId"], json!("li-1"));

        let AdfBlock::CodeBlock { attrs, .. } = &parsed.content[3] else {
            panic!("expected a code block");
        };
        assert_eq!(
            attrs.as_ref().expect("attrs are present").other["uniqueId"],
            json!("cb-1")
        );

        let AdfBlock::Blockquote { other, .. } = &parsed.content[4] else {
            panic!("expected a blockquote");
        };
        assert_eq!(other["localId"], json!("bq-1"));

        let AdfBlock::BulletList { other, .. } = &parsed.content[5] else {
            panic!("expected a bullet list");
        };
        assert_eq!(other["localId"], json!("ul-1"));
    }

    #[test]
    fn a_modelled_node_with_no_unmodelled_keys_carries_an_empty_map() {
        // The map must not put anything on the wire of its own, or every
        // constructed document would gain a key.
        let doc = AdfDocument::new([AdfBlock::paragraph_text("hello")]);
        assert!(doc.other.is_empty());
        assert_eq!(
            serde_json::to_value(&doc).expect("serializes"),
            json!({"type": "doc", "version": 1, "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": "hello"}]}
            ]})
        );
    }

    #[test]
    fn the_attribute_free_nodes_stay_unit_variants() {
        // The documented exception: ADF gives `rule`, `hardBreak` and the five
        // formatting marks no attributes, so they carry no map and a key that
        // turns up on one is dropped rather than kept.
        let raw = doc_with(&json!([
            {"type": "rule", "attrs": {"localId": "r-1"}},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "a", "marks": [{"type": "strong", "attrs": {"x": 1}}]}
            ]}
        ]));
        let parsed: AdfDocument = serde_json::from_str(&raw).expect("parses");

        assert_eq!(
            serde_json::to_value(&parsed).expect("serializes"),
            json!({"type": "doc", "version": 1, "content": [
                {"type": "rule"},
                {"type": "paragraph", "content": [
                    {"type": "text", "text": "a", "marks": [{"type": "strong"}]}
                ]}
            ]})
        );
    }

    // --- The three documented normalizations. ---

    #[test]
    fn an_empty_paragraph_round_trips_in_jiras_bare_form() {
        let parsed = round_trip(&doc_with(&json!([{"type": "paragraph"}])));
        assert_eq!(parsed.content, vec![AdfBlock::empty_paragraph()]);
    }

    #[test]
    fn an_explicit_empty_content_array_normalizes_to_the_bare_form() {
        let raw = doc_with(&json!([{"type": "paragraph", "content": []}]));
        let parsed: AdfDocument = serde_json::from_str(&raw).expect("parses");
        assert_eq!(
            serde_json::to_value(&parsed).expect("serializes"),
            json!({"type": "doc", "version": 1, "content": [{"type": "paragraph"}]})
        );
    }

    #[test]
    fn an_explicit_empty_marks_array_normalizes_away() {
        let raw = doc_with(&json!([{
            "type": "paragraph",
            "content": [{"type": "text", "text": "a", "marks": []}]
        }]));
        let parsed: AdfDocument = serde_json::from_str(&raw).expect("parses");
        assert_eq!(
            serde_json::to_value(&parsed).expect("serializes"),
            json!({"type": "doc", "version": 1, "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": "a"}]}
            ]})
        );
    }

    #[test]
    fn hard_break_attrs_are_dropped_and_the_node_stays_modelled() {
        let raw = doc_with(&json!([{
            "type": "paragraph",
            "content": [{"type": "hardBreak", "attrs": {"text": "\n"}}]
        }]));
        let parsed: AdfDocument = serde_json::from_str(&raw).expect("parses");
        assert_eq!(
            serde_json::to_value(&parsed).expect("serializes"),
            json!({"type": "doc", "version": 1, "content": [
                {"type": "paragraph", "content": [{"type": "hardBreak"}]}
            ]})
        );
    }

    // --- Constructors. ---

    #[test]
    fn constructors_emit_the_documented_wire_form() {
        let doc = AdfDocument::new([
            AdfBlock::heading_text(1, "Title"),
            AdfBlock::empty_paragraph(),
            AdfBlock::rule(),
            AdfBlock::ordered_list([AdfListItem::text("step")]),
            AdfBlock::blockquote([AdfBlock::paragraph_text("quoted")]),
        ]);
        assert_eq!(
            serde_json::to_value(&doc).expect("serializes"),
            json!({"type": "doc", "version": 1, "content": [
                {"type": "heading", "attrs": {"level": 1},
                 "content": [{"type": "text", "text": "Title"}]},
                {"type": "paragraph"},
                {"type": "rule"},
                {"type": "orderedList", "content": [{"type": "listItem", "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": "step"}]}
                ]}]},
                {"type": "blockquote", "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": "quoted"}]}
                ]}
            ]})
        );
    }

    #[test]
    fn an_empty_code_block_holds_no_text_node() {
        // An empty `text` node is invalid ADF, so an empty code block has no
        // children at all.
        assert_eq!(
            serde_json::to_value(AdfBlock::code_block("")).expect("serializes"),
            json!({"type": "codeBlock"})
        );
    }

    #[test]
    fn document_defaults_and_helpers() {
        let empty = AdfDocument::default();
        assert_eq!(empty, AdfDocument::empty());
        assert!(empty.is_empty());

        let one = empty.with_block(AdfBlock::paragraph_text("x"));
        assert!(!one.is_empty());
        assert_eq!(one.content.len(), 1);
    }

    #[test]
    fn the_model_produces_a_json_schema() {
        // `types.rs` derives `JsonSchema` on every model type and consumers rely on
        // it; the recursive `blockquote` variant is the part that could regress.
        let schema = serde_json::to_value(schemars::schema_for!(AdfDocument)).expect("serializes");
        assert!(schema.get("$defs").is_some(), "schema has no definitions");
    }

    #[test]
    fn the_unit_marks_serialize_as_bare_tags() {
        for (mark, tag) in [
            (AdfMark::Strong, "strong"),
            (AdfMark::Em, "em"),
            (AdfMark::Code, "code"),
            (AdfMark::Strike, "strike"),
            (AdfMark::Underline, "underline"),
        ] {
            assert_eq!(
                serde_json::to_value(&mark).expect("serializes"),
                json!({ "type": tag })
            );
            assert_eq!(
                serde_json::from_value::<AdfMark>(json!({ "type": tag })).expect("parses"),
                mark
            );
        }
    }
}
