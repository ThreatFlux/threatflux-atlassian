//! Typed Atlassian Document Format (ADF).
//!
//! Jira Cloud's v3 API carries every rich-text field -- issue descriptions,
//! comment bodies -- as ADF rather than as a string. ADF is deeply nested,
//! internally tagged JSON: every node is an object with a `type`, and depending
//! on that type an optional `content` array, an `attrs` object, and a `marks`
//! array.
//!
//! ```json
//! {
//!   "type": "doc",
//!   "version": 1,
//!   "content": [
//!     {
//!       "type": "paragraph",
//!       "content": [
//!         {"type": "text", "text": "see "},
//!         {"type": "text", "text": "the advisory",
//!          "marks": [{"type": "link", "attrs": {"href": "https://example.test/a"}}]}
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! # The model
//!
//! [`AdfDocument`] is the root. Its children are [`AdfBlock`]s; a block's inline
//! children are [`AdfInline`]s; a list's children are [`AdfListItem`]s; a text
//! run's formatting is a list of [`AdfMark`]s. Splitting the enums by ADF's own
//! block/inline content categories -- rather than modelling one flat `Node` type
//! -- is what makes an invalid tree unrepresentable: a `hardBreak` cannot appear
//! at document top level and a `paragraph` cannot appear inside a `paragraph`,
//! because neither type-checks.
//!
//! Construct documents with the node constructors or with
//! [`AdfDocumentBuilder`]:
//!
//! ```
//! use threatflux_atlassian_sdk::adf::{AdfBlock, AdfDocument, AdfInline};
//! use serde_json::json;
//!
//! let doc = AdfDocument::new([AdfBlock::paragraph([
//!     AdfInline::text("first line"),
//!     AdfInline::hard_break(),
//!     AdfInline::text("second line"),
//! ])]);
//!
//! doc.validate()?;
//! assert_eq!(
//!     serde_json::to_value(&doc)?,
//!     json!({
//!         "type": "doc",
//!         "version": 1,
//!         "content": [{
//!             "type": "paragraph",
//!             "content": [
//!                 {"type": "text", "text": "first line"},
//!                 {"type": "hardBreak"},
//!                 {"type": "text", "text": "second line"}
//!             ]
//!         }]
//!     })
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Unmodelled nodes survive a round trip
//!
//! This crate models the node types its own write paths emit. Human-edited Jira
//! descriptions contain many more: `table`, `panel`, `mediaSingle`, `expand`,
//! `mention`, `inlineCard`, and whatever Atlassian ships next. A closed enum
//! would fail those reads outright (`unknown variant`), and a
//! `#[serde(other)]`-style catch-all would parse them and then re-serialize them
//! as something else, quietly destroying a table on the first read-modify-write.
//!
//! So each enum ends in an `Unknown` variant holding the raw
//! [`serde_json::Value`], reached through an untagged fallback that serde tries
//! only after every modelled variant has failed. An unmodelled node is preserved
//! byte-for-byte and re-emitted exactly as it arrived:
//!
//! ```
//! use threatflux_atlassian_sdk::adf::AdfDocument;
//!
//! let raw = r#"{"type":"doc","version":1,"content":[
//!     {"type":"paragraph","content":[{"type":"text","text":"before"}]},
//!     {"type":"mediaSingle","attrs":{"layout":"center"},"content":[
//!         {"type":"media","attrs":{"id":"abc","type":"file","collection":"c"}}
//!     ]}
//! ]}"#;
//!
//! let original: serde_json::Value = serde_json::from_str(raw)?;
//! let parsed: AdfDocument = serde_json::from_value(original.clone())?;
//! assert_eq!(serde_json::to_value(&parsed)?, original);
//! # Ok::<(), serde_json::Error>(())
//! ```
//!
//! The same fallback also catches a *malformed* known node -- a `heading` whose
//! `attrs` carry no `level` degrades to `Unknown` instead of failing the parse.
//! That is the deliberate cost of read tolerance, and it is why
//! [`AdfDocument::validate`] rejects `Unknown` on every write path: a document
//! that came in damaged must not go back out as a request body.
//!
//! # Unmodelled keys survive too
//!
//! An `Unknown` variant makes a whole unmodelled *node type* lossless. It does
//! nothing for an unmodelled *key* on a node type this crate does model, and
//! that is the case a read-modify-write actually hits: parse an issue's
//! description, change one paragraph, write it back, and any attribute this
//! crate has no field for would be gone -- silently, because
//! [`AdfDocument::validate`], the gate that keeps read tolerances out of request
//! bodies, sees a perfectly ordinary paragraph and passes it.
//!
//! So every modelled node ADF gives attributes to also carries an
//! [`AdfExtraKeys`] map, flattened into the node, holding whatever this crate
//! had no field for. Those keys go back out exactly as they came in:
//!
//! ```
//! use threatflux_atlassian_sdk::adf::AdfDocument;
//!
//! // `localId` on the paragraph and `occurrenceKey` on the link mark are keys
//! // this crate does not model, on nodes it does.
//! let raw = r#"{"type":"doc","version":1,"content":[
//!     {"type":"paragraph","attrs":{"localId":"p-1"},"content":[
//!         {"type":"text","text":"advisory","marks":[
//!             {"type":"link","attrs":{"href":"https://example.test/a",
//!                                     "occurrenceKey":"k-1"}}
//!         ]}
//!     ]}
//! ]}"#;
//!
//! let original: serde_json::Value = serde_json::from_str(raw)?;
//! let parsed: AdfDocument = serde_json::from_value(original.clone())?;
//! assert_eq!(serde_json::to_value(&parsed)?, original);
//! # Ok::<(), serde_json::Error>(())
//! ```
//!
//! The exceptions are the nodes ADF defines with no attributes at all --
//! [`Rule`](AdfBlock::Rule), [`HardBreak`](AdfInline::HardBreak) and the five
//! formatting marks [`Strong`](AdfMark::Strong), [`Em`](AdfMark::Em),
//! [`Code`](AdfMark::Code), [`Strike`](AdfMark::Strike) and
//! [`Underline`](AdfMark::Underline). They stay unit variants, so a key that
//! turns up on one of them is dropped. Nothing in the published schema can put
//! one there, and making them struct variants would cost every caller of
//! `AdfMark::Strong` a field it can never use.
//!
//! Writes stay strict about the map: [`AdfDocument::validate`] refuses one
//! holding a key its own node writes, which a parse can never produce and a
//! hand-assembled document could use to overwrite a node's `type`.
//!
//! # What is and is not preserved exactly
//!
//! `to_value(from_value(x)) == x` holds for every document in the shape Jira
//! emits. Three normalizations apply to shapes Jira does not emit, all of them
//! semantics-preserving:
//!
//! | Input | Re-emitted as | Why |
//! |---|---|---|
//! | `{"type":"paragraph","content":[]}` | `{"type":"paragraph"}` | An absent `content` and an empty one mean the same empty paragraph; the bare form is Jira's own. |
//! | `{"type":"text","text":"a","marks":[]}` | `{"type":"text","text":"a"}` | Same, for an unmarked run. |
//! | `{"type":"hardBreak","attrs":{"text":"\n"}}` | `{"type":"hardBreak"}` | [`AdfInline::HardBreak`] is a unit variant; the schema fixes those `attrs` to that one literal, so nothing is lost but the keystrokes. |
//!
//! # Reads are tolerant, writes are strict
//!
//! Deserialization accepts whatever Atlassian sends. [`AdfDocument::validate`]
//! is the gate that keeps those tolerances out of request bodies, and it is
//! applied on every v3 write. Its exact contract -- including what it
//! deliberately does not check -- is on the method.
//!
//! # Not provided
//!
//! There is no ADF-to-plain-text conversion. Providing one would re-create the
//! plain-text fallback that typed ADF exists to eliminate: a caller reaching for
//! it on a write path would silently flatten every table, link and code block in
//! the document.

mod builder;
mod node;
mod rich_text;
mod text;
mod validate;

pub use builder::AdfDocumentBuilder;
pub use node::{
    AdfBlock, AdfCodeBlockAttrs, AdfDocType, AdfDocument, AdfExtraKeys, AdfHeadingAttrs, AdfInline,
    AdfLinkAttrs, AdfListItem, AdfListItemType, AdfMark, AdfOrderedListAttrs, ADF_VERSION,
};
pub use rich_text::RichText;
pub use text::{
    text_to_adf, text_to_adf_bounded, AdfLimits, DEFAULT_MAX_CHARS, DEFAULT_MAX_NODES,
    TRUNCATION_MARKER,
};
pub use validate::{AdfValidationError, MAX_NESTING_DEPTH};
