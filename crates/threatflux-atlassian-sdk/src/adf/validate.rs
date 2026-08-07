//! The write-path gate: [`AdfDocument::validate`] and [`AdfValidationError`].
//!
//! Reads are tolerant and writes are strict. Deserialization accepts anything
//! Atlassian might send, degrading what it cannot model to an `Unknown`
//! fallback; `validate` is what stops those tolerances from reaching a Jira
//! request body. See the [module documentation](super) for the full contract.

use std::fmt::Write as _;

use super::node::{
    AdfBlock, AdfDocument, AdfExtraKeys, AdfInline, AdfListItem, AdfMark, ADF_VERSION,
};
use crate::error::AtlassianError;

/// Deepest block nesting [`AdfDocument::validate`] accepts.
///
/// Bounds the validator's own recursion, so a document assembled in a loop
/// cannot turn the write-path gate into a stack overflow. Documents read off the
/// wire are already bounded by `serde_json`'s recursion limit; documents built
/// through this crate's constructors are not bounded by anything else. Real
/// descriptions nest three or four levels deep, so the limit is not reachable by
/// accident.
pub const MAX_NESTING_DEPTH: usize = 32;

/// Highest legal `heading` level.
const MAX_HEADING_LEVEL: u8 = 6;

/// Keys the root node writes for itself.
const DOC_OWN_KEYS: &[&str] = &["type", "version", "content"];

/// Keys a node with children but no modelled `attrs` writes for itself.
const CONTENT_OWN_KEYS: &[&str] = &["type", "content"];

/// Keys a node with both children and modelled `attrs` writes for itself.
const ATTRS_AND_CONTENT_OWN_KEYS: &[&str] = &["type", "attrs", "content"];

/// Keys a `text` node writes for itself.
const TEXT_OWN_KEYS: &[&str] = &["type", "text", "marks"];

/// Keys a `link` mark writes for itself.
const LINK_OWN_KEYS: &[&str] = &["type", "attrs"];

/// Attributes a `heading`'s `attrs` object writes for itself.
const HEADING_ATTRS_OWN_KEYS: &[&str] = &["level"];

/// Attributes an `orderedList`'s `attrs` object writes for itself.
const ORDERED_LIST_ATTRS_OWN_KEYS: &[&str] = &["order"];

/// Attributes a `codeBlock`'s `attrs` object writes for itself.
const CODE_BLOCK_ATTRS_OWN_KEYS: &[&str] = &["language"];

/// Attributes a `link` mark's `attrs` object writes for itself.
const LINK_ATTRS_OWN_KEYS: &[&str] = &["href", "title"];

/// Why an [`AdfDocument`] cannot be written to Jira.
///
/// Every variant carries a `path` locating the offending node -- `doc`,
/// `doc.content[0]`, `doc.content[0].content[2].marks[0]`. The path is built
/// from structural indices and this crate's own node names only: no text, href,
/// or other caller-supplied value ever reaches the message, which keeps the
/// error safe to log in full.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AdfValidationError {
    /// A node, inline node, or mark this crate does not model.
    ///
    /// Unmodelled nodes exist so reads round-trip losslessly. Emitting one would
    /// mean serializing an arbitrary `serde_json::Value` into a request body, so
    /// the write path refuses.
    #[error("ADF node at {path} is not modelled by this crate and cannot be written")]
    UnknownNode {
        /// Location of the node within the document.
        path: String,
    },

    /// The document declared a schema version other than [`ADF_VERSION`].
    #[error("ADF document declares version {version}, expected {ADF_VERSION}")]
    UnsupportedVersion {
        /// The version the document declared.
        version: u32,
    },

    /// A `text` node held the empty string, which ADF forbids.
    #[error("ADF text node at {path} is empty")]
    EmptyText {
        /// Location of the node within the document.
        path: String,
    },

    /// A `heading` declared a level outside 1..=6.
    #[error("ADF heading at {path} has level {level}, expected 1..={MAX_HEADING_LEVEL}")]
    InvalidHeadingLevel {
        /// The level the heading declared.
        level: u8,
        /// Location of the node within the document.
        path: String,
    },

    /// A node ADF requires to have children had none.
    #[error("ADF {node} at {path} has no content")]
    EmptyContent {
        /// The node type that was empty.
        node: &'static str,
        /// Location of the node within the document.
        path: String,
    },

    /// A node held a child ADF does not allow there.
    #[error("ADF {parent} at {path} cannot contain a {child} node")]
    DisallowedChild {
        /// The containing node type.
        parent: &'static str,
        /// The child node type that is not allowed in it.
        child: &'static str,
        /// Location of the child within the document.
        path: String,
    },

    /// A marked run appeared where ADF does not allow marks.
    #[error("ADF text inside a {parent} at {path} cannot carry marks")]
    DisallowedMark {
        /// The containing node type.
        parent: &'static str,
        /// Location of the marked text within the document.
        path: String,
    },

    /// A `link` mark had a blank `href`.
    #[error("ADF link mark at {path} has an empty href")]
    EmptyLinkHref {
        /// Location of the mark within the document.
        path: String,
    },

    /// An [`AdfExtraKeys`] map held a key the node writes for itself.
    ///
    /// [`AdfExtraKeys`] carries the keys this crate has no field for, so that an
    /// attribute it does not model survives a read-modify-write. A key it *does*
    /// write cannot survive there: both copies go into the same JSON object and
    /// the one from the map is written last, so a hand-assembled document could
    /// overwrite a node's own `type` or `content` and put JSON structure on the
    /// wire that no constructor in this crate can build -- the injection
    /// primitive [`UnknownNode`](Self::UnknownNode) exists to refuse.
    ///
    /// A parse never produces one, because a modelled key is taken by its field
    /// before the map sees it. This fires on a document assembled in code.
    #[error("ADF node at {path} carries `{key}`, which that node writes for itself")]
    ReservedExtraKey {
        /// The offending key, from this crate's own fixed list of the names a
        /// node writes. Never a caller-supplied string.
        key: &'static str,
        /// Location of the node within the document.
        path: String,
    },

    /// Block nesting exceeded [`MAX_NESTING_DEPTH`].
    #[error("ADF node at {path} nests deeper than {max_depth} levels")]
    TooDeep {
        /// The limit that was exceeded.
        max_depth: usize,
        /// Location of the node within the document.
        path: String,
    },
}

impl From<AdfValidationError> for AtlassianError {
    /// A structurally invalid document is a validation failure, and the message
    /// already carries everything a caller could branch on. Mirrors
    /// [`JqlError`](crate::jql::JqlError).
    fn from(err: AdfValidationError) -> Self {
        Self::validation(err.to_string())
    }
}

impl AdfDocument {
    /// Checks that this document can be written to Jira.
    ///
    /// This is the gate every v3 write applies. It rejects, and nothing else:
    ///
    /// | Rejected | Error |
    /// |---|---|
    /// | any `Unknown` block, inline node or mark | [`UnknownNode`](AdfValidationError::UnknownNode) |
    /// | `version` other than [`ADF_VERSION`] | [`UnsupportedVersion`](AdfValidationError::UnsupportedVersion) |
    /// | an empty `text` node | [`EmptyText`](AdfValidationError::EmptyText) |
    /// | a `heading` level outside 1..=6 | [`InvalidHeadingLevel`](AdfValidationError::InvalidHeadingLevel) |
    /// | a `bulletList`/`orderedList` with no items, or a `listItem` with no content | [`EmptyContent`](AdfValidationError::EmptyContent) |
    /// | a `hardBreak` or a non-`text` node inside a `codeBlock`, or a `blockquote` inside a `blockquote` | [`DisallowedChild`](AdfValidationError::DisallowedChild) |
    /// | a marked `text` node inside a `codeBlock` | [`DisallowedMark`](AdfValidationError::DisallowedMark) |
    /// | a `link` mark whose `href` is blank | [`EmptyLinkHref`](AdfValidationError::EmptyLinkHref) |
    /// | an [`AdfExtraKeys`] map holding a key its node writes for itself | [`ReservedExtraKey`](AdfValidationError::ReservedExtraKey) |
    /// | block nesting past [`MAX_NESTING_DEPTH`] | [`TooDeep`](AdfValidationError::TooDeep) |
    ///
    /// Deliberately **not** checked, each because the check belongs somewhere
    /// else or would be wrong here:
    ///
    /// - **Emptiness of the document.** `{"type":"doc","version":1,"content":[]}`
    ///   is legal ADF and is how a description is cleared. A caller that means
    ///   "no description" sends `None`, which is a decision above this layer.
    /// - **Size.** Jira caps a description at roughly 32,767 characters and ADF
    ///   costs tens of bytes per line on top of the text. Bounding output is the
    ///   text-to-ADF conversion's job, where the limits are configurable and the
    ///   truncation can land on a character boundary.
    /// - **Control characters in text.** Stripping or rejecting them belongs to
    ///   the conversion that produces the text, not to a check that would have
    ///   to reject documents Jira itself would accept.
    /// - **URL schemes on a `link` mark.** `mailto:`, `tel:` and Atlassian's own
    ///   smart-link schemes are all legitimate, Jira sanitizes at render time,
    ///   and a scheme allowlist here would break valid documents while a
    ///   denylist would give false assurance.
    /// - **The ordering rule for `listItem` children.** ADF wants the first child
    ///   to be a `paragraph`, `codeBlock` or `mediaSingle`; that rule is not
    ///   reproduced here because getting it subtly wrong would reject documents
    ///   Jira accepts.
    /// - **The *contents* of an [`AdfExtraKeys`] map.** Only a collision with a
    ///   key the node writes itself is refused. What is left is by construction
    ///   an attribute Jira sent on that node, and refusing it would be refusing
    ///   the read-modify-write the map exists to make lossless.
    ///
    /// The first failure found wins; validation is a gate, not a report.
    ///
    /// ```
    /// use threatflux_atlassian_sdk::adf::{AdfBlock, AdfDocument, AdfValidationError};
    ///
    /// let good = AdfDocument::new([AdfBlock::paragraph_text("ready")]);
    /// assert!(good.validate().is_ok());
    ///
    /// let unmodelled: AdfDocument =
    ///     serde_json::from_str(r#"{"type":"doc","version":1,"content":[{"type":"table"}]}"#)?;
    /// assert!(matches!(
    ///     unmodelled.validate(),
    ///     Err(AdfValidationError::UnknownNode { .. })
    /// ));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns the first [`AdfValidationError`] found, per the table above.
    pub fn validate(&self) -> Result<(), AdfValidationError> {
        if self.version != ADF_VERSION {
            return Err(AdfValidationError::UnsupportedVersion {
                version: self.version,
            });
        }

        let mut path = PathStack::new();
        check_extra_keys(&self.other, DOC_OWN_KEYS, &path)?;
        validate_blocks(&self.content, &mut path, 1)
    }
}

/// One step of a node's location within a document.
#[derive(Debug, Clone, Copy)]
enum Segment {
    /// An index into a `content` array.
    Content(usize),
    /// An index into a `marks` array.
    Marks(usize),
    /// The node's `attrs` object.
    Attrs,
}

/// The path to the node currently being validated.
///
/// Kept as a stack and rendered only when an error is raised, so the common case
/// allocates one `Vec` for the whole walk.
struct PathStack(Vec<Segment>);

impl PathStack {
    const fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, segment: Segment) {
        self.0.push(segment);
    }

    fn pop(&mut self) {
        self.0.pop();
    }

    /// Renders the current location, for example `doc.content[0].marks[1]`.
    fn render(&self) -> String {
        let mut out = String::from("doc");
        for segment in &self.0 {
            let (field, index) = match *segment {
                Segment::Content(index) => ("content", index),
                Segment::Marks(index) => ("marks", index),
                Segment::Attrs => {
                    // Writing into a String cannot fail.
                    let _ = write!(out, ".attrs");
                    continue;
                }
            };
            // Writing into a String cannot fail.
            let _ = write!(out, ".{field}[{index}]");
        }
        out
    }
}

/// Refuses an [`AdfExtraKeys`] map holding a key the node writes for itself.
///
/// `reserved` is always one of this module's own constants, so the `key` in the
/// error is a fixed string and never a name that came in from outside.
fn check_extra_keys(
    other: &AdfExtraKeys,
    reserved: &[&'static str],
    path: &PathStack,
) -> Result<(), AdfValidationError> {
    if other.is_empty() {
        return Ok(());
    }

    reserved
        .iter()
        .copied()
        .find(|key| other.contains_key(*key))
        .map_or(Ok(()), |key| {
            Err(AdfValidationError::ReservedExtraKey {
                key,
                path: path.render(),
            })
        })
}

/// The same check applied to a node's `attrs` object, one path segment down.
fn check_attrs_extra_keys(
    other: &AdfExtraKeys,
    reserved: &[&'static str],
    path: &mut PathStack,
) -> Result<(), AdfValidationError> {
    path.push(Segment::Attrs);
    let outcome = check_extra_keys(other, reserved, path);
    path.pop();
    outcome
}

fn validate_blocks(
    blocks: &[AdfBlock],
    path: &mut PathStack,
    depth: usize,
) -> Result<(), AdfValidationError> {
    for (index, block) in blocks.iter().enumerate() {
        path.push(Segment::Content(index));
        validate_block(block, path, depth)?;
        path.pop();
    }
    Ok(())
}

fn validate_block(
    block: &AdfBlock,
    path: &mut PathStack,
    depth: usize,
) -> Result<(), AdfValidationError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(AdfValidationError::TooDeep {
            max_depth: MAX_NESTING_DEPTH,
            path: path.render(),
        });
    }

    match block {
        AdfBlock::Paragraph { content, other } => {
            check_extra_keys(other, CONTENT_OWN_KEYS, path)?;
            validate_inlines(content, path)
        }
        AdfBlock::Heading {
            attrs,
            content,
            other,
        } => {
            check_extra_keys(other, ATTRS_AND_CONTENT_OWN_KEYS, path)?;
            check_attrs_extra_keys(&attrs.other, HEADING_ATTRS_OWN_KEYS, path)?;
            if attrs.level == 0 || attrs.level > MAX_HEADING_LEVEL {
                return Err(AdfValidationError::InvalidHeadingLevel {
                    level: attrs.level,
                    path: path.render(),
                });
            }
            validate_inlines(content, path)
        }
        AdfBlock::BulletList { content, other } => {
            check_extra_keys(other, CONTENT_OWN_KEYS, path)?;
            validate_list(content, path, depth, "bulletList")
        }
        AdfBlock::OrderedList {
            attrs,
            content,
            other,
        } => {
            check_extra_keys(other, ATTRS_AND_CONTENT_OWN_KEYS, path)?;
            if let Some(attrs) = attrs {
                check_attrs_extra_keys(&attrs.other, ORDERED_LIST_ATTRS_OWN_KEYS, path)?;
            }
            validate_list(content, path, depth, "orderedList")
        }
        AdfBlock::CodeBlock {
            attrs,
            content,
            other,
        } => {
            check_extra_keys(other, ATTRS_AND_CONTENT_OWN_KEYS, path)?;
            if let Some(attrs) = attrs {
                check_attrs_extra_keys(&attrs.other, CODE_BLOCK_ATTRS_OWN_KEYS, path)?;
            }
            validate_code_block(content, path)
        }
        AdfBlock::Blockquote { content, other } => {
            check_extra_keys(other, CONTENT_OWN_KEYS, path)?;
            validate_blockquote(content, path, depth)
        }
        AdfBlock::Rule => Ok(()),
        AdfBlock::Unknown(_) => Err(AdfValidationError::UnknownNode {
            path: path.render(),
        }),
    }
}

fn validate_blockquote(
    content: &[AdfBlock],
    path: &mut PathStack,
    depth: usize,
) -> Result<(), AdfValidationError> {
    for (index, child) in content.iter().enumerate() {
        path.push(Segment::Content(index));
        if matches!(child, AdfBlock::Blockquote { .. }) {
            return Err(AdfValidationError::DisallowedChild {
                parent: "blockquote",
                child: "blockquote",
                path: path.render(),
            });
        }
        validate_block(child, path, depth + 1)?;
        path.pop();
    }
    Ok(())
}

fn validate_list(
    items: &[AdfListItem],
    path: &mut PathStack,
    depth: usize,
    node: &'static str,
) -> Result<(), AdfValidationError> {
    if items.is_empty() {
        return Err(AdfValidationError::EmptyContent {
            node,
            path: path.render(),
        });
    }

    for (index, item) in items.iter().enumerate() {
        path.push(Segment::Content(index));
        check_extra_keys(&item.other, CONTENT_OWN_KEYS, path)?;
        if item.content.is_empty() {
            return Err(AdfValidationError::EmptyContent {
                node: "listItem",
                path: path.render(),
            });
        }
        validate_blocks(&item.content, path, depth + 2)?;
        path.pop();
    }
    Ok(())
}

fn validate_code_block(
    content: &[AdfInline],
    path: &mut PathStack,
) -> Result<(), AdfValidationError> {
    for (index, inline) in content.iter().enumerate() {
        path.push(Segment::Content(index));
        match inline {
            AdfInline::Text { text, marks, other } => {
                check_extra_keys(other, TEXT_OWN_KEYS, path)?;
                if text.is_empty() {
                    return Err(AdfValidationError::EmptyText {
                        path: path.render(),
                    });
                }
                if !marks.is_empty() {
                    return Err(AdfValidationError::DisallowedMark {
                        parent: "codeBlock",
                        path: path.render(),
                    });
                }
            }
            AdfInline::HardBreak => {
                return Err(AdfValidationError::DisallowedChild {
                    parent: "codeBlock",
                    child: "hardBreak",
                    path: path.render(),
                });
            }
            AdfInline::Unknown(_) => {
                return Err(AdfValidationError::UnknownNode {
                    path: path.render(),
                });
            }
        }
        path.pop();
    }
    Ok(())
}

fn validate_inlines(content: &[AdfInline], path: &mut PathStack) -> Result<(), AdfValidationError> {
    for (index, inline) in content.iter().enumerate() {
        path.push(Segment::Content(index));
        match inline {
            AdfInline::Text { text, marks, other } => {
                check_extra_keys(other, TEXT_OWN_KEYS, path)?;
                if text.is_empty() {
                    return Err(AdfValidationError::EmptyText {
                        path: path.render(),
                    });
                }
                validate_marks(marks, path)?;
            }
            AdfInline::HardBreak => {}
            AdfInline::Unknown(_) => {
                return Err(AdfValidationError::UnknownNode {
                    path: path.render(),
                });
            }
        }
        path.pop();
    }
    Ok(())
}

fn validate_marks(marks: &[AdfMark], path: &mut PathStack) -> Result<(), AdfValidationError> {
    for (index, mark) in marks.iter().enumerate() {
        path.push(Segment::Marks(index));
        match mark {
            AdfMark::Link { attrs, other } => {
                check_extra_keys(other, LINK_OWN_KEYS, path)?;
                check_attrs_extra_keys(&attrs.other, LINK_ATTRS_OWN_KEYS, path)?;
                if attrs.href.trim().is_empty() {
                    return Err(AdfValidationError::EmptyLinkHref {
                        path: path.render(),
                    });
                }
            }
            AdfMark::Strong
            | AdfMark::Em
            | AdfMark::Code
            | AdfMark::Strike
            | AdfMark::Underline => {}
            AdfMark::Unknown(_) => {
                return Err(AdfValidationError::UnknownNode {
                    path: path.render(),
                });
            }
        }
        path.pop();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adf::{AdfCodeBlockAttrs, AdfHeadingAttrs, AdfLinkAttrs, AdfListItemType};
    use serde_json::json;

    /// Parses `raw`, asserts it round-trips byte-for-byte, and returns it.
    ///
    /// The two halves of the unmodelled-key contract are a pair: capturing a key
    /// is worth nothing if it is not re-emitted, and re-emitting is worth nothing
    /// if the validator then refuses the document.
    fn round_trip(raw: &str) -> AdfDocument {
        let original: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let parsed: AdfDocument =
            serde_json::from_value(original.clone()).expect("fixture parses as a document");
        assert_eq!(
            serde_json::to_value(&parsed).expect("document serializes"),
            original,
            "round trip changed the document"
        );
        parsed
    }

    fn parse(raw: &str) -> AdfDocument {
        serde_json::from_str(raw).expect("fixture parses as a document")
    }

    fn error_of(document: &AdfDocument) -> AdfValidationError {
        document
            .validate()
            .expect_err("document should not have validated")
    }

    #[test]
    fn a_well_formed_document_validates() {
        let document = AdfDocument::new([
            AdfBlock::heading_text(1, "Title"),
            AdfBlock::paragraph([
                AdfInline::text("line one"),
                AdfInline::hard_break(),
                AdfInline::link("advisory", "https://example.test/a"),
            ]),
            AdfBlock::empty_paragraph(),
            AdfBlock::bullet_list([AdfListItem::text("item")]),
            AdfBlock::code_block_with_language("rust", "fn main() {}"),
            AdfBlock::blockquote([AdfBlock::paragraph_text("quoted")]),
            AdfBlock::rule(),
        ]);
        assert_eq!(document.validate(), Ok(()));
    }

    #[test]
    fn an_empty_document_validates() {
        // Deliberate: `{"type":"doc","version":1,"content":[]}` is how a
        // description is cleared. "No description at all" is `None`, decided a
        // layer up.
        assert_eq!(AdfDocument::empty().validate(), Ok(()));
    }

    #[test]
    fn an_unmodelled_block_is_rejected_with_its_path() {
        let document = parse(
            r#"{"type":"doc","version":1,"content":[
                {"type":"paragraph","content":[{"type":"text","text":"ok"}]},
                {"type":"table","content":[]}
            ]}"#,
        );
        assert_eq!(
            error_of(&document),
            AdfValidationError::UnknownNode {
                path: "doc.content[1]".to_string()
            }
        );
    }

    #[test]
    fn an_unmodelled_inline_is_rejected_with_its_path() {
        let document = parse(
            r#"{"type":"doc","version":1,"content":[{"type":"paragraph","content":[
                {"type":"text","text":"hi "},
                {"type":"mention","attrs":{"id":"557058:x"}}
            ]}]}"#,
        );
        assert_eq!(
            error_of(&document),
            AdfValidationError::UnknownNode {
                path: "doc.content[0].content[1]".to_string()
            }
        );
    }

    #[test]
    fn an_unmodelled_mark_is_rejected_with_its_path() {
        let document = parse(
            r##"{"type":"doc","version":1,"content":[{"type":"paragraph","content":[
                {"type":"text","text":"hi","marks":[
                    {"type":"strong"},
                    {"type":"textColor","attrs":{"color":"#ff5630"}}
                ]}
            ]}]}"##,
        );
        assert_eq!(
            error_of(&document),
            AdfValidationError::UnknownNode {
                path: "doc.content[0].content[0].marks[1]".to_string()
            }
        );
    }

    #[test]
    fn an_unmodelled_node_inside_a_list_item_is_rejected() {
        let document = parse(
            r#"{"type":"doc","version":1,"content":[{"type":"bulletList","content":[
                {"type":"listItem","content":[{"type":"mediaSingle","content":[]}]}
            ]}]}"#,
        );
        assert_eq!(
            error_of(&document),
            AdfValidationError::UnknownNode {
                path: "doc.content[0].content[0].content[0]".to_string()
            }
        );
    }

    #[test]
    fn a_document_carrying_unmodelled_keys_is_still_writable() {
        // The whole point of capturing them: a read-modify-write must go back out
        // with the keys it came in with, and the gate must not stand in the way.
        let document = round_trip(
            r#"{"type":"doc","version":1,"schema":"unreleased","content":[
                {"type":"paragraph","attrs":{"localId":"p-1"},"content":[
                    {"type":"text","text":"advisory","annotationId":"a-1","marks":[
                        {"type":"link","attrs":{"href":"https://example.test/a",
                                                "occurrenceKey":"k-1"}}
                    ]}
                ]},
                {"type":"heading","attrs":{"level":2,"localId":"h-1"},
                 "content":[{"type":"text","text":"Impact"}]},
                {"type":"bulletList","localId":"ul-1","content":[
                    {"type":"listItem","localId":"li-1","content":[
                        {"type":"paragraph","content":[{"type":"text","text":"x"}]}
                    ]}
                ]},
                {"type":"orderedList","attrs":{"order":2,"localId":"ol-1"},"content":[
                    {"type":"listItem","content":[
                        {"type":"paragraph","content":[{"type":"text","text":"y"}]}
                    ]}
                ]},
                {"type":"codeBlock","attrs":{"language":"rust","uniqueId":"cb-1"},
                 "content":[{"type":"text","text":"fn main() {}"}]},
                {"type":"blockquote","localId":"bq-1","content":[
                    {"type":"paragraph","content":[{"type":"text","text":"q"}]}
                ]}
            ]}"#,
        );
        assert_eq!(document.validate(), Ok(()));
    }

    #[test]
    fn an_unmodelled_key_that_collides_with_a_key_the_node_writes_is_rejected() {
        // The map is a public field, so a hand-assembled node could use it to
        // write a second `type` over the one the variant emits -- the forged-node
        // primitive `Unknown` is refused for. A parse cannot produce this: a
        // modelled key is taken by its field before the map sees it.
        let mut document = AdfDocument::new([AdfBlock::paragraph_text("ok")]);
        let AdfBlock::Paragraph { other, .. } = &mut document.content[0] else {
            panic!("expected a paragraph");
        };
        other.insert("type".to_string(), json!("table"));

        assert_eq!(
            error_of(&document),
            AdfValidationError::ReservedExtraKey {
                key: "type",
                path: "doc.content[0]".to_string()
            }
        );
    }

    #[test]
    fn a_reserved_key_is_refused_wherever_a_map_lives() {
        // Every site that carries a map is checked, including the two that sit one
        // level down inside an `attrs` object.
        let mut document = AdfDocument::new([]);
        document.other.insert("content".to_string(), json!([]));
        assert_eq!(
            error_of(&document),
            AdfValidationError::ReservedExtraKey {
                key: "content",
                path: "doc".to_string()
            }
        );

        let mut attrs = AdfHeadingAttrs::new(1);
        attrs.other.insert("level".to_string(), json!(9));
        let document = AdfDocument::new([AdfBlock::Heading {
            attrs,
            content: Vec::new(),
            other: AdfExtraKeys::new(),
        }]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::ReservedExtraKey {
                key: "level",
                path: "doc.content[0].attrs".to_string()
            }
        );

        let mut attrs = AdfLinkAttrs::new("https://example.test/a");
        attrs
            .other
            .insert("href".to_string(), json!("javascript:0"));
        let document = AdfDocument::new([AdfBlock::paragraph([AdfInline::text_with_marks(
            "text",
            [AdfMark::Link {
                attrs,
                other: AdfExtraKeys::new(),
            }],
        )])]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::ReservedExtraKey {
                key: "href",
                path: "doc.content[0].content[0].marks[0].attrs".to_string()
            }
        );

        let mut item = AdfListItem::text("x");
        item.other.insert("content".to_string(), json!([]));
        let document = AdfDocument::new([AdfBlock::bullet_list([item])]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::ReservedExtraKey {
                key: "content",
                path: "doc.content[0].content[0]".to_string()
            }
        );
    }

    #[test]
    fn a_reserved_key_error_names_only_this_crates_own_key() {
        // Bounded logging: the key comes from a fixed list in this module, and the
        // value it was paired with never reaches the message.
        let secret = "s3cr3t-token-value";
        let mut document = AdfDocument::new([AdfBlock::paragraph_text("ok")]);
        let AdfBlock::Paragraph { other, .. } = &mut document.content[0] else {
            panic!("expected a paragraph");
        };
        other.insert("content".to_string(), json!([secret]));

        let message = error_of(&document).to_string();
        assert!(!message.contains(secret), "error leaked a node value");
        assert!(message.contains("`content`"));
    }

    #[test]
    fn a_foreign_schema_version_is_rejected() {
        let document = parse(r#"{"type":"doc","version":2,"content":[]}"#);
        assert_eq!(
            error_of(&document),
            AdfValidationError::UnsupportedVersion { version: 2 }
        );
    }

    #[test]
    fn an_empty_text_node_is_rejected() {
        let document = AdfDocument::new([AdfBlock::paragraph([AdfInline::text("")])]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::EmptyText {
                path: "doc.content[0].content[0]".to_string()
            }
        );
    }

    #[test]
    fn a_heading_level_outside_one_through_six_is_rejected() {
        for level in [0_u8, 7, 200] {
            let document = AdfDocument::new([AdfBlock::heading_text(level, "x")]);
            assert_eq!(
                error_of(&document),
                AdfValidationError::InvalidHeadingLevel {
                    level,
                    path: "doc.content[0]".to_string()
                }
            );
        }
        for level in 1..=6_u8 {
            let document = AdfDocument::new([AdfBlock::heading_text(level, "x")]);
            assert_eq!(document.validate(), Ok(()), "level {level} should validate");
        }
    }

    #[test]
    fn a_heading_with_no_content_validates() {
        // ADF allows it, so this gate does not invent a rejection Jira would not
        // make.
        let document = AdfDocument::new([AdfBlock::heading(1, [])]);
        assert_eq!(document.validate(), Ok(()));
    }

    #[test]
    fn a_list_with_no_items_is_rejected() {
        let document = AdfDocument::new([AdfBlock::bullet_list([])]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::EmptyContent {
                node: "bulletList",
                path: "doc.content[0]".to_string()
            }
        );

        let document = AdfDocument::new([AdfBlock::ordered_list([])]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::EmptyContent {
                node: "orderedList",
                path: "doc.content[0]".to_string()
            }
        );
    }

    #[test]
    fn a_list_item_with_no_content_is_rejected() {
        let document = AdfDocument::new([AdfBlock::bullet_list([AdfListItem::new([])])]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::EmptyContent {
                node: "listItem",
                path: "doc.content[0].content[0]".to_string()
            }
        );
    }

    #[test]
    fn a_hard_break_inside_a_code_block_is_rejected() {
        let document = AdfDocument::new([AdfBlock::CodeBlock {
            attrs: None,
            content: vec![AdfInline::text("one"), AdfInline::hard_break()],
            other: AdfExtraKeys::new(),
        }]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::DisallowedChild {
                parent: "codeBlock",
                child: "hardBreak",
                path: "doc.content[0].content[1]".to_string()
            }
        );
    }

    #[test]
    fn a_marked_run_inside_a_code_block_is_rejected() {
        let document = AdfDocument::new([AdfBlock::CodeBlock {
            attrs: Some(AdfCodeBlockAttrs {
                language: Some("rust".to_string()),
                other: AdfExtraKeys::new(),
            }),
            content: vec![AdfInline::text_with_marks("code", [AdfMark::Strong])],
            other: AdfExtraKeys::new(),
        }]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::DisallowedMark {
                parent: "codeBlock",
                path: "doc.content[0].content[0]".to_string()
            }
        );
    }

    #[test]
    fn a_blockquote_inside_a_blockquote_is_rejected() {
        let document = AdfDocument::new([AdfBlock::blockquote([AdfBlock::blockquote([
            AdfBlock::paragraph_text("deep"),
        ])])]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::DisallowedChild {
                parent: "blockquote",
                child: "blockquote",
                path: "doc.content[0].content[0]".to_string()
            }
        );
    }

    #[test]
    fn a_blank_link_href_is_rejected() {
        for href in ["", "   "] {
            let document = AdfDocument::new([AdfBlock::paragraph([AdfInline::text_with_marks(
                "text",
                [AdfMark::Link {
                    attrs: AdfLinkAttrs::new(href),
                    other: AdfExtraKeys::new(),
                }],
            )])]);
            assert_eq!(
                error_of(&document),
                AdfValidationError::EmptyLinkHref {
                    path: "doc.content[0].content[0].marks[0]".to_string()
                }
            );
        }
    }

    #[test]
    fn a_non_http_link_scheme_is_not_rejected() {
        // Documented non-check: `mailto:` and Atlassian's smart-link schemes are
        // legitimate, and Jira sanitizes at render time.
        let document =
            AdfDocument::new([AdfBlock::paragraph([AdfInline::link("mail", "mailto:a@b")])]);
        assert_eq!(document.validate(), Ok(()));
    }

    #[test]
    fn nesting_past_the_limit_is_rejected() {
        // Blockquotes cannot nest, so the deep chain is built out of lists: each
        // level costs a `bulletList` plus its `listItem`.
        let mut block = AdfBlock::paragraph_text("bottom");
        for _ in 0..MAX_NESTING_DEPTH {
            block = AdfBlock::bullet_list([AdfListItem::new([block])]);
        }
        let document = AdfDocument::new([block]);
        assert!(matches!(
            document.validate(),
            Err(AdfValidationError::TooDeep {
                max_depth: MAX_NESTING_DEPTH,
                ..
            })
        ));
    }

    #[test]
    fn ordinary_nesting_is_well_inside_the_limit() {
        let document = AdfDocument::new([AdfBlock::bullet_list([AdfListItem::new([
            AdfBlock::paragraph_text("outer"),
            AdfBlock::bullet_list([AdfListItem::text("inner")]),
        ])])]);
        assert_eq!(document.validate(), Ok(()));
    }

    #[test]
    fn the_first_failure_wins() {
        let document = AdfDocument::new([
            AdfBlock::Heading {
                attrs: AdfHeadingAttrs::new(9),
                content: vec![AdfInline::text("")],
                other: AdfExtraKeys::new(),
            },
            AdfBlock::bullet_list([]),
        ]);
        assert_eq!(
            error_of(&document),
            AdfValidationError::InvalidHeadingLevel {
                level: 9,
                path: "doc.content[0]".to_string()
            }
        );
    }

    #[test]
    fn validation_errors_convert_to_the_crates_validation_error() {
        let err = AtlassianError::from(AdfValidationError::UnknownNode {
            path: "doc.content[0]".to_string(),
        });
        assert!(matches!(err, AtlassianError::Validation { .. }));
        assert!(err.to_string().contains("doc.content[0]"));
    }

    #[test]
    fn error_messages_carry_structure_and_never_document_text() {
        // Bounded logging: an error may name a location and this crate's own node
        // names, never a caller-supplied string.
        let secret = "s3cr3t-token-value";
        let document = AdfDocument::new([AdfBlock::paragraph([
            AdfInline::text(secret),
            AdfInline::Unknown(json!({"type": "mention", "attrs": {"id": secret}})),
        ])]);
        let message = error_of(&document).to_string();
        assert!(!message.contains(secret), "error leaked node content");
        assert!(message.contains("doc.content[0].content[1]"));
    }

    #[test]
    fn a_list_item_holding_a_list_item_type_marker_is_still_a_list_item() {
        // Guards the marker field against being silently defaulted away.
        let item = AdfListItem::text("x");
        assert_eq!(item.node_type, AdfListItemType::ListItem);
    }
}
