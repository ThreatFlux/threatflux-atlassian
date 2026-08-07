//! Fluent construction of a document, on top of the node constructors.

use super::node::{AdfBlock, AdfDocument, AdfInline, AdfListItem};
use super::validate::AdfValidationError;

/// Assembles an [`AdfDocument`] block by block.
///
/// The node constructors ([`AdfBlock::paragraph`], [`AdfInline::text`], ...) are
/// enough on their own; this exists so the common shapes -- a paragraph of
/// text, a heading, a bullet list of strings -- read as one expression.
///
/// ```
/// use threatflux_atlassian_sdk::adf::AdfDocumentBuilder;
///
/// let doc = AdfDocumentBuilder::new()
///     .heading(2, "Advisory")
///     .paragraph_text("A dependency needs updating.")
///     .bullet_list_text(["upgrade", "or pin"])
///     .code_block_with_language("toml", "serde = \"1\"")
///     .try_build()?;
///
/// assert_eq!(doc.content.len(), 4);
/// # Ok::<(), threatflux_atlassian_sdk::adf::AdfValidationError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct AdfDocumentBuilder {
    content: Vec<AdfBlock>,
}

impl AdfDocumentBuilder {
    /// An empty builder.
    pub const fn new() -> Self {
        Self {
            content: Vec::new(),
        }
    }

    /// Appends an already-built block.
    #[must_use]
    pub fn block(mut self, block: AdfBlock) -> Self {
        self.content.push(block);
        self
    }

    /// Appends a paragraph holding a single run of text.
    #[must_use]
    pub fn paragraph_text(self, text: impl Into<String>) -> Self {
        self.block(AdfBlock::paragraph_text(text))
    }

    /// Appends a paragraph holding `content`.
    #[must_use]
    pub fn paragraph(self, content: impl IntoIterator<Item = AdfInline>) -> Self {
        self.block(AdfBlock::paragraph(content))
    }

    /// Appends an empty paragraph, which renders as a blank line.
    #[must_use]
    pub fn empty_paragraph(self) -> Self {
        self.block(AdfBlock::empty_paragraph())
    }

    /// Appends a heading at `level` holding a single run of text.
    ///
    /// A `level` outside 1..=6 is not rejected here; it surfaces from
    /// [`try_build`](Self::try_build) or [`AdfDocument::validate`].
    #[must_use]
    pub fn heading(self, level: u8, text: impl Into<String>) -> Self {
        self.block(AdfBlock::heading_text(level, text))
    }

    /// Appends a bullet list, one single-paragraph item per string.
    #[must_use]
    pub fn bullet_list_text<I, S>(self, items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.block(AdfBlock::bullet_list(
            items.into_iter().map(AdfListItem::text),
        ))
    }

    /// Appends a code block with no language hint.
    #[must_use]
    pub fn code_block(self, code: impl Into<String>) -> Self {
        self.block(AdfBlock::code_block(code))
    }

    /// Appends a code block tagged with a language hint.
    #[must_use]
    pub fn code_block_with_language(
        self,
        language: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        self.block(AdfBlock::code_block_with_language(language, code))
    }

    /// Finishes the document without validating it.
    pub fn build(self) -> AdfDocument {
        AdfDocument::new(self.content)
    }

    /// Finishes the document and runs [`AdfDocument::validate`] on it.
    ///
    /// # Errors
    ///
    /// Returns the first [`AdfValidationError`] the assembled document trips.
    pub fn try_build(self) -> Result<AdfDocument, AdfValidationError> {
        let document = self.build();
        document.validate()?;
        Ok(document)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adf::{AdfMark, ADF_VERSION};
    use serde_json::json;

    #[test]
    fn an_empty_builder_yields_an_empty_document() {
        let document = AdfDocumentBuilder::new().build();
        assert_eq!(document, AdfDocument::empty());
        assert_eq!(document.version, ADF_VERSION);
    }

    #[test]
    fn the_builder_emits_the_documented_wire_form() {
        let document = AdfDocumentBuilder::new()
            .heading(2, "Advisory")
            .paragraph_text("A dependency needs updating.")
            .empty_paragraph()
            .paragraph([
                AdfInline::text("see "),
                AdfInline::text_with_marks("the note", [AdfMark::Strong]),
            ])
            .bullet_list_text(["upgrade", "or pin"])
            .code_block("cargo update")
            .try_build()
            .expect("the assembled document is valid");

        assert_eq!(
            serde_json::to_value(&document).expect("serializes"),
            json!({"type": "doc", "version": 1, "content": [
                {"type": "heading", "attrs": {"level": 2},
                 "content": [{"type": "text", "text": "Advisory"}]},
                {"type": "paragraph",
                 "content": [{"type": "text", "text": "A dependency needs updating."}]},
                {"type": "paragraph"},
                {"type": "paragraph", "content": [
                    {"type": "text", "text": "see "},
                    {"type": "text", "text": "the note", "marks": [{"type": "strong"}]}
                ]},
                {"type": "bulletList", "content": [
                    {"type": "listItem", "content": [
                        {"type": "paragraph", "content": [{"type": "text", "text": "upgrade"}]}]},
                    {"type": "listItem", "content": [
                        {"type": "paragraph", "content": [{"type": "text", "text": "or pin"}]}]}
                ]},
                {"type": "codeBlock", "content": [{"type": "text", "text": "cargo update"}]}
            ]})
        );
    }

    #[test]
    fn try_build_reports_what_build_would_have_shipped() {
        let builder = AdfDocumentBuilder::new().heading(0, "no such level");
        assert_eq!(
            builder.clone().try_build(),
            Err(AdfValidationError::InvalidHeadingLevel {
                level: 0,
                path: "doc.content[0]".to_string()
            })
        );
        // `build` is the unchecked door, and stays that way on purpose: the write
        // paths validate, and a builder that could not produce an invalid document
        // could not be used to test one.
        assert_eq!(builder.build().content.len(), 1);
    }

    #[test]
    fn a_block_appended_directly_keeps_its_position() {
        let document = AdfDocumentBuilder::new()
            .paragraph_text("first")
            .block(AdfBlock::rule())
            .paragraph_text("second")
            .build();
        assert_eq!(document.content.len(), 3);
        assert_eq!(document.content[1], AdfBlock::rule());
    }
}
