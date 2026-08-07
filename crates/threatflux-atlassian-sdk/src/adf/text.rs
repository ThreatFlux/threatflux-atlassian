//! Plain text into ADF: [`text_to_adf`], [`text_to_adf_bounded`], [`AdfLimits`].
//!
//! This module is private and its items are re-exported from
//! [`adf`](super), so nothing here is rendered in the published
//! documentation. The contract -- above all the *negative* one, that this is not
//! a Markdown renderer -- therefore lives on [`text_to_adf`] and
//! [`text_to_adf_bounded`] themselves, where a caller will actually read it.

use super::node::{AdfBlock, AdfDocument, AdfInline};

/// Characters of text [`AdfLimits::DEFAULT`] admits.
///
/// Jira Cloud rejects a description longer than roughly 32,767 characters, so
/// nothing above this could have been written anyway.
pub const DEFAULT_MAX_CHARS: usize = 32_767;

/// Nodes [`AdfLimits::DEFAULT`] admits.
///
/// A line of text costs two nodes, so this admits about 2,000 lines -- far more
/// than a human-authored description and far less than the ~64,000 nodes a
/// pathological body of one-character lines would otherwise produce. It bounds a
/// worst-case document at roughly 160 KB of JSON.
pub const DEFAULT_MAX_NODES: usize = 4_096;

/// Appended to the last `text` node of a document that was truncated:
/// `…` (`U+2026`).
///
/// One character, so it fits inside a budget that has just been exhausted, and
/// no words, so it needs no translation.
pub const TRUNCATION_MARKER: char = '…';

/// Nodes a single line of text costs, and so the smallest node budget that can
/// admit anything at all.
///
/// A line is charged for its `text` node plus either the `paragraph` that opens
/// it or the `hardBreak` that separates it from the line before -- both or
/// neither, which is what keeps a truncated paragraph from ending in a dangling
/// `hardBreak`.
const NODES_PER_LINE: usize = 2;

/// What [`text_to_adf_bounded`] will let a document grow to.
///
/// # What is bounded, and what is not
///
/// | Field | Bounds | Why this axis |
/// |---|---|---|
/// | [`max_chars`](Self::max_chars) | `char`s summed over every `text` node | Jira states its own description limit in characters, and a budget spent in `char`s cannot cut a multi-byte one in half. |
/// | [`max_nodes`](Self::max_nodes) | every `paragraph`, `text` and `hardBreak` below the root | The one that actually bounds the request. ADF costs tens of bytes of JSON per node whatever the node carries, so a 64 KB body of one-character lines is only ~32,000 characters but ~64,000 nodes and over 1.5 MB of JSON. |
///
/// # A node budget of one is raised to two
///
/// A line costs two nodes indivisibly, so [`max_nodes`](Self::max_nodes) of `1`
/// is a budget nothing can be charged to: the conversion would return an empty
/// document, and [`TRUNCATION_MARKER`] -- the only place the loss is visible to
/// a human -- has nowhere to go once there is no `text` node left to append it
/// to. Every constructor here raises a `1` to `2`, and
/// [`text_to_adf_bounded`] raises one assigned to the field directly. Rounding
/// down to zero would have been the other option, and it deletes the alert this
/// conversion exists to deliver.
///
/// An explicit `0` on either axis is left alone: it says "emit nothing", which
/// is unambiguous, and it is the one setting at which a document can be lost
/// without a marker to show for it.
///
/// Neither byte length nor nesting depth is a field. Byte length is a function
/// of the two above and would be a third number to keep consistent with them.
/// Depth cannot vary: this conversion emits exactly `doc` → `paragraph` →
/// `text`/`hardBreak` and has no recursive case, so a depth limit would be a
/// knob that can never fire. Depth on documents built elsewhere is bounded by
/// [`MAX_NESTING_DEPTH`](super::MAX_NESTING_DEPTH) inside
/// [`AdfDocument::validate`].
///
/// ```
/// use threatflux_atlassian_sdk::adf::AdfLimits;
///
/// let tight = AdfLimits::DEFAULT.with_max_chars(4_000);
/// assert_eq!(tight.max_chars, 4_000);
/// assert_eq!(tight.max_nodes, AdfLimits::DEFAULT.max_nodes);
/// ```
///
/// `#[non_exhaustive]`, so a limit added later is not a breaking change; build
/// one from [`DEFAULT`](Self::DEFAULT), [`new`](Self::new) or
/// [`unbounded`](Self::unbounded) rather than from a struct literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdfLimits {
    /// Largest number of `char`s the document's `text` nodes may hold in total.
    pub max_chars: usize,
    /// Largest number of nodes below the root: `paragraph`, `text`, `hardBreak`.
    ///
    /// A `1` here is raised to `2`; see [above](Self#a-node-budget-of-one-is-raised-to-two).
    pub max_nodes: usize,
}

impl AdfLimits {
    /// [`DEFAULT_MAX_CHARS`] characters and [`DEFAULT_MAX_NODES`] nodes -- what
    /// [`text_to_adf`] applies.
    pub const DEFAULT: Self = Self {
        max_chars: DEFAULT_MAX_CHARS,
        max_nodes: DEFAULT_MAX_NODES,
    };

    /// Limits of `max_chars` characters and `max_nodes` nodes.
    ///
    /// A `max_nodes` of `1` is raised to `2`; see
    /// [above](Self#a-node-budget-of-one-is-raised-to-two).
    pub const fn new(max_chars: usize, max_nodes: usize) -> Self {
        Self {
            max_chars,
            max_nodes: usable_max_nodes(max_nodes),
        }
    }

    /// No limit at all.
    ///
    /// For a caller who has already bounded the input and wants the whole of it.
    /// The conversion then cannot keep a hostile body from producing a request
    /// Jira rejects -- that becomes the caller's job.
    pub const fn unbounded() -> Self {
        Self {
            max_chars: usize::MAX,
            max_nodes: usize::MAX,
        }
    }

    /// These limits with [`max_chars`](Self::max_chars) replaced.
    #[must_use]
    pub const fn with_max_chars(mut self, max_chars: usize) -> Self {
        self.max_chars = max_chars;
        self
    }

    /// These limits with [`max_nodes`](Self::max_nodes) replaced.
    ///
    /// A `max_nodes` of `1` is raised to `2`; see
    /// [above](Self#a-node-budget-of-one-is-raised-to-two).
    #[must_use]
    pub const fn with_max_nodes(mut self, max_nodes: usize) -> Self {
        self.max_nodes = usable_max_nodes(max_nodes);
        self
    }

    /// These limits as [`text_to_adf_bounded`] will actually apply them.
    ///
    /// The fields are public, so the constructors are not the only way a `1`
    /// reaches [`max_nodes`](Self::max_nodes); the conversion normalizes again on
    /// entry rather than trusting how the value got there.
    const fn usable(self) -> Self {
        Self {
            max_chars: self.max_chars,
            max_nodes: usable_max_nodes(self.max_nodes),
        }
    }
}

/// A node budget rounded up to one that can hold a line, leaving zero alone.
const fn usable_max_nodes(max_nodes: usize) -> usize {
    if max_nodes == 0 || max_nodes >= NODES_PER_LINE {
        max_nodes
    } else {
        NODES_PER_LINE
    }
}

impl Default for AdfLimits {
    /// [`AdfLimits::DEFAULT`].
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Converts plain text into an ADF document, bounded by [`AdfLimits::DEFAULT`].
///
/// # This is not a Markdown renderer
///
/// **No markup of any kind is interpreted.** `**bold**` becomes the eight literal
/// characters `**bold**` inside one `text` node; it does **not** become a
/// [`Strong`](super::AdfMark::Strong) mark. Nor does `# Impact` become a heading,
/// `- item` a list item, `` `x` `` a code mark, `[text](url)` a
/// [`Link`](super::AdfMark::Link), or a bare `https://example.test` an auto-link.
/// No flag turns any of that on, and none will be added.
///
/// That negative contract is the point of the function, not a gap in it. The
/// input is typically a rendered template built from a GitHub issue body -- text
/// an outside author controls. The guarantee worth having is that such text
/// **never re-enters a parser** on its way to Jira: every character it holds ends
/// up inside the string of a `text` node, where it can only ever be read as
/// characters. A Markdown pass would hand that outside author a way to choose the
/// *structure* of the document -- the same class of primitive as
/// [`RichText::Unknown`](super::RichText::Unknown) on a write path, and the
/// reason that variant is refused there.
///
/// # What it does do
///
/// | Input | Output |
/// |---|---|
/// | `\r\n`, or a lone `\r` | `\n`, before anything else is decided |
/// | a control character other than `\n` and `\t` | removed |
/// | a single `\n` inside a paragraph | a `hardBreak` node |
/// | a run of one or more blank lines | a paragraph break |
/// | an empty line, or one left empty by stripping | never an empty `text` node |
///
/// Line endings normalize first, so a CRLF document does not read as a blank line
/// between every pair of lines. The stripped set is every character Unicode
/// classifies as a control (category `Cc`) except `\n` and `\t`: the C0 range
/// `U+0000..=U+001F`, `DEL` (`U+007F`), and the C1 range `U+0080..=U+009F`. `\t`
/// survives because it is ordinary content inside a line; the rest carry no
/// meaning in a Jira description, and an `ESC` that reached one would travel on
/// into every log line and terminal that echoes it. This matches the
/// control-character handling in [`jql`](crate::jql).
///
/// A whitespace-only line is *not* treated as blank -- it is not empty, so it
/// becomes a `text` node holding that whitespace. Deciding that `"   "` means a
/// paragraph break would be an interpretation, and interpreting is the thing this
/// function does not do.
///
/// # Output is bounded even here
///
/// This is [`text_to_adf_bounded`] at [`AdfLimits::DEFAULT`]. There is
/// deliberately no unbounded entry point: an unbounded conversion of a 65 KB body
/// can only produce a document Jira answers with a 400. Text past the limits is
/// truncated and marked with [`TRUNCATION_MARKER`], never rejected -- see
/// [`text_to_adf_bounded`] for why, and [`AdfLimits::unbounded`] for the opt-out.
///
/// # Postcondition
///
/// The returned document always passes [`AdfDocument::validate`], at every limit,
/// so a v3 write path can take it without checking again.
///
/// ```
/// use threatflux_atlassian_sdk::adf::text_to_adf;
/// use serde_json::json;
///
/// let doc = text_to_adf("first line\r\nsecond line\n\n**not bold**");
///
/// assert_eq!(
///     serde_json::to_value(&doc)?,
///     json!({
///         "type": "doc",
///         "version": 1,
///         "content": [
///             {"type": "paragraph", "content": [
///                 {"type": "text", "text": "first line"},
///                 {"type": "hardBreak"},
///                 {"type": "text", "text": "second line"}
///             ]},
///             {"type": "paragraph", "content": [
///                 {"type": "text", "text": "**not bold**"}
///             ]}
///         ]
///     })
/// );
/// assert!(doc.validate().is_ok());
/// # Ok::<(), serde_json::Error>(())
/// ```
pub fn text_to_adf(text: &str) -> AdfDocument {
    text_to_adf_bounded(text, AdfLimits::DEFAULT)
}

/// Converts plain text into an ADF document no larger than `limits`.
///
/// Exactly the conversion [`text_to_adf`] performs -- including that **it is not
/// a Markdown renderer and interprets no markup at all**, which is documented in
/// full there -- with the caller choosing the ceiling instead of taking
/// [`AdfLimits::DEFAULT`]. See [`AdfLimits`] for what the two fields bound and
/// why those are the axes.
///
/// # Over the limit truncates; it does not reject
///
/// This conversion sits on an alerting path: the text is a rendered template
/// built from an issue body, and the document is the description of the Jira
/// issue that tells a human the alert happened. A 65 KB body is something any
/// author can paste and any hostile author can craft on purpose. Rejecting one
/// would turn it into a hard failure of the routing step, and the alert would be
/// lost -- destroyed by the bound that exists to protect it. Truncation degrades
/// the message; rejection deletes it, and hands an outside author a switch for
/// doing so.
///
/// Truncation is therefore total and infallible: no `Result`, no error variant,
/// nothing for a caller to forget to handle. Its cost is that content
/// disappears, so the loss is made visible where a human will see it -- the last
/// `text` node ends with [`TRUNCATION_MARKER`]. The marker is charged to the
/// character budget rather than added on top of it, replacing the final
/// character when the budget is exactly spent, so the promise that the document
/// holds at most `limits.max_chars` characters holds even for a document that
/// was cut.
///
/// The marker needs a `text` node to sit in, so the guarantee is exactly as
/// broad as "the limits admit a line at all". They always do unless a limit is
/// zero: a [`max_nodes`](AdfLimits::max_nodes) of `1` -- the one value that
/// admitted nothing while looking like it admitted something -- is raised to
/// `2` on the way in.
///
/// A caller who would rather refuse an over-long body can compare its length
/// against the limits before calling, which is a decision above this layer and
/// stays there.
///
/// # Where the cut lands
///
/// The last line kept is cut mid-line when the character budget runs out, always
/// on a `char` boundary -- the budget is spent in `char`s, so a multi-byte
/// character is never split. When the node budget runs out instead, the cut
/// lands at the end of the last complete line, and never leaves a paragraph
/// ending in a dangling `hardBreak`: a line costs its `hardBreak` and its `text`
/// node together or not at all.
///
/// A limit of zero on either axis yields an empty document, which is legal ADF
/// and still validates -- and is the one setting under which content can
/// disappear with no marker to show for it, because a marker is itself a
/// character in a `text` node inside a `paragraph`. Zero is left to mean what it
/// says; a caller that wants the loss reported rather than shown compares the
/// input against the limits before calling.
///
/// ```
/// use threatflux_atlassian_sdk::adf::{text_to_adf_bounded, AdfLimits};
/// use serde_json::json;
///
/// let doc = text_to_adf_bounded("a very long line", AdfLimits::DEFAULT.with_max_chars(6));
///
/// // Six characters out, not seven: the marker replaced the character it could
/// // not be added after.
/// assert_eq!(
///     serde_json::to_value(&doc)?,
///     json!({
///         "type": "doc",
///         "version": 1,
///         "content": [
///             {"type": "paragraph", "content": [{"type": "text", "text": "a ver…"}]}
///         ]
///     })
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
pub fn text_to_adf_bounded(text: &str, limits: AdfLimits) -> AdfDocument {
    let limits = limits.usable();
    let normalized = normalize(text);

    let mut blocks: Vec<AdfBlock> = Vec::new();
    let mut paragraph: Vec<AdfInline> = Vec::new();
    let mut nodes: usize = 0;
    let mut chars_used: usize = 0;
    let mut truncated = false;

    for line in normalized.split('\n') {
        if line.is_empty() {
            // A run of blank lines flushes once and then no-ops, so two blank
            // lines and five blank lines both mean one paragraph break. Nothing
            // is charged: a blank line adds no node.
            if !paragraph.is_empty() {
                blocks.push(AdfBlock::paragraph(std::mem::take(&mut paragraph)));
            }
            continue;
        }

        // A line always costs `NODES_PER_LINE`: its `text` node, plus either the
        // `paragraph` that will hold it or the `hardBreak` separating it from the
        // line before. Charging both before either is pushed is what keeps a
        // truncated paragraph from ending in a dangling `hardBreak`.
        if nodes.saturating_add(NODES_PER_LINE) > limits.max_nodes || chars_used >= limits.max_chars
        {
            truncated = true;
            break;
        }

        // Subtraction is guarded by the `>=` above.
        let (kept, kept_chars, clipped) = take_chars(line, limits.max_chars - chars_used);

        if !paragraph.is_empty() {
            paragraph.push(AdfInline::hard_break());
        }
        // Never an empty `text` node: `line` is non-empty here and the budget was
        // at least one character, so `kept` holds at least one.
        paragraph.push(AdfInline::text(kept));
        nodes += NODES_PER_LINE;
        chars_used += kept_chars;

        if clipped {
            truncated = true;
            break;
        }
    }

    if !paragraph.is_empty() {
        blocks.push(AdfBlock::paragraph(paragraph));
    }
    if truncated {
        mark_truncated(&mut blocks, chars_used, limits.max_chars);
    }

    AdfDocument::new(blocks)
}

/// Collapses both line-ending conventions to `\n` and drops every control
/// character except `\n` and `\t`.
///
/// One pass, so a lone `\r` becomes a line break rather than disappearing as a
/// control character -- stripping first would silently join the two lines it
/// separated.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' | '\t' => out.push(ch),
            _ if ch.is_control() => {}
            _ => out.push(ch),
        }
    }

    out
}

/// The first `budget` `char`s of `line`, how many that was, and whether anything
/// was left behind.
///
/// Counting in `char`s is what makes the cut boundary-safe: the string is grown
/// one whole character at a time, so a multi-byte character is either kept or
/// dropped and never split.
fn take_chars(line: &str, budget: usize) -> (String, usize, bool) {
    let mut kept = String::new();
    let mut kept_chars = 0_usize;

    for ch in line.chars() {
        if kept_chars == budget {
            return (kept, kept_chars, true);
        }
        kept.push(ch);
        kept_chars += 1;
    }

    (kept, kept_chars, false)
}

/// Marks the end of a truncated document with [`TRUNCATION_MARKER`].
///
/// The marker is charged to the character budget: when the budget is exactly
/// spent it replaces the final character instead of following it, so a truncated
/// document is never one character over its own limit. `String::pop` removes a
/// whole `char`, so replacing cannot split a multi-byte one, and a `text` node
/// reduced to nothing is immediately refilled by the marker -- an empty `text`
/// node would be invalid ADF.
fn mark_truncated(blocks: &mut [AdfBlock], chars_used: usize, max_chars: usize) {
    // Nothing was emitted at all, so there is nowhere to put a marker. Reachable
    // only from a limit of zero: any other limits admit a first line, because
    // `AdfLimits::usable` has already raised a node budget of one to the cost of
    // a line. That case is documented on `text_to_adf_bounded` as the one place
    // where a loss is not made visible.
    let Some(AdfBlock::Paragraph { content, .. }) = blocks.last_mut() else {
        return;
    };
    let Some(AdfInline::Text { text, .. }) = content.last_mut() else {
        return;
    };

    if chars_used >= max_chars {
        text.pop();
    }
    text.push(TRUNCATION_MARKER);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every block this module emits is a paragraph; anything else is a bug in
    /// the conversion rather than a case the helpers below should tolerate.
    fn paragraphs(document: &AdfDocument) -> Vec<&Vec<AdfInline>> {
        document
            .content
            .iter()
            .map(|block| match block {
                AdfBlock::Paragraph { content, .. } => content,
                other => panic!("conversion emitted a non-paragraph block: {other:?}"),
            })
            .collect()
    }

    /// One string per paragraph, with a `hardBreak` rendered as `\n`. Lets a test
    /// name the text it expects instead of a JSON tree.
    fn rendered(document: &AdfDocument) -> Vec<String> {
        paragraphs(document)
            .into_iter()
            .map(|inlines| {
                inlines
                    .iter()
                    .map(|inline| match inline {
                        AdfInline::Text { text, marks, .. } => {
                            assert!(marks.is_empty(), "conversion invented a mark: {marks:?}");
                            text.clone()
                        }
                        AdfInline::HardBreak => "\n".to_string(),
                        other => panic!("conversion emitted an unmodelled inline: {other:?}"),
                    })
                    .collect()
            })
            .collect()
    }

    /// Nodes below the root -- the quantity [`AdfLimits::max_nodes`] bounds.
    fn node_count(document: &AdfDocument) -> usize {
        paragraphs(document)
            .into_iter()
            .map(|inlines| 1 + inlines.len())
            .sum()
    }

    /// Characters of text -- the quantity [`AdfLimits::max_chars`] bounds.
    fn char_count(document: &AdfDocument) -> usize {
        paragraphs(document)
            .into_iter()
            .flatten()
            .map(|inline| match inline {
                AdfInline::Text { text, .. } => text.chars().count(),
                _ => 0,
            })
            .sum()
    }

    /// Inputs every invariant test runs over: ordinary text, hostile text, and
    /// the shapes that historically produce an empty `text` node.
    const CORPUS: &[&str] = &[
        "",
        " ",
        "\t",
        "\n",
        "\r",
        "\r\n",
        "\n\n\n",
        "\u{0}",
        "\u{0}\u{1}\u{1b}",
        "a",
        "a\nb",
        "a\n\nb",
        "a\r\n\r\nb",
        " \n \n ",
        "line\n\n\n\nline",
        "\u{1b}[31mred\u{0}\u{7}",
        "emoji \u{1f600}\u{1f600}\u{1f600}",
        "**bold** `code` [link](https://example.test) # heading\n- item",
        "trailing newline\n",
        "\nleading newline",
    ];

    // --- CRLF normalization. ---

    #[test]
    fn crlf_and_lone_cr_read_as_a_single_line_break() {
        let lf = text_to_adf("a\nb");
        assert_eq!(text_to_adf("a\r\nb"), lf, "CRLF must read as one LF");
        assert_eq!(text_to_adf("a\rb"), lf, "a lone CR must read as one LF");
        assert_eq!(rendered(&lf), vec!["a\nb"]);
    }

    #[test]
    fn a_crlf_blank_line_is_one_paragraph_break_not_two() {
        // The bug normalization exists to prevent: stripping `\r` as a control
        // character first would leave `\n\n` reading as `\n\n` here but a plain
        // `a\rb` reading as `ab`, and a CRLF document would gain a blank line
        // between every pair of lines.
        let crlf = text_to_adf("a\r\n\r\nb");
        assert_eq!(crlf, text_to_adf("a\n\nb"));
        assert_eq!(rendered(&crlf), vec!["a", "b"]);
    }

    #[test]
    fn a_cr_is_a_line_break_and_not_a_stripped_control_character() {
        assert_eq!(rendered(&text_to_adf("a\rb")), vec!["a\nb"]);
        assert_eq!(rendered(&text_to_adf("a\r\r\rb")), vec!["a", "b"]);
    }

    // --- Control-character stripping. ---

    #[test]
    fn control_characters_are_stripped_except_tab_and_newline() {
        assert_eq!(
            rendered(&text_to_adf("a\u{0}\u{1}\u{7}b\tc")),
            vec!["ab\tc"],
            "tab must survive and the rest must not"
        );

        for control in ['\u{0}', '\u{1}', '\u{1b}', '\u{7f}', '\u{80}', '\u{9f}'] {
            let document = text_to_adf(&format!("a{control}b"));
            assert_eq!(
                rendered(&document),
                vec!["ab"],
                "{control:?} survived the strip"
            );
        }
    }

    #[test]
    fn a_terminal_escape_sequence_loses_its_escape() {
        // The reason ESC is stripped rather than kept: a description travels on
        // into logs and terminals that echo it.
        assert_eq!(
            rendered(&text_to_adf("\u{1b}[31mred\u{1b}[0m")),
            vec!["[31mred[0m"]
        );
    }

    #[test]
    fn no_control_character_survives_anywhere_in_the_corpus() {
        for input in CORPUS {
            for paragraph in rendered(&text_to_adf(input)) {
                let survivor = paragraph
                    .chars()
                    .find(|ch| ch.is_control() && *ch != '\n' && *ch != '\t');
                assert!(
                    survivor.is_none(),
                    "{input:?} let {survivor:?} through into the document"
                );
            }
        }
    }

    // --- Blank-line paragraph splitting. ---

    #[test]
    fn a_single_line_break_is_a_hard_break_inside_one_paragraph() {
        let document = text_to_adf("first\nsecond\nthird");
        assert_eq!(document.content.len(), 1);
        assert_eq!(
            document.content[0],
            AdfBlock::paragraph([
                AdfInline::text("first"),
                AdfInline::hard_break(),
                AdfInline::text("second"),
                AdfInline::hard_break(),
                AdfInline::text("third"),
            ])
        );
    }

    #[test]
    fn a_run_of_blank_lines_is_one_paragraph_break() {
        for separator in ["\n\n", "\n\n\n", "\n\n\n\n\n", "\r\n\r\n\r\n"] {
            let document = text_to_adf(&format!("first{separator}second"));
            assert_eq!(
                rendered(&document),
                vec!["first", "second"],
                "{separator:?} should split exactly once"
            );
        }
    }

    #[test]
    fn leading_and_trailing_blank_lines_add_no_paragraph() {
        assert_eq!(rendered(&text_to_adf("\n\nbody\n\n")), vec!["body"]);
    }

    #[test]
    fn a_line_left_empty_by_stripping_becomes_a_paragraph_break() {
        // Stripping runs before the split, so a line of nothing but control
        // characters is an empty line by the time the split sees it -- which is
        // also what keeps it from becoming an empty `text` node.
        let document = text_to_adf("a\n\u{0}\u{1}\n b");
        assert_eq!(rendered(&document), vec!["a", " b"]);
    }

    #[test]
    fn a_whitespace_only_line_is_not_a_paragraph_break() {
        // Deliberately literal: treating "   " as blank would be an
        // interpretation, and this module does not interpret. Pinned so the
        // behaviour cannot drift into Markdown's rule by accident.
        let document = text_to_adf("a\n   \nb");
        assert_eq!(document.content.len(), 1);
        assert_eq!(rendered(&document), vec!["a\n   \nb"]);
    }

    // --- The no-empty-text-node rule. ---

    #[test]
    fn no_empty_text_node_is_ever_emitted() {
        // Jira answers a document containing one with a 400, so this holds over
        // the hostile corpus and at every limit, not just for tidy input.
        let limits = [
            AdfLimits::DEFAULT,
            AdfLimits::unbounded(),
            AdfLimits::new(0, 0),
            AdfLimits::new(1, 2),
            AdfLimits::new(3, 4),
            AdfLimits::new(8, 6),
        ];

        for input in CORPUS {
            for limit in limits {
                let document = text_to_adf_bounded(input, limit);
                for inline in paragraphs(&document).into_iter().flatten() {
                    if let AdfInline::Text { text, .. } = inline {
                        assert!(
                            !text.is_empty(),
                            "{input:?} at {limit:?} produced an empty text node"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn text_that_is_only_line_breaks_yields_an_empty_document() {
        // Not an empty `text` node and not an empty paragraph: nothing at all. A
        // caller that means "no description" sends `None`, a layer up.
        for empty in ["", "\n", "\n\n\n", "\r\n\r\n", "\u{0}", "\u{0}\n\u{1b}"] {
            let document = text_to_adf(empty);
            assert!(
                document.is_empty(),
                "{empty:?} should have produced an empty document, got {document:?}"
            );
            assert_eq!(document.validate(), Ok(()));
        }
    }

    // --- The negative contract. ---

    #[test]
    fn markdown_is_not_interpreted() {
        // The failure this module's documentation exists to prevent: a caller
        // expecting `**bold**` to arrive as a `strong` mark.
        let source = "# Heading\n\n**bold** and _em_ and `code`\n\n- item\n- item\n\n\
                      [text](https://example.test) and https://example.test";
        let document = text_to_adf(source);

        assert_eq!(
            rendered(&document),
            vec![
                "# Heading",
                "**bold** and _em_ and `code`",
                "- item\n- item",
                "[text](https://example.test) and https://example.test",
            ],
            "markup was interpreted instead of being carried literally"
        );

        // `rendered` already asserts no marks were invented; this pins the block
        // side of the same claim.
        for block in &document.content {
            assert!(
                matches!(block, AdfBlock::Paragraph { .. }),
                "markup produced a non-paragraph block: {block:?}"
            );
        }
    }

    #[test]
    fn json_and_adf_syntax_in_the_input_stays_text() {
        // The structure-injection case: text that looks like the document format
        // is still just characters inside a `text` node.
        let source = r#"{"type":"doc","content":[{"type":"mediaSingle"}]}"#;
        let document = text_to_adf(source);
        assert_eq!(rendered(&document), vec![source]);
        assert_eq!(document.validate(), Ok(()));
    }

    // --- Bounds. ---

    #[test]
    fn the_character_limit_truncates_and_marks_the_cut() {
        let document = text_to_adf_bounded("a very long line", AdfLimits::new(6, 64));
        assert_eq!(rendered(&document), vec!["a ver…"]);
        assert_eq!(char_count(&document), 6);
    }

    #[test]
    fn a_truncated_document_never_exceeds_its_character_budget() {
        // The marker is charged to the budget rather than added on top of it, so
        // this holds at every limit including one and zero.
        let long = "lorem ipsum dolor sit amet\nconsectetur\n\nadipiscing elit";
        for max_chars in 0..=long.chars().count() + 4 {
            let document = text_to_adf_bounded(long, AdfLimits::new(max_chars, usize::MAX));
            assert!(
                char_count(&document) <= max_chars,
                "{max_chars} characters allowed, {} emitted",
                char_count(&document)
            );
            assert_eq!(document.validate(), Ok(()), "limit {max_chars}");
        }
    }

    #[test]
    fn the_cut_lands_on_a_character_boundary() {
        // Each emoji is four bytes; a byte-counted budget would split one and the
        // `String` would not even be constructible.
        let emoji = "\u{1f600}\u{1f600}\u{1f600}\u{1f600}";
        let document = text_to_adf_bounded(emoji, AdfLimits::new(3, 64));
        assert_eq!(
            rendered(&document),
            vec![format!("\u{1f600}\u{1f600}{TRUNCATION_MARKER}")]
        );
        assert_eq!(char_count(&document), 3);
    }

    #[test]
    fn the_node_limit_stops_the_document_without_a_dangling_hard_break() {
        // Two nodes per line: the first line costs its paragraph plus its text,
        // every later line costs a `hardBreak` plus its text. A budget of four
        // therefore admits exactly two lines, and the third must not push a
        // `hardBreak` it cannot follow with text.
        let document = text_to_adf_bounded("one\ntwo\nthree\nfour", AdfLimits::new(usize::MAX, 4));
        assert_eq!(rendered(&document), vec!["one\ntwo…"]);
        assert_eq!(node_count(&document), 4);

        for block in &document.content {
            let AdfBlock::Paragraph { content, .. } = block else {
                panic!("expected a paragraph");
            };
            assert!(
                !matches!(content.last(), Some(AdfInline::HardBreak)),
                "paragraph ends in a dangling hard break: {content:?}"
            );
        }
    }

    #[test]
    fn a_node_budget_of_zero_yields_an_empty_document() {
        let document = text_to_adf_bounded("a\nb", AdfLimits::new(usize::MAX, 0));
        assert!(document.is_empty(), "zero nodes produced {document:?}");
        assert_eq!(document.validate(), Ok(()));
    }

    #[test]
    fn a_node_budget_of_one_is_raised_to_the_cost_of_a_line() {
        // A line costs two nodes indivisibly, so a budget of one admits nothing
        // at all -- and the whole document used to vanish with no marker on it,
        // because the marker has nowhere to go once the last `text` node is gone.
        // Rounding the budget up to the smallest one that can hold something is
        // what keeps the loss visible; rounding it down to zero would delete the
        // alert this conversion exists to deliver.
        assert_eq!(AdfLimits::new(9, 1).max_nodes, 2);
        assert_eq!(AdfLimits::DEFAULT.with_max_nodes(1).max_nodes, 2);
        // Zero says "emit nothing" and is left alone; two and above are already
        // usable and must not move either.
        assert_eq!(AdfLimits::new(9, 0).max_nodes, 0);
        assert_eq!(AdfLimits::new(9, 2).max_nodes, 2);
        assert_eq!(AdfLimits::new(9, 3).max_nodes, 3);

        let document = text_to_adf_bounded("alpha\nbeta", AdfLimits::new(usize::MAX, 1));

        assert!(!document.is_empty(), "the document vanished: {document:?}");
        assert!(
            rendered(&document).concat().contains(TRUNCATION_MARKER),
            "content was dropped with nothing to show for it: {document:?}"
        );
        assert_eq!(document.validate(), Ok(()));
    }

    #[test]
    fn a_node_budget_assigned_past_the_constructors_is_still_raised() {
        // The fields are public, so the clamp cannot live only in `new`.
        let mut limits = AdfLimits::DEFAULT;
        limits.max_nodes = 1;

        let document = text_to_adf_bounded("alpha\nbeta", limits);
        assert!(rendered(&document).concat().contains(TRUNCATION_MARKER));
    }

    #[test]
    fn truncation_is_never_invisible_at_limits_that_admit_anything() {
        // The visibility guarantee as an invariant rather than an example: at any
        // limits that can hold a line at all, a document that lost content says
        // so. `AdfLimits::new(1, 1)` is the case that used to break it.
        let limits = [
            AdfLimits::new(1, 1),
            AdfLimits::new(1, 2),
            AdfLimits::new(2, 2),
            AdfLimits::new(3, 4),
            AdfLimits::new(5, 8),
            AdfLimits::DEFAULT,
        ];

        for input in CORPUS {
            let whole = text_to_adf_bounded(input, AdfLimits::unbounded());
            for limit in limits {
                let document = text_to_adf_bounded(input, limit);
                if document == whole {
                    continue;
                }
                assert!(
                    rendered(&document).concat().contains(TRUNCATION_MARKER),
                    "{input:?} at {limit:?} lost content and said nothing: {document:?}"
                );
            }
        }
    }

    #[test]
    fn the_node_budget_holds_over_a_pathological_body() {
        // The regression the ADF migration introduces: a body of one-character
        // lines costs almost nothing in characters and would cost ~64,000 nodes
        // and over 1.5 MB of JSON unbounded.
        let hostile = "x\n".repeat(32_768);
        let document = text_to_adf(&hostile);

        assert!(node_count(&document) <= DEFAULT_MAX_NODES);
        assert!(char_count(&document) <= DEFAULT_MAX_CHARS);
        assert_eq!(document.validate(), Ok(()));

        let wire = serde_json::to_string(&document).expect("serializes");
        assert!(
            wire.len() < 200_000,
            "default limits let the document reach {} bytes of JSON",
            wire.len()
        );
    }

    #[test]
    fn the_default_character_limit_bounds_a_long_body() {
        let long = "x".repeat(DEFAULT_MAX_CHARS * 2);
        let document = text_to_adf(&long);
        assert_eq!(char_count(&document), DEFAULT_MAX_CHARS);
        assert!(rendered(&document)[0].ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn ordinary_text_is_nowhere_near_the_default_limits() {
        // The defaults must not be reachable by real content, or every routed
        // issue would arrive with a marker on it.
        let realistic = "A dependency needs updating.\n\nSeverity: high\nAdvisory: \
                         GHSA-xxxx-xxxx-xxxx\n\nUpgrade or pin the affected crate.\n\n"
            .repeat(20);
        let document = text_to_adf(&realistic);

        assert!(char_count(&document) < DEFAULT_MAX_CHARS / 4);
        assert!(node_count(&document) < DEFAULT_MAX_NODES / 4);
        assert!(
            !rendered(&document).concat().contains(TRUNCATION_MARKER),
            "realistic content was truncated by the default limits"
        );
    }

    #[test]
    fn unbounded_limits_keep_everything_and_add_no_marker() {
        let source = "one\ntwo\n\nthree";
        let document = text_to_adf_bounded(source, AdfLimits::unbounded());
        assert_eq!(rendered(&document), vec!["one\ntwo", "three"]);
        assert!(!rendered(&document).concat().contains(TRUNCATION_MARKER));
    }

    #[test]
    fn text_that_exactly_fills_the_budget_is_not_marked() {
        // Off-by-one guard: the marker means "content was dropped", so a document
        // that fits exactly must not carry one.
        let document = text_to_adf_bounded("abcdef", AdfLimits::new(6, 64));
        assert_eq!(rendered(&document), vec!["abcdef"]);
    }

    // --- Postcondition and defaults. ---

    #[test]
    fn every_document_this_module_returns_validates() {
        // What lets a v3 write path take the result without re-checking it.
        for input in CORPUS {
            for limits in [
                AdfLimits::DEFAULT,
                AdfLimits::default(),
                AdfLimits::unbounded(),
                AdfLimits::new(0, 0),
                AdfLimits::new(1, 1),
                AdfLimits::new(2, 3),
                AdfLimits::new(5, 8),
            ] {
                let document = text_to_adf_bounded(input, limits);
                assert_eq!(
                    document.validate(),
                    Ok(()),
                    "{input:?} at {limits:?} produced an invalid document"
                );
            }
        }
    }

    #[test]
    fn text_to_adf_is_text_to_adf_bounded_at_the_default_limits() {
        for input in CORPUS {
            assert_eq!(
                text_to_adf(input),
                text_to_adf_bounded(input, AdfLimits::DEFAULT),
                "the two entry points disagree on {input:?}"
            );
        }
    }

    #[test]
    fn the_limit_constructors_agree_with_the_documented_defaults() {
        assert_eq!(AdfLimits::default(), AdfLimits::DEFAULT);
        assert_eq!(AdfLimits::DEFAULT.max_chars, DEFAULT_MAX_CHARS);
        assert_eq!(AdfLimits::DEFAULT.max_nodes, DEFAULT_MAX_NODES);
        assert_eq!(
            AdfLimits::new(7, 9),
            AdfLimits::default().with_max_chars(7).with_max_nodes(9)
        );
        assert_eq!(AdfLimits::unbounded().max_chars, usize::MAX);
        assert_eq!(AdfLimits::unbounded().max_nodes, usize::MAX);
    }

    #[test]
    fn the_emitted_wire_form_is_the_documented_one() {
        assert_eq!(
            serde_json::to_value(text_to_adf("first\r\nsecond\n\n\nthird")).expect("serializes"),
            json!({
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [
                        {"type": "text", "text": "first"},
                        {"type": "hardBreak"},
                        {"type": "text", "text": "second"}
                    ]},
                    {"type": "paragraph", "content": [{"type": "text", "text": "third"}]}
                ]
            })
        );
    }
}
