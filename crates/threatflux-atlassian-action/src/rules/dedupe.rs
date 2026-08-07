//! Dedupe identity: the label this Action writes, the labels it still
//! recognises, and the single query that finds either.
//!
//! # Identity is readable, and it is not the content
//!
//! [`canonical_label`] is `{prefix}-gh-{repository_id}-{issue_number}`. It is
//! not a digest, and that is deliberate three times over: `{repository_id}` and
//! `{issue_number}` are collision-free by construction where a truncated hash is
//! 48 bits of birthday problem, the label is legible in the Jira UI where a hex
//! digest is not, and every character it can produce is already JQL-safe.
//!
//! It is also *stable*, which the scheme it replaces was not.
//! [`LegacyLabelSpec::v0`] reproduces the scheme this crate shipped through
//! `0.4.x`: a SHA-256 over the values of the configured `dedupe.fields`, and
//! every shipped configuration lists `issue.title` among them. A title is
//! mutable, so retitling one GitHub issue used to mint a second Jira issue.
//!
//! **The change runs in both directions, and the second one is louder.** Two
//! *different* GitHub issues that share a title in one repository used to
//! collapse onto a single Jira issue; under [`canonical_label`] they are two.
//! For a feed that reuses titles across dependency bumps -- Dependabot
//! advisories above all -- that is a real and permanent increase in Jira ticket
//! volume. It is a behaviour change rather than a bug fix, and it belongs in the
//! release notes next to the retitle fix, not folded into it.
//!
//! # The ladder is one query, not four
//!
//! [`build_lookup_plan`] emits a single JQL query whose `labels IN (...)` clause
//! carries every rung at once, and [`rank_candidates`] recovers the precedence
//! client-side. Four queries would cost four round trips to answer a question
//! one round trip answers, and would make the answer depend on the order they
//! were asked in. Ranking is a pure function of the rows, so it is deterministic
//! and order-independent, and it is unit-testable without a mock server.
//!
//! # Legacy formats are configurable, never hardcoded
//!
//! [`LegacyLabelSpec`] spells out the digest, the truncation, the field order,
//! the joiner and whether the prefix participates in the preimage, because those
//! are exactly the parameters this repository cannot verify for the SHA-256/16
//! and SHA-1/12 labels a consumer reports having. A wrong guess baked into a
//! release costs a release cycle; a wrong guess in a caller-supplied spec costs
//! an edit. Only the `v0` rung is auto-registered, and it is auto-registered
//! because it is the one scheme this crate itself wrote and can prove.
//!
//! # The summary fallback is opt-in and post-filtered
//!
//! Issues created before any label existed can only be found by their summary,
//! and `summary ~ "..."` is a Lucene *text* match: it matches on word overlap,
//! stems, and quite happily on a different issue. So the fallback is off unless
//! a caller arms it, and when it is armed [`rank_candidates`] keeps a
//! summary-only row **only** if the row's summary is byte-equal to the one the
//! caller asked for. That post-filter is not optional and cannot be forgotten:
//! it lives on the [`LookupPlan`] that also put the term in the query, so there
//! is no way to run the query with the filter switched off.

use super::resolve_event_value;
use crate::config::{RuleConfig, DEDUPE_IDENTITY_FIELDS};
use crate::github::{EventIdentity, GitHubIssueEvent};
use crate::output::preview;
use anyhow::{Context as _, Result};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use std::fmt;
use threatflux_atlassian_sdk::jql::{
    quote_text_operand, try_quote_string_literal, JqlBuilder, JqlError,
};
use threatflux_atlassian_sdk::search::{SearchIssue, SearchRequest};

/// Label prefix applied when `jira.dedupe.label_prefix` is not configured.
///
/// Unchanged from the scheme this replaces: a consumer who never set a prefix
/// keeps the one their existing Jira issues carry.
pub const DEFAULT_LABEL_PREFIX: &str = "jira-automation";

/// Source-system tag between the prefix and the identity in a canonical label.
///
/// Present so that `{prefix}-42-7` cannot be read as a GitHub identity by
/// accident, and so a second source system can be added later without the two
/// namespaces colliding.
pub const CANONICAL_SOURCE_TAG: &str = "gh";

/// Longest label Jira accepts, in characters.
pub const MAX_LABEL_CHARS: usize = 255;

/// Fields the lookup query asks for.
///
/// `labels` and `summary` are what [`rank_candidates`] classifies a row by, so
/// dropping either would silently reclassify every row as "no match" -- which
/// fails closed, but fails. `status` is here for the reconciliation policy that
/// reads it; asking for it costs nothing and saves a second round trip.
pub const LOOKUP_FIELDS: &[&str] = &["summary", "labels", "status"];

/// Page size for the lookup query.
///
/// A dedupe ladder that matches more rows than this is a misconfiguration, not
/// a large result set, so the query is bounded rather than paginated.
pub const MAX_LOOKUP_RESULTS: u32 = 50;

/// A string that cannot be used as a Jira label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelError {
    /// The label is empty.
    Empty,
    /// The label is longer than [`MAX_LABEL_CHARS`] characters.
    TooLong {
        /// Length of the rejected label, in characters.
        chars: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The label carries a character outside `[A-Za-z0-9._-]`.
    ForbiddenCharacter {
        /// Byte offset of the offending character.
        index: usize,
        /// The offending character.
        character: char,
        /// The rejected label. Rendered through the crate's bounded
        /// `output::preview` helper when displayed, never echoed whole.
        label: String,
    },
}

impl fmt::Display for LabelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Jira label cannot be empty"),
            Self::TooLong { chars, limit } => write!(
                formatter,
                "Jira label is {chars} characters, over the {limit} character limit"
            ),
            // Previewed rather than echoed: a label is built from a
            // configuration value of unbounded length, and this message is
            // logged as well as returned.
            Self::ForbiddenCharacter {
                index,
                character,
                label,
            } => write!(
                formatter,
                "Jira label {} carries {character:?} at byte {index}, outside `[A-Za-z0-9._-]`",
                preview(label)
            ),
        }
    }
}

impl std::error::Error for LabelError {}

/// Reports whether `label` is a Jira label this crate is willing to write.
///
/// The rule is `[A-Za-z0-9._-]+` of at most [`MAX_LABEL_CHARS`] characters.
/// Jira's own label rule is narrower than "any string" -- a space ends a label
/// -- and this set is additionally the set that needs no JQL escaping, so a
/// label that passes here round-trips through a query unchanged.
///
/// This is the gate on labels this crate *mints*. It is deliberately not
/// applied to a legacy rung: a label that is already on a Jira issue has to be
/// queryable whatever it looks like, and refusing to look for it would strand
/// exactly the issues the migration exists to find.
///
/// # Errors
///
/// [`LabelError`], naming the first character that fails.
pub fn validate_label(label: &str) -> Result<(), LabelError> {
    if label.is_empty() {
        return Err(LabelError::Empty);
    }

    let chars = label.chars().count();
    if chars > MAX_LABEL_CHARS {
        return Err(LabelError::TooLong {
            chars,
            limit: MAX_LABEL_CHARS,
        });
    }

    for (index, character) in label.char_indices() {
        if !is_label_character(character) {
            return Err(LabelError::ForbiddenCharacter {
                index,
                character,
                label: label.to_owned(),
            });
        }
    }

    Ok(())
}

const fn is_label_character(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '-')
}

/// The label this Action writes for `identity`.
///
/// `{prefix}-gh-{repository_id}-{issue_number}`, with no hashing: see the module
/// documentation for why the identity is readable rather than digested.
///
/// Infallible, and so able to produce a label [`validate_label`] rejects, for
/// one reason: `label_prefix` is a consumer configuration value and the scheme
/// this replaces was equally permissive about it. Refusing here would turn a
/// configuration that reconciles today into a failed run. Callers that are about
/// to *write* the label use [`try_canonical_label`].
pub fn canonical_label(label_prefix: &str, identity: &EventIdentity) -> String {
    format!(
        "{label_prefix}-{CANONICAL_SOURCE_TAG}-{}-{}",
        identity.repository_id, identity.issue_number
    )
}

/// [`canonical_label`], validated.
///
/// # Errors
///
/// [`LabelError`] when the configured prefix pushes the label outside the set
/// Jira accepts.
pub fn try_canonical_label(
    label_prefix: &str,
    identity: &EventIdentity,
) -> Result<String, LabelError> {
    let label = canonical_label(label_prefix, identity);
    validate_label(&label)?;
    Ok(label)
}

/// The label `rule` writes for `event`, under the identity scheme it declares.
///
/// This is the dispatch on [`DedupeConfig::identity`](crate::config::DedupeConfig::identity),
/// and it is the only place that dispatch happens -- both the label written onto
/// a new issue ([`crate::rules::evaluate_rule`]) and the canonical rung of the
/// lookup ladder ([`build_lookup_plan`]) come through here, so a rule cannot
/// search for one label and write another.
///
/// - [`DEDUPE_IDENTITY_REPO_ISSUE`](crate::config::DEDUPE_IDENTITY_REPO_ISSUE)
///   (the default) is [`canonical_label`].
/// - [`DEDUPE_IDENTITY_FIELDS`] is [`v0_label`] -- the `0.4.x` content grouping,
///   which a consumer opts back into when they want title-level grouping on
///   purpose.
///
/// An identity the loader does not accept cannot reach here: `validate_config`
/// rejects it against [`SUPPORTED_DEDUPE_IDENTITY`](crate::config::SUPPORTED_DEDUPE_IDENTITY)
/// before a rule is evaluated. The unreachable arm therefore falls back to the
/// default scheme rather than panicking -- a mislabelled issue is recoverable and
/// a panicked Action run is not.
///
/// # Errors
///
/// Only under [`DEDUPE_IDENTITY_FIELDS`], and then as [`v0_label`]: a
/// `dedupe.fields` path the event model does not resolve. Unreachable for a
/// configuration that loaded. The `repo_issue` scheme is infallible, so the
/// default path cannot fail a run that used to succeed.
pub fn rule_identity_label(rule: &RuleConfig, event: &GitHubIssueEvent) -> Result<String> {
    let label_prefix = rule_label_prefix(rule);
    match rule.jira.dedupe.identity.as_str() {
        DEDUPE_IDENTITY_FIELDS => v0_label(label_prefix, &rule.jira.dedupe.fields, event),
        // `DEDUPE_IDENTITY_REPO_ISSUE`, and -- unreachably -- anything else.
        _ => Ok(canonical_label(label_prefix, &event.identity())),
    }
}

/// The label prefix `rule` writes with.
pub fn rule_label_prefix(rule: &RuleConfig) -> &str {
    rule.jira
        .dedupe
        .label_prefix
        .as_deref()
        .unwrap_or(DEFAULT_LABEL_PREFIX)
}

/// Digest a [`LegacyLabelSpec`] hashes its preimage with.
///
/// SHA-1 is present to *read* labels an earlier generation of routing scripts
/// wrote, and for nothing else. No path in this crate mints one: the label this
/// Action writes is [`canonical_label`], which does not hash at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelDigest {
    /// SHA-1, 40 hex characters. Recognition only.
    Sha1,
    /// SHA-256, 64 hex characters.
    Sha256,
}

impl LabelDigest {
    /// Length of the full hex rendering of this digest.
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    /// The name a configuration file spells this digest with.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    fn hex(self, preimage: &str) -> String {
        match self {
            Self::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(preimage.as_bytes());
                hex::encode(hasher.finalize())
            }
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(preimage.as_bytes());
                hex::encode(hasher.finalize())
            }
        }
    }
}

/// Where the label prefix sits inside the hashed preimage, if at all.
///
/// This is one of the three parameters this repository cannot verify for the
/// legacy schemes (the others being the field order and the joiner), which is
/// why it is a knob rather than an assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreimagePrefix {
    /// The prefix is not hashed. Only the field values are. This is `v0`.
    #[default]
    Excluded,
    /// The prefix is joined ahead of the field values.
    First,
    /// The prefix is joined after the field values.
    Last,
}

/// A dedupe label format this Action can recognise but does not write.
///
/// Every parameter of the preimage is explicit, so a consumer whose earlier
/// tooling used a different digest, truncation, field order or joiner can
/// describe it instead of waiting for a release that guesses right.
///
/// ```
/// use threatflux_atlassian_action::rules::dedupe::{LabelDigest, LegacyLabelSpec};
///
/// // A SHA-1/12 scheme over the repository and the issue number, prefix hashed.
/// let spec = LegacyLabelSpec::new(
///     "acme-sha1-12",
///     "jira-automation",
///     LabelDigest::Sha1,
///     12,
///     ["repository.full_name".to_string(), "issue.number".to_string()],
/// )
/// .with_joiner("|")
/// .with_preimage_prefix(threatflux_atlassian_action::rules::dedupe::PreimagePrefix::First);
///
/// spec.validate()?;
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyLabelSpec {
    /// Name this rung is reported under. Appears in [`LadderTier::Legacy`].
    pub id: String,
    /// Prefix the label starts with.
    pub label_prefix: String,
    /// Text between the prefix and the truncated digest.
    pub separator: String,
    /// Digest the preimage is hashed with.
    pub digest: LabelDigest,
    /// Number of leading hex characters of the digest kept.
    pub hex_chars: usize,
    /// Event field paths, in preimage order.
    pub fields: Vec<String>,
    /// Text the preimage elements are joined with.
    pub joiner: String,
    /// Whether, and where, the prefix joins the preimage.
    pub preimage_prefix: PreimagePrefix,
}

impl LegacyLabelSpec {
    /// The scheme this crate shipped through `0.4.x`.
    ///
    /// SHA-256 over the `dedupe.fields` values joined with a bare newline,
    /// truncated to 12 hex characters, appended to the prefix after a `-`. Live
    /// Jira issues carry these exact strings, so this reproduction is a wire
    /// format: `crates/threatflux-atlassian-action/tests/dedupe_v0_golden.rs`
    /// pins it against a golden table and an independent SHA-256 oracle.
    pub fn v0(label_prefix: &str, fields: &[String]) -> Self {
        Self {
            id: "v0-sha256-12".to_owned(),
            label_prefix: label_prefix.to_owned(),
            separator: "-".to_owned(),
            digest: LabelDigest::Sha256,
            hex_chars: 12,
            fields: fields.to_vec(),
            joiner: "\n".to_owned(),
            preimage_prefix: PreimagePrefix::Excluded,
        }
    }

    /// A spec with `v0`'s separator (`-`), joiner (`\n`) and preimage rule.
    pub fn new<I, S>(
        id: &str,
        label_prefix: &str,
        digest: LabelDigest,
        hex_chars: usize,
        fields: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            id: id.to_owned(),
            label_prefix: label_prefix.to_owned(),
            separator: "-".to_owned(),
            digest,
            hex_chars,
            fields: fields.into_iter().map(Into::into).collect(),
            joiner: "\n".to_owned(),
            preimage_prefix: PreimagePrefix::Excluded,
        }
    }

    /// Replaces the text between the prefix and the digest.
    #[must_use]
    pub fn with_separator(mut self, separator: &str) -> Self {
        separator.clone_into(&mut self.separator);
        self
    }

    /// Replaces the text the preimage elements are joined with.
    #[must_use]
    pub fn with_joiner(mut self, joiner: &str) -> Self {
        joiner.clone_into(&mut self.joiner);
        self
    }

    /// Sets whether, and where, the prefix joins the preimage.
    #[must_use]
    pub const fn with_preimage_prefix(mut self, preimage_prefix: PreimagePrefix) -> Self {
        self.preimage_prefix = preimage_prefix;
        self
    }

    /// Checks that this spec can produce a label at all.
    ///
    /// # Errors
    ///
    /// A blank id or prefix, an empty field list -- which would give every issue
    /// in the repository one shared label -- or a truncation length outside
    /// `1..=digest.hex_len()`.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.id.trim().is_empty(),
            "legacy dedupe label spec needs an id"
        );
        anyhow::ensure!(
            !self.label_prefix.is_empty(),
            "legacy dedupe label spec {} needs a label prefix",
            preview(&self.id)
        );
        anyhow::ensure!(
            !self.fields.is_empty(),
            "legacy dedupe label spec {} needs at least one field: a preimage with no fields \
             gives every issue the same label",
            preview(&self.id)
        );
        anyhow::ensure!(
            self.hex_chars >= 1 && self.hex_chars <= self.digest.hex_len(),
            "legacy dedupe label spec {} keeps {} hex characters, outside 1..={} for {}",
            preview(&self.id),
            self.hex_chars,
            self.digest.hex_len(),
            self.digest.name()
        );
        Ok(())
    }

    /// The label this spec produces for `event`.
    ///
    /// # Errors
    ///
    /// [`validate`](Self::validate)'s failures, or a field path the event model
    /// does not resolve.
    pub fn label(&self, event: &GitHubIssueEvent) -> Result<String> {
        self.validate()?;

        let mut values = Vec::with_capacity(self.fields.len() + 1);
        if self.preimage_prefix == PreimagePrefix::First {
            values.push(self.label_prefix.clone());
        }
        for field in &self.fields {
            values.push(resolve_event_value(field, event)?);
        }
        if self.preimage_prefix == PreimagePrefix::Last {
            values.push(self.label_prefix.clone());
        }

        let digest = self.digest.hex(&values.join(&self.joiner));
        // `validate` bounded `hex_chars` by the digest's own hex length, and hex
        // is ASCII, so every index in that range is a character boundary.
        let truncated = &digest[..self.hex_chars];
        Ok(format!(
            "{}{}{truncated}",
            self.label_prefix, self.separator
        ))
    }
}

/// The label the `0.4.x` releases wrote, reproduced byte for byte.
///
/// Kept as a named function rather than left implicit in
/// [`LegacyLabelSpec::v0`] because it is the compatibility contract: an issue
/// created by an earlier release is found again only if this returns exactly
/// what that release wrote.
///
/// # Errors
///
/// As [`LegacyLabelSpec::label`]. Unreachable for a configuration that loaded:
/// `validate_config` already rejects an empty `dedupe.fields` and any field path
/// outside the allowlist.
pub fn v0_label(label_prefix: &str, fields: &[String], event: &GitHubIssueEvent) -> Result<String> {
    LegacyLabelSpec::v0(label_prefix, fields).label(event)
}

/// Which rung of the ladder a row matched on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LadderTier {
    /// The label this Action writes today.
    Canonical,
    /// A legacy label, `rung` counting from zero in registration order.
    Legacy {
        /// Position among the legacy rungs; `0` is the highest-precedence one.
        rung: usize,
        /// [`LegacyLabelSpec::id`] of the rung that matched.
        spec_id: String,
    },
    /// No label matched; the opt-in summary fallback did, exactly.
    SummaryFallback,
}

impl LadderTier {
    /// Sort position: lower is higher precedence.
    const fn order(&self) -> (u8, usize) {
        match self {
            Self::Canonical => (0, 0),
            Self::Legacy { rung, .. } => (1, *rung),
            Self::SummaryFallback => (2, 0),
        }
    }
}

/// One label the lookup query asks for, and the rung it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderLabel {
    /// The label as it appears in the query.
    pub label: String,
    /// The rung this label came from.
    pub tier: LadderTier,
}

/// Knobs on [`build_lookup_plan`] beyond what the rule itself carries.
///
/// Both default to off, so a plan built with [`LookupOptions::default`] asks
/// exactly what today's reconciliation asks plus the auto-registered `v0` rung.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LookupOptions {
    /// Legacy rungs, in precedence order, after the auto-registered `v0` rung.
    pub legacy_labels: Vec<LegacyLabelSpec>,
    /// Exact summary to fall back on for issues created before labels existed.
    ///
    /// `None` -- the default -- keeps the summary term out of the query
    /// entirely. `Some` puts a `summary ~ "..."` term in the query **and** arms
    /// the exact post-filter in [`rank_candidates`]; the two are set together
    /// and cannot be separated.
    pub summary_fallback: Option<String>,
}

impl LookupOptions {
    /// Registers legacy rungs, in precedence order.
    #[must_use]
    pub fn with_legacy_labels<I>(mut self, specs: I) -> Self
    where
        I: IntoIterator<Item = LegacyLabelSpec>,
    {
        self.legacy_labels.extend(specs);
        self
    }

    /// Arms the summary fallback against an exact summary.
    #[must_use]
    pub fn with_summary_fallback(mut self, summary: impl Into<String>) -> Self {
        self.summary_fallback = Some(summary.into());
        self
    }
}

/// One JQL query that finds every issue any rung of the ladder would match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupPlan {
    jql: String,
    canonical: String,
    labels: Vec<LadderLabel>,
    summary_filter: Option<String>,
}

impl LookupPlan {
    /// The single query to send.
    pub fn jql(&self) -> &str {
        &self.jql
    }

    /// The label this Action writes for the delivery the plan was built from.
    pub fn canonical_label(&self) -> &str {
        &self.canonical
    }

    /// Every label in the query, canonical first, then the legacy rungs.
    pub fn labels(&self) -> &[LadderLabel] {
        &self.labels
    }

    /// The exact summary a summary-only row has to carry to count.
    ///
    /// `Some` exactly when the query carries a `summary ~` term.
    pub fn summary_filter(&self) -> Option<&str> {
        self.summary_filter.as_deref()
    }

    /// The enhanced-search request for [`jql`](Self::jql).
    ///
    /// Asks for [`LOOKUP_FIELDS`], which is what makes the client-side
    /// classification possible: a narrower field set would leave every row
    /// looking unlabelled.
    pub fn search_request(&self) -> SearchRequest {
        SearchRequest::new(self.jql.clone())
            .with_fields(LOOKUP_FIELDS.iter().copied())
            .with_max_results(MAX_LOOKUP_RESULTS)
    }
}

/// Builds the one query that answers "is there already a Jira issue for this".
///
/// The ladder is, in precedence order: the canonical label, the auto-registered
/// `v0` rung derived from `rule.jira.dedupe`, then `options.legacy_labels` in
/// the order given. A rung whose label repeats one already in the ladder is
/// dropped rather than queried twice, so a consumer who declares `v0`
/// explicitly gets the same query as one who does not.
///
/// # Errors
///
/// A legacy spec that does not [`validate`](LegacyLabelSpec::validate), a field
/// path the event model does not resolve, a blank summary fallback, or a project
/// key or label carrying U+0000 -- the one character JQL cannot escape.
pub fn build_lookup_plan(
    rule: &RuleConfig,
    event: &GitHubIssueEvent,
    options: &LookupOptions,
) -> Result<LookupPlan> {
    build_lookup_plan_inner(rule, event, options).with_context(|| {
        format!(
            "Rule {} cannot build a dedupe lookup plan",
            preview(&rule.id)
        )
    })
}

fn build_lookup_plan_inner(
    rule: &RuleConfig,
    event: &GitHubIssueEvent,
    options: &LookupOptions,
) -> Result<LookupPlan> {
    let label_prefix = rule_label_prefix(rule);
    // Whatever identity scheme the rule declares. Under `fields` this *is* the
    // `v0` label, and the de-duplication in the rung loop below then drops the
    // auto-registered `v0` entry as a repeat -- so the opt-out yields exactly
    // the single-label query `0.4.x` issued, not the same label queried twice.
    let canonical = rule_identity_label(rule, event)?;

    let mut labels = vec![LadderLabel {
        label: canonical.clone(),
        tier: LadderTier::Canonical,
    }];

    // The `v0` rung is registered without being asked for. Every issue an
    // earlier release created carries that label and nothing else, so a
    // consumer would otherwise have to edit their configuration to keep
    // reconciling against issues they already have.
    let v0 = LegacyLabelSpec::v0(label_prefix, &rule.jira.dedupe.fields);
    let mut rung = 0;
    for spec in std::iter::once(&v0).chain(options.legacy_labels.iter()) {
        let label = spec.label(event)?;
        if labels.iter().any(|entry| entry.label == label) {
            continue;
        }
        labels.push(LadderLabel {
            label,
            tier: LadderTier::Legacy {
                rung,
                spec_id: spec.id.clone(),
            },
        });
        rung += 1;
    }

    let summary_filter = match options.summary_fallback.as_deref() {
        None => None,
        Some(summary) => {
            anyhow::ensure!(
                !summary.trim().is_empty(),
                "the summary fallback needs a summary: a blank text operand matches nothing \
                 usefully and everything cheaply"
            );
            Some(summary.to_owned())
        }
    };

    let jql = build_lookup_jql(&rule.jira.project_key, &labels, summary_filter.as_deref())?;

    Ok(LookupPlan {
        jql,
        canonical,
        labels,
        summary_filter,
    })
}

/// Renders `project = "..." AND labels IN (...)`, with an optional `OR summary ~`.
///
/// The membership term is assembled by hand and passed through
/// [`JqlBuilder::raw_term`] rather than through
/// [`JqlBuilder::in_list`](threatflux_atlassian_sdk::jql::JqlBuilder::in_list),
/// for one reason: the builder joins its terms with `AND` and has no `OR` group,
/// and the fallback needs the labels and the summary inside one. Every operand
/// still goes through the SDK's own escapers -- nothing caller-derived is
/// interpolated raw -- and the no-fallback rendering is asserted byte-identical
/// to what `in_list` emits, so the hand assembly cannot drift from it.
fn build_lookup_jql(
    project_key: &str,
    labels: &[LadderLabel],
    summary_filter: Option<&str>,
) -> Result<String, JqlError> {
    let mut operands = Vec::with_capacity(labels.len());
    for entry in labels {
        operands.push(try_quote_string_literal(&entry.label)?);
    }

    let mut term = format!("labels IN ({})", operands.join(", "));
    if let Some(summary) = summary_filter {
        term = format!("({term} OR summary ~ {})", quote_text_operand(summary)?);
    }

    JqlBuilder::new()
        .eq("project", project_key)?
        .raw_term(&term)?
        .build()
}

/// A row the ladder claims, and the rung it was claimed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Jira issue key, such as `KAN-42`.
    pub issue_key: String,
    /// Numeric Jira id, absent only for a malformed response.
    pub issue_id: Option<i64>,
    /// The rung that claimed this row.
    pub tier: LadderTier,
}

impl Candidate {
    fn order_key(&self) -> ((u8, usize), i64, &str) {
        (
            self.tier.order(),
            // A row whose id did not parse sorts last rather than first: it
            // must never win an election by looking like id zero.
            self.issue_id.unwrap_or(i64::MAX),
            self.issue_key.as_str(),
        )
    }
}

/// Ranks the rows one lookup returned, highest precedence first.
///
/// Rows are ordered by rung, then by ascending numeric Jira id, then by key.
/// The numeric id matters: Jira sends ids as strings, and `"10100"` sorts before
/// `"9999"` as text, so an election run on the string would pick a different
/// winner than one run on the number. The key is the last tiebreak so that two
/// rows with the same unparseable id still order deterministically.
///
/// **Rows the ladder does not claim are dropped**, and that is where the summary
/// fallback's post-filter lives. `summary ~ "..."` is a Lucene text match, so
/// the query happily returns issues whose summary merely shares words with the
/// one asked for; a row that carries no ladder label survives only if its
/// summary is byte-equal to [`LookupPlan::summary_filter`]. When the fallback
/// was never armed there is no filter to pass, and such a row is dropped
/// outright.
pub fn rank_candidates(plan: &LookupPlan, issues: &[SearchIssue]) -> Vec<Candidate> {
    let mut candidates: Vec<Candidate> = issues
        .iter()
        .filter_map(|issue| classify_candidate(plan, issue))
        .collect();
    candidates.sort_by(|left, right| left.order_key().cmp(&right.order_key()));
    candidates
}

fn classify_candidate(plan: &LookupPlan, issue: &SearchIssue) -> Option<Candidate> {
    // `plan.labels` is already in precedence order, so the first hit is the
    // best one and the scan does not need to look at the rest.
    let labelled = plan
        .labels
        .iter()
        .find(|entry| issue.fields.has_label(&entry.label));

    let tier = if let Some(entry) = labelled {
        entry.tier.clone()
    } else {
        // The mandatory post-filter. Reached only when the fallback was armed,
        // and passed only on a byte-equal summary.
        let expected = plan.summary_filter.as_deref()?;
        let actual = issue.fields.summary.as_deref()?;
        if actual != expected {
            return None;
        }
        LadderTier::SummaryFallback
    };

    Some(Candidate {
        issue_key: issue.key.clone(),
        issue_id: issue.numeric_id(),
        tier,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_lookup_plan, canonical_label, rank_candidates, rule_identity_label,
        rule_label_prefix, try_canonical_label, v0_label, Candidate, LabelDigest, LabelError,
        LadderTier, LegacyLabelSpec, LookupOptions, PreimagePrefix, DEDUPE_IDENTITY_FIELDS,
        DEFAULT_LABEL_PREFIX, LOOKUP_FIELDS, MAX_LABEL_CHARS,
    };
    use crate::config::{
        load_config_from_str, RuleConfig, DEDUPE_IDENTITY_REPO_ISSUE, DEFAULT_DEDUPE_IDENTITY,
        SUPPORTED_DEDUPE_IDENTITY,
    };
    use crate::github::{load_issue_event_from_str, GitHubIssueEvent};
    use serde_json::json;
    use sha1::Sha1;
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    use threatflux_atlassian_sdk::jql::JqlBuilder;
    use threatflux_atlassian_sdk::search::SearchIssue;
    use threatflux_atlassian_testkit::fixtures;

    fn parse_event(name: &str) -> GitHubIssueEvent {
        load_issue_event_from_str("issues", fixtures::github_event(name))
            .expect("event should parse")
    }

    fn shipped_rule() -> RuleConfig {
        let mut config = load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("the shipped dependabot config should load");
        config.rules.remove(0)
    }

    fn repo_and_title() -> Vec<String> {
        vec![
            "repository.full_name".to_string(),
            "issue.title".to_string(),
        ]
    }

    /// A second implementation of the `v0` preimage, for the byte-for-byte pin.
    fn sha256_hex(preimage: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(preimage.as_bytes());
        let mut rendered = String::with_capacity(64);
        for byte in hasher.finalize() {
            write!(&mut rendered, "{byte:02x}").expect("write to string");
        }
        rendered
    }

    fn sha1_hex(preimage: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(preimage.as_bytes());
        let mut rendered = String::with_capacity(40);
        for byte in hasher.finalize() {
            write!(&mut rendered, "{byte:02x}").expect("write to string");
        }
        rendered
    }

    fn issue(key: &str, id: &str, labels: &[&str], summary: Option<&str>) -> SearchIssue {
        let mut fields = json!({ "labels": labels });
        if let Some(summary) = summary {
            fields["summary"] = json!(summary);
        }
        serde_json::from_value(json!({ "id": id, "key": key, "fields": fields }))
            .expect("the search issue fixture should parse")
    }

    #[test]
    fn canonical_label_is_the_readable_repository_and_issue_pair() {
        let event = parse_event("issues-opened-dependabot");

        assert_eq!(
            canonical_label("dependabot-alert", &event.identity()),
            "dependabot-alert-gh-598178766-123"
        );
    }

    #[test]
    fn canonical_label_survives_a_retitle_and_separates_two_issues_in_one_repository() {
        let one = parse_event("issues-opened-dependabot");
        let two = parse_event("issues-opened-dependabot-high");
        assert_eq!(one.repository.id, two.repository.id);

        let mut retitled = fixtures::github_event_json("issues-opened-dependabot");
        retitled["issue"]["title"] = json!("Bump openssl from 1.0 to 1.1.1");
        let retitled = load_issue_event_from_str("issues", &retitled.to_string())
            .expect("the retitled delivery should parse");

        assert_eq!(
            canonical_label("p", &one.identity()),
            canonical_label("p", &retitled.identity()),
            "a retitle may not move the identity"
        );
        assert_ne!(
            canonical_label("p", &one.identity()),
            canonical_label("p", &two.identity()),
            "two issues in one repository may not share an identity"
        );
    }

    #[test]
    fn validate_label_accepts_the_labels_this_crate_mints() {
        let event = parse_event("issues-opened-dependabot");

        for prefix in ["dependabot-alert", DEFAULT_LABEL_PREFIX, "a.b_c-d", "X9"] {
            let label = try_canonical_label(prefix, &event.identity())
                .unwrap_or_else(|error| panic!("prefix {prefix:?} was rejected: {error}"));
            assert!(label.starts_with(prefix));
        }
    }

    #[test]
    fn validate_label_rejects_the_shapes_jira_will_not_carry() {
        assert_eq!(super::validate_label(""), Err(LabelError::Empty));

        let long = "a".repeat(MAX_LABEL_CHARS + 1);
        assert_eq!(
            super::validate_label(&long),
            Err(LabelError::TooLong {
                chars: MAX_LABEL_CHARS + 1,
                limit: MAX_LABEL_CHARS,
            })
        );
        assert!(super::validate_label(&"a".repeat(MAX_LABEL_CHARS)).is_ok());

        for (label, index, character) in [
            ("has space", 3, ' '),
            ("dep\"bot-gh-1-2", 3, '"'),
            ("dep'bot", 3, '\''),
            ("tab\there", 3, '\t'),
            ("emoji-\u{1f680}", 6, '\u{1f680}'),
        ] {
            assert_eq!(
                super::validate_label(label),
                Err(LabelError::ForbiddenCharacter {
                    index,
                    character,
                    label: label.to_string(),
                }),
                "label {label:?}"
            );
        }
    }

    #[test]
    fn validate_label_counts_characters_rather_than_bytes() {
        // 255 two-byte characters is 510 bytes and still a legal length; the
        // charset is what rejects it, not the limit.
        let accented = "\u{e9}".repeat(MAX_LABEL_CHARS);
        assert_eq!(accented.len(), MAX_LABEL_CHARS * 2);
        assert!(matches!(
            super::validate_label(&accented),
            Err(LabelError::ForbiddenCharacter { .. })
        ));
    }

    #[test]
    fn a_forbidden_character_error_is_bounded_and_single_line() {
        let label = format!("{}\n{}", "a".repeat(4096), "b".repeat(4096));
        let rendered = super::validate_label(&label)
            .expect_err("a newline is not a label character")
            .to_string();

        assert!(rendered.len() < 200, "unbounded error: {rendered}");
        assert!(!rendered.contains('\n'), "error broke its log line");
    }

    #[test]
    fn v0_label_reproduces_the_shipped_scheme_byte_for_byte() {
        let event = parse_event("issues-opened-dependabot");
        let values = ["ThreatFlux/demo", "Bump openssl from 1.0 to 1.1"];
        let expected = format!("dependabot-alert-{}", &sha256_hex(&values.join("\n"))[..12]);

        assert_eq!(
            v0_label("dependabot-alert", &repo_and_title(), &event).expect("v0 label should build"),
            expected
        );
        // The literal the golden vector pins, restated here so a change to the
        // oracle above cannot make both sides move together.
        assert_eq!(expected, "dependabot-alert-e6bebe4d0a17");
    }

    #[test]
    fn the_v0_rung_is_expressible_as_an_ordinary_configurable_spec() {
        // The whole point of the spec being data: the one scheme this crate can
        // prove is reproduced by the same machinery a consumer configures, so a
        // consumer-supplied legacy format is not on a separate, untested path.
        let event = parse_event("issues-opened-dependabot");
        let configured = LegacyLabelSpec::new(
            "restated-v0",
            "dependabot-alert",
            LabelDigest::Sha256,
            12,
            repo_and_title(),
        )
        .with_separator("-")
        .with_joiner("\n")
        .with_preimage_prefix(PreimagePrefix::Excluded);

        assert_eq!(
            configured.label(&event).expect("spec should build a label"),
            v0_label("dependabot-alert", &repo_and_title(), &event).expect("v0 label should build")
        );
    }

    #[test]
    fn a_spec_can_name_sha1_and_sixteen_hex_characters() {
        // Q1's two unverifiable formats, expressed without a code change.
        let event = parse_event("issues-opened-dependabot");

        let sha1_12 = LegacyLabelSpec::new(
            "consumer-sha1-12",
            "jira-automation",
            LabelDigest::Sha1,
            12,
            repo_and_title(),
        );
        let sha256_16 = LegacyLabelSpec::new(
            "consumer-sha256-16",
            "jira-automation",
            LabelDigest::Sha256,
            16,
            repo_and_title(),
        );

        let preimage = "ThreatFlux/demo\nBump openssl from 1.0 to 1.1";
        assert_eq!(
            sha1_12.label(&event).expect("sha1 spec should build"),
            format!("jira-automation-{}", &sha1_hex(preimage)[..12])
        );
        assert_eq!(
            sha256_16
                .label(&event)
                .expect("sha256/16 spec should build"),
            format!("jira-automation-{}", &sha256_hex(preimage)[..16])
        );
    }

    #[test]
    fn a_spec_can_move_the_joiner_the_field_order_and_the_prefix() {
        // The three parameters this repository cannot verify. Each has to change
        // the label, or the knob is decoration.
        let event = parse_event("issues-opened-dependabot");
        let base = LegacyLabelSpec::new(
            "base",
            "jira-automation",
            LabelDigest::Sha256,
            12,
            repo_and_title(),
        );
        let baseline = base.label(&event).expect("base spec should build");

        let joined = base
            .clone()
            .with_joiner("|")
            .label(&event)
            .expect("joiner variant should build");
        let reordered = LegacyLabelSpec::new(
            "reordered",
            "jira-automation",
            LabelDigest::Sha256,
            12,
            [
                "issue.title".to_string(),
                "repository.full_name".to_string(),
            ],
        )
        .label(&event)
        .expect("field-order variant should build");
        let prefixed = base
            .clone()
            .with_preimage_prefix(PreimagePrefix::First)
            .label(&event)
            .expect("prefix-first variant should build");
        let suffixed = base
            .with_preimage_prefix(PreimagePrefix::Last)
            .label(&event)
            .expect("prefix-last variant should build");

        for (name, variant) in [
            ("joiner", &joined),
            ("field order", &reordered),
            ("prefix first", &prefixed),
            ("prefix last", &suffixed),
        ] {
            assert_ne!(&baseline, variant, "{name} did not change the label");
        }
        assert_ne!(
            prefixed, suffixed,
            "prefix position must be distinguishable"
        );
    }

    #[test]
    fn a_spec_with_a_separator_of_its_own_keeps_it() {
        let event = parse_event("issues-opened-dependabot");
        let label = LegacyLabelSpec::new(
            "underscored",
            "jira-automation",
            LabelDigest::Sha256,
            12,
            repo_and_title(),
        )
        .with_separator("_")
        .label(&event)
        .expect("separator variant should build");

        assert!(label.starts_with("jira-automation_"), "label: {label}");
    }

    #[test]
    fn spec_validation_refuses_the_specs_that_cannot_identify_anything() {
        let event = parse_event("issues-opened-dependabot");
        let base = LegacyLabelSpec::new(
            "base",
            "jira-automation",
            LabelDigest::Sha256,
            12,
            repo_and_title(),
        );

        let mut no_fields = base.clone();
        no_fields.fields.clear();
        assert!(no_fields
            .label(&event)
            .expect_err("an empty preimage labels every issue the same")
            .to_string()
            .contains("at least one field"));

        let mut over_long = base.clone();
        over_long.hex_chars = 65;
        assert!(over_long
            .label(&event)
            .expect_err("65 hex characters do not exist in a SHA-256")
            .to_string()
            .contains("outside 1..=64"));

        let mut zero = base.clone();
        zero.hex_chars = 0;
        assert!(zero.label(&event).is_err());

        let mut sha1_too_long = base.clone();
        sha1_too_long.digest = LabelDigest::Sha1;
        sha1_too_long.hex_chars = 41;
        assert!(sha1_too_long
            .label(&event)
            .expect_err("41 hex characters do not exist in a SHA-1")
            .to_string()
            .contains("outside 1..=40"));

        let mut unnamed = base.clone();
        unnamed.id = "   ".to_string();
        assert!(unnamed.label(&event).is_err());

        let mut unprefixed = base;
        unprefixed.label_prefix = String::new();
        assert!(unprefixed.label(&event).is_err());
    }

    #[test]
    fn rule_label_prefix_falls_back_to_the_documented_default() {
        let mut rule = shipped_rule();
        assert_eq!(rule_label_prefix(&rule), "dependabot-alert");

        rule.jira.dedupe.label_prefix = None;
        assert_eq!(rule_label_prefix(&rule), DEFAULT_LABEL_PREFIX);
    }

    #[test]
    fn the_identity_names_the_dispatch_knows_are_the_ones_the_loader_accepts() {
        // `rule_identity_label` matches on two names and treats everything else
        // as the default. That is only safe while the loader refuses every other
        // name, so the two lists have to be the same list.
        assert_eq!(
            SUPPORTED_DEDUPE_IDENTITY,
            [DEDUPE_IDENTITY_REPO_ISSUE, DEDUPE_IDENTITY_FIELDS],
            "the dispatch and the loader disagree about which identities exist"
        );
        assert_eq!(DEFAULT_DEDUPE_IDENTITY, DEDUPE_IDENTITY_REPO_ISSUE);
    }

    #[test]
    fn the_declared_identity_decides_the_label_the_rule_writes() {
        // `jira.dedupe.identity` is documented in USAGE.md as the opt-out from
        // this release's identity change. A key that validates and then changes
        // nothing is worse than no key at all: a consumer who sets it believes
        // they kept `0.4.x` grouping and silently did not.
        let event = parse_event("issues-opened-dependabot");
        let mut rule = shipped_rule();

        assert_eq!(
            rule.jira.dedupe.identity, DEDUPE_IDENTITY_REPO_ISSUE,
            "the shipped config should exercise the default"
        );
        assert_eq!(
            rule_identity_label(&rule, &event).expect("the default identity is infallible"),
            canonical_label(rule_label_prefix(&rule), &event.identity())
        );

        rule.jira.dedupe.identity = DEDUPE_IDENTITY_FIELDS.to_string();
        assert_eq!(
            rule_identity_label(&rule, &event).expect("the fields identity resolves"),
            v0_label(rule_label_prefix(&rule), &rule.jira.dedupe.fields, &event)
                .expect("the v0 label resolves"),
            "`identity: fields` must write the 0.4.x content digest"
        );
    }

    #[test]
    fn the_fields_identity_reaches_the_written_label_and_the_lookup_together() {
        // The two consumers of the dispatch must not disagree: a rule that
        // searches for one label and writes another finds nothing, creates a
        // second issue, and does it again on every delivery.
        let event = parse_event("issues-opened-dependabot");
        let mut rule = shipped_rule();
        rule.jira.dedupe.identity = DEDUPE_IDENTITY_FIELDS.to_string();

        let written = crate::rules::evaluate_rule(&rule, &event)
            .expect("the rule evaluates")
            .expect("the shipped rule matches its own fixture")
            .dedupe_label;
        let plan =
            build_lookup_plan(&rule, &event, &LookupOptions::default()).expect("plan should build");

        assert_eq!(written, plan.canonical_label());
        assert_eq!(
            written,
            v0_label(rule_label_prefix(&rule), &rule.jira.dedupe.fields, &event)
                .expect("the v0 label resolves")
        );

        // The auto-registered `v0` rung is the same label, so it is dropped as a
        // repeat rather than queried twice: the opt-out reproduces the single
        // label query `0.4.x` issued.
        assert_eq!(
            plan.labels().len(),
            1,
            "expected one rung, got {:?}",
            plan.labels()
        );
        assert_eq!(plan.labels()[0].tier, LadderTier::Canonical);
    }

    #[test]
    fn the_two_identities_do_not_produce_the_same_label() {
        // Guards the previous two tests against passing vacuously.
        let event = parse_event("issues-opened-dependabot");
        let mut rule = shipped_rule();
        let repo_issue = rule_identity_label(&rule, &event).expect("resolves");

        rule.jira.dedupe.identity = DEDUPE_IDENTITY_FIELDS.to_string();
        let fields = rule_identity_label(&rule, &event).expect("resolves");

        assert_ne!(repo_issue, fields);
    }

    #[test]
    fn the_lookup_is_one_query_carrying_every_rung() {
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");
        let extra = LegacyLabelSpec::new(
            "consumer-sha1-12",
            "dependabot-alert",
            LabelDigest::Sha1,
            12,
            repo_and_title(),
        );
        let options = LookupOptions::default().with_legacy_labels([extra.clone()]);

        let plan = build_lookup_plan(&rule, &event, &options).expect("plan should build");

        assert_eq!(plan.canonical_label(), "dependabot-alert-gh-598178766-123");
        assert_eq!(
            plan.labels()
                .iter()
                .map(|entry| entry.label.clone())
                .collect::<Vec<_>>(),
            vec![
                "dependabot-alert-gh-598178766-123".to_string(),
                v0_label("dependabot-alert", &repo_and_title(), &event).expect("v0 label"),
                extra.label(&event).expect("extra label"),
            ]
        );
        assert_eq!(
            plan.labels()
                .iter()
                .map(|entry| entry.tier.clone())
                .collect::<Vec<_>>(),
            vec![
                LadderTier::Canonical,
                LadderTier::Legacy {
                    rung: 0,
                    spec_id: "v0-sha256-12".to_string(),
                },
                LadderTier::Legacy {
                    rung: 1,
                    spec_id: "consumer-sha1-12".to_string(),
                },
            ]
        );
        // One query, and one `labels IN` clause inside it.
        assert_eq!(plan.jql().matches("labels IN (").count(), 1);
        assert!(!plan.jql().contains(" OR "), "query: {}", plan.jql());
    }

    #[test]
    fn the_membership_term_is_rendered_exactly_as_the_sdk_renders_one() {
        // The term is assembled by hand because the builder has no OR group.
        // This is what keeps the hand assembly from drifting away from the
        // escaping and spacing the SDK would have produced.
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");
        let plan =
            build_lookup_plan(&rule, &event, &LookupOptions::default()).expect("plan should build");

        let expected = JqlBuilder::new()
            .eq("project", &rule.jira.project_key)
            .and_then(|builder| {
                builder.in_list("labels", plan.labels().iter().map(|entry| &entry.label))
            })
            .and_then(JqlBuilder::build)
            .expect("the SDK should render the same query");

        assert_eq!(plan.jql(), expected);
    }

    #[test]
    fn a_rung_repeating_a_label_already_in_the_ladder_is_not_queried_twice() {
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");
        let restated_v0 = LegacyLabelSpec::v0("dependabot-alert", &repo_and_title());

        let plain =
            build_lookup_plan(&rule, &event, &LookupOptions::default()).expect("plan should build");
        let restated = build_lookup_plan(
            &rule,
            &event,
            &LookupOptions::default().with_legacy_labels([restated_v0]),
        )
        .expect("plan should build");

        assert_eq!(plain.jql(), restated.jql());
        assert_eq!(plain.labels().len(), 2);
    }

    #[test]
    fn the_v0_rung_is_registered_without_being_asked_for() {
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");
        let plan =
            build_lookup_plan(&rule, &event, &LookupOptions::default()).expect("plan should build");

        let v0 = v0_label("dependabot-alert", &repo_and_title(), &event).expect("v0 label");
        assert!(plan.jql().contains(&v0), "query: {}", plan.jql());
        assert_eq!(
            plan.labels()[1].tier,
            LadderTier::Legacy {
                rung: 0,
                spec_id: "v0-sha256-12".to_string(),
            }
        );
    }

    #[test]
    fn the_summary_term_and_the_post_filter_are_set_together_or_not_at_all() {
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");

        let off =
            build_lookup_plan(&rule, &event, &LookupOptions::default()).expect("plan should build");
        assert_eq!(off.summary_filter(), None);
        assert!(!off.jql().contains("summary ~"), "query: {}", off.jql());

        let on = build_lookup_plan(
            &rule,
            &event,
            &LookupOptions::default().with_summary_fallback("[Dependabot][High] Bump openssl"),
        )
        .expect("plan should build");
        assert_eq!(on.summary_filter(), Some("[Dependabot][High] Bump openssl"));
        assert!(on.jql().contains("summary ~"), "query: {}", on.jql());
        assert_eq!(
            on.jql().contains("summary ~"),
            on.summary_filter().is_some(),
            "the query term and the post-filter may never disagree"
        );
        assert!(
            on.jql().contains(" OR summary ~ "),
            "the fallback has to widen the one query, not replace the labels: {}",
            on.jql()
        );
    }

    #[test]
    fn a_blank_summary_fallback_is_refused_rather_than_armed() {
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");

        let error = build_lookup_plan(
            &rule,
            &event,
            &LookupOptions::default().with_summary_fallback("   "),
        )
        .expect_err("a blank text operand may not reach the query");
        assert!(format!("{error:#}").contains("summary fallback needs a summary"));
    }

    /// Replaces every JQL string literal with nothing, leaving the skeleton.
    ///
    /// Comparing skeletons is what proves a hostile value stayed inside its own
    /// token: a value that merely *contains* `OR project = ` is inert, and a
    /// value that escaped its literal changes the shape this leaves behind.
    fn jql_skeleton(jql: &str) -> String {
        let mut skeleton = String::new();
        let mut chars = jql.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '"' => {
                    while let Some(inner) = chars.next() {
                        match inner {
                            '\\' => {
                                chars.next();
                            }
                            '"' => break,
                            _ => {}
                        }
                    }
                }
                other => skeleton.push(other),
            }
        }
        skeleton
    }

    #[test]
    fn hostile_configuration_and_summary_text_stay_inside_their_own_terms() {
        let mut rule = shipped_rule();
        rule.jira.project_key = r#"KAN" OR project = "EVIL"#.to_string();
        rule.jira.dedupe.label_prefix = Some(r#"dep"bot"#.to_string());
        let event = parse_event("issues-opened-dependabot");

        let plan = build_lookup_plan(
            &rule,
            &event,
            &LookupOptions::default()
                .with_summary_fallback(r#"x" OR summary ~ "y ORDER BY created DESC"#),
        )
        .expect("plan should build");

        // One project term, one label set, one summary term, and no ORDER BY:
        // every hostile fragment is inside a literal, where it is inert text.
        assert_eq!(
            jql_skeleton(plan.jql()),
            "project =  AND (labels IN (, ) OR summary ~ )",
            "query: {}",
            plan.jql()
        );
        assert!(
            plan.jql()
                .starts_with(r#"project = "KAN\" OR project = \"EVIL""#),
            "query: {}",
            plan.jql()
        );
        // The prefix's `"` reaches the label and is escaped rather than refused:
        // a label already on a Jira issue has to stay queryable.
        assert!(
            plan.jql().contains(r#""dep\"bot-gh-598178766-123""#),
            "query: {}",
            plan.jql()
        );
    }

    #[test]
    fn a_nul_in_the_project_key_is_reported_rather_than_sent() {
        let mut rule = shipped_rule();
        rule.jira.project_key = "K\0AN".to_string();
        let event = parse_event("issues-opened-dependabot");

        let error = build_lookup_plan(&rule, &event, &LookupOptions::default())
            .expect_err("a NUL has no JQL escape sequence");
        assert!(format!("{error:#}").contains("cannot build a dedupe lookup plan"));
        assert!(format!("{error:#}").contains("NUL character"));
    }

    #[test]
    fn the_search_request_asks_for_the_fields_the_post_filter_needs() {
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");
        let plan =
            build_lookup_plan(&rule, &event, &LookupOptions::default()).expect("plan should build");

        let request = plan.search_request();
        request.validate().expect("the request should validate");
        assert_eq!(request.jql(), plan.jql());
        for needed in ["summary", "labels"] {
            assert!(
                request.fields().iter().any(|field| field == needed),
                "the classification reads {needed} and the request has to ask for it"
            );
        }
        assert_eq!(request.fields(), LOOKUP_FIELDS);
    }

    fn ranking_plan() -> super::LookupPlan {
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");
        build_lookup_plan(
            &rule,
            &event,
            &LookupOptions::default()
                .with_legacy_labels([LegacyLabelSpec::new(
                    "consumer-sha1-12",
                    "dependabot-alert",
                    LabelDigest::Sha1,
                    12,
                    repo_and_title(),
                )])
                .with_summary_fallback("[Dependabot][High] Bump openssl from 1.0 to 1.1"),
        )
        .expect("plan should build")
    }

    #[test]
    fn ranking_puts_the_canonical_label_ahead_of_every_legacy_rung_and_the_fallback() {
        let plan = ranking_plan();
        let labels: Vec<String> = plan
            .labels()
            .iter()
            .map(|entry| entry.label.clone())
            .collect();
        let summary = plan
            .summary_filter()
            .expect("the fallback is armed")
            .to_string();

        let rows = [
            issue("KAN-4", "10004", &[], Some(&summary)),
            issue("KAN-3", "10003", &[labels[2].as_str()], None),
            issue("KAN-2", "10002", &[labels[1].as_str()], None),
            issue("KAN-1", "10001", &[labels[0].as_str()], None),
        ];

        let ranked = rank_candidates(&plan, &rows);
        assert_eq!(
            ranked
                .iter()
                .map(|candidate| candidate.issue_key.as_str())
                .collect::<Vec<_>>(),
            vec!["KAN-1", "KAN-2", "KAN-3", "KAN-4"]
        );
        assert_eq!(ranked[0].tier, LadderTier::Canonical);
        assert_eq!(
            ranked[1].tier,
            LadderTier::Legacy {
                rung: 0,
                spec_id: "v0-sha256-12".to_string(),
            }
        );
        assert_eq!(
            ranked[2].tier,
            LadderTier::Legacy {
                rung: 1,
                spec_id: "consumer-sha1-12".to_string(),
            }
        );
        assert_eq!(ranked[3].tier, LadderTier::SummaryFallback);
    }

    #[test]
    fn a_tier_tie_is_broken_on_the_lowest_numeric_id_not_the_string() {
        let plan = ranking_plan();
        let canonical = plan.canonical_label().to_string();

        // "10100" sorts before "9999" as text and after it as a number. An
        // election run on the string picks a different winner.
        let rows = [
            issue("KAN-A", "10100", &[canonical.as_str()], None),
            issue("KAN-B", "9999", &[canonical.as_str()], None),
        ];

        let ranked = rank_candidates(&plan, &rows);
        assert_eq!(ranked[0].issue_key, "KAN-B");
        assert_eq!(ranked[0].issue_id, Some(9999));
        assert_eq!(ranked[1].issue_id, Some(10100));
    }

    #[test]
    fn an_unparseable_id_sorts_last_rather_than_winning_as_zero() {
        let plan = ranking_plan();
        let canonical = plan.canonical_label().to_string();

        let rows = [
            issue("KAN-BAD", "not-a-number", &[canonical.as_str()], None),
            issue("KAN-OK", "10100", &[canonical.as_str()], None),
        ];

        let ranked = rank_candidates(&plan, &rows);
        assert_eq!(ranked[0].issue_key, "KAN-OK");
        assert_eq!(ranked[1].issue_id, None);
    }

    #[test]
    fn ranking_does_not_depend_on_the_order_jira_returned() {
        let plan = ranking_plan();
        let labels: Vec<String> = plan
            .labels()
            .iter()
            .map(|entry| entry.label.clone())
            .collect();

        let forward = [
            issue("KAN-1", "10001", &[labels[0].as_str()], None),
            issue("KAN-2", "10002", &[labels[1].as_str()], None),
            issue("KAN-3", "9999", &[labels[0].as_str()], None),
        ];
        let mut reversed: Vec<SearchIssue> = forward.to_vec();
        reversed.reverse();

        let keys = |ranked: Vec<Candidate>| -> Vec<String> {
            ranked
                .into_iter()
                .map(|candidate| candidate.issue_key)
                .collect()
        };
        assert_eq!(
            keys(rank_candidates(&plan, &forward)),
            keys(rank_candidates(&plan, &reversed))
        );
        assert_eq!(
            keys(rank_candidates(&plan, &forward)),
            vec!["KAN-3", "KAN-1", "KAN-2"]
        );
    }

    #[test]
    fn a_summary_only_row_survives_only_on_an_exact_match() {
        // This is the mandatory post-filter. `summary ~ "..."` is a Lucene text
        // match, so Jira returns issues that merely share words -- attaching to
        // one of those is attaching to the wrong issue, silently and forever.
        let plan = ranking_plan();
        let exact = plan
            .summary_filter()
            .expect("the fallback is armed")
            .to_string();

        let rows = [
            issue("KAN-EXACT", "10001", &[], Some(&exact)),
            issue(
                "KAN-PREFIX",
                "10002",
                &[],
                Some(&format!("{exact} (retry)")),
            ),
            issue("KAN-CASE", "10003", &[], Some(&exact.to_uppercase())),
            issue("KAN-TRIM", "10004", &[], Some(&format!(" {exact}"))),
            issue("KAN-WORDS", "10005", &[], Some("Bump openssl")),
            issue("KAN-NONE", "10006", &[], None),
        ];

        let ranked = rank_candidates(&plan, &rows);
        assert_eq!(
            ranked
                .iter()
                .map(|candidate| candidate.issue_key.as_str())
                .collect::<Vec<_>>(),
            vec!["KAN-EXACT"],
            "only a byte-equal summary may claim a row"
        );
    }

    #[test]
    fn an_unlabelled_row_is_dropped_when_the_fallback_was_never_armed() {
        let rule = shipped_rule();
        let event = parse_event("issues-opened-dependabot");
        let plan =
            build_lookup_plan(&rule, &event, &LookupOptions::default()).expect("plan should build");

        let rows = [
            issue(
                "KAN-1",
                "10001",
                &[],
                Some("[Dependabot][High] Bump openssl"),
            ),
            issue("KAN-2", "10002", &["some-other-label"], None),
        ];

        assert!(
            rank_candidates(&plan, &rows).is_empty(),
            "without the fallback there is nothing for an unlabelled row to match"
        );
    }

    #[test]
    fn a_label_claims_a_row_even_when_the_summary_would_have_too() {
        let plan = ranking_plan();
        let canonical = plan.canonical_label().to_string();
        let exact = plan
            .summary_filter()
            .expect("the fallback is armed")
            .to_string();

        let rows = [issue("KAN-1", "10001", &[canonical.as_str()], Some(&exact))];

        let ranked = rank_candidates(&plan, &rows);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].tier, LadderTier::Canonical);
    }

    #[test]
    fn ranking_an_empty_result_set_yields_no_candidates() {
        let plan = ranking_plan();
        assert!(rank_candidates(&plan, &[]).is_empty());
    }
}
