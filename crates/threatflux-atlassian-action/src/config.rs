use crate::rules::dedupe::{rule_label_prefix, LabelDigest, LegacyLabelSpec, PreimagePrefix};
use crate::rules::{is_supported_event_field_path, validate_template, SUPPORTED_EVENT_NAME};
use anyhow::{Context as _, Result};
use regex::Regex;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use yaml_serde::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutomationConfig {
    pub version: u32,
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleConfig {
    pub id: String,
    pub when: WhenConfig,
    pub extract: ExtractConfig,
    pub jira: JiraRuleConfig,
    /// What to do when the delivery reconciles to a Jira issue that exists.
    ///
    /// One of [`SUPPORTED_ON_EXISTING`], defaulting to
    /// [`DEFAULT_ON_EXISTING`]. The default is what every release through
    /// `0.4.x` did -- find the issue, report it as deduped, write nothing -- so
    /// a configuration that omits the key keeps the behaviour it has today and
    /// a consumer opts into everything else deliberately.
    #[serde(default = "default_on_existing")]
    pub on_existing: String,
    /// How to reach Jira issues an earlier labelling scheme created.
    #[serde(default)]
    pub migration: MigrationConfig,
    /// Bounds on the writes [`RuleConfig::on_existing`] authorises.
    #[serde(default)]
    pub update: UpdateConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhenConfig {
    pub event: String,
    pub action: String,
    #[serde(default)]
    pub actor_in: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractConfig {
    pub severity: SeverityExtractConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeverityExtractConfig {
    pub from: String,
    pub regex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JiraRuleConfig {
    pub project_key: String,
    pub issue_type: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub assignee_account_id: Option<String>,
    pub priority_by_severity: BTreeMap<String, String>,
    pub summary: String,
    /// How `description` is to be read. `text` is the only accepted value.
    ///
    /// The obvious second value would be `adf`, and it is refused on purpose --
    /// see [`SUPPORTED_DESCRIPTION_FORMAT`] and
    /// `load_config_rejects_the_adf_format_that_would_let_a_config_choose_json_structure`,
    /// which carries the reasoning.
    #[serde(default = "default_description_format")]
    pub description_format: String,
    pub description: String,
    #[serde(default)]
    pub labels: Vec<String>,
    pub dedupe: DedupeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DedupeConfig {
    pub strategy: String,
    /// What makes two deliveries the same Jira issue.
    ///
    /// One of [`SUPPORTED_DEDUPE_IDENTITY`], defaulting to
    /// [`DEFAULT_DEDUPE_IDENTITY`]. Unlike every other key added alongside it,
    /// the default here is *not* the `0.4.x` behaviour, because the identity
    /// scheme changed in this release:
    /// [`canonical_label`](crate::rules::dedupe::canonical_label) is now keyed
    /// on the GitHub issue rather than on a hash of `fields`. `fields` is the
    /// opt-out for a consumer who wants the old content grouping on purpose --
    /// see the module documentation of [`crate::rules::dedupe`] for what moves
    /// in each direction.
    #[serde(default = "default_dedupe_identity")]
    pub identity: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub label_prefix: Option<String>,
    pub fields: Vec<String>,
}

/// How a rule reaches Jira issues labelled by an earlier scheme.
///
/// Every field defaults to off, so a rule that omits the whole block queries
/// exactly the two rungs [`build_lookup_plan`](crate::rules::dedupe::build_lookup_plan)
/// registers on its own: the canonical label and the `v0` label this crate
/// itself wrote through `0.4.x`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MigrationConfig {
    /// Whether to write the canonical label onto an issue found on a legacy rung.
    ///
    /// Without adoption the legacy rungs are permanent: every future delivery
    /// keeps finding the issue through the old label and the ladder never
    /// retires. Adoption is a write to the *identity* of an issue rather than
    /// to its content, which is why it is governed here and not by
    /// [`RuleConfig::on_existing`] -- a rule can keep `on_existing: noop`,
    /// change nothing a reader sees, and still finish its migration.
    pub adopt: bool,
    /// Whether to also look for an issue by its exact summary.
    ///
    /// For issues created before any dedupe label existed, which no rung of the
    /// ladder can find. Off by default because `summary ~ "..."` is a Lucene
    /// text match that happily returns a *different* issue sharing words with
    /// this one; when it is armed the lookup keeps a summary-only row only if
    /// its summary is byte-equal to the rendered `jira.summary`, and that
    /// post-filter is not optional.
    pub summary_fallback: bool,
    /// Label formats to recognise, in precedence order, after the `v0` rung.
    ///
    /// This is the reason the legacy formats are configuration rather than
    /// code. The SHA-256/16 and SHA-1/12 labels consumers report are not
    /// reproducible from anything in this repository -- the digest, the
    /// truncation, the field order, the joiner and whether the prefix is part
    /// of the hashed preimage are all unknown -- so a release that guessed
    /// would cost a release cycle to correct. Declared here, a wrong guess
    /// costs a config edit.
    pub legacy_labels: Vec<LegacyLabelConfig>,
}

/// One label format [`MigrationConfig::legacy_labels`] recognises.
///
/// Deserializes into [`LegacyLabelSpec`] through
/// [`to_spec`](LegacyLabelConfig::to_spec); every field of that type is
/// reachable from here, because any one of them being wrong produces a label
/// that matches nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyLabelConfig {
    /// Name this rung is reported under. Must be unique within the rule.
    pub id: String,
    /// One of [`SUPPORTED_LEGACY_DIGESTS`].
    pub digest: String,
    /// Leading hex characters of the digest the label keeps.
    pub hex_chars: usize,
    /// Event field paths, in the order the preimage joins them.
    pub fields: Vec<String>,
    /// Prefix the label starts with. Defaults to `jira.dedupe.label_prefix`.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub label_prefix: Option<String>,
    /// Text between the prefix and the truncated digest.
    #[serde(default = "default_legacy_separator")]
    pub separator: String,
    /// Text the preimage values are joined with.
    #[serde(default = "default_legacy_joiner")]
    pub joiner: String,
    /// Whether, and where, the prefix joins the preimage. One of
    /// [`SUPPORTED_PREIMAGE_PREFIX`].
    #[serde(default = "default_preimage_prefix")]
    pub preimage_prefix: String,
}

impl LegacyLabelConfig {
    /// The [`LegacyLabelSpec`] this entry describes.
    ///
    /// `default_label_prefix` is used when the entry names no prefix of its
    /// own; [`rule_label_prefix`] is what supplies it during validation, so an
    /// entry that omits the key inherits the prefix the rule already writes.
    ///
    /// # Errors
    ///
    /// A digest or preimage-prefix name outside its supported set, or anything
    /// [`LegacyLabelSpec::validate`] refuses -- an empty field list, a blank id
    /// or prefix, a truncation longer than the digest.
    pub fn to_spec(&self, default_label_prefix: &str) -> Result<LegacyLabelSpec> {
        let spec = LegacyLabelSpec::new(
            &self.id,
            self.label_prefix.as_deref().unwrap_or(default_label_prefix),
            parse_label_digest(&self.digest)?,
            self.hex_chars,
            self.fields.clone(),
        )
        .with_separator(&self.separator)
        .with_joiner(&self.joiner)
        .with_preimage_prefix(parse_preimage_prefix(&self.preimage_prefix)?);

        // Validated here rather than only at lookup time: a spec that cannot
        // produce a label is a configuration error, and a configuration error
        // that surfaces on the first live delivery instead of on the load is
        // one a consumer finds in production.
        spec.validate()?;
        Ok(spec)
    }
}

/// Bounds on the writes [`RuleConfig::on_existing`] authorises.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateConfig {
    /// What to do when the issue the delivery reconciles to is resolved.
    ///
    /// One of [`SUPPORTED_WHEN_RESOLVED`], defaulting to
    /// [`DEFAULT_WHEN_RESOLVED`]. The default is today's behaviour, and today's
    /// behaviour is the problem: a Jira issue closed months ago still carries
    /// its dedupe label, so it still matches, so it silences the delivery
    /// forever. `reconcile` is the opt-in that will stop it being silent -- and
    /// is refused until it does, because nothing reads this key yet and the two
    /// values are byte-identical in this release. See [`MILESTONE_GATED_KEYS`].
    #[serde(default = "default_when_resolved")]
    pub when_resolved: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            when_resolved: default_when_resolved(),
        }
    }
}

/// The only value [`JiraRuleConfig::description_format`] admits.
///
/// The Action sends its description to Jira as ADF, so `adf` looks like the
/// natural second value. It is refused because of where the description comes
/// from: it is a template interpolating `{{ issue.body }}`, so accepting raw ADF
/// would hand whoever authored the repo-local config -- and, through the
/// template, whoever opened the GitHub issue -- a way to choose the *structure*
/// of the emitted JSON rather than only its text. Running the rendered string
/// through `text_to_adf` instead is safe by construction: it interprets no
/// markup, so the text never re-enters a parser and every character of it lands
/// inside a `text` node.
pub const SUPPORTED_DESCRIPTION_FORMAT: &str = "text";

fn default_description_format() -> String {
    SUPPORTED_DESCRIPTION_FORMAT.to_string()
}

// The reconciliation surface below is *schema*. Nothing in this release reads
// these values yet -- the planner that consumes them is the reconciliation
// engine -- and they are landed ahead of it deliberately, so that the engine
// has a settled type to read and a consumer can write and validate a
// configuration before the behaviour arrives. Every default reproduces the
// behaviour of the release before this one, with one stated exception
// ([`DedupeConfig::identity`]), so an existing configuration that names none of
// these keys is unaffected by all of them.
//
// Each list is compared against the schema table in `docs/USAGE.md` by
// `scripts/check_docs.py`, in both directions: a value added here and not
// documented fails the build, and so does a value documented here that the
// loader would reject.

/// Values [`RuleConfig::on_existing`] admits, in order of how much they write.
///
/// The order is load-bearing for readers rather than for the code: `noop`
/// writes nothing, `update` rewrites the issue's fields, `comment` leaves a new
/// comment, and `update_and_comment` does both.
pub const SUPPORTED_ON_EXISTING: &[&str] = &["noop", "update", "comment", "update_and_comment"];

/// The [`RuleConfig::on_existing`] a rule that omits the key gets.
pub const DEFAULT_ON_EXISTING: &str = "noop";

/// Values [`UpdateConfig::when_resolved`] admits.
///
/// `skip` stops at a resolved match, which is what `0.4.x` does. `reconcile`
/// applies [`RuleConfig::on_existing`] to it anyway, so the delivery is
/// recorded on the closed issue instead of vanishing.
///
/// There is deliberately no value that creates a second issue. Under the
/// canonical identity both issues would carry the same label, the ladder would
/// then find two rows for one GitHub issue, and the duplicate election would
/// have to undo what the configuration asked for.
pub const SUPPORTED_WHEN_RESOLVED: &[&str] = &["skip", "reconcile"];

/// The [`UpdateConfig::when_resolved`] a rule that omits the key gets.
pub const DEFAULT_WHEN_RESOLVED: &str = "skip";

/// Values [`DedupeConfig::identity`] admits.
///
/// `repo_issue` is the canonical `{prefix}-gh-{repository_id}-{issue_number}`
/// identity: one Jira issue per GitHub issue, stable across a retitle.
/// `fields` is the `0.4.x` content grouping, a digest over `dedupe.fields`:
/// two GitHub issues sharing a title collapse onto one Jira issue, and
/// retitling one mints a second.
pub const SUPPORTED_DEDUPE_IDENTITY: &[&str] = &["repo_issue", "fields"];

/// The [`DedupeConfig::identity`] a rule that omits the key gets.
pub const DEFAULT_DEDUPE_IDENTITY: &str = "repo_issue";

/// The [`DedupeConfig::identity`] naming
/// [`canonical_label`](crate::rules::dedupe::canonical_label).
///
/// Spelled once here so the value the loader accepts and the value the label
/// builder dispatches on cannot drift apart; `the_identity_names_are_the_ones_the_loader_accepts`
/// pins both against [`SUPPORTED_DEDUPE_IDENTITY`].
pub const DEDUPE_IDENTITY_REPO_ISSUE: &str = "repo_issue";

/// The [`DedupeConfig::identity`] naming
/// [`v0_label`](crate::rules::dedupe::v0_label) -- the `0.4.x` content grouping.
pub const DEDUPE_IDENTITY_FIELDS: &str = "fields";

/// The milestone the reconciliation engine arrives in.
///
/// Named in the error every [`MILESTONE_GATED_KEYS`] entry produces, so a
/// consumer who set one learns *when* it starts working rather than only that it
/// does not today.
pub const RECONCILIATION_MILESTONE: &str = "M4";

/// Keys this release parses and validates but refuses to run with.
///
/// The rest of the reconciliation surface above is a settled type landed ahead
/// of the engine that reads it, and every default reproduces the previous
/// release, so a configuration that names none of these keys is unaffected. The
/// keys here are the ones where "landed ahead of the engine" and "documented as
/// working" would part company: nothing reads them, so a rule that sets one gets
/// a config which loads cleanly, validates cleanly, and changes nothing.
///
/// They are refused rather than accepted-and-ignored because the two failures
/// are not equally bad. A consumer who is told `on_existing: comment` is not
/// implemented yet edits their config; a consumer who believes every duplicate
/// delivery is being commented onto its Jira issue, and is wrong, finds out when
/// somebody asks why the audit trail is empty. Refusing costs nothing that
/// works, because nothing consumes these keys and they were added in the same
/// unmerged milestone as this gate -- there is no released configuration to
/// break.
///
/// `jira.dedupe.identity` is deliberately absent: it is live, and
/// [`rule_identity_label`](crate::rules::dedupe::rule_identity_label) is where.
///
/// Mirrored into `docs/USAGE.md` and compared against it by
/// `scripts/check_docs.py`, in both directions, so the guide cannot describe a
/// gated key as working or a working key as gated.
pub const MILESTONE_GATED_KEYS: &[&str] = &[
    "on_existing",
    "update.when_resolved",
    "migration.adopt",
    "migration.summary_fallback",
    "migration.legacy_labels",
];

/// Values [`LegacyLabelConfig::digest`] admits.
///
/// The names [`LabelDigest`] itself spells, restated as strings because this is
/// the surface a YAML file writes; `the_documented_digest_names_are_the_ones_a_spec_resolves`
/// pins the two together.
pub const SUPPORTED_LEGACY_DIGESTS: &[&str] = &["sha1", "sha256"];

/// Values [`LegacyLabelConfig::preimage_prefix`] admits.
pub const SUPPORTED_PREIMAGE_PREFIX: &[&str] = &["excluded", "first", "last"];

/// The [`LegacyLabelConfig::preimage_prefix`] an entry that omits the key gets.
pub const DEFAULT_PREIMAGE_PREFIX: &str = "excluded";

/// The [`LegacyLabelConfig::separator`] an entry that omits the key gets.
pub const DEFAULT_LEGACY_SEPARATOR: &str = "-";

/// The [`LegacyLabelConfig::joiner`] an entry that omits the key gets.
///
/// A bare newline, which is what the `v0` preimage joins with.
pub const DEFAULT_LEGACY_JOINER: &str = "\n";

/// The digests a configuration may name, as the values they resolve to.
const LEGACY_DIGESTS: &[LabelDigest] = &[LabelDigest::Sha1, LabelDigest::Sha256];

fn default_on_existing() -> String {
    DEFAULT_ON_EXISTING.to_string()
}

fn default_when_resolved() -> String {
    DEFAULT_WHEN_RESOLVED.to_string()
}

fn default_dedupe_identity() -> String {
    DEFAULT_DEDUPE_IDENTITY.to_string()
}

fn default_preimage_prefix() -> String {
    DEFAULT_PREIMAGE_PREFIX.to_string()
}

fn default_legacy_separator() -> String {
    DEFAULT_LEGACY_SEPARATOR.to_string()
}

fn default_legacy_joiner() -> String {
    DEFAULT_LEGACY_JOINER.to_string()
}

/// Resolves a configured digest name.
fn parse_label_digest(value: &str) -> Result<LabelDigest> {
    LEGACY_DIGESTS
        .iter()
        .copied()
        .find(|digest| digest.name() == value)
        .ok_or_else(|| {
            // Previewed rather than echoed, as everywhere else a config-supplied
            // scalar reaches an error: it is unbounded and free to carry the
            // newline a `::error::` needs to be read as a workflow command.
            anyhow::anyhow!(
                "unsupported legacy dedupe digest {}; supported digests: {}",
                crate::output::preview(value),
                SUPPORTED_LEGACY_DIGESTS.join(", ")
            )
        })
}

/// Resolves a configured preimage-prefix position.
fn parse_preimage_prefix(value: &str) -> Result<PreimagePrefix> {
    match value {
        "excluded" => Ok(PreimagePrefix::Excluded),
        "first" => Ok(PreimagePrefix::First),
        "last" => Ok(PreimagePrefix::Last),
        other => anyhow::bail!(
            "unsupported legacy dedupe preimage_prefix {}; supported positions: {}",
            crate::output::preview(other),
            SUPPORTED_PREIMAGE_PREFIX.join(", ")
        ),
    }
}

fn empty_string_as_none<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.filter(|inner| !inner.trim().is_empty()))
}

pub fn load_config_from_str(raw: &str) -> Result<AutomationConfig> {
    let mut value: Value = yaml_serde::from_str(raw)?;
    expand_env_vars_in_value(&mut value)?;
    let config: AutomationConfig = yaml_serde::from_value(value)?;
    validate_config(&config)?;
    Ok(config)
}

fn expand_env_vars_in_value(value: &mut Value) -> Result<()> {
    match value {
        Value::String(inner) => {
            *inner = expand_env_vars_in_string(inner)?;
        }
        Value::Sequence(items) => {
            for item in items {
                expand_env_vars_in_value(item)?;
            }
        }
        Value::Mapping(entries) => {
            for entry in entries.values_mut() {
                expand_env_vars_in_value(entry)?;
            }
        }
        _ => {}
    }

    Ok(())
}

/// Environment variables a config may expand with no further opt-in.
///
/// The gate is an allowlist because the alternative cannot work: the process
/// environment on a runner is a namespace this Action does not own, and a
/// substring denylist over it can only catch the names someone thought of --
/// `MY_PAT`, `GH_PAT`, `NPM_AUTH`, `SSH_KEY` and `DEPLOY_CREDS` all read as
/// ordinary names to one. This list is what the shipped fixtures, the examples
/// and the usage guide actually expand; anything else is one workflow-level
/// [`ENV_ALLOWLIST_VAR`] entry away.
const ALLOWED_ENV_NAMES: &[&str] = &[
    "JIRA_ASSIGNEE_ACCOUNT_ID",
    "JIRA_DESCRIPTION",
    "JIRA_PROJECT_KEY",
];

/// Environment variable a workflow sets to widen the expansion allowlist.
///
/// Comma-separated names, whitespace around each ignored. It is read from the
/// environment rather than from the config on purpose: the config file travels
/// with the branch a pull request proposes, and a file that could widen its own
/// allowlist would not be a gate at all. The workflow -- which only someone with
/// write access to the default branch can change for a `pull_request` run -- is
/// the side of the boundary that grants it.
pub const ENV_ALLOWLIST_VAR: &str = "THREATFLUX_CONFIG_ENV_ALLOWLIST";

/// Name fragments that mark an environment variable as credential-bearing.
///
/// This is the second gate, behind [`ALLOWED_ENV_NAMES`], and it exists to catch
/// a name someone opts in without thinking rather than to be complete on its
/// own -- a substring list cannot be complete over a namespace it does not own.
/// Matched as a substring so the variants the SDK reads are covered without
/// enumerating them: `JIRA_API_TOKEN`, `JIRA_API_TOKEN_ENCRYPTED`,
/// `JIRA_API_TOKEN_PRIVATE_KEY`, `ENV_FILE_ENCRYPTED`, `GITHUB_TOKEN`. `KEY`
/// alone is deliberately absent -- `JIRA_PROJECT_KEY` is a routine expansion
/// and the shipped fixtures use it.
const DENIED_ENV_NAME_FRAGMENTS: &[&str] = &[
    "ACCESS_KEY",
    "APIKEY",
    "API_KEY",
    "AUTHORIZATION",
    "COOKIE",
    "CREDENTIAL",
    "ENCRYPTED",
    "ENCRYPTION_KEY",
    "PASSPHRASE",
    "PASSWD",
    "PASSWORD",
    "PRIVATE_KEY",
    "SECRET",
    "SESSION",
    "SIGNING_KEY",
    "TOKEN",
];

/// Name prefixes that mark an environment variable as credential-bearing.
///
/// `INPUT_` is the channel a workflow passes `secrets.*` through, and
/// `ACTIONS_` carries the runner's own `ACTIONS_RUNTIME_TOKEN` and
/// `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
const DENIED_ENV_NAME_PREFIXES: &[&str] = &["ACTIONS_", "INPUT_"];

/// Reports whether a config may expand `name` at all.
///
/// The expansion walk substitutes `${NAME}` into every string of the parsed
/// YAML, and this process holds the Jira credential in its own environment, so
/// without a gate a repo-local config can route a secret into `rule.id` -- and
/// from there into `GITHUB_OUTPUT` -- or into `jira.summary` and
/// `jira.description`, and from there into the created Jira issue.
pub fn env_expansion_allowed(name: &str) -> bool {
    ALLOWED_ENV_NAMES.contains(&name) || is_opted_in(name)
}

/// Reports whether the workflow opted `name` in through [`ENV_ALLOWLIST_VAR`].
fn is_opted_in(name: &str) -> bool {
    std::env::var(ENV_ALLOWLIST_VAR).is_ok_and(|raw| {
        raw.split(',')
            .map(str::trim)
            .any(|allowed| !allowed.is_empty() && allowed == name)
    })
}

/// Returns the denylist entry that forbids expanding `name`, if any.
///
/// Checked ahead of [`env_expansion_allowed`], so a credential name a workflow
/// opts in by mistake is still refused, and refused with the reason that matters.
pub fn denied_env_var(name: &str) -> Option<&'static str> {
    DENIED_ENV_NAME_PREFIXES
        .iter()
        .find(|prefix| name.starts_with(**prefix))
        .or_else(|| {
            DENIED_ENV_NAME_FRAGMENTS
                .iter()
                .find(|fragment| name.contains(**fragment))
        })
        .copied()
}

fn expand_env_vars_in_string(raw: &str) -> Result<String> {
    let pattern = Regex::new(r"\$\{([A-Z0-9_]+)(:-([^}]*))?\}")?;
    let mut rendered = String::with_capacity(raw.len());
    let mut last = 0;

    for captures in pattern.captures_iter(raw) {
        let matched = captures.get(0).expect("match should exist");
        rendered.push_str(&raw[last..matched.start()]);

        let name = captures
            .get(1)
            .expect("env var capture should exist")
            .as_str();

        // Both gates are checked before the lookup, and before any `:-default`
        // is consulted: a refused name must fail the load whether or not the
        // variable is set, because expanding to a default here would let a
        // config that is rejected on the runner pass silently anywhere else.
        if let Some(entry) = denied_env_var(name) {
            anyhow::bail!(
                "Config may not expand environment variable '{name}': the name matches the credential denylist entry '{entry}'"
            );
        }

        if !env_expansion_allowed(name) {
            anyhow::bail!(
                "Config may not expand environment variable '{name}': it is not on the expansion allowlist ({}); a workflow opts a name in by setting {ENV_ALLOWLIST_VAR}=NAME[,NAME...]",
                ALLOWED_ENV_NAMES.join(", ")
            );
        }

        let default = captures.get(3).map(|value| value.as_str());
        let value = resolve_env_var(name, default)?;

        rendered.push_str(&value);
        last = matched.end();
    }

    rendered.push_str(&raw[last..]);
    Ok(rendered)
}

fn resolve_env_var(name: &str, default: Option<&str>) -> Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => default.map_or_else(|| Ok(String::new()), |value| Ok(value.to_string())),
        Err(_) => default.map_or_else(
            || anyhow::bail!("Missing required environment variable: {name}"),
            |value| Ok(value.to_string()),
        ),
    }
}

/// Reports whether `ch` may not appear in a Jira project key or label prefix.
///
/// A Jira label cannot carry a control character, and an apostrophe is a JQL
/// metacharacter that the query escaper has to escape as `\'` -- which the
/// escaper this crate replaced did not. Refusing both at load time is what makes
/// the emitted dedupe query byte-identical to the one earlier releases sent for
/// every config that loads, so a consumer's existing Jira issues keep matching.
/// Nothing legitimate is lost: none of these characters can be in a Jira label,
/// so a config carrying one could never have deduped against a real issue.
// Not a `const fn`: `char::is_control` is only const from 1.97 and the MSRV is
// 1.96.
pub fn is_forbidden_jira_text_char(ch: char) -> bool {
    ch == '\'' || ch.is_control()
}

/// Rejects a Jira text field carrying a character a Jira label cannot hold.
///
/// The message names the character by code point rather than echoing the field,
/// which may carry an expanded environment value.
fn validate_jira_text(rule_id: &str, field: &str, value: &str) -> Result<()> {
    if let Some(ch) = value.chars().find(|ch| is_forbidden_jira_text_char(*ch)) {
        anyhow::bail!(
            "Rule {} has an unusable {field}: U+{:04X} cannot appear in a Jira label",
            crate::output::preview(rule_id),
            u32::from(ch)
        );
    }

    Ok(())
}

/// Rejects a value outside the set a key admits.
///
/// One helper rather than four copies of the same `bail!`, so every one of
/// these errors names the offending key, previews the value it refused, and
/// lists what would have worked.
///
/// The id is previewed for the same reason the value is, and the reason
/// [`gated_until_reconciliation_engine`] states: it is a YAML scalar from a
/// repo-local config, so it is as long as its author wants and free to carry the
/// newline a `::error::` needs to be read as a workflow command by the runner.
fn validate_enumerated(rule_id: &str, key: &str, value: &str, supported: &[&str]) -> Result<()> {
    if !supported.contains(&value) {
        anyhow::bail!(
            "Rule {} has an unsupported {key} {}; supported values: {}",
            crate::output::preview(rule_id),
            crate::output::preview(value),
            supported.join(", ")
        );
    }

    Ok(())
}

/// The error a [`MILESTONE_GATED_KEYS`] entry produces.
///
/// `set_to` is the caller's own responsibility to bound -- every call site
/// passes either a literal, a count, or a [`crate::output::preview`]. The rule id
/// is previewed here rather than echoed: it is a YAML scalar from a repo-local
/// config, so it is as long as its author wants and free to carry the newline a
/// `::error::` needs to be read as a workflow command by the runner.
fn gated_until_reconciliation_engine(rule_id: &str, key: &str, set_to: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Rule {} sets {key} to {set_to}, which no released version acts on: the reconciliation \
         engine that reads it arrives in {RECONCILIATION_MILESTONE}. Remove the key until then. \
         It is refused rather than ignored because a consumer who believes a policy is in force \
         when it is not is worse off than one who gets this error.",
        crate::output::preview(rule_id)
    )
}

/// Refuses the reconciliation keys nothing in this release reads.
///
/// See [`MILESTONE_GATED_KEYS`] for why these fail closed rather than loading
/// and doing nothing.
///
/// Run *after* the structural checks in [`validate_reconciliation`], so that a
/// consumer preparing a `migration` block against their real labels still gets
/// the specific error about their entry -- an unresolvable field path, a
/// truncation the digest cannot produce -- rather than only being told the block
/// is not live yet. The specific errors outlive this gate; the gate does not.
fn validate_milestone_gate(rule: &RuleConfig) -> Result<()> {
    if rule.on_existing != DEFAULT_ON_EXISTING {
        // The value is one of `SUPPORTED_ON_EXISTING` by the time it reaches
        // here -- `validate_enumerated` ran first -- but previewed anyway, so
        // that widening the set can never widen this error.
        return Err(gated_until_reconciliation_engine(
            &rule.id,
            "on_existing",
            &crate::output::preview(&rule.on_existing),
        ));
    }

    if rule.update.when_resolved != DEFAULT_WHEN_RESOLVED {
        // Gated for the same reason as `on_existing`, and it is the key where
        // accepting-and-ignoring is least visible: `skip` and `reconcile` are
        // byte-identical today, because `finalize_action` reconciles onto any
        // matching row regardless of status. A consumer who sets `reconcile` to
        // stop a long-closed Jira issue swallowing new alerts would otherwise
        // get a config that loads clean and changes nothing.
        return Err(gated_until_reconciliation_engine(
            &rule.id,
            "update.when_resolved",
            &crate::output::preview(&rule.update.when_resolved),
        ));
    }

    if rule.migration.adopt {
        return Err(gated_until_reconciliation_engine(
            &rule.id,
            "migration.adopt",
            "true",
        ));
    }

    if rule.migration.summary_fallback {
        return Err(gated_until_reconciliation_engine(
            &rule.id,
            "migration.summary_fallback",
            "true",
        ));
    }

    if !rule.migration.legacy_labels.is_empty() {
        return Err(gated_until_reconciliation_engine(
            &rule.id,
            "migration.legacy_labels",
            &format!("{} entries", rule.migration.legacy_labels.len()),
        ));
    }

    Ok(())
}

/// Checks the reconciliation surface of one rule.
///
/// Split out of [`validate_config`] rather than inlined into its loop: the
/// migration block alone carries more rejection rules than the whole rest of a
/// rule, and none of them interacts with the checks above.
fn validate_reconciliation(rule: &RuleConfig) -> Result<()> {
    validate_enumerated(
        &rule.id,
        "on_existing",
        &rule.on_existing,
        SUPPORTED_ON_EXISTING,
    )?;
    validate_enumerated(
        &rule.id,
        "update.when_resolved",
        &rule.update.when_resolved,
        SUPPORTED_WHEN_RESOLVED,
    )?;
    validate_enumerated(
        &rule.id,
        "jira.dedupe.identity",
        &rule.jira.dedupe.identity,
        SUPPORTED_DEDUPE_IDENTITY,
    )?;

    let default_prefix = rule_label_prefix(rule);
    let mut declared: Vec<&str> = Vec::with_capacity(rule.migration.legacy_labels.len());

    // The rule id is previewed everywhere below for the reason
    // `gated_until_reconciliation_engine` states: it is a YAML scalar from a
    // repo-local config, so it is unbounded and free to carry the newline a
    // `::error::` needs to be read as a workflow command by the runner. These
    // errors reach the step log through `main`'s `Result` like every other.
    for entry in &rule.migration.legacy_labels {
        if entry.id.trim().is_empty() {
            anyhow::bail!(
                "Rule {} has a migration.legacy_labels entry with a blank id",
                crate::output::preview(&rule.id)
            );
        }

        // Rung ids name a rung in a lookup result, and two rungs answering to
        // one name would make that report ambiguous exactly when it matters --
        // while a consumer is deciding which of their old labels an issue was
        // found by.
        if declared.contains(&entry.id.as_str()) {
            anyhow::bail!(
                "Rule {} declares two migration.legacy_labels entries with id {}",
                crate::output::preview(&rule.id),
                crate::output::preview(&entry.id)
            );
        }
        declared.push(&entry.id);

        for field in &entry.fields {
            if !is_supported_event_field_path(field) {
                anyhow::bail!(
                    "Rule {} migration.legacy_labels entry {} has unsupported field {}",
                    crate::output::preview(&rule.id),
                    crate::output::preview(&entry.id),
                    crate::output::preview(field)
                );
            }
        }

        // Only a prefix the entry states is checked. The one it inherits is
        // `jira.dedupe.label_prefix`, which the loop in `validate_config`
        // already put through the same gate.
        if let Some(prefix) = &entry.label_prefix {
            validate_jira_text(&rule.id, "migration.legacy_labels[].label_prefix", prefix)?;
        }

        entry.to_spec(default_prefix).with_context(|| {
            format!(
                "Rule {} has an unusable migration.legacy_labels entry {}",
                crate::output::preview(&rule.id),
                crate::output::preview(&entry.id)
            )
        })?;
    }

    validate_milestone_gate(rule)
}

fn validate_config(config: &AutomationConfig) -> Result<()> {
    if config.version != 1 {
        anyhow::bail!("Unsupported config version: {}", config.version);
    }

    if config.rules.is_empty() {
        anyhow::bail!("Config must contain at least one rule");
    }

    for rule in &config.rules {
        if rule.id.trim().is_empty() {
            anyhow::bail!("Rule id cannot be empty");
        }

        if rule.when.event.trim().is_empty() || rule.when.action.trim().is_empty() {
            anyhow::bail!("Rule '{}' must define non-empty event and action", rule.id);
        }

        if rule.when.event != SUPPORTED_EVENT_NAME {
            anyhow::bail!(
                "Rule '{}' has unsupported event '{}'; supported events: {}",
                rule.id,
                rule.when.event,
                SUPPORTED_EVENT_NAME
            );
        }

        if rule.extract.severity.from != "issue.body" {
            anyhow::bail!(
                "Rule '{}' has unsupported severity source '{}'",
                rule.id,
                rule.extract.severity.from
            );
        }

        let severity_pattern = Regex::new(&rule.extract.severity.regex)?;
        if severity_pattern.captures_len() < 2 {
            anyhow::bail!(
                "Rule '{}' severity regex must define capture group 1 for extraction",
                rule.id
            );
        }

        if rule.jira.project_key.trim().is_empty() || rule.jira.issue_type.trim().is_empty() {
            anyhow::bail!(
                "Rule '{}' must define non-empty jira.project_key and jira.issue_type",
                rule.id
            );
        }

        validate_jira_text(&rule.id, "jira.project_key", &rule.jira.project_key)?;
        if let Some(prefix) = &rule.jira.dedupe.label_prefix {
            validate_jira_text(&rule.id, "jira.dedupe.label_prefix", prefix)?;
        }

        if rule.jira.summary.trim().is_empty() {
            anyhow::bail!("Rule '{}' must define a non-empty jira.summary", rule.id);
        }

        if rule.jira.description_format != SUPPORTED_DESCRIPTION_FORMAT {
            // Previewed rather than echoed: the value is a YAML scalar from a
            // repo-local config, so it is unbounded and free to carry the
            // newline a `::error::` needs to be read as a workflow command.
            anyhow::bail!(
                "Rule '{}' has unsupported description format {}; the only supported format is '{}'",
                rule.id,
                crate::output::preview(&rule.jira.description_format),
                SUPPORTED_DESCRIPTION_FORMAT
            );
        }

        if rule.jira.dedupe.fields.is_empty() {
            anyhow::bail!("Rule '{}' must define at least one dedupe field", rule.id);
        }

        for field in &rule.jira.dedupe.fields {
            if !is_supported_event_field_path(field) {
                anyhow::bail!(
                    "Rule '{}' has unsupported dedupe field '{}'",
                    rule.id,
                    field
                );
            }
        }

        if rule.jira.dedupe.strategy != "sha256" {
            anyhow::bail!(
                "Rule '{}' has unsupported dedupe strategy '{}'",
                rule.id,
                rule.jira.dedupe.strategy
            );
        }

        validate_template(
            &format!("Rule '{}' jira.summary", rule.id),
            &rule.jira.summary,
        )?;
        validate_template(
            &format!("Rule '{}' jira.description", rule.id),
            &rule.jira.description,
        )?;

        validate_reconciliation(rule)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        denied_env_var, is_forbidden_jira_text_char, load_config_from_str, parse_label_digest,
        parse_preimage_prefix, AutomationConfig, LabelDigest, LegacyLabelSpec, MigrationConfig,
        PreimagePrefix, UpdateConfig, DEFAULT_DEDUPE_IDENTITY, DEFAULT_LEGACY_JOINER,
        DEFAULT_LEGACY_SEPARATOR, DEFAULT_ON_EXISTING, DEFAULT_PREIMAGE_PREFIX,
        DEFAULT_WHEN_RESOLVED, ENV_ALLOWLIST_VAR, MILESTONE_GATED_KEYS, RECONCILIATION_MILESTONE,
        SUPPORTED_DEDUPE_IDENTITY, SUPPORTED_LEGACY_DIGESTS, SUPPORTED_ON_EXISTING,
        SUPPORTED_PREIMAGE_PREFIX, SUPPORTED_WHEN_RESOLVED,
    };
    use crate::rules::dedupe::rule_label_prefix;
    use serial_test::serial;
    use threatflux_atlassian_testkit::fixtures;

    /// The secret an attacker-authored config would be trying to reach.
    const CANARY: &str = "ATATT-canary-must-never-appear";

    /// A loadable config with `project_key` and `label_prefix` spliced in as
    /// written, so a caller passing a value that needs quoting has to quote it.
    fn config_with_jira_text(project_key: &str, label_prefix: &str) -> String {
        format!(
            concat!(
                "version: 1\n",
                "rules:\n",
                "  - id: dependabot-high-issues\n",
                "    when:\n",
                "      event: issues\n",
                "      action: opened\n",
                "    extract:\n",
                "      severity:\n",
                "        from: issue.body\n",
                "        regex: '(?mi)^severity:\\s*(high|critical)\\b'\n",
                "    jira:\n",
                "      project_key: {project_key}\n",
                "      issue_type: Bug\n",
                "      priority_by_severity:\n",
                "        high: High\n",
                "      summary: test\n",
                "      description: test\n",
                "      dedupe:\n",
                "        strategy: sha256\n",
                "        label_prefix: {label_prefix}\n",
                "        fields: [repository.full_name, issue.title]\n",
            ),
            project_key = project_key,
            label_prefix = label_prefix,
        )
    }

    /// A YAML double-quoted scalar carrying `ch`, whatever `ch` is.
    ///
    /// YAML's `\u` escape takes four hex digits and so cannot spell an
    /// astral-plane character; those need the eight-digit `\U` form.
    fn quoted_with(ch: char) -> String {
        let code = u32::from(ch);
        if code > 0xffff {
            format!("\"K\\U{code:08x}AN\"")
        } else {
            format!("\"K\\u{code:04x}AN\"")
        }
    }

    /// Every character `validate_config` refuses in a Jira text field: Unicode
    /// category Cc -- U+0000-U+001F and U+007F-U+009F, which is all
    /// `char::is_control` reports -- plus the apostrophe.
    fn forbidden_characters() -> impl Iterator<Item = char> {
        (0u32..=0xffff)
            .filter_map(char::from_u32)
            .filter(|ch| is_forbidden_jira_text_char(*ch))
    }

    #[test]
    fn the_forbidden_character_set_is_the_control_characters_and_the_apostrophe() {
        let forbidden: Vec<char> = forbidden_characters().collect();
        let expected: Vec<char> = (0u32..=0x1f)
            .chain(0x7f..=0x9f)
            .filter_map(char::from_u32)
            .chain(std::iter::once('\''))
            .collect();
        let mut sorted = expected;
        sorted.sort_unstable();

        assert_eq!(forbidden, sorted);
        // Nothing above the C1 block is forbidden, so ordinary text -- accents,
        // CJK, astral-plane emoji -- is untouched by this gate.
        assert!(!is_forbidden_jira_text_char('\u{2028}'));
        assert!(!is_forbidden_jira_text_char('\u{1f680}'));
    }

    #[test]
    fn load_config_rejects_a_forbidden_character_in_the_project_key() {
        for ch in forbidden_characters() {
            let error =
                load_config_from_str(&config_with_jira_text(&quoted_with(ch), "dependabot-alert"))
                    .expect_err("a character a Jira label cannot carry must fail the load");
            assert!(
                error.to_string().contains("jira.project_key"),
                "{ch:?}: unexpected error: {error}"
            );
        }
    }

    #[test]
    fn load_config_rejects_a_forbidden_character_in_the_dedupe_label_prefix() {
        for ch in forbidden_characters() {
            let error = load_config_from_str(&config_with_jira_text("KAN", &quoted_with(ch)))
                .expect_err("a character a Jira label cannot carry must fail the load");
            assert!(
                error.to_string().contains("jira.dedupe.label_prefix"),
                "{ch:?}: unexpected error: {error}"
            );
        }
    }

    #[test]
    fn load_config_still_admits_the_characters_a_jira_label_can_carry() {
        for ch in [
            '"',
            '\\',
            ' ',
            '-',
            '_',
            '.',
            'é',
            '€',
            '\u{1f680}',
            '\u{2028}',
        ] {
            let config =
                load_config_from_str(&config_with_jira_text(&quoted_with(ch), &quoted_with(ch)))
                    .unwrap_or_else(|error| panic!("{ch:?} must still load: {error}"));

            assert_eq!(config.rules[0].jira.project_key, format!("K{ch}AN"));
            assert_eq!(
                config.rules[0].jira.dedupe.label_prefix.as_deref(),
                Some(format!("K{ch}AN").as_str())
            );
        }
    }

    /// Returns `minimal-critical` with `field` set to `${NAME}`.
    fn config_expanding(field: &str, name: &str) -> String {
        let replaced = match field {
            "id" => ("id: dependabot-high-issues", format!("id: \"${{{name}}}\"")),
            "summary" => ("summary: test", format!("summary: \"${{{name}}}\"")),
            "description" => ("description: test", format!("description: \"${{{name}}}\"")),
            other => panic!("no substitution site for field '{other}'"),
        };
        let yaml = fixtures::action_config("minimal-critical").replace(replaced.0, &replaced.1);
        assert!(
            yaml.contains(&replaced.1),
            "substitution site '{field}' moved"
        );
        yaml
    }

    #[test]
    #[serial]
    fn load_config_expands_env_defaults_and_values() {
        std::env::set_var("JIRA_ASSIGNEE_ACCOUNT_ID", "account-123");

        let yaml = fixtures::action_config("env-expansion-defaults");

        let config = load_config_from_str(yaml).expect("config should load");
        let rule = &config.rules[0];

        assert_eq!(config.version, 1);
        assert_eq!(rule.jira.project_key, "KAN");
        assert_eq!(
            rule.jira.assignee_account_id.as_deref(),
            Some("account-123")
        );
        assert_eq!(rule.jira.description_format, "text");
    }

    #[test]
    #[serial]
    fn load_config_treats_empty_env_as_unset_when_default_is_present() {
        std::env::set_var("JIRA_PROJECT_KEY", "");
        std::env::remove_var("JIRA_ASSIGNEE_ACCOUNT_ID");

        let yaml = fixtures::action_config("env-empty-with-default");

        let config = load_config_from_str(yaml).expect("config should load");
        let rule = &config.rules[0];

        assert_eq!(rule.jira.project_key, "KAN");
        assert_eq!(rule.jira.assignee_account_id, None);
    }

    #[test]
    #[serial]
    fn load_config_treats_whitespace_env_as_unset_when_default_is_present() {
        std::env::set_var("JIRA_PROJECT_KEY", "   ");

        let yaml = fixtures::action_config("env-whitespace-with-default");

        let config = load_config_from_str(yaml).expect("config should load");
        assert_eq!(config.rules[0].jira.project_key, "KAN");
    }

    #[test]
    #[serial]
    fn load_config_rejects_missing_required_env_value() {
        std::env::remove_var("JIRA_PROJECT_KEY");

        let yaml = fixtures::action_config("env-required-no-default");

        let error = load_config_from_str(yaml).expect_err("missing env should fail");
        assert_eq!(
            error.to_string(),
            "Missing required environment variable: JIRA_PROJECT_KEY"
        );
    }

    #[test]
    #[serial]
    fn load_config_keeps_empty_required_env_when_no_default_is_provided() {
        std::env::set_var("JIRA_PROJECT_KEY", "");

        let yaml = fixtures::action_config("env-required-no-default");

        let error =
            load_config_from_str(yaml).expect_err("empty required env should fail validation");
        assert!(error.to_string().contains("jira.project_key"));
    }

    #[test]
    #[serial]
    fn load_config_expands_env_values_without_yaml_structure_injection() {
        std::env::set_var("JIRA_DESCRIPTION", "first line\njira:\n  injected: value");

        let yaml = fixtures::action_config("env-description-injection");

        let config = load_config_from_str(yaml).expect("config should load");
        let rule = &config.rules[0];

        assert_eq!(rule.jira.issue_type, "Bug");
        assert_eq!(
            rule.jira.description,
            "first line\njira:\n  injected: value"
        );
    }

    #[test]
    #[serial]
    fn load_config_hard_errors_rather_than_expanding_a_denied_name() {
        std::env::set_var("JIRA_API_TOKEN", CANARY);

        for field in ["id", "summary", "description"] {
            let error = load_config_from_str(&config_expanding(field, "JIRA_API_TOKEN"))
                .expect_err("a denied name must fail the load");
            let rendered = error.to_string();

            assert!(
                rendered.contains("may not expand environment variable 'JIRA_API_TOKEN'"),
                "{field}: unexpected error: {rendered}"
            );
            assert!(
                !rendered.contains(CANARY),
                "{field}: the error echoed the secret"
            );
        }
    }

    #[test]
    #[serial]
    fn a_denied_name_fails_even_when_the_variable_is_unset() {
        // Failing open here would mean a config rejected on the runner loads
        // clean anywhere the variable happens to be absent.
        std::env::remove_var("JIRA_API_TOKEN");

        let error = load_config_from_str(&config_expanding("summary", "JIRA_API_TOKEN"))
            .expect_err("an unset denied name must still fail the load");
        assert!(error
            .to_string()
            .contains("may not expand environment variable 'JIRA_API_TOKEN'"));
    }

    #[test]
    #[serial]
    fn a_denied_name_fails_even_with_a_default_supplied() {
        std::env::set_var("JIRA_API_TOKEN", CANARY);

        let yaml = fixtures::action_config("minimal-critical")
            .replace("summary: test", r#"summary: "${JIRA_API_TOKEN:-fallback}""#);
        let error =
            load_config_from_str(&yaml).expect_err("a default must not soften the denylist");

        assert!(error
            .to_string()
            .contains("may not expand environment variable 'JIRA_API_TOKEN'"));
    }

    #[test]
    #[serial]
    fn a_credential_name_the_denylist_cannot_see_is_still_refused() {
        // The denylist matches substrings of a namespace the Action does not
        // own, so these names are invisible to it. The allowlist is what decides
        // whether a config may expand them.
        for name in ["MY_PAT", "GH_PAT", "NPM_AUTH", "SSH_KEY", "DEPLOY_CREDS"] {
            assert_eq!(
                denied_env_var(name),
                None,
                "the denylist is not what refuses {name}"
            );

            std::env::remove_var(ENV_ALLOWLIST_VAR);
            std::env::set_var(name, CANARY);
            let error = load_config_from_str(&config_expanding("summary", name))
                .expect_err("a name outside the allowlist must fail the load");
            std::env::remove_var(name);

            let rendered = error.to_string();
            assert!(
                rendered.contains(&format!("may not expand environment variable '{name}'")),
                "{name}: unexpected error: {rendered}"
            );
            assert!(
                rendered.contains(ENV_ALLOWLIST_VAR),
                "{name}: the error must name the opt-in: {rendered}"
            );
            assert!(
                !rendered.contains(CANARY),
                "{name}: the error echoed the secret"
            );
        }
    }

    #[test]
    #[serial]
    fn a_workflow_can_opt_a_name_into_the_expansion_allowlist() {
        // The opt-in is read from the environment, which the workflow controls;
        // the config file, which a pull request can carry, cannot widen itself.
        std::env::set_var("TEAM_LABEL", "platform-security");
        std::env::set_var(ENV_ALLOWLIST_VAR, "OTHER_NAME, TEAM_LABEL ");

        let config = load_config_from_str(&config_expanding("summary", "TEAM_LABEL"))
            .expect("an opted-in name should expand");
        assert_eq!(config.rules[0].jira.summary, "platform-security");

        std::env::remove_var(ENV_ALLOWLIST_VAR);
        let error = load_config_from_str(&config_expanding("summary", "TEAM_LABEL"))
            .expect_err("the opt-in must not outlive the variable that grants it");
        assert!(error
            .to_string()
            .contains("may not expand environment variable 'TEAM_LABEL'"));

        std::env::remove_var("TEAM_LABEL");
    }

    #[test]
    #[serial]
    fn opting_a_denied_name_in_does_not_re_enable_it() {
        // The denylist stays as the second gate: a workflow that opts a
        // credential name in still cannot route it into a config.
        std::env::set_var("JIRA_API_TOKEN", CANARY);
        std::env::set_var(ENV_ALLOWLIST_VAR, "JIRA_API_TOKEN");

        let error = load_config_from_str(&config_expanding("summary", "JIRA_API_TOKEN"))
            .expect_err("an opted-in credential name must still fail the load");
        let rendered = error.to_string();

        assert!(
            rendered.contains("credential denylist entry 'TOKEN'"),
            "unexpected error: {rendered}"
        );
        assert!(!rendered.contains(CANARY), "the error echoed the secret");

        std::env::remove_var(ENV_ALLOWLIST_VAR);
    }

    #[test]
    fn the_default_allowlist_is_the_set_the_shipped_configs_expand() {
        let mut sorted = super::ALLOWED_ENV_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(super::ALLOWED_ENV_NAMES, sorted.as_slice());

        // Every name the fixtures, the examples and the usage guide expand.
        for name in [
            "JIRA_PROJECT_KEY",
            "JIRA_ASSIGNEE_ACCOUNT_ID",
            "JIRA_DESCRIPTION",
        ] {
            assert!(
                super::ALLOWED_ENV_NAMES.contains(&name),
                "a shipped config expands {name}"
            );
            assert_eq!(
                denied_env_var(name),
                None,
                "{name} must also clear the denylist"
            );
        }
    }

    #[test]
    fn the_denylist_covers_the_credential_names_it_enumerates() {
        for name in [
            "JIRA_API_TOKEN",
            "JIRA_API_TOKEN_ENCRYPTED",
            "JIRA_API_TOKEN_PRIVATE_KEY",
            "JIRA_USERNAME_ENCRYPTED",
            "JIRA_USERNAME_PRIVATE_KEY",
            "ENV_FILE_ENCRYPTED",
            "ENV_FILE_ENCRYPTED_PATH",
            "ENV_FILE_PRIVATE_KEY",
            "ENV_FILE_PRIVATE_KEY_PASSWORD",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "INPUT_CONFIG_PATH",
            "AWS_SECRET_ACCESS_KEY",
            "SLACK_WEBHOOK_SECRET",
            "NPM_AUTHORIZATION",
            "DB_PASSWORD",
            "SSH_PASSPHRASE",
        ] {
            assert!(denied_env_var(name).is_some(), "name {name} must be denied");
        }
    }

    #[test]
    fn the_denylist_entries_are_sorted_and_free_of_redundancy() {
        let mut sorted = super::DENIED_ENV_NAME_FRAGMENTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(super::DENIED_ENV_NAME_FRAGMENTS, sorted.as_slice());

        for fragment in super::DENIED_ENV_NAME_FRAGMENTS {
            let covered = super::DENIED_ENV_NAME_FRAGMENTS
                .iter()
                .any(|other| other != fragment && fragment.contains(other));
            assert!(
                !covered,
                "fragment {fragment} is already covered by another"
            );
        }
    }

    #[test]
    fn the_denylist_leaves_the_routine_expansions_alone() {
        for name in [
            "JIRA_PROJECT_KEY",
            "JIRA_ASSIGNEE_ACCOUNT_ID",
            "JIRA_DESCRIPTION",
            "JIRA_URL",
            "JIRA_USERNAME",
            "GITHUB_REPOSITORY",
            "RUNNER_OS",
        ] {
            assert_eq!(denied_env_var(name), None, "name {name} must be allowed");
        }
    }

    #[test]
    fn load_config_rejects_invalid_version() {
        let error = load_config_from_str(fixtures::action_config("reject-version-2"))
            .expect_err("invalid version should fail");
        assert!(error.to_string().contains("Unsupported config version"));
    }

    #[test]
    fn load_config_rejects_the_adf_format_that_would_let_a_config_choose_json_structure() {
        // The rationale lives here rather than only in a comment on the check,
        // because this test is the thing that keeps it true.
        //
        // The Action now sends the description to Jira as ADF, so
        // `description_format: adf` reads like the natural companion value --
        // "I already wrote a document, take it as-is". It is refused, and the
        // reason is the provenance of the field it would apply to.
        // `jira.description` is a *template*, and every shipped example
        // interpolates `{{ issue.body }}` into it, so the string this format
        // would govern is written partly by the repo-local config author and
        // partly by whoever opened the GitHub issue.
        //
        // Under `text` that string can only ever become characters:
        // `text_to_adf` interprets no markup, so the whole of it lands inside
        // the strings of `text` nodes and never re-enters a parser. Under an
        // `adf` mode the same string would be parsed as JSON and spliced into
        // the request body as *structure* -- sibling keys, a replaced document
        // root, node types this crate refuses to build. That is the same
        // primitive the SDK refuses when it rejects `RichText::Unknown` on a
        // write path, arriving instead through a config file that only needs
        // repo write access to land. There is no sanitizing version of it: the
        // value's usefulness is exactly its ability to choose structure.
        //
        // The paired positive assertion -- that a hostile body which *is* a
        // complete ADF document still reaches Jira as text -- is
        // `a_body_that_is_itself_an_adf_document_reaches_jira_as_text` in
        // `crate::jira`.
        let error = load_config_from_str(fixtures::action_config("reject-description-format-adf"))
            .expect_err("unsupported format should fail");
        let rendered = error.to_string();

        assert!(
            rendered.contains("unsupported description format"),
            "unexpected error: {rendered}"
        );
        assert!(
            rendered.contains("adf"),
            "the error must name the value it refused: {rendered}"
        );
        assert!(
            rendered.contains("the only supported format is 'text'"),
            "the error must name the one value that works: {rendered}"
        );
    }

    #[test]
    fn an_unbounded_description_format_is_previewed_rather_than_echoed_into_the_error() {
        // The value is a YAML scalar a repo-local config supplies, so it is as
        // long as its author wants and can carry the newline a `::error::`
        // needs to be read as a workflow command by the runner. This error is
        // returned from `main` and printed into the step log.
        let format = format!("adf\n::error::forged{}::end-of-payload", "a".repeat(4096));
        let yaml = fixtures::action_config("minimal-critical").replace(
            "      description:",
            &format!(
                "      description_format: {}\n      description:",
                yaml_double_quoted(&format)
            ),
        );

        let error = load_config_from_str(&yaml).expect_err("unsupported format should fail");
        let rendered = format!("{error:#}");

        assert!(
            rendered.len() < 300,
            "the error is unbounded ({} bytes): {rendered}",
            rendered.len()
        );
        assert!(
            !rendered.contains("::end-of-payload"),
            "the end of the value reached the error: {rendered}"
        );
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "a raw newline reached the error: {rendered}"
        );
        assert!(
            rendered.contains("unsupported description format"),
            "the error stopped naming its failure: {rendered}"
        );
    }

    /// Renders `value` as a YAML double-quoted scalar.
    ///
    /// Splicing a value with newlines into the fixture verbatim would change
    /// the document's shape rather than one scalar in it. YAML 1.2 is a
    /// superset of JSON, so a JSON string literal is one.
    fn yaml_double_quoted(value: &str) -> String {
        serde_json::to_string(value).expect("a string is always JSON-encodable")
    }

    #[test]
    fn load_config_rejects_unsupported_severity_source() {
        let error = load_config_from_str(fixtures::action_config(
            "reject-severity-source-issue-title",
        ))
        .expect_err("unsupported severity source should fail");
        assert!(error.to_string().contains("unsupported severity source"));
    }

    #[test]
    fn load_config_rejects_unsupported_dedupe_strategy() {
        let error = load_config_from_str(fixtures::action_config("reject-dedupe-strategy-sha1"))
            .expect_err("unsupported dedupe strategy should fail");
        assert!(error.to_string().contains("unsupported dedupe strategy"));
    }

    #[test]
    fn load_config_rejects_empty_rules() {
        let error = load_config_from_str(fixtures::action_config("reject-empty-rules"))
            .expect_err("empty rules should fail");
        assert!(error.to_string().contains("at least one rule"));
    }

    #[test]
    fn load_config_rejects_empty_rule_id() {
        let error = load_config_from_str(fixtures::action_config("reject-blank-rule-id"))
            .expect_err("empty rule id should fail");
        assert!(error.to_string().contains("Rule id cannot be empty"));
    }

    #[test]
    fn load_config_rejects_empty_event_or_action() {
        let error = load_config_from_str(fixtures::action_config("reject-blank-event"))
            .expect_err("empty event should fail");
        assert!(error
            .to_string()
            .contains("must define non-empty event and action"));
    }

    #[test]
    fn load_config_rejects_unsupported_event() {
        let error = load_config_from_str(fixtures::action_config("reject-unsupported-event"))
            .expect_err("unsupported event should fail");
        assert!(error.to_string().contains("unsupported event"));
    }

    #[test]
    fn load_config_rejects_empty_project_key_or_issue_type() {
        let error = load_config_from_str(fixtures::action_config("reject-blank-project-key"))
            .expect_err("empty project key should fail");
        assert!(error.to_string().contains("jira.project_key"));
    }

    #[test]
    fn load_config_rejects_empty_summary() {
        let error = load_config_from_str(fixtures::action_config("reject-blank-summary"))
            .expect_err("empty summary should fail");
        assert!(error.to_string().contains("non-empty jira.summary"));
    }

    #[test]
    fn load_config_rejects_unknown_summary_template_field() {
        let error = load_config_from_str(fixtures::action_config(
            "reject-unknown-summary-template-field",
        ))
        .expect_err("unknown summary template field should fail");
        assert!(error.to_string().contains("jira.summary"));
        assert!(error.to_string().contains("unknown template field"));
    }

    #[test]
    fn load_config_rejects_unknown_description_template_field() {
        let error = load_config_from_str(fixtures::action_config(
            "reject-unknown-description-template-field",
        ))
        .expect_err("unknown description template field should fail");
        assert!(error.to_string().contains("jira.description"));
        assert!(error.to_string().contains("unknown template field"));
    }

    #[test]
    fn load_config_rejects_unsupported_dedupe_field() {
        let error =
            load_config_from_str(fixtures::action_config("reject-unsupported-dedupe-field"))
                .expect_err("unsupported dedupe field should fail");
        assert!(error.to_string().contains("unsupported dedupe field"));
    }

    #[test]
    fn load_config_rejects_empty_dedupe_fields() {
        let error = load_config_from_str(fixtures::action_config("reject-empty-dedupe-fields"))
            .expect_err("empty dedupe fields should fail");
        assert!(error.to_string().contains("at least one dedupe field"));
    }

    #[test]
    fn load_config_rejects_severity_regex_without_capture_group() {
        let error = load_config_from_str(fixtures::action_config(
            "reject-severity-regex-without-capture",
        ))
        .expect_err("missing capture group should fail");
        assert!(error.to_string().contains("capture group 1"));
    }

    #[test]
    fn load_config_rejects_unknown_template_field_in_summary() {
        let error = load_config_from_str(fixtures::action_config(
            "reject-unknown-summary-template-field",
        ))
        .expect_err("unknown template field in summary should fail");
        assert!(error.to_string().contains("unknown template field"));
        assert!(error.to_string().contains("issue.titel"));
    }

    #[test]
    fn load_config_rejects_unknown_template_field_in_description() {
        let error = load_config_from_str(fixtures::action_config(
            "reject-unknown-description-template-field-repo",
        ))
        .expect_err("unknown template field in description should fail");
        assert!(error.to_string().contains("unknown template field"));
        assert!(error.to_string().contains("repo.full_name"));
    }

    // --- the reconciliation surface ---------------------------------------

    /// `minimal-critical` with YAML spliced in at rule level, under `dedupe`,
    /// or both.
    ///
    /// `rule_block` is indented for the rule mapping (four spaces) and lands
    /// immediately before `jira:`; `dedupe_block` is indented for the dedupe
    /// mapping (eight spaces) and lands under it. Both must end in a newline.
    /// The substitution sites are asserted rather than assumed, so a fixture
    /// edit that moves them fails here instead of quietly producing a config
    /// that tests nothing.
    fn config_with(rule_block: &str, dedupe_block: &str) -> String {
        const RULE_SITE: &str = "    jira:\n";
        const DEDUPE_SITE: &str = "        strategy: sha256\n";

        let yaml = fixtures::action_config("minimal-critical");
        assert!(
            yaml.contains(RULE_SITE) && yaml.contains(DEDUPE_SITE),
            "a substitution site moved in the minimal-critical fixture"
        );

        yaml.replace(RULE_SITE, &format!("{rule_block}{RULE_SITE}"))
            .replace(DEDUPE_SITE, &format!("{DEDUPE_SITE}{dedupe_block}"))
    }

    /// A config carrying exactly one `migration.legacy_labels` entry.
    ///
    /// The four required keys are parameters rather than text a caller patches,
    /// because the rule's own `jira.dedupe` block spells several of the same
    /// scalars and a `replace` aimed at one of them hits both.
    fn config_with_legacy_label(
        id: &str,
        digest: &str,
        hex_chars: &str,
        fields: &str,
        extra: &str,
    ) -> String {
        config_with(
            &format!(
                concat!(
                    "    migration:\n",
                    "      legacy_labels:\n",
                    "        - id: {id}\n",
                    "          digest: {digest}\n",
                    "          hex_chars: {hex_chars}\n",
                    "          fields: {fields}\n",
                    "{extra}",
                ),
                id = id,
                digest = digest,
                hex_chars = hex_chars,
                fields = fields,
                extra = extra
            ),
            "",
        )
    }

    /// [`config_with_legacy_label`] with a usable SHA-1/12 entry.
    fn config_with_default_legacy_label(extra: &str) -> String {
        config_with_legacy_label(
            "acme-sha1-12",
            "sha1",
            "12",
            "[repository.full_name, issue.title]",
            extra,
        )
    }

    #[test]
    fn a_config_naming_none_of_the_reconciliation_keys_keeps_todays_behaviour() {
        // The whole point of the defaults: this milestone adds a schema, and an
        // existing consumer who does not write any of it must be unable to tell
        // that it landed.
        for fixture in ["minimal-critical", "dependabot-high"] {
            let config = load_config_from_str(fixtures::action_config(fixture))
                .unwrap_or_else(|error| panic!("{fixture} should load: {error}"));
            let rule = &config.rules[0];

            assert_eq!(rule.on_existing, DEFAULT_ON_EXISTING, "{fixture}");
            assert_eq!(rule.on_existing, "noop", "{fixture}");
            assert_eq!(rule.update, UpdateConfig::default(), "{fixture}");
            assert_eq!(
                rule.update.when_resolved, DEFAULT_WHEN_RESOLVED,
                "{fixture}"
            );
            assert_eq!(rule.migration, MigrationConfig::default(), "{fixture}");
            assert!(!rule.migration.adopt, "{fixture}");
            assert!(!rule.migration.summary_fallback, "{fixture}");
            assert!(rule.migration.legacy_labels.is_empty(), "{fixture}");
            assert_eq!(
                rule.jira.dedupe.identity, DEFAULT_DEDUPE_IDENTITY,
                "{fixture}"
            );
        }
    }

    /// The rule schema without the milestone gate or the rest of validation.
    ///
    /// The reconciliation surface is a settled type landed ahead of the engine
    /// that reads it, and `load_config_from_str` refuses the half of it nothing
    /// acts on yet. The *type* still has to round-trip -- that is what "landed
    /// ahead of the engine" means and what M4 will build on -- so the schema
    /// assertions go through the deserializer directly and the behavioural ones
    /// keep going through the loader.
    fn load_schema_from_str(raw: &str) -> AutomationConfig {
        yaml_serde::from_str(raw).expect("the reconciliation schema should deserialize")
    }

    #[test]
    fn every_value_the_schema_documents_is_recognised() {
        // Two claims, and the split between them is the milestone gate. A value
        // that is *recognised* deserializes and survives its own enumeration
        // check; a value that is *live* also survives the gate. Documenting the
        // second where only the first is true is the defect this pins.
        for value in SUPPORTED_ON_EXISTING {
            let yaml = config_with(&format!("    on_existing: {value}\n"), "");
            assert_eq!(load_schema_from_str(&yaml).rules[0].on_existing, *value);

            let loaded = load_config_from_str(&yaml);
            if *value == DEFAULT_ON_EXISTING {
                let config = loaded
                    .unwrap_or_else(|error| panic!("on_existing {value} should load: {error}"));
                assert_eq!(config.rules[0].on_existing, *value);
            } else {
                let Err(error) = loaded else {
                    panic!("on_existing {value} is gated and must not load");
                };
                let rendered = format!("{error:#}");
                assert!(
                    rendered.contains(RECONCILIATION_MILESTONE),
                    "on_existing {value}: unexpected error: {rendered}"
                );
            }
        }

        for value in SUPPORTED_WHEN_RESOLVED {
            let yaml = config_with(&format!("    update:\n      when_resolved: {value}\n"), "");
            assert_eq!(
                load_schema_from_str(&yaml).rules[0].update.when_resolved,
                *value
            );

            let loaded = load_config_from_str(&yaml);
            if *value == DEFAULT_WHEN_RESOLVED {
                let config = loaded
                    .unwrap_or_else(|error| panic!("when_resolved {value} should load: {error}"));
                assert_eq!(config.rules[0].update.when_resolved, *value);
            } else {
                let Err(error) = loaded else {
                    panic!("when_resolved {value} is gated and must not load");
                };
                let rendered = format!("{error:#}");
                assert!(
                    rendered.contains(RECONCILIATION_MILESTONE),
                    "when_resolved {value}: unexpected error: {rendered}"
                );
            }
        }

        for value in SUPPORTED_DEDUPE_IDENTITY {
            let yaml = config_with("", &format!("        identity: {value}\n"));
            let config = load_config_from_str(&yaml)
                .unwrap_or_else(|error| panic!("identity {value} should load: {error}"));
            assert_eq!(config.rules[0].jira.dedupe.identity, *value);
        }

        // The legacy-label values are recognised -- the digest and the preimage
        // position resolve, and the entry builds a usable spec -- and the block
        // they sit in is then refused as a whole. That the error is the gate's
        // and not the digest's is what proves the value was recognised.
        for value in SUPPORTED_LEGACY_DIGESTS {
            let yaml = config_with_legacy_label("acme", value, "12", "[repository.full_name]", "");
            assert_eq!(
                load_schema_from_str(&yaml).rules[0].migration.legacy_labels[0].digest,
                *value
            );

            let Err(error) = load_config_from_str(&yaml) else {
                panic!("a legacy_labels block is gated and must not load");
            };
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("migration.legacy_labels")
                    && rendered.contains(RECONCILIATION_MILESTONE),
                "digest {value}: unexpected error: {rendered}"
            );
        }

        for value in SUPPORTED_PREIMAGE_PREFIX {
            let yaml =
                config_with_default_legacy_label(&format!("          preimage_prefix: {value}\n"));
            assert_eq!(
                load_schema_from_str(&yaml).rules[0].migration.legacy_labels[0].preimage_prefix,
                *value
            );

            let Err(error) = load_config_from_str(&yaml) else {
                panic!("a legacy_labels block is gated and must not load");
            };
            assert!(
                format!("{error:#}").contains(RECONCILIATION_MILESTONE),
                "preimage_prefix {value}: unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_an_unsupported_on_existing_value() {
        // `reopen` is the value a reader most plausibly guesses at, and it is
        // not one: reopening needs a per-project transition name this schema
        // does not carry.
        let error = load_config_from_str(&config_with("    on_existing: reopen\n", ""))
            .expect_err("an unsupported on_existing should fail");
        let rendered = error.to_string();

        assert!(
            rendered.contains("unsupported on_existing"),
            "unexpected error: {rendered}"
        );
        assert!(
            rendered.contains("reopen"),
            "the error must name the value it refused: {rendered}"
        );
        assert!(
            rendered.contains("noop, update, comment, update_and_comment"),
            "the error must name the values that work: {rendered}"
        );
    }

    #[test]
    fn load_config_rejects_an_unsupported_when_resolved_value() {
        let error = load_config_from_str(&config_with(
            "    update:\n      when_resolved: create_new\n",
            "",
        ))
        .expect_err("an unsupported when_resolved should fail");
        let rendered = error.to_string();

        assert!(
            rendered.contains("unsupported update.when_resolved"),
            "unexpected error: {rendered}"
        );
        assert!(
            rendered.contains("create_new") && rendered.contains("skip, reconcile"),
            "the error must name both the refused and the supported values: {rendered}"
        );
    }

    #[test]
    fn load_config_rejects_an_unsupported_dedupe_identity() {
        let error = load_config_from_str(&config_with("", "        identity: sha256\n"))
            .expect_err("an unsupported dedupe identity should fail");
        let rendered = error.to_string();

        assert!(
            rendered.contains("unsupported jira.dedupe.identity"),
            "unexpected error: {rendered}"
        );
        assert!(
            rendered.contains("repo_issue, fields"),
            "the error must name the values that work: {rendered}"
        );
    }

    #[test]
    fn an_unbounded_reconciliation_value_is_previewed_rather_than_echoed() {
        // Same hazard as `description_format`: the value is a YAML scalar from
        // a repo-local config, so it is as long as its author wants and can
        // carry the newline a `::error::` needs to be read as a workflow
        // command by the runner.
        let value = format!(
            "update\n::error::forged{}::end-of-payload",
            "a".repeat(4096)
        );
        let yaml = config_with(
            &format!("    on_existing: {}\n", yaml_double_quoted(&value)),
            "",
        );

        let error = load_config_from_str(&yaml).expect_err("an unsupported value should fail");
        let rendered = format!("{error:#}");

        assert!(
            rendered.len() < 300,
            "the error is unbounded ({} bytes): {rendered}",
            rendered.len()
        );
        assert!(
            !rendered.contains("::end-of-payload"),
            "the end of the value reached the error: {rendered}"
        );
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "a raw newline reached the error: {rendered}"
        );
        assert!(
            rendered.contains("unsupported on_existing"),
            "the error stopped naming its failure: {rendered}"
        );
    }

    #[test]
    fn a_migration_block_deserializes_into_the_spec_the_ladder_queries() {
        let yaml = config_with(
            concat!(
                "    migration:\n",
                "      adopt: true\n",
                "      summary_fallback: true\n",
                "      legacy_labels:\n",
                "        - id: acme-sha1-12\n",
                "          digest: sha1\n",
                "          hex_chars: 12\n",
                "          fields: [repository.full_name, issue.title]\n",
                "          label_prefix: jira-automation\n",
                "          separator: \"_\"\n",
                "          joiner: \"|\"\n",
                "          preimage_prefix: first\n",
            ),
            "",
        );

        // Through the deserializer, not the loader: the block is refused until
        // the engine that reads it ships, and the type is what has to be right
        // in the meantime.
        let config = load_schema_from_str(&yaml);
        let rule = &config.rules[0];

        assert!(rule.migration.adopt);
        assert!(rule.migration.summary_fallback);
        assert_eq!(rule.migration.legacy_labels.len(), 1);

        let entry = &rule.migration.legacy_labels[0];
        assert_eq!(entry.hex_chars, 12);
        assert_eq!(entry.label_prefix.as_deref(), Some("jira-automation"));

        // The config type is only useful if it lands on the spec the lookup
        // ladder actually queries with, so the assertion is on that spec rather
        // than on the parsed strings.
        assert_eq!(
            entry
                .to_spec("inherited-and-unused")
                .expect("the entry should describe a usable spec"),
            LegacyLabelSpec::new(
                "acme-sha1-12",
                "jira-automation",
                LabelDigest::Sha1,
                12,
                [
                    "repository.full_name".to_string(),
                    "issue.title".to_string(),
                ],
            )
            .with_separator("_")
            .with_joiner("|")
            .with_preimage_prefix(PreimagePrefix::First)
        );
    }

    #[test]
    fn a_legacy_entry_inherits_the_rule_prefix_and_the_v0_shape_unless_it_says_otherwise() {
        let yaml = config_with(
            concat!(
                "    migration:\n",
                "      legacy_labels:\n",
                "        - id: acme-sha256-16\n",
                "          digest: sha256\n",
                "          hex_chars: 16\n",
                "          fields: [repository.full_name, issue.title]\n",
            ),
            "        label_prefix: dependabot-alert\n",
        );

        let config = load_schema_from_str(&yaml);
        let rule = &config.rules[0];
        let entry = &rule.migration.legacy_labels[0];

        assert_eq!(entry.label_prefix, None);
        assert_eq!(entry.separator, DEFAULT_LEGACY_SEPARATOR);
        assert_eq!(entry.joiner, DEFAULT_LEGACY_JOINER);
        assert_eq!(entry.preimage_prefix, DEFAULT_PREIMAGE_PREFIX);

        let spec = entry
            .to_spec(rule_label_prefix(rule))
            .expect("the entry should describe a usable spec");
        assert_eq!(spec.label_prefix, "dependabot-alert");
        assert_eq!(spec.separator, DEFAULT_LEGACY_SEPARATOR);
        assert_eq!(spec.joiner, DEFAULT_LEGACY_JOINER);
        assert_eq!(spec.preimage_prefix, PreimagePrefix::Excluded);
    }

    #[test]
    fn load_config_rejects_an_unsupported_legacy_digest() {
        let yaml = config_with_legacy_label(
            "acme-sha1-12",
            "md5",
            "12",
            "[repository.full_name, issue.title]",
            "",
        );
        let error = load_config_from_str(&yaml).expect_err("an unsupported digest should fail");
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("unsupported legacy dedupe digest"),
            "unexpected error: {rendered}"
        );
        assert!(
            rendered.contains("md5") && rendered.contains("sha1, sha256"),
            "the error must name both the refused and the supported digests: {rendered}"
        );
        assert!(
            rendered.contains("acme-sha1-12"),
            "the error must name the entry it refused: {rendered}"
        );
    }

    #[test]
    fn load_config_rejects_an_unsupported_preimage_prefix() {
        let yaml = config_with_default_legacy_label("          preimage_prefix: middle\n");
        let error =
            load_config_from_str(&yaml).expect_err("an unsupported preimage prefix should fail");
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("unsupported legacy dedupe preimage_prefix"),
            "unexpected error: {rendered}"
        );
        assert!(
            rendered.contains("middle") && rendered.contains("excluded, first, last"),
            "the error must name both the refused and the supported positions: {rendered}"
        );
    }

    #[test]
    fn load_config_rejects_a_truncation_the_digest_cannot_produce() {
        for (digest, hex_chars, expected) in [
            ("sha1", "41", "outside 1..=40"),
            ("sha256", "65", "outside 1..=64"),
            ("sha256", "0", "outside 1..=64"),
        ] {
            let yaml = config_with_legacy_label(
                "acme",
                digest,
                hex_chars,
                "[repository.full_name, issue.title]",
                "",
            );
            let error = load_config_from_str(&yaml).unwrap_err();
            let rendered = format!("{error:#}");

            assert!(
                rendered.contains(expected),
                "{digest}/{hex_chars}: unexpected error: {rendered}"
            );
        }
    }

    #[test]
    fn load_config_rejects_a_legacy_entry_that_identifies_nothing() {
        // An empty preimage gives every issue in the repository one shared
        // label, which is the one failure that looks like it works.
        let yaml = config_with_legacy_label("acme", "sha1", "12", "[]", "");
        let error = load_config_from_str(&yaml).expect_err("an empty preimage should fail");
        assert!(
            format!("{error:#}").contains("at least one field"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn load_config_rejects_an_unsupported_legacy_field_path() {
        let yaml = config_with_legacy_label(
            "acme",
            "sha1",
            "12",
            "[repository.full_name, issue.titel]",
            "",
        );
        let error = load_config_from_str(&yaml).expect_err("an unknown field path should fail");
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("has unsupported field"),
            "unexpected error: {rendered}"
        );
        assert!(
            rendered.contains("issue.titel"),
            "the error must name the field it refused: {rendered}"
        );
    }

    #[test]
    fn load_config_rejects_two_legacy_entries_sharing_an_id() {
        let yaml = config_with(
            concat!(
                "    migration:\n",
                "      legacy_labels:\n",
                "        - id: acme\n",
                "          digest: sha1\n",
                "          hex_chars: 12\n",
                "          fields: [issue.title]\n",
                "        - id: acme\n",
                "          digest: sha256\n",
                "          hex_chars: 16\n",
                "          fields: [issue.title]\n",
            ),
            "",
        );

        let error = load_config_from_str(&yaml).expect_err("a repeated rung id should fail");
        assert!(
            error
                .to_string()
                .contains("declares two migration.legacy_labels entries with id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_config_rejects_a_blank_legacy_entry_id() {
        let yaml = config_with_legacy_label(
            "\"   \"",
            "sha1",
            "12",
            "[repository.full_name, issue.title]",
            "",
        );
        let error = load_config_from_str(&yaml).expect_err("a blank rung id should fail");
        assert!(
            error
                .to_string()
                .contains("migration.legacy_labels entry with a blank id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_config_rejects_a_forbidden_character_in_a_legacy_label_prefix() {
        for ch in forbidden_characters() {
            let yaml = config_with_default_legacy_label(&format!(
                "          label_prefix: {}\n",
                quoted_with(ch)
            ));
            let error = load_config_from_str(&yaml)
                .expect_err("a character a Jira label cannot carry must fail the load");
            assert!(
                error
                    .to_string()
                    .contains("migration.legacy_labels[].label_prefix"),
                "{ch:?}: unexpected error: {error}"
            );
        }
    }

    #[test]
    fn the_documented_digest_names_are_the_ones_a_spec_resolves() {
        for digest in [LabelDigest::Sha1, LabelDigest::Sha256] {
            assert!(
                SUPPORTED_LEGACY_DIGESTS.contains(&digest.name()),
                "{digest:?} is resolvable but undocumented"
            );
            assert_eq!(
                parse_label_digest(digest.name()).expect("a documented name must resolve"),
                digest
            );
        }
        assert_eq!(SUPPORTED_LEGACY_DIGESTS.len(), 2);
        assert!(parse_label_digest("sha512").is_err());
        assert!(parse_label_digest("SHA256").is_err());
    }

    #[test]
    fn every_documented_preimage_position_resolves_to_a_distinct_one() {
        let resolved: Vec<PreimagePrefix> = SUPPORTED_PREIMAGE_PREFIX
            .iter()
            .map(|value| parse_preimage_prefix(value).expect("a documented name must resolve"))
            .collect();

        assert_eq!(
            resolved,
            vec![
                PreimagePrefix::Excluded,
                PreimagePrefix::First,
                PreimagePrefix::Last
            ]
        );
        // The default this schema writes and the default the spec type carries
        // have to be the same one, or an entry that omits the key would hash a
        // different preimage than the documentation says.
        assert_eq!(
            parse_preimage_prefix(DEFAULT_PREIMAGE_PREFIX).expect("the default must resolve"),
            PreimagePrefix::default()
        );
        assert!(parse_preimage_prefix("middle").is_err());
    }

    #[test]
    fn every_gated_key_is_refused_with_an_error_naming_itself_and_its_milestone() {
        // The keys nothing in this release reads. Accepting them would hand a
        // consumer a configuration that loads, validates, and silently does not
        // do what it says -- and `docs/USAGE.md` documents them, so the consumer
        // has every reason to believe it does.
        for (key, yaml) in [
            ("on_existing", config_with("    on_existing: update\n", "")),
            (
                "update.when_resolved",
                config_with("    update:\n      when_resolved: reconcile\n", ""),
            ),
            (
                "migration.adopt",
                config_with("    migration:\n      adopt: true\n", ""),
            ),
            (
                "migration.summary_fallback",
                config_with("    migration:\n      summary_fallback: true\n", ""),
            ),
            (
                "migration.legacy_labels",
                config_with_default_legacy_label(""),
            ),
        ] {
            assert!(
                MILESTONE_GATED_KEYS.contains(&key),
                "{key} is refused but not declared gated"
            );

            let Err(error) = load_config_from_str(&yaml) else {
                panic!("{key} must not load as a working policy");
            };
            let error = format!("{error:#}");

            assert!(
                error.contains(key),
                "the error must name the key it refused: {error}"
            );
            assert!(
                error.contains(RECONCILIATION_MILESTONE),
                "the error must name the milestone the key arrives in: {error}"
            );
        }

        assert_eq!(
            MILESTONE_GATED_KEYS.len(),
            5,
            "a key was added to the gate list without a case here"
        );
    }

    /// `yaml` with a rule id no bounded error can carry whole.
    ///
    /// The id is a YAML scalar from a repo-local config, so it is as long as its
    /// author wants and free to carry the newline a `::error::` needs to be read
    /// as a workflow command by the runner. The marker sits at the end, past any
    /// budget a preview allows, so a rendered error containing it is one that
    /// echoed the id rather than previewing it.
    fn with_an_oversized_rule_id(yaml: &str) -> String {
        const SITE: &str = "id: dependabot-high-issues";

        assert!(
            yaml.contains(SITE),
            "the rule id substitution site moved in the fixture"
        );
        yaml.replace(
            SITE,
            &format!("id: \"{}::end-of-payload\"", "a".repeat(4096)),
        )
    }

    #[test]
    fn a_reconciliation_error_stays_bounded_and_single_line() {
        // Every error the reconciliation surface raises about a named rule, not
        // just the gate's: they all reach `main`'s `Result` through
        // `load_config_from_str` and `run_from_env`, and they all print into the
        // step log, so a raw id in any one of them is the same defect.
        for (case, yaml) in [
            (
                "gated on_existing",
                config_with("    on_existing: update\n", ""),
            ),
            (
                "out-of-set on_existing",
                config_with("    on_existing: reopen\n", ""),
            ),
            (
                "out-of-set update.when_resolved",
                config_with("    update:\n      when_resolved: create_new\n", ""),
            ),
            (
                "out-of-set jira.dedupe.identity",
                config_with("", "        identity: sha512\n"),
            ),
            (
                "blank legacy id",
                config_with_legacy_label("\"   \"", "sha1", "12", "[issue.title]", ""),
            ),
            (
                "duplicate legacy id",
                config_with(
                    concat!(
                        "    migration:\n",
                        "      legacy_labels:\n",
                        "        - id: acme\n",
                        "          digest: sha1\n",
                        "          hex_chars: 12\n",
                        "          fields: [issue.title]\n",
                        "        - id: acme\n",
                        "          digest: sha256\n",
                        "          hex_chars: 16\n",
                        "          fields: [issue.title]\n",
                    ),
                    "",
                ),
            ),
            (
                "unsupported legacy field",
                config_with_legacy_label("acme", "sha1", "12", "[issue.titel]", ""),
            ),
            (
                "unusable legacy entry",
                config_with_legacy_label("acme", "sha1", "99", "[issue.title]", ""),
            ),
            // `validate_jira_text` is reached from three call sites and was the one
            // helper in this surface still formatting the id raw. The table omitting
            // it is why four review rounds passed over it.
            (
                "legacy entry label_prefix carrying a control character",
                config_with_legacy_label(
                    "acme",
                    "sha1",
                    "12",
                    "[issue.title]",
                    "          label_prefix: \"a\\u0001b\"\n",
                ),
            ),
        ] {
            let yaml = with_an_oversized_rule_id(&yaml);
            let Err(error) = load_config_from_str(&yaml) else {
                panic!("{case} must not load");
            };
            let error = format!("{error:#}");

            assert!(
                error.len() < 500,
                "{case}: the error is unbounded ({} bytes): {error}",
                error.len()
            );
            assert!(
                !error.contains("::end-of-payload"),
                "{case}: the end of the rule id reached the error: {error}"
            );
            assert!(
                !error.contains('\n') && !error.contains('\r'),
                "{case}: a raw newline reached the error: {error}"
            );
        }
    }

    #[test]
    fn the_defaults_are_members_of_the_sets_they_default_to() {
        for (default, supported) in [
            (DEFAULT_ON_EXISTING, SUPPORTED_ON_EXISTING),
            (DEFAULT_WHEN_RESOLVED, SUPPORTED_WHEN_RESOLVED),
            (DEFAULT_DEDUPE_IDENTITY, SUPPORTED_DEDUPE_IDENTITY),
            (DEFAULT_PREIMAGE_PREFIX, SUPPORTED_PREIMAGE_PREFIX),
        ] {
            assert!(
                supported.contains(&default),
                "{default} is a default no config could have written"
            );
        }
    }
}
