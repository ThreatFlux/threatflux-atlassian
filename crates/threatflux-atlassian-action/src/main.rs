//! The container action's entry point, and the `dedupe-label` validator behind it.
//!
//! # Two modes, chosen by argv alone
//!
//! `action.yml` declares no `args:`, so a GitHub runner starts this binary with
//! an empty argument list and every real delivery lands in
//! [`threatflux_atlassian_action::run_from_env`]. The validator is reachable
//! only by passing `dedupe-label` as the first argument, which a workflow cannot
//! do by accident. `tests/action_cli.rs` invokes the binary exactly the way the
//! runner does -- no arguments at all -- so the no-argument path stays pinned
//! against this dispatch growing a surprise.
//!
//! # What the validator is for
//!
//! The canonical rung of the dedupe ladder is a label this crate writes and can
//! therefore prove. Every *legacy* rung is a guess about a scheme some earlier
//! generation of routing scripts used, and the parameters of that guess -- the
//! digest, the truncation, the field order, the joiner, whether the label prefix
//! is part of the hashed preimage -- are not recoverable from this repository.
//! They are configuration for exactly that reason.
//!
//! This command closes the loop. Given a real event payload and a real
//! automation config it prints every label the lookup would ask for and the
//! query it would ask with, so a consumer can run that query against their own
//! Jira **before** the reconciliation engine commits to a format, and correct a
//! wrong guess with an edit rather than a release cycle.
//!
//! It reads two files and prints. It opens no socket, reads no credential, and
//! writes nothing back.
//!
//! # Why it lives here rather than in `threatflux-atlassian-cli`
//!
//! Its inputs are this crate's types --
//! [`build_lookup_plan`](threatflux_atlassian_action::rules::dedupe::build_lookup_plan)
//! takes a `RuleConfig` and a `GitHubIssueEvent`, both defined here, and the
//! ladder itself is `rules::dedupe`. The CLI could not reach any of them: it is
//! published to crates.io and this crate is `publish = false`, so a dependency
//! in that direction makes `cargo publish -p threatflux-atlassian-cli`
//! unresolvable and `make release-check` red. That holds even for an optional,
//! non-default, version-bearing entry, because cargo resolves optional
//! dependencies when it packages. The container image is also the artifact this
//! command's audience already has.

use anyhow::{bail, Context as _, Result};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use threatflux_atlassian_action::config::{
    load_config_from_str, AutomationConfig, RuleConfig, DEDUPE_IDENTITY_FIELDS,
};
use threatflux_atlassian_action::github::{load_issue_event_from_str, GitHubIssueEvent};
use threatflux_atlassian_action::jira::{build_create_issue_request, truncate_chars};
use threatflux_atlassian_action::rules::dedupe::{
    build_lookup_plan, rule_label_prefix, validate_label, LabelDigest, LadderTier, LegacyLabelSpec,
    LookupOptions, PreimagePrefix,
};
use threatflux_atlassian_action::rules::evaluate_rule;

/// The one subcommand this binary answers to.
const DEDUPE_LABEL: &str = "dedupe-label";

/// Event name the payload is parsed as when `--event-name` is not given.
const DEFAULT_EVENT_NAME: &str = "issues";

/// Longest *incidental* value a report line carries.
///
/// Titles, paths and error text are bounded because they are unbounded at the
/// source -- an issue body reaches the severity capture, and a path is whatever
/// the operator typed. Labels and the JQL are deliberately **not** bounded by
/// this; see [`render_rule`].
const MAX_INCIDENTAL_CHARS: usize = 200;

/// Longest label or query the report prints in full.
///
/// A Jira label cannot exceed 255 characters, so a label longer than this is
/// already unusable and cutting it costs nothing. The JQL gets a far larger
/// budget because it is the artifact: a truncated query is a query that differs
/// from the one the reconciliation issues, which is precisely the mistake this
/// command exists to prevent.
const MAX_LABEL_LINE_CHARS: usize = 256;

/// Ceiling on the printed JQL. Large enough that the ladder cannot reach it with
/// labels Jira would accept, present only so a pathological config cannot emit
/// megabytes to a terminal.
const MAX_QUERY_LINE_CHARS: usize = 16_384;

#[tokio::main]
async fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);

    // The runner's invocation. Anything else is an operator at a terminal.
    let Some(first) = arguments.next() else {
        threatflux_atlassian_action::run_from_env().await?;
        return Ok(());
    };

    let first = into_utf8(first)?;
    let rest = arguments.map(into_utf8).collect::<Result<Vec<String>>>()?;

    match first.as_str() {
        DEDUPE_LABEL => {
            if rest.iter().any(|argument| is_help_flag(argument)) {
                print!("{}", usage());
                return Ok(());
            }
            let arguments = parse_dedupe_label_args(&rest)?;
            print!("{}", run_dedupe_label(&arguments)?);
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print!("{}", usage());
            Ok(())
        }
        other => bail!(
            "unknown argument {}: this binary is the GitHub Action when it is given no arguments, \
             and the `{DEDUPE_LABEL}` validator when it is given that. `--help` prints the details.",
            quoted(other)
        ),
    }
}

fn into_utf8(value: std::ffi::OsString) -> Result<String> {
    value.into_string().map_err(|lossy| {
        anyhow::anyhow!(
            "argument is not valid UTF-8: {}",
            quoted(&one_line(&lossy.to_string_lossy(), MAX_INCIDENTAL_CHARS))
        )
    })
}

fn is_help_flag(argument: &str) -> bool {
    matches!(argument, "-h" | "--help")
}

fn usage() -> String {
    format!(
        "\
threatflux-atlassian-action -- the ThreatFlux Jira automation Action.

With no arguments it runs the Action from the environment, which is how a
GitHub runner invokes it. The subcommand below is for operators.

USAGE
  threatflux-atlassian-action {DEDUPE_LABEL} --config <PATH> --event <PATH> [OPTIONS]

  Prints every label in the dedupe lookup ladder and the exact JQL the
  reconciliation would issue for one GitHub event payload. Reads the two files
  named below and prints to stdout: it opens no network connection, reads no
  Jira credential, and changes nothing.

REQUIRED
  --config <PATH>            repo-local automation YAML -- the file that
                             action.yml's `config-path` points at
  --event <PATH>             GitHub event payload JSON -- the file that
                             GITHUB_EVENT_PATH points at during a real delivery

OPTIONS
  --event-name <NAME>        event name to parse the payload as
                             (default: {DEFAULT_EVENT_NAME})
  --rule <ID>                report only the rule with this id
                             (default: every rule in the config)
  --summary-fallback <TEXT>  arm the opt-in summary rung with this exact summary
  --legacy <SPEC>            add one legacy rung; repeatable, in precedence order
  -h, --help                 print this help

LEGACY SPEC
  Semicolon-separated `key=value` pairs. Values understand the escapes
  \\n \\t \\r \\\\ \\; \\, and \\=, so a joiner may be any text at all.

    id                required  name this rung is reported under
    digest            required  sha1 | sha256
    hex               required  number of leading hex characters kept
    fields            required  comma-separated event field paths, in preimage
                                order
    prefix            optional  label prefix (default: the rule's own)
    separator         optional  text between the prefix and the digest
                                (default: -)
    joiner            optional  text the preimage elements are joined with
                                (default: \\n)
    preimage-prefix   optional  excluded | first | last -- whether, and where,
                                the label prefix joins the hashed preimage
                                (default: excluded)

  A SHA-1/12 scheme over the repository and the title, joined with a pipe, with
  the prefix hashed ahead of the fields:

    --legacy 'id=acme-sha1-12;digest=sha1;hex=12;\
fields=repository.full_name,issue.title;joiner=|;preimage-prefix=first'

  The scheme this Action shipped through 0.4.x is registered automatically and
  never has to be declared.
"
    )
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// One `--legacy` rung as the operator described it.
///
/// Separate from [`LegacyLabelSpec`] for one reason: `label_prefix` is optional
/// here and mandatory there. A rung whose prefix is unstated takes the prefix of
/// whichever rule it is being reported under, which is what a consumer means
/// when they say "the old scheme, same prefix" -- and a config can carry several
/// rules with several prefixes, so the answer is per rule rather than per run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacySpecRequest {
    id: String,
    label_prefix: Option<String>,
    separator: String,
    digest: LabelDigest,
    hex_chars: usize,
    fields: Vec<String>,
    joiner: String,
    preimage_prefix: PreimagePrefix,
}

impl LegacySpecRequest {
    fn materialize(&self, rule_prefix: &str) -> LegacyLabelSpec {
        LegacyLabelSpec::new(
            &self.id,
            self.label_prefix.as_deref().unwrap_or(rule_prefix),
            self.digest,
            self.hex_chars,
            self.fields.clone(),
        )
        .with_separator(&self.separator)
        .with_joiner(&self.joiner)
        .with_preimage_prefix(self.preimage_prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DedupeLabelArgs {
    config_path: PathBuf,
    event_path: PathBuf,
    event_name: String,
    rule_id: Option<String>,
    legacy: Vec<LegacySpecRequest>,
    summary_fallback: Option<String>,
}

impl DedupeLabelArgs {
    /// The lookup options for one rule, with every `--legacy` rung bound to that
    /// rule's own label prefix.
    fn lookup_options(&self, rule_prefix: &str) -> LookupOptions {
        let options = LookupOptions::default().with_legacy_labels(
            self.legacy
                .iter()
                .map(|request| request.materialize(rule_prefix)),
        );
        match &self.summary_fallback {
            None => options,
            Some(summary) => options.with_summary_fallback(summary.clone()),
        }
    }
}

fn parse_dedupe_label_args(arguments: &[String]) -> Result<DedupeLabelArgs> {
    let mut config_path: Option<PathBuf> = None;
    let mut event_path: Option<PathBuf> = None;
    let mut event_name: Option<String> = None;
    let mut rule_id: Option<String> = None;
    let mut summary_fallback: Option<String> = None;
    let mut legacy: Vec<LegacySpecRequest> = Vec::new();

    let mut index = 0;
    while index < arguments.len() {
        let raw = arguments[index].as_str();
        // `--flag=value` and `--flag value` are the same thing. The split is
        // gated on a `--` prefix so a bare positional carrying an `=` is
        // reported as the unknown argument it is rather than silently becoming
        // a flag.
        let (flag, inline) = match raw.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (raw, None),
        };

        match flag {
            "--config" => set_once(
                &mut config_path,
                PathBuf::from(value_for(flag, inline, arguments, &mut index)?),
                flag,
            )?,
            "--event" => set_once(
                &mut event_path,
                PathBuf::from(value_for(flag, inline, arguments, &mut index)?),
                flag,
            )?,
            "--event-name" => set_once(
                &mut event_name,
                value_for(flag, inline, arguments, &mut index)?.to_owned(),
                flag,
            )?,
            "--rule" => set_once(
                &mut rule_id,
                value_for(flag, inline, arguments, &mut index)?.to_owned(),
                flag,
            )?,
            "--summary-fallback" => set_once(
                &mut summary_fallback,
                value_for(flag, inline, arguments, &mut index)?.to_owned(),
                flag,
            )?,
            "--legacy" => {
                let spec = parse_legacy_spec(value_for(flag, inline, arguments, &mut index)?)?;
                if let Some(clash) = legacy.iter().find(|other| other.id == spec.id) {
                    bail!(
                        "two --legacy rungs share the id {}: rung ids name a rung in the report \
                         and have to tell two rungs apart",
                        quoted(&clash.id)
                    );
                }
                legacy.push(spec);
            }
            other => bail!(
                "unknown option {} for `{DEDUPE_LABEL}`; `--help` lists the options",
                quoted(&one_line(other, MAX_INCIDENTAL_CHARS))
            ),
        }

        index += 1;
    }

    Ok(DedupeLabelArgs {
        config_path: config_path
            .context("--config is required: point it at the repo-local automation YAML")?,
        event_path: event_path
            .context("--event is required: point it at a GitHub event payload JSON")?,
        event_name: event_name.unwrap_or_else(|| DEFAULT_EVENT_NAME.to_owned()),
        rule_id,
        legacy,
        summary_fallback,
    })
}

fn value_for<'a>(
    flag: &str,
    inline: Option<&'a str>,
    arguments: &'a [String],
    index: &mut usize,
) -> Result<&'a str> {
    if let Some(value) = inline {
        return Ok(value);
    }
    *index += 1;
    arguments
        .get(*index)
        .map(String::as_str)
        .with_context(|| format!("{flag} needs a value"))
}

/// Rejects a repeated single-valued flag rather than letting the last one win.
///
/// Silently discarding the first `--config` would make this command report a
/// ladder for a file the operator is not looking at, which is the one failure a
/// validator may not have.
fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<()> {
    if slot.is_some() {
        bail!("{flag} was given more than once");
    }
    *slot = Some(value);
    Ok(())
}

fn parse_legacy_spec(raw: &str) -> Result<LegacySpecRequest> {
    let mut id: Option<String> = None;
    let mut digest: Option<LabelDigest> = None;
    let mut hex_chars: Option<usize> = None;
    let mut fields: Option<Vec<String>> = None;
    let mut label_prefix: Option<String> = None;
    let mut separator: Option<String> = None;
    let mut joiner: Option<String> = None;
    let mut preimage_prefix: Option<PreimagePrefix> = None;

    for pair in split_unescaped(raw, ';') {
        if pair.trim().is_empty() {
            continue;
        }
        let (key, value) = split_once_unescaped(&pair, '=').with_context(|| {
            format!(
                "--legacy takes `key=value` pairs; {} is not one",
                quoted(&one_line(&pair, MAX_INCIDENTAL_CHARS))
            )
        })?;

        match key.trim() {
            "id" => set_once(&mut id, unescape(value)?, "--legacy id")?,
            "digest" => set_once(
                &mut digest,
                parse_digest(&unescape(value)?)?,
                "--legacy digest",
            )?,
            "hex" => set_once(
                &mut hex_chars,
                parse_hex_chars(&unescape(value)?)?,
                "--legacy hex",
            )?,
            "fields" => set_once(&mut fields, parse_fields(value)?, "--legacy fields")?,
            "prefix" => set_once(&mut label_prefix, unescape(value)?, "--legacy prefix")?,
            "separator" => set_once(&mut separator, unescape(value)?, "--legacy separator")?,
            "joiner" => set_once(&mut joiner, unescape(value)?, "--legacy joiner")?,
            "preimage-prefix" => set_once(
                &mut preimage_prefix,
                parse_preimage_prefix(&unescape(value)?)?,
                "--legacy preimage-prefix",
            )?,
            other => bail!(
                "unknown --legacy key {}; the keys are id, digest, hex, fields, prefix, \
                 separator, joiner and preimage-prefix",
                quoted(&one_line(other, MAX_INCIDENTAL_CHARS))
            ),
        }
    }

    let id = id.context("--legacy needs an id, which is how the rung is named in the report")?;
    // The auto-registered rung owns this id. Letting a `--legacy` reuse it would
    // put two different descriptions under one name in the report, and the
    // report's whole job is telling schemes apart.
    let reserved = LegacyLabelSpec::v0("reserved-id-probe", &[]).id;
    if id == reserved {
        bail!(
            "{} is the id of the rung this Action registers on its own -- the scheme it shipped \
             through 0.4.x -- so a --legacy rung needs a different id. That rung is always in the \
             ladder and never has to be declared.",
            quoted(&reserved)
        );
    }

    Ok(LegacySpecRequest {
        id,
        label_prefix,
        separator: separator.unwrap_or_else(|| "-".to_owned()),
        digest: digest.context("--legacy needs a digest: sha1 or sha256")?,
        hex_chars: hex_chars
            .context("--legacy needs hex=<n>, the number of leading hex characters kept")?,
        fields: fields.context(
            "--legacy needs fields=<path>[,<path>...], the event fields in preimage order",
        )?,
        joiner: joiner.unwrap_or_else(|| "\n".to_owned()),
        preimage_prefix: preimage_prefix.unwrap_or_default(),
    })
}

fn parse_digest(value: &str) -> Result<LabelDigest> {
    match value.trim() {
        name if name == LabelDigest::Sha1.name() => Ok(LabelDigest::Sha1),
        name if name == LabelDigest::Sha256.name() => Ok(LabelDigest::Sha256),
        other => bail!(
            "unknown --legacy digest {}; the digests this Action can read are {} and {}",
            quoted(&one_line(other, MAX_INCIDENTAL_CHARS)),
            LabelDigest::Sha1.name(),
            LabelDigest::Sha256.name()
        ),
    }
}

fn parse_hex_chars(value: &str) -> Result<usize> {
    value.trim().parse::<usize>().with_context(|| {
        format!(
            "--legacy hex takes a number of hex characters, not {}",
            quoted(&one_line(value, MAX_INCIDENTAL_CHARS))
        )
    })
}

fn parse_fields(raw: &str) -> Result<Vec<String>> {
    let mut fields = Vec::new();
    for field in split_unescaped(raw, ',') {
        let field = unescape(&field)?;
        let field = field.trim().to_owned();
        if !field.is_empty() {
            fields.push(field);
        }
    }
    if fields.is_empty() {
        bail!(
            "--legacy fields needs at least one event field path: a preimage with no fields gives \
             every issue in the repository the same label"
        );
    }
    Ok(fields)
}

fn parse_preimage_prefix(value: &str) -> Result<PreimagePrefix> {
    match value.trim() {
        "excluded" => Ok(PreimagePrefix::Excluded),
        "first" => Ok(PreimagePrefix::First),
        "last" => Ok(PreimagePrefix::Last),
        other => bail!(
            "unknown --legacy preimage-prefix {}; it is excluded, first or last",
            quoted(&one_line(other, MAX_INCIDENTAL_CHARS))
        ),
    }
}

// ---------------------------------------------------------------------------
// The mini-grammar `--legacy` values are written in
// ---------------------------------------------------------------------------

/// Splits on `delimiter`, ignoring one that a backslash escaped.
///
/// Escapes are left intact in the segments so [`unescape`] can resolve them
/// afterwards; splitting and unescaping in one pass would make `\;` inside a
/// value indistinguishable from a separator that had already been consumed.
fn split_unescaped(input: &str, delimiter: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for character in input.chars() {
        if escaped {
            current.push('\\');
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == delimiter {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    if escaped {
        // A trailing backslash is left for `unescape` to reject, so the error
        // names the escape rather than a mysteriously shortened value.
        current.push('\\');
    }
    parts.push(current);
    parts
}

fn split_once_unescaped(input: &str, delimiter: char) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (index, character) in input.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == delimiter {
            return Some((&input[..index], &input[index + character.len_utf8()..]));
        }
    }
    None
}

fn unescape(raw: &str) -> Result<String> {
    let mut resolved = String::with_capacity(raw.len());
    let mut characters = raw.chars();

    while let Some(character) = characters.next() {
        if character != '\\' {
            resolved.push(character);
            continue;
        }
        let Some(escape) = characters.next() else {
            bail!("a --legacy value ends in a lone backslash; write `\\\\` for a literal one");
        };
        resolved.push(match escape {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            ';' => ';',
            ',' => ',',
            '=' => '=',
            other => bail!(
                "unknown escape `\\{other}` in a --legacy value; the escapes are \
                 \\n \\t \\r \\\\ \\; \\, and \\="
            ),
        });
    }

    Ok(resolved)
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

fn run_dedupe_label(arguments: &DedupeLabelArgs) -> Result<String> {
    let config_raw = fs::read_to_string(&arguments.config_path).with_context(|| {
        format!(
            "failed to read the automation config from {}",
            display_path(&arguments.config_path)
        )
    })?;
    let config = load_config_from_str(&config_raw).with_context(|| {
        format!(
            "failed to load the automation config at {}",
            display_path(&arguments.config_path)
        )
    })?;

    let event_raw = fs::read_to_string(&arguments.event_path).with_context(|| {
        format!(
            "failed to read the event payload from {}",
            display_path(&arguments.event_path)
        )
    })?;
    let event =
        load_issue_event_from_str(&arguments.event_name, &event_raw).with_context(|| {
            format!(
                "failed to parse the event payload at {}",
                display_path(&arguments.event_path)
            )
        })?;

    render_report(&config, &event, arguments)
}

fn render_report(
    config: &AutomationConfig,
    event: &GitHubIssueEvent,
    arguments: &DedupeLabelArgs,
) -> Result<String> {
    let wanted = arguments.rule_id.as_deref();
    let selected: Vec<&RuleConfig> = config
        .rules
        .iter()
        .filter(|rule| wanted.is_none_or(|id| rule.id == id))
        .collect();
    if selected.is_empty() {
        let known: Vec<String> = config
            .rules
            .iter()
            .map(|rule| one_line(&rule.id, MAX_INCIDENTAL_CHARS))
            .collect();
        bail!(
            "no rule in the config has the id {}; the config declares {}",
            quoted(&one_line(
                arguments.rule_id.as_deref().unwrap_or_default(),
                MAX_INCIDENTAL_CHARS
            )),
            known.join(", ")
        );
    }

    let mut report = String::new();
    render_header(&mut report, event, arguments, selected.len());
    for (position, rule) in selected.iter().enumerate() {
        render_rule(
            &mut report,
            position + 1,
            selected.len(),
            rule,
            event,
            arguments,
        )?;
    }
    render_footer(&mut report);
    Ok(report)
}

fn render_header(
    report: &mut String,
    event: &GitHubIssueEvent,
    arguments: &DedupeLabelArgs,
    rules: usize,
) {
    let identity = event.identity();
    let line = |report: &mut String, label: &str, value: &str| {
        writeln!(report, "  {label:<12}{value}").expect("writing to a String cannot fail");
    };

    writeln!(
        report,
        "dedupe-label -- every label the lookup asks for, and the query it asks with\n"
    )
    .expect("writing to a String cannot fail");

    line(report, "config", &display_path(&arguments.config_path));
    line(report, "event", &display_path(&arguments.event_path));
    line(
        report,
        "delivery",
        &format!(
            "{} / {}",
            one_line(&arguments.event_name, MAX_INCIDENTAL_CHARS),
            one_line(&event.action, MAX_INCIDENTAL_CHARS)
        ),
    );
    line(
        report,
        "repository",
        &format!(
            "{}   id {}",
            one_line(&event.repository.full_name, MAX_INCIDENTAL_CHARS),
            identity.repository_id
        ),
    );
    line(
        report,
        "issue",
        &format!(
            "#{}   id {}   state {}",
            identity.issue_number,
            identity.issue_id,
            one_line(&event.issue.state, MAX_INCIDENTAL_CHARS)
        ),
    );
    line(
        report,
        "title",
        &one_line(&event.issue.title, MAX_INCIDENTAL_CHARS),
    );

    let plural = if rules == 1 { "rule" } else { "rules" };
    writeln!(
        report,
        "\n{rules} {plural} reported. Exactly one rung of each ladder -- the canonical one --\n\
         is a label this Action would WRITE. Every other rung is recognition only:\n\
         it is there so issues an earlier scheme labelled are still found.\n"
    )
    .expect("writing to a String cannot fail");
}

// The rule block is one contiguous piece of formatting; splitting it would move
// `writeln!` calls into helpers without removing a decision from any of them.
#[allow(clippy::too_many_lines, reason = "one contiguous report block")]
fn render_rule(
    report: &mut String,
    position: usize,
    total: usize,
    rule: &RuleConfig,
    event: &GitHubIssueEvent,
    arguments: &DedupeLabelArgs,
) -> Result<()> {
    let prefix = rule_label_prefix(rule);
    let options = arguments.lookup_options(prefix);
    let plan = build_lookup_plan(rule, event, &options)?;

    // The auto-registered rung is rebuilt here for its *description* only. The
    // labels below all come out of the plan, so nothing in this report can
    // disagree with what the lookup would send.
    let v0 = LegacyLabelSpec::v0(prefix, &rule.jira.dedupe.fields);
    let declared: Vec<LegacyLabelSpec> = arguments
        .legacy
        .iter()
        .map(|request| request.materialize(prefix))
        .collect();
    let describable: Vec<&LegacyLabelSpec> = std::iter::once(&v0).chain(declared.iter()).collect();

    writeln!(
        report,
        "{}\nrule  {}   ({position} of {total})",
        "=".repeat(78),
        one_line(&rule.id, MAX_INCIDENTAL_CHARS)
    )?;
    writeln!(
        report,
        "  project       {}",
        one_line(&rule.jira.project_key, MAX_INCIDENTAL_CHARS)
    )?;
    writeln!(
        report,
        "  label prefix  {}",
        one_line(prefix, MAX_INCIDENTAL_CHARS)
    )?;

    let evaluation = evaluate_rule(rule, event);
    match &evaluation {
        Ok(Some(rule_match)) => writeln!(
            report,
            "  matches       yes -- severity {}",
            quoted(&one_line(&rule_match.severity, MAX_INCIDENTAL_CHARS))
        )?,
        Ok(None) => writeln!(
            report,
            "  matches       no -- this rule would not run for this delivery, but the ladder\n\
             \x20               below is still the one it would ask with"
        )?,
        Err(error) => writeln!(
            report,
            "  matches       could not be decided: {}",
            one_line(&format!("{error:#}"), MAX_INCIDENTAL_CHARS)
        )?,
    }

    // The exact string a consumer would paste into `--summary-fallback`, taken
    // from the request builder rather than re-rendered here, so the summary
    // bound stays in one place.
    if let Ok(Some(rule_match)) = &evaluation {
        match build_create_issue_request(rule, event, rule_match) {
            Ok(request) => writeln!(
                report,
                "  summary       {}",
                one_line(&request.fields.summary, MAX_LABEL_LINE_CHARS)
            )?,
            Err(error) => writeln!(
                report,
                "  summary       unavailable: {}",
                one_line(&format!("{error:#}"), MAX_INCIDENTAL_CHARS)
            )?,
        }
    }

    writeln!(report, "\n  ladder, highest precedence first")?;
    for (position, entry) in plan.labels().iter().enumerate() {
        let (tier, detail) = match &entry.tier {
            // The description follows `jira.dedupe.identity`, because the
            // canonical rung *is* whichever scheme the rule declares. Printing
            // the `repo_issue` shape next to a `fields` digest would describe a
            // label the report is not showing.
            LadderTier::Canonical if rule.jira.dedupe.identity == DEDUPE_IDENTITY_FIELDS => (
                "canonical".to_owned(),
                vec![
                    "written by this Action under identity: fields -- the 0.4.x content".to_owned(),
                    "digest, prefix then the first 12 hex of SHA-256 over jira.dedupe.fields"
                        .to_owned(),
                ],
            ),
            LadderTier::Canonical => (
                "canonical".to_owned(),
                vec![
                    "written by this Action -- prefix, then gh, then the repository id".to_owned(),
                    "and the issue number; readable by construction and never hashed".to_owned(),
                ],
            ),
            LadderTier::Legacy { rung, spec_id } => (
                format!(
                    "legacy {rung}   {}",
                    one_line(spec_id, MAX_INCIDENTAL_CHARS)
                ),
                describable
                    .iter()
                    .find(|spec| &spec.id == spec_id)
                    .map_or_else(Vec::new, |spec| describe_spec(spec).to_vec()),
            ),
            LadderTier::SummaryFallback => ("summary".to_owned(), Vec::new()),
        };

        writeln!(report, "\n    {}  {tier}", position + 1)?;
        // Printed in full rather than through the incidental bound: this line is
        // the artifact a consumer pastes into Jira.
        writeln!(
            report,
            "       {}",
            one_line(&entry.label, MAX_LABEL_LINE_CHARS)
        )?;
        for line in detail {
            writeln!(report, "       {line}")?;
        }
    }

    // A rung whose label repeats one already in the ladder is dropped by
    // `build_lookup_plan` rather than queried twice. Saying so is the whole
    // answer to "why is my rung missing" -- and a rung that collides with the
    // auto-registered one is a consumer discovering their old scheme *is* v0.
    for spec in &describable {
        if plan.labels().iter().any(|entry| match &entry.tier {
            LadderTier::Legacy { spec_id, .. } => spec_id == &spec.id,
            LadderTier::Canonical | LadderTier::SummaryFallback => false,
        }) {
            continue;
        }
        let produced = spec.label(event).unwrap_or_default();
        writeln!(
            report,
            "\n    --  {}   not queried: it produces {}, which a higher rung already asks for",
            one_line(&spec.id, MAX_INCIDENTAL_CHARS),
            quoted(&one_line(&produced, MAX_LABEL_LINE_CHARS))
        )?;
    }

    match plan.summary_filter() {
        Some(summary) => writeln!(
            report,
            "\n  summary fallback  armed on {}\n\
             \x20   A `summary ~` match is a Lucene text match, so the query returns issues that\n\
             \x20   merely share words. A row with no ladder label is kept only when its summary\n\
             \x20   is byte-equal to the text above.",
            quoted(&one_line(summary, MAX_LABEL_LINE_CHARS))
        )?,
        None => writeln!(
            report,
            "\n  summary fallback  off\n\
             \x20   Arm it with --summary-fallback \"<exact summary>\" to also find issues created\n\
             \x20   before any label existed."
        )?,
    }

    // Validated from the plan, not recomputed: under `identity: fields` the
    // canonical rung is the `v0` digest, and re-deriving the `repo_issue` label
    // here would warn about a label this rule never writes -- or stay silent
    // about the one it does.
    if let Err(error) = validate_label(plan.canonical_label()) {
        writeln!(
            report,
            "\n  WARNING  the canonical label is not one Jira will accept: {error}\n\
             \x20         The lookup below still asks for it, but a create would be refused.\n\
             \x20         The label prefix is the only part of it this config controls."
        )?;
    }

    writeln!(report, "\n  JQL, byte for byte what the lookup issues\n")?;
    writeln!(report, "    {}", one_line(plan.jql(), MAX_QUERY_LINE_CHARS))?;

    let request = plan.search_request();
    writeln!(
        report,
        "\n  fields {}   maxResults {}\n",
        request.fields().join(", "),
        request
            .max_results()
            .map_or_else(|| "default".to_owned(), |value| value.to_string())
    )?;

    Ok(())
}

/// The two lines that say how a legacy rung's label was produced.
///
/// Every parameter this repository cannot verify for a consumer's old scheme --
/// the digest, the truncation, the field order, the joiner, the separator, and
/// whether the prefix is part of the hashed preimage -- is named here. A rung is
/// useless in this report without them: the label alone says what was tried, and
/// these lines say what to change when it turns out to be wrong.
fn describe_spec(spec: &LegacyLabelSpec) -> [String; 2] {
    [
        format!(
            "{}, first {} hex over {}, joined {}",
            spec.digest.name(),
            spec.hex_chars,
            spec.fields.join(" + "),
            quoted(&one_line(&spec.joiner, MAX_INCIDENTAL_CHARS)),
        ),
        format!(
            "label = prefix {} + {} + digest; {}",
            quoted(&one_line(&spec.label_prefix, MAX_INCIDENTAL_CHARS)),
            quoted(&one_line(&spec.separator, MAX_INCIDENTAL_CHARS)),
            match spec.preimage_prefix {
                PreimagePrefix::Excluded => "the prefix is not part of the preimage",
                PreimagePrefix::First => "the prefix is hashed ahead of the fields",
                PreimagePrefix::Last => "the prefix is hashed after the fields",
            }
        ),
    ]
}

fn render_footer(report: &mut String) {
    writeln!(
        report,
        "{}\nDiffing this against live Jira\n\n\
         \x20 1. Paste a rule's JQL into Jira -> Filters -> Advanced issue search. It is byte for\n\
         \x20    byte the query the reconciliation issues, so what comes back is what the Action\n\
         \x20    would reconcile against.\n\
         \x20 2. Then narrow to one rung at a time with  labels = \"<label>\"  to see which scheme\n\
         \x20    the issues you already have actually carry.\n\
         \x20 3. A legacy rung that returns nothing has the wrong preimage. Change the --legacy\n\
         \x20    description and run again -- the ladder is configuration, so a wrong guess costs\n\
         \x20    an edit rather than a release cycle.\n\
         \x20 4. Nothing here contacted Jira. This command read two files and printed.",
        "=".repeat(78)
    )
    .expect("writing to a String cannot fail");
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// Renders `value` as one printable line of at most `max_chars` characters.
///
/// Two jobs, and the first is the load-bearing one: an issue title, a rule id
/// and a label prefix are all caller-supplied and may carry a newline, so
/// echoing one raw would let a payload forge a line of this report -- a fake
/// ladder rung reads exactly like a real one. Control characters are escaped
/// rather than stripped so the value stays legible and stays one line.
fn one_line(value: &str, max_chars: usize) -> String {
    let mut rendered = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            control if control.is_control() => {
                write!(&mut rendered, "\\u{{{:04x}}}", control as u32)
                    .expect("writing to a String cannot fail");
            }
            other => rendered.push(other),
        }
    }
    truncate_chars(&rendered, max_chars)
}

fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

fn display_path(path: &Path) -> String {
    one_line(&path.display().to_string(), MAX_INCIDENTAL_CHARS)
}

#[cfg(test)]
mod tests {
    use super::{
        describe_spec, one_line, parse_dedupe_label_args, parse_legacy_spec, render_report,
        split_once_unescaped, split_unescaped, unescape, usage, DedupeLabelArgs, LegacySpecRequest,
        DEFAULT_EVENT_NAME,
    };
    use std::path::PathBuf;
    use threatflux_atlassian_action::config::{
        load_config_from_str, AutomationConfig, DEDUPE_IDENTITY_FIELDS,
    };
    use threatflux_atlassian_action::github::{load_issue_event_from_str, GitHubIssueEvent};
    use threatflux_atlassian_action::rules::dedupe::{
        build_lookup_plan, rule_label_prefix, v0_label, LabelDigest, LegacyLabelSpec,
        PreimagePrefix,
    };
    use threatflux_atlassian_testkit::fixtures;

    fn arguments(flags: &[&str]) -> Vec<String> {
        flags.iter().map(|flag| (*flag).to_string()).collect()
    }

    fn base_args() -> DedupeLabelArgs {
        DedupeLabelArgs {
            config_path: PathBuf::from("jira-automation.yml"),
            event_path: PathBuf::from("event.json"),
            event_name: DEFAULT_EVENT_NAME.to_owned(),
            rule_id: None,
            legacy: Vec::new(),
            summary_fallback: None,
        }
    }

    fn shipped_config() -> AutomationConfig {
        load_config_from_str(fixtures::action_config("dependabot-high"))
            .expect("the shipped dependabot config should load")
    }

    fn event(name: &str) -> GitHubIssueEvent {
        load_issue_event_from_str("issues", fixtures::github_event(name))
            .expect("event should parse")
    }

    fn report_for(args: &DedupeLabelArgs) -> String {
        render_report(&shipped_config(), &event("issues-opened-dependabot"), args)
            .expect("the report should render")
    }

    // -- the mini-grammar -------------------------------------------------

    #[test]
    fn a_legacy_spec_names_every_knob_the_preimage_has() {
        let spec = parse_legacy_spec(
            "id=acme-sha1-12;digest=sha1;hex=12;fields=repository.full_name,issue.title;\
             prefix=jira-automation;separator=_;joiner=|;preimage-prefix=first",
        )
        .expect("a fully specified rung should parse");

        assert_eq!(
            spec,
            LegacySpecRequest {
                id: "acme-sha1-12".to_owned(),
                label_prefix: Some("jira-automation".to_owned()),
                separator: "_".to_owned(),
                digest: LabelDigest::Sha1,
                hex_chars: 12,
                fields: vec!["repository.full_name".to_owned(), "issue.title".to_owned()],
                joiner: "|".to_owned(),
                preimage_prefix: PreimagePrefix::First,
            }
        );
    }

    #[test]
    fn an_unstated_knob_takes_the_default_the_help_text_promises() {
        let spec = parse_legacy_spec("id=minimal;digest=sha256;hex=16;fields=issue.title")
            .expect("a minimal rung should parse");

        assert_eq!(spec.separator, "-");
        assert_eq!(spec.joiner, "\n");
        assert_eq!(spec.preimage_prefix, PreimagePrefix::Excluded);
        assert_eq!(
            spec.label_prefix, None,
            "the rule's own prefix is the default"
        );
    }

    #[test]
    fn an_unstated_prefix_binds_to_the_rule_being_reported() {
        // The reason `LegacySpecRequest` exists: one run can report several
        // rules, and "the same prefix as before" means a different string in
        // each of them.
        let spec = parse_legacy_spec("id=r;digest=sha256;hex=12;fields=issue.title")
            .expect("rung should parse");

        assert_eq!(spec.materialize("alpha").label_prefix, "alpha");
        assert_eq!(spec.materialize("beta").label_prefix, "beta");
    }

    #[test]
    fn a_joiner_may_be_any_text_because_the_value_grammar_escapes() {
        let spec = parse_legacy_spec(
            "id=escaped;digest=sha256;hex=12;fields=issue.title;joiner=\\n;separator=\\;",
        )
        .expect("escaped values should parse");

        assert_eq!(spec.joiner, "\n");
        assert_eq!(spec.separator, ";");

        let tabbed = parse_legacy_spec("id=t;digest=sha256;hex=12;fields=issue.title;joiner=\\t")
            .expect("a tab joiner should parse");
        assert_eq!(tabbed.joiner, "\t");
    }

    #[test]
    fn a_legacy_spec_reports_what_is_wrong_with_it_rather_than_guessing() {
        for (spec, needle) in [
            ("digest=sha1;hex=12;fields=issue.title", "needs an id"),
            ("id=a;hex=12;fields=issue.title", "needs a digest"),
            ("id=a;digest=sha1;fields=issue.title", "needs hex="),
            ("id=a;digest=sha1;hex=12", "needs fields="),
            (
                "id=a;digest=md5;hex=12;fields=issue.title",
                "unknown --legacy digest",
            ),
            (
                "id=a;digest=sha1;hex=twelve;fields=issue.title",
                "takes a number",
            ),
            (
                "id=a;digest=sha1;hex=12;fields=",
                "at least one event field",
            ),
            (
                "id=a;digest=sha1;hex=12;fields=issue.title;nope=1",
                "unknown --legacy key",
            ),
            (
                "id=a;digest=sha1;hex=12;fields=issue.title;preimage-prefix=middle",
                "unknown --legacy preimage-prefix",
            ),
            (
                "id=a;digest=sha1;hex=12;fields=issue.title;joiner=\\q",
                "unknown escape",
            ),
            (
                "id=a;digest=sha1;hex=12;fields=issue.title;joiner=\\",
                "lone backslash",
            ),
            ("id=a;digest=sha1;hex=12;bare", "is not one"),
            (
                "id=a;id=b;digest=sha1;hex=12;fields=issue.title",
                "more than once",
            ),
        ] {
            let error = parse_legacy_spec(spec)
                .map(|parsed| format!("{parsed:?}"))
                .expect_err(&format!("{spec} should be refused"));
            assert!(
                format!("{error:#}").contains(needle),
                "{spec} was refused with the wrong message: {error:#}"
            );
        }
    }

    #[test]
    fn the_auto_registered_rungs_id_may_not_be_taken_by_a_declared_rung() {
        // Two descriptions under one name would make the report's rung column
        // ambiguous, and the report exists to tell schemes apart.
        let reserved = LegacyLabelSpec::v0("p", &[]).id;
        let error = parse_legacy_spec(&format!(
            "id={reserved};digest=sha256;hex=12;fields=issue.title"
        ))
        .expect_err("the auto-registered id is reserved");

        assert!(format!("{error:#}").contains("registers on its own"));
    }

    #[test]
    fn splitting_ignores_a_delimiter_that_was_escaped() {
        assert_eq!(split_unescaped("a;b;c", ';'), vec!["a", "b", "c"]);
        assert_eq!(split_unescaped(r"a\;b;c", ';'), vec![r"a\;b", "c"]);
        assert_eq!(split_unescaped("", ';'), vec![""]);

        assert_eq!(split_once_unescaped("k=v=w", '='), Some(("k", "v=w")));
        assert_eq!(split_once_unescaped(r"k\=x=v", '='), Some((r"k\=x", "v")));
        assert_eq!(split_once_unescaped("kv", '='), None);
    }

    #[test]
    fn unescape_resolves_only_the_escapes_the_help_text_lists() {
        assert_eq!(unescape(r"a\nb").unwrap(), "a\nb");
        assert_eq!(unescape(r"a\\b").unwrap(), r"a\b");
        assert_eq!(unescape(r"a\;b").unwrap(), "a;b");
        assert_eq!(unescape("plain").unwrap(), "plain");
        assert!(unescape(r"a\z").is_err());
    }

    // -- argument parsing -------------------------------------------------

    #[test]
    fn the_two_file_inputs_are_required() {
        for (flags, needle) in [
            (vec!["--event", "e.json"], "--config is required"),
            (vec!["--config", "c.yml"], "--event is required"),
        ] {
            let error = parse_dedupe_label_args(&arguments(&flags))
                .map(|parsed| format!("{parsed:?}"))
                .expect_err("a missing file input should be refused");
            assert!(format!("{error:#}").contains(needle), "{error:#}");
        }
    }

    #[test]
    fn a_flag_takes_its_value_attached_or_separated() {
        let separated = parse_dedupe_label_args(&arguments(&[
            "--config",
            "c.yml",
            "--event",
            "e.json",
            "--rule",
            "only-this-one",
        ]))
        .expect("separated values should parse");
        let attached = parse_dedupe_label_args(&arguments(&[
            "--config=c.yml",
            "--event=e.json",
            "--rule=only-this-one",
        ]))
        .expect("attached values should parse");

        assert_eq!(separated, attached);
        assert_eq!(separated.rule_id.as_deref(), Some("only-this-one"));
        assert_eq!(separated.event_name, DEFAULT_EVENT_NAME);
    }

    #[test]
    fn a_repeated_single_valued_flag_is_refused_rather_than_silently_overwritten() {
        // Last-wins would report a ladder for a file the operator is not looking
        // at, which is the one failure a validator may not have.
        let error = parse_dedupe_label_args(&arguments(&[
            "--config", "one.yml", "--config", "two.yml", "--event", "e.json",
        ]))
        .map(|parsed| format!("{parsed:?}"))
        .expect_err("a repeated --config should be refused");

        assert!(format!("{error:#}").contains("--config was given more than once"));
    }

    #[test]
    fn a_flag_with_no_value_and_an_unknown_flag_are_both_named() {
        let missing = parse_dedupe_label_args(&arguments(&["--config"]))
            .map(|parsed| format!("{parsed:?}"))
            .expect_err("a valueless flag should be refused");
        assert!(format!("{missing:#}").contains("--config needs a value"));

        let unknown = parse_dedupe_label_args(&arguments(&[
            "--config", "c.yml", "--event", "e.json", "--nope",
        ]))
        .map(|parsed| format!("{parsed:?}"))
        .expect_err("an unknown flag should be refused");
        assert!(format!("{unknown:#}").contains("unknown option"));
    }

    #[test]
    fn two_legacy_rungs_may_not_share_one_id() {
        let error = parse_dedupe_label_args(&arguments(&[
            "--config",
            "c.yml",
            "--event",
            "e.json",
            "--legacy",
            "id=same;digest=sha1;hex=12;fields=issue.title",
            "--legacy",
            "id=same;digest=sha256;hex=16;fields=issue.title",
        ]))
        .map(|parsed| format!("{parsed:?}"))
        .expect_err("duplicate rung ids should be refused");

        assert!(format!("{error:#}").contains("share the id"));
    }

    #[test]
    fn legacy_rungs_keep_the_order_they_were_declared_in() {
        let parsed = parse_dedupe_label_args(&arguments(&[
            "--config",
            "c.yml",
            "--event",
            "e.json",
            "--legacy",
            "id=first;digest=sha1;hex=12;fields=issue.title",
            "--legacy",
            "id=second;digest=sha256;hex=16;fields=issue.title",
        ]))
        .expect("two rungs should parse");

        assert_eq!(
            parsed
                .legacy
                .iter()
                .map(|spec| spec.id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"],
            "precedence is declaration order, so the report must not reorder them"
        );
    }

    // -- the report -------------------------------------------------------

    #[test]
    fn the_report_prints_every_label_in_the_ladder() {
        let mut args = base_args();
        args.legacy.push(
            parse_legacy_spec(
                "id=acme-sha1-12;digest=sha1;hex=12;fields=repository.full_name,issue.title;\
                 joiner=|;preimage-prefix=first",
            )
            .expect("rung should parse"),
        );

        let config = shipped_config();
        let delivery = event("issues-opened-dependabot");
        let rule = &config.rules[0];
        let plan = build_lookup_plan(
            rule,
            &delivery,
            &args.lookup_options(rule_label_prefix(rule)),
        )
        .expect("plan should build");

        let report = report_for(&args);

        assert_eq!(plan.labels().len(), 3, "canonical plus two legacy rungs");
        for entry in plan.labels() {
            assert!(
                report.contains(&entry.label),
                "the report dropped the label {}: {report}",
                entry.label
            );
        }
        assert!(report.contains("dependabot-alert-gh-598178766-123"));
        assert!(report.contains(
            &v0_label("dependabot-alert", &rule.jira.dedupe.fields, &delivery).expect("v0 label")
        ));
        assert!(report.contains("acme-sha1-12"));
    }

    #[test]
    fn the_report_follows_the_rules_declared_dedupe_identity() {
        // Under `identity: fields` the canonical rung *is* the 0.4.x content
        // digest, and the auto-registered v0 rung collapses into it. A report
        // that still printed the repo_issue label -- or still described the
        // canonical rung as "prefix, then gh, then the repository id" -- would
        // send an operator to Jira looking for a label this config never writes,
        // which is the one failure this command exists to prevent.
        let mut config = shipped_config();
        config.rules[0].jira.dedupe.identity = DEDUPE_IDENTITY_FIELDS.to_owned();
        let delivery = event("issues-opened-dependabot");
        let rule = &config.rules[0];
        let expected = v0_label(rule_label_prefix(rule), &rule.jira.dedupe.fields, &delivery)
            .expect("v0 label");

        let report =
            render_report(&config, &delivery, &base_args()).expect("the report should render");

        assert!(
            report.contains(&expected),
            "the fields-identity label is missing: {report}"
        );
        assert!(
            !report.contains("dependabot-alert-gh-598178766-123"),
            "the repo_issue label must not appear under identity: fields: {report}"
        );
        assert!(
            report.contains("identity: fields"),
            "the canonical rung must say which scheme it is: {report}"
        );
        assert!(
            !report.contains("then gh, then the repository id"),
            "the repo_issue description must not appear under identity: fields: {report}"
        );
    }

    #[test]
    fn the_report_prints_the_query_byte_for_byte() {
        // The whole point of the command: what is printed has to be the string
        // that goes on the wire, not a reconstruction of it.
        let args = base_args();
        let config = shipped_config();
        let delivery = event("issues-opened-dependabot");
        let rule = &config.rules[0];
        let plan = build_lookup_plan(
            rule,
            &delivery,
            &args.lookup_options(rule_label_prefix(rule)),
        )
        .expect("plan should build");

        let report = report_for(&args);

        assert!(
            report.contains(plan.jql()),
            "the report's query is not the plan's query.\nplan: {}\nreport: {report}",
            plan.jql()
        );
        assert!(
            report.lines().any(|line| line.trim() == plan.jql()),
            "the query has to be on a line of its own so it can be copied"
        );
    }

    #[test]
    fn the_report_is_deterministic() {
        let args = base_args();
        assert_eq!(report_for(&args), report_for(&args));
    }

    #[test]
    fn the_report_says_which_rung_writes_and_which_only_reads() {
        let report = report_for(&base_args());

        assert!(report.contains("canonical"));
        assert!(report.contains("written by this Action"));
        assert!(report.contains("legacy 0   v0-sha256-12"));
        assert!(report.contains("recognition only"));

        // Everything except the query is prose a human reads at a terminal. The
        // query is exempt on purpose -- it is copied, not read, and wrapping it
        // would produce a string that is no longer the one on the wire.
        let config = shipped_config();
        let delivery = event("issues-opened-dependabot");
        let rule = &config.rules[0];
        let query = build_lookup_plan(
            rule,
            &delivery,
            &base_args().lookup_options(rule_label_prefix(rule)),
        )
        .expect("plan should build")
        .jql()
        .to_owned();
        for line in report.lines().filter(|line| line.trim() != query) {
            assert!(
                line.chars().count() <= 100,
                "a line a human is meant to read runs past a terminal: {line:?}"
            );
        }
    }

    #[test]
    fn the_report_describes_the_preimage_of_every_legacy_rung() {
        // Q1's actual question is "which preimage did the old scheme use", so a
        // rung is useless in this report unless the parameters that produced it
        // are printed next to the label it produced.
        let mut args = base_args();
        args.legacy.push(
            parse_legacy_spec(
                "id=acme;digest=sha1;hex=16;fields=issue.number,repository.full_name;\
                 joiner=|;preimage-prefix=last",
            )
            .expect("rung should parse"),
        );

        let report = report_for(&args);

        assert!(report
            .contains("sha1, first 16 hex over issue.number + repository.full_name, joined \"|\""));
        assert!(report.contains("the prefix is hashed after the fields"));
        // The auto-registered rung is described the same way, so a consumer can
        // compare their guess against the one scheme this crate can prove.
        assert!(report.contains(
            "sha256, first 12 hex over repository.full_name + issue.title, joined \"\\n\""
        ));
        assert!(report.contains("the prefix is not part of the preimage"));
    }

    #[test]
    fn a_rung_that_repeats_one_already_in_the_ladder_is_reported_rather_than_vanishing() {
        // A consumer whose guess reproduces v0 has learned something, and a rung
        // that silently disappeared from the report would have taught them
        // nothing.
        let mut args = base_args();
        args.legacy.push(
            parse_legacy_spec(
                "id=my-guess;digest=sha256;hex=12;fields=repository.full_name,issue.title",
            )
            .expect("rung should parse"),
        );

        let report = report_for(&args);

        assert!(
            report.contains("my-guess") && report.contains("not queried"),
            "a dropped rung has to be named and explained: {report}"
        );
        assert!(report.contains("a higher rung already asks for"));
    }

    #[test]
    fn the_summary_rung_appears_only_when_it_is_armed() {
        let off = report_for(&base_args());
        assert!(off.contains("summary fallback  off"));
        assert!(!off.contains("summary ~"));

        let mut armed = base_args();
        armed.summary_fallback = Some("[Dependabot][High] Bump openssl from 1.0 to 1.1".to_owned());
        let on = report_for(&armed);

        assert!(on.contains("summary fallback  armed on"));
        assert!(on.contains("summary ~"), "the query has to carry the term");
        assert!(
            on.contains("byte-equal"),
            "the post-filter has to be stated"
        );
    }

    #[test]
    fn a_rule_that_does_not_match_the_delivery_is_reported_and_still_gets_a_ladder() {
        // The ladder is what the rule *would* ask with, so it is still worth
        // printing -- but a consumer diffing against Jira has to know this rule
        // would never have run.
        let report = render_report(
            &shipped_config(),
            &event("issues-opened-human-medium"),
            &base_args(),
        )
        .expect("the report should render for a non-matching delivery");

        assert!(report.contains("matches       no --"));
        assert!(report.contains("labels IN ("));
        assert!(
            report.contains("jira-automation-gh-598178766-2") || report.contains("-gh-598178766-2")
        );
    }

    #[test]
    fn a_matching_rule_prints_the_summary_a_consumer_can_paste_into_the_fallback() {
        let report = report_for(&base_args());

        assert!(
            report.contains("[Dependabot][High] Bump openssl from 1.0 to 1.1"),
            "the rendered summary is the value --summary-fallback wants: {report}"
        );
    }

    #[test]
    fn the_rule_filter_selects_one_rule_and_names_the_ids_it_knows() {
        let two_rules = load_config_from_str(&fixtures::action_config("dependabot-high").replace(
            "  - id: dependabot-high-issues",
            "  - id: second-rule\n\
             \x20   when:\n\
             \x20     event: issues\n\
             \x20     action: opened\n\
             \x20   extract:\n\
             \x20     severity:\n\
             \x20       from: issue.body\n\
             \x20       regex: '(?mi)^severity:\\s*(high)\\b'\n\
             \x20   jira:\n\
             \x20     project_key: OPS\n\
             \x20     issue_type: Bug\n\
             \x20     priority_by_severity:\n\
             \x20       high: High\n\
             \x20     summary: second\n\
             \x20     description: second\n\
             \x20     dedupe:\n\
             \x20       strategy: sha256\n\
             \x20       fields: [repository.full_name]\n\
             \x20 - id: dependabot-high-issues",
        ))
        .expect("a two-rule config should load");
        assert_eq!(two_rules.rules.len(), 2);

        let delivery = event("issues-opened-dependabot");
        let both = render_report(&two_rules, &delivery, &base_args()).expect("both rules render");
        assert!(both.contains("(1 of 2)") && both.contains("(2 of 2)"));

        let mut only = base_args();
        only.rule_id = Some("second-rule".to_owned());
        let one = render_report(&two_rules, &delivery, &only).expect("one rule renders");
        assert!(one.contains("(1 of 1)"));
        assert!(one.contains("second-rule"));
        assert!(!one.contains("dependabot-high-issues"));

        let mut missing = base_args();
        missing.rule_id = Some("no-such-rule".to_owned());
        let error = render_report(&two_rules, &delivery, &missing)
            .map(|report| report.len().to_string())
            .expect_err("an unknown rule id should be refused");
        assert!(format!("{error:#}").contains("no rule in the config has the id"));
        assert!(
            format!("{error:#}").contains("second-rule"),
            "the error has to list the ids that do exist: {error:#}"
        );
    }

    #[test]
    fn a_prefix_that_makes_an_unwritable_canonical_label_is_warned_about() {
        // `canonical_label` is infallible on purpose -- refusing here would turn
        // a configuration that reconciles today into a failed run -- so the only
        // place a consumer can learn their prefix produces a label Jira will not
        // carry is a report like this one, before the first create fails.
        let mut config = shipped_config();
        config.rules[0].jira.dedupe.label_prefix = Some(r#"dep"bot"#.to_owned());

        let report = render_report(&config, &event("issues-opened-dependabot"), &base_args())
            .expect("an unwritable canonical label is reported, not an error");

        assert!(report.contains("WARNING"), "{report}");
        assert!(report.contains("not one Jira will accept"), "{report}");
        // The lookup still asks for it: an issue already carrying that label has
        // to stay findable, which is why only the *write* is in question.
        assert!(report.contains(r#"dep\"bot-gh-598178766-123"#), "{report}");
    }

    #[test]
    fn a_payload_cannot_forge_a_line_of_the_report() {
        // The issue title is the one unbounded, wholly attacker-controlled value
        // in the header. A raw newline in it would put an arbitrary line into a
        // report a human reads as authoritative -- a fake ladder rung reads
        // exactly like a real one.
        let mut payload = fixtures::github_event_json("issues-opened-dependabot");
        payload["issue"]["title"] =
            serde_json::json!("innocent\n    9  canonical\n       forged-label-gh-1-1");
        let delivery = load_issue_event_from_str("issues", &payload.to_string())
            .expect("the hostile delivery should parse");

        let report = render_report(&shipped_config(), &delivery, &base_args())
            .expect("the report should render");

        assert!(
            !report.contains("\n       forged-label-gh-1-1"),
            "the title escaped its line: {report}"
        );
        assert!(
            report.contains("innocent\\n"),
            "the newline has to show as an escape"
        );
    }

    #[test]
    fn one_line_escapes_control_characters_and_bounds_the_result() {
        assert_eq!(one_line("a\nb\tc\rd", 64), "a\\nb\\tc\\rd");
        assert_eq!(one_line("a\u{7}b", 64), "a\\u{0007}b");
        assert_eq!(one_line("abcdef", 3).chars().count(), 3);
        assert_eq!(one_line("abc", 3), "abc", "an exact fit is not truncated");
    }

    #[test]
    fn describe_spec_names_every_parameter_a_wrong_guess_could_be_in() {
        let described = describe_spec(
            &LegacyLabelSpec::new(
                "spec",
                "pfx",
                LabelDigest::Sha256,
                16,
                ["issue.title".to_owned()],
            )
            .with_separator("_")
            .with_joiner("|")
            .with_preimage_prefix(PreimagePrefix::First),
        );

        let joined = described.join("\n");
        for expected in [
            "sha256",
            "first 16 hex",
            "issue.title",
            "joined \"|\"",
            "prefix \"pfx\"",
            "\"_\"",
            "the prefix is hashed ahead of the fields",
        ] {
            assert!(joined.contains(expected), "{expected} missing: {joined}");
        }
        for line in &described {
            assert!(
                line.chars().count() <= 100,
                "a rung description has to fit a terminal: {line:?}"
            );
        }
    }

    #[test]
    fn the_help_text_documents_every_flag_the_parser_accepts() {
        let help = usage();
        for flag in [
            "--config",
            "--event",
            "--event-name",
            "--rule",
            "--summary-fallback",
            "--legacy",
        ] {
            assert!(help.contains(flag), "{flag} is undocumented");
        }
        for key in [
            "id",
            "digest",
            "hex",
            "fields",
            "prefix",
            "separator",
            "joiner",
            "preimage-prefix",
        ] {
            assert!(help.contains(key), "the --legacy key {key} is undocumented");
        }
        assert!(
            help.contains("opens no network connection"),
            "the read-only promise is the reason this is safe to run against a production config"
        );
    }
}
