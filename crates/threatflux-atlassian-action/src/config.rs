use crate::rules::{is_supported_event_field_path, validate_template, SUPPORTED_EVENT_NAME};
use anyhow::Result;
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
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub label_prefix: Option<String>,
    pub fields: Vec<String>,
}

fn default_description_format() -> String {
    "text".to_string()
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
            "Rule '{rule_id}' has an unusable {field}: U+{:04X} cannot appear in a Jira label",
            u32::from(ch)
        );
    }

    Ok(())
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

        if rule.jira.description_format != "text" {
            anyhow::bail!(
                "Rule '{}' has unsupported description format '{}'",
                rule.id,
                rule.jira.description_format
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
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        denied_env_var, is_forbidden_jira_text_char, load_config_from_str, ENV_ALLOWLIST_VAR,
    };
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
    fn load_config_rejects_unsupported_description_format() {
        let error = load_config_from_str(fixtures::action_config("reject-description-format-adf"))
            .expect_err("unsupported format should fail");
        assert!(error.to_string().contains("unsupported description format"));
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
}
