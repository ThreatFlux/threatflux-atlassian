//! Resolution of the inputs declared in `action.yml`.
//!
//! GitHub exposes a container-action input as `INPUT_` + the declared name
//! uppercased with spaces -- and only spaces -- replaced by underscores. Hyphens
//! are preserved, so the hyphenated names in `action.yml` reach the container as
//! `INPUT_CONFIG-PATH`, `INPUT_DRY-RUN`, `INPUT_LOG-LEVEL`, `INPUT_EVENT-NAME`
//! and `INPUT_EVENT-PATH`. The underscored spelling is kept as an accepted alias
//! because local and manual invocations conventionally set it, and because
//! nothing in the runner forbids it.
//!
//! Every input is read here rather than at its point of use, so the runner
//! spelling cannot drift away from `action.yml` one call site at a time.

use anyhow::{anyhow, bail, Result};

/// Config file read when the `config-path` input is unset or blank.
///
/// Must stay equal to the `config-path` default in `action.yml`.
pub const DEFAULT_CONFIG_PATH: &str = ".github/threatflux/jira-automation.yml";

/// Tracing filter used when the `log-level` input is unset or blank.
///
/// Must stay equal to the `log-level` default in `action.yml`.
pub const DEFAULT_LOG_LEVEL: &str = "info";

const CONFIG_PATH: &str = "config-path";
const DRY_RUN: &str = "dry-run";
const LOG_LEVEL: &str = "log-level";
const EVENT_NAME: &str = "event-name";
const EVENT_PATH: &str = "event-path";

/// Every `action.yml` input, resolved once from the process environment.
///
/// `event_name` and `event_path` are optional here because the runner supplies
/// `GITHUB_EVENT_NAME`/`GITHUB_EVENT_PATH` for a real delivery; the inputs of the
/// same name are overrides for tests and local debugging. Use
/// [`ActionEnv::require_event_name`] and [`ActionEnv::require_event_path`] to
/// turn an unset value into the error a caller can report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionEnv {
    /// Path to the repo-local automation config.
    pub config_path: String,
    /// Whether rules are evaluated without calling Jira.
    pub dry_run: bool,
    /// Tracing filter for action logs.
    pub log_level: String,
    /// GitHub event name, from the input or `GITHUB_EVENT_NAME`.
    pub event_name: Option<String>,
    /// GitHub event payload path, from the input or `GITHUB_EVENT_PATH`.
    pub event_path: Option<String>,
}

impl Default for ActionEnv {
    fn default() -> Self {
        Self {
            config_path: DEFAULT_CONFIG_PATH.to_string(),
            dry_run: false,
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            event_name: None,
            event_path: None,
        }
    }
}

impl ActionEnv {
    /// Reads every declared input from the process environment.
    ///
    /// Blank and whitespace-only values are treated as unset, so a workflow that
    /// passes an empty `with:` value gets the documented default rather than an
    /// empty path.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            config_path: input(CONFIG_PATH).unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string()),
            dry_run: bool_input(DRY_RUN)?,
            log_level: input(LOG_LEVEL).unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string()),
            event_name: input(EVENT_NAME).or_else(|| non_empty_env_var("GITHUB_EVENT_NAME")),
            event_path: input(EVENT_PATH).or_else(|| non_empty_env_var("GITHUB_EVENT_PATH")),
        })
    }

    /// Returns the resolved event name, or an error naming both sources.
    pub fn require_event_name(&self) -> Result<&str> {
        self.event_name.as_deref().ok_or_else(|| {
            anyhow!("Missing event name: set the `event-name` input (INPUT_EVENT-NAME) or GITHUB_EVENT_NAME")
        })
    }

    /// Returns the resolved event payload path, or an error naming both sources.
    pub fn require_event_path(&self) -> Result<&str> {
        self.event_path.as_deref().ok_or_else(|| {
            anyhow!("Missing event path: set the `event-path` input (INPUT_EVENT-PATH) or GITHUB_EVENT_PATH")
        })
    }
}

/// Environment variable names carrying the input `name`, runner spelling first.
///
/// The runner spelling replaces spaces only; the alias additionally replaces
/// hyphens. For a name containing neither, both entries are identical.
fn input_env_names(name: &str) -> [String; 2] {
    let runner = format!("INPUT_{}", name.to_ascii_uppercase().replace(' ', "_"));
    let alias = runner.replace('-', "_");
    [runner, alias]
}

/// Reads the input `name` as declared in `action.yml`.
fn input(name: &str) -> Option<String> {
    let [runner, alias] = input_env_names(name);
    non_empty_env_var(&runner).or_else(|| non_empty_env_var(&alias))
}

/// Reads a boolean input, rejecting values that cannot be interpreted.
///
/// An unrecognized value is an error rather than `false`: `dry-run` gates every
/// Jira write, so guessing on a typo would call Jira for real on an input whose
/// intent is unknown.
fn bool_input(name: &str) -> Result<bool> {
    let Some(raw) = input(name) else {
        return Ok(false);
    };

    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("Invalid `{name}` input value `{raw}`: expected one of true, false, 1, 0, yes, no, on, off"),
    }
}

/// Reads `primary`, falling back to `alias` when it is unset or blank.
pub(crate) fn resolve_env_alias(primary: &str, alias: &str) -> Option<String> {
    non_empty_env_var(primary).or_else(|| non_empty_env_var(alias))
}

/// Reads `name`, treating a blank or whitespace-only value as unset.
pub(crate) fn non_empty_env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        input_env_names, resolve_env_alias, ActionEnv, CONFIG_PATH, DEFAULT_CONFIG_PATH,
        DEFAULT_LOG_LEVEL, DRY_RUN, EVENT_NAME, EVENT_PATH, LOG_LEVEL,
    };
    use serial_test::serial;
    use threatflux_atlassian_testkit::env::EnvGuard;

    const ACTION_YML: &str = include_str!("../../../action.yml");

    #[test]
    fn input_env_names_preserve_hyphens_and_replace_spaces() {
        assert_eq!(
            input_env_names("config-path"),
            [
                "INPUT_CONFIG-PATH".to_string(),
                "INPUT_CONFIG_PATH".to_string()
            ]
        );
        assert_eq!(
            input_env_names("my input"),
            ["INPUT_MY_INPUT".to_string(), "INPUT_MY_INPUT".to_string()]
        );
    }

    #[test]
    #[serial]
    fn from_env_reads_the_names_the_runner_actually_sets() {
        let mut guard = EnvGuard::new();
        clear_inputs(&mut guard);
        guard
            .set("INPUT_CONFIG-PATH", "/tmp/runner-config.yml")
            .set("INPUT_DRY-RUN", "true")
            .set("INPUT_LOG-LEVEL", "debug")
            .set("INPUT_EVENT-NAME", "issues")
            .set("INPUT_EVENT-PATH", "/tmp/runner-event.json");

        let action_env = ActionEnv::from_env().expect("runner inputs should resolve");

        assert_eq!(action_env.config_path, "/tmp/runner-config.yml");
        assert!(action_env.dry_run);
        assert_eq!(action_env.log_level, "debug");
        assert_eq!(action_env.event_name.as_deref(), Some("issues"));
        assert_eq!(
            action_env.event_path.as_deref(),
            Some("/tmp/runner-event.json")
        );
    }

    #[test]
    #[serial]
    fn from_env_accepts_underscored_aliases() {
        let mut guard = EnvGuard::new();
        clear_inputs(&mut guard);
        guard
            .set("INPUT_CONFIG_PATH", "/tmp/alias-config.yml")
            .set("INPUT_DRY_RUN", "true")
            .set("INPUT_LOG_LEVEL", "trace")
            .set("INPUT_EVENT_NAME", "issues")
            .set("INPUT_EVENT_PATH", "/tmp/alias-event.json");

        let action_env = ActionEnv::from_env().expect("alias inputs should resolve");

        assert_eq!(action_env.config_path, "/tmp/alias-config.yml");
        assert!(action_env.dry_run);
        assert_eq!(action_env.log_level, "trace");
        assert_eq!(action_env.event_name.as_deref(), Some("issues"));
        assert_eq!(
            action_env.event_path.as_deref(),
            Some("/tmp/alias-event.json")
        );
    }

    #[test]
    #[serial]
    fn from_env_prefers_the_runner_spelling_over_the_alias() {
        let mut guard = EnvGuard::new();
        clear_inputs(&mut guard);
        guard
            .set("INPUT_CONFIG-PATH", "/tmp/runner-config.yml")
            .set("INPUT_CONFIG_PATH", "/tmp/alias-config.yml")
            .set("INPUT_DRY-RUN", "true")
            .set("INPUT_DRY_RUN", "false");

        let action_env = ActionEnv::from_env().expect("both spellings should resolve");

        assert_eq!(action_env.config_path, "/tmp/runner-config.yml");
        assert!(action_env.dry_run);
    }

    #[test]
    #[serial]
    fn from_env_falls_back_to_defaults_for_unset_and_blank_inputs() {
        let mut guard = EnvGuard::new();
        clear_inputs(&mut guard);
        guard
            .set("INPUT_CONFIG-PATH", "   ")
            .set("INPUT_LOG-LEVEL", "")
            .set("INPUT_EVENT-NAME", "  ")
            .set("INPUT_EVENT-PATH", "");

        let action_env = ActionEnv::from_env().expect("blank inputs should resolve to defaults");

        assert_eq!(action_env, ActionEnv::default());
        assert_eq!(action_env.config_path, DEFAULT_CONFIG_PATH);
        assert_eq!(action_env.log_level, DEFAULT_LOG_LEVEL);
        assert!(!action_env.dry_run);
    }

    #[test]
    #[serial]
    fn from_env_falls_back_to_the_github_event_environment() {
        let mut guard = EnvGuard::new();
        clear_inputs(&mut guard);
        guard
            .set("INPUT_EVENT-NAME", "  ")
            .set("GITHUB_EVENT_NAME", "issues")
            .set("GITHUB_EVENT_PATH", "/tmp/github-event.json");

        let action_env = ActionEnv::from_env().expect("github event env should resolve");

        assert_eq!(action_env.event_name.as_deref(), Some("issues"));
        assert_eq!(
            action_env.event_path.as_deref(),
            Some("/tmp/github-event.json")
        );
    }

    #[test]
    #[serial]
    fn from_env_parses_every_documented_dry_run_token() {
        for (raw, expected) in [
            ("1", true),
            ("true", true),
            ("TRUE", true),
            (" True ", true),
            ("yes", true),
            ("on", true),
            ("0", false),
            ("false", false),
            ("FALSE", false),
            ("no", false),
            ("off", false),
            ("   ", false),
        ] {
            let mut guard = EnvGuard::new();
            clear_inputs(&mut guard);
            guard.set("INPUT_DRY-RUN", raw);

            let action_env = ActionEnv::from_env().expect("documented token should parse");
            assert_eq!(action_env.dry_run, expected, "dry-run value `{raw}`");
        }
    }

    #[test]
    #[serial]
    fn from_env_rejects_an_uninterpretable_dry_run_value() {
        let mut guard = EnvGuard::new();
        clear_inputs(&mut guard);
        guard.set("INPUT_DRY-RUN", "maybe");

        let error = ActionEnv::from_env().expect_err("an unknown token must not mean `false`");
        assert!(
            error.to_string().contains("Invalid `dry-run` input value"),
            "unexpected error: {error}"
        );
    }

    #[test]
    #[serial]
    fn every_action_yml_input_has_a_reader() {
        let declared = declared_inputs();
        assert_eq!(
            declared,
            vec![
                CONFIG_PATH.to_string(),
                DRY_RUN.to_string(),
                LOG_LEVEL.to_string(),
                EVENT_NAME.to_string(),
                EVENT_PATH.to_string(),
            ],
            "action.yml inputs and the ActionEnv readers have drifted apart"
        );

        for name in declared {
            let probe = probe_value(&name);
            let [runner, _alias] = input_env_names(&name);

            let mut guard = EnvGuard::new();
            clear_inputs(&mut guard);
            guard.set(&runner, &probe);

            let action_env = ActionEnv::from_env().expect("probe value should resolve");
            assert_eq!(
                observed_input(&action_env, &name),
                probe,
                "input `{name}` is not read from `{runner}`"
            );
        }
    }

    fn declared_inputs() -> Vec<String> {
        let document: yaml_serde::Value =
            yaml_serde::from_str(ACTION_YML).expect("action.yml should parse");
        let inputs = document
            .get("inputs")
            .and_then(yaml_serde::Value::as_mapping)
            .expect("action.yml should declare inputs");

        inputs
            .keys()
            .map(|key| {
                key.as_str()
                    .expect("input names should be strings")
                    .to_string()
            })
            .collect()
    }

    fn probe_value(name: &str) -> String {
        if name == DRY_RUN {
            "true".to_string()
        } else {
            format!("probe-{name}")
        }
    }

    fn observed_input(action_env: &ActionEnv, name: &str) -> String {
        match name {
            CONFIG_PATH => action_env.config_path.clone(),
            DRY_RUN => action_env.dry_run.to_string(),
            LOG_LEVEL => action_env.log_level.clone(),
            EVENT_NAME => action_env.event_name.clone().unwrap_or_default(),
            EVENT_PATH => action_env.event_path.clone().unwrap_or_default(),
            other => panic!("action.yml declares input `{other}` but ActionEnv has no reader"),
        }
    }

    fn clear_inputs(guard: &mut EnvGuard) {
        for name in [CONFIG_PATH, DRY_RUN, LOG_LEVEL, EVENT_NAME, EVENT_PATH] {
            for variable in input_env_names(name) {
                guard.remove(variable);
            }
        }
        guard.remove("GITHUB_EVENT_NAME");
        guard.remove("GITHUB_EVENT_PATH");
    }

    #[test]
    #[serial]
    fn resolve_env_alias_ignores_blank_primary_values() {
        let mut guard = EnvGuard::new();
        guard.set("PRIMARY_ENV", "  ").set("ALIAS_ENV", "fallback");

        let resolved = resolve_env_alias("PRIMARY_ENV", "ALIAS_ENV");
        assert_eq!(resolved.as_deref(), Some("fallback"));
    }
}
