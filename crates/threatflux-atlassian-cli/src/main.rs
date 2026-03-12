#![allow(clippy::all, clippy::pedantic, clippy::nursery)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use fluxencrypt::keys::parsing::parse_public_key_from_str;
use fluxencrypt::keys::KeyPair;
use fluxencrypt::{Config as FluxConfig, HybridCipher};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{self, json};
use threatflux_atlassian_sdk::{AtlassianClient, AtlassianConfig, CreateIssueRequest, JiraField};
use tracing::Level;

/// Default maximum number of issues to return when not specified.
const DEFAULT_ISSUE_LIMIT: u32 = 50;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "CLI for interacting with Atlassian Jira APIs",
    propagate_version = true
)]
struct Cli {
    /// Override the Jira base URL (e.g., `https://company.atlassian.net`).
    #[arg(long)]
    base_url: Option<String>,
    /// Provide the Jira username/email (overrides environment configuration).
    #[arg(long)]
    username: Option<String>,
    /// Provide the Jira API token (overrides environment configuration).
    #[arg(long)]
    api_token: Option<String>,
    /// Request timeout in seconds.
    #[arg(long)]
    timeout: Option<u64>,
    /// Disable TLS certificate verification.
    #[arg(long, default_value_t = false)]
    insecure: bool,
    /// Custom user-agent string for requests.
    #[arg(long)]
    user_agent: Option<String>,
    /// Enable verbose logging output.
    #[arg(long, default_value_t = false)]
    verbose: bool,
    /// Operation to execute.
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Display the currently authenticated user profile.
    Profile,
    /// Run a health check against the Jira API.
    Health,
    /// Fetch a single issue by key (e.g., PROJ-123).
    IssueGet {
        #[arg(value_name = "KEY")]
        issue: String,
    },
    /// Search for issues using a JQL query string.
    IssueSearch {
        #[arg(long, value_name = "JQL", required = true)]
        jql: String,
        #[arg(long, value_name = "START")]
        start: Option<u32>,
        #[arg(long, value_name = "LIMIT")]
        limit: Option<u32>,
    },
    /// List all projects accessible to the user.
    ProjectsList,
    /// Retrieve a specific project by key or ID.
    ProjectGet {
        #[arg(value_name = "KEY_OR_ID")]
        project: String,
    },
    /// Search for issues within a project.
    ProjectIssues {
        #[arg(value_name = "KEY")]
        project: String,
        #[arg(long, value_name = "START")]
        start: Option<u32>,
        #[arg(long, value_name = "LIMIT")]
        limit: Option<u32>,
    },
    /// List Jira fields (optionally show only custom fields).
    FieldsList {
        #[arg(long, default_value_t = false)]
        custom_only: bool,
    },
    /// Locate a field by display name (case-insensitive).
    FieldFind {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Create a new issue from a JSON request body.
    IssueCreate {
        #[arg(value_name = "PATH")]
        request: PathBuf,
    },
    /// Update the story points on an issue.
    IssueUpdateStoryPoints {
        #[arg(value_name = "KEY")]
        issue: String,
        #[arg(long, value_name = "VALUE")]
        value: f64,
        #[arg(long, value_name = "FIELD", default_value = "customfield_10016")]
        field_id: String,
    },
    /// Update a custom field value on an issue.
    IssueUpdateField {
        #[arg(value_name = "KEY")]
        issue: String,
        #[arg(long, value_name = "FIELD")]
        field_id: String,
        #[arg(long, value_name = "VALUE")]
        value: String,
    },
    /// Transition an issue to a different workflow state.
    ///
    /// Provide either `--status` (transition name) or `--transition-id`. When no option is
    /// supplied the CLI outputs the available transitions for that issue.
    IssueTransition {
        #[arg(value_name = "KEY")]
        issue: String,
        #[arg(long, value_name = "STATUS", conflicts_with = "transition_id")]
        status: Option<String>,
        #[arg(long, value_name = "TRANSITION_ID", conflicts_with = "status")]
        transition_id: Option<String>,
        #[arg(long, value_name = "COMMENT")]
        comment: Option<String>,
    },
    /// Generate a FluxEncrypt-compatible RSA key pair.
    Keygen {
        #[arg(long, default_value_t = 4096)]
        bits: usize,
        #[arg(long, value_name = "PATH")]
        private_out: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        public_out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        stdout: bool,
    },
    /// Encrypt a Jira credential using a FluxEncrypt public key.
    SecretEncrypt {
        #[arg(long, value_name = "PATH", conflicts_with = "public_key_inline")]
        public_key_path: Option<PathBuf>,
        #[arg(long, value_name = "PEM", conflicts_with = "public_key_path")]
        public_key_inline: Option<String>,
        #[arg(long, value_name = "SECRET", conflicts_with_all = ["secret_file", "secret_env"])]
        secret: Option<String>,
        #[arg(long, value_name = "PATH", conflicts_with_all = ["secret", "secret_env"])]
        secret_file: Option<PathBuf>,
        #[arg(long, value_name = "NAME", conflicts_with_all = ["secret", "secret_file"])]
        secret_env: Option<String>,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen {
            bits,
            private_out,
            public_out,
            stdout,
        } => {
            handle_keygen(*bits, private_out.clone(), public_out.clone(), *stdout)?;
            return Ok(());
        }
        Commands::SecretEncrypt {
            public_key_path,
            public_key_inline,
            secret,
            secret_file,
            secret_env,
            output,
        } => {
            handle_secret_encrypt(
                public_key_path.clone(),
                public_key_inline.clone(),
                secret.clone(),
                secret_file.clone(),
                secret_env.clone(),
                output.clone(),
            )?;
            return Ok(());
        }
        _ => {}
    }

    init_tracing(cli.verbose);

    let config = build_config(&cli).context("failed to construct Atlassian configuration")?;
    let client = AtlassianClient::new(config).context("failed to build Atlassian client")?;

    match cli.command {
        Commands::Profile => {
            let user = client
                .get_myself()
                .await
                .context("failed to fetch user profile")?;
            print_json(&user)?;
        }
        Commands::Health => {
            let healthy = client
                .health_check()
                .await
                .context("failed to perform Jira health check")?;
            print_json(&json!({ "healthy": healthy }))?;
        }
        Commands::IssueGet { issue } => {
            let record = client
                .get_issue(&issue)
                .await
                .with_context(|| format!("failed to fetch issue {issue}"))?;
            print_json(&record)?;
        }
        Commands::IssueSearch { jql, start, limit } => {
            let start_at = start.unwrap_or(0);
            let max_results = limit.unwrap_or(DEFAULT_ISSUE_LIMIT);
            let results = client
                .search_issues(&jql, start_at, max_results)
                .await
                .with_context(|| format!("JQL search failed: {jql}"))?;
            print_json(&results)?;
        }
        Commands::ProjectsList => {
            let projects = client
                .get_projects()
                .await
                .context("failed to list Jira projects")?;
            print_json(&projects)?;
        }
        Commands::ProjectGet { project } => {
            let project = client
                .get_project(&project)
                .await
                .with_context(|| format!("failed to fetch project {project}"))?;
            print_json(&project)?;
        }
        Commands::ProjectIssues {
            project,
            start,
            limit,
        } => {
            let start_at = start.unwrap_or(0);
            let max_results = limit.unwrap_or(DEFAULT_ISSUE_LIMIT);
            let jql = format!("project = {}", project);
            let results = client
                .search_issues(&jql, start_at, max_results)
                .await
                .with_context(|| format!("failed to search issues for project {project}"))?;
            print_json(&results)?;
        }
        Commands::FieldsList { custom_only } => {
            let mut fields = client
                .get_fields()
                .await
                .context("failed to retrieve Jira fields")?;
            if custom_only {
                fields.retain(|field| field.custom);
            }
            print_json(&fields)?;
        }
        Commands::FieldFind { name } => {
            let fields = client
                .get_fields()
                .await
                .context("failed to retrieve Jira fields")?;
            let matches: Vec<JiraField> = fields
                .into_iter()
                .filter(|field| field.name.eq_ignore_ascii_case(&name))
                .collect();
            if matches.is_empty() {
                bail!("No field found with name '{name}'");
            }
            print_json(&matches)?;
        }
        Commands::IssueCreate { request } => {
            let payload: CreateIssueRequest = load_json_file(&request).with_context(|| {
                format!("failed to load issue request from {}", request.display())
            })?;
            let issue = client
                .create_issue(payload)
                .await
                .context("failed to create issue")?;
            print_json(&issue)?;
        }
        Commands::IssueUpdateStoryPoints {
            issue,
            value,
            field_id,
        } => {
            client
                .update_story_points(&issue, value, &field_id)
                .await
                .with_context(|| format!("failed to update story points for {issue}"))?;
            print_json(&json!({
                "issue": issue,
                "action": "update_story_points",
                "field_id": field_id,
                "value": value,
            }))?;
        }
        Commands::IssueUpdateField {
            issue,
            field_id,
            value,
        } => {
            client
                .update_custom_field(&issue, &field_id, &value)
                .await
                .with_context(|| format!("failed to update field {field_id} on {issue}"))?;
            print_json(&json!({
                "issue": issue,
                "action": "update_custom_field",
                "field_id": field_id,
                "value": value,
            }))?;
        }
        Commands::IssueTransition {
            issue,
            status,
            transition_id,
            comment,
        } => {
            let normalized_comment = normalize_comment(&comment);
            let comment_arg = normalized_comment.as_deref();
            let comment_added = normalized_comment.is_some();

            match (status, transition_id) {
                (None, None) => {
                    let transitions = client
                        .get_issue_transitions(&issue)
                        .await
                        .with_context(|| format!("failed to list transitions for issue {issue}"))?;
                    print_json(&transitions)?;
                }
                (Some(name), None) => {
                    client
                        .transition_issue_by_name(&issue, &name, comment_arg)
                        .await
                        .with_context(|| {
                            format!("failed to transition issue {issue} using status {name}")
                        })?;

                    print_json(&json!({
                        "issue": issue,
                        "action": "transition",
                        "transition": {
                            "name": name,
                        },
                        "comment_added": comment_added,
                        "comment": normalized_comment.clone(),
                    }))?;
                }
                (None, Some(id)) => {
                    client
                        .transition_issue(&issue, &id, comment_arg)
                        .await
                        .with_context(|| {
                            format!("failed to transition issue {issue} using transition id {id}")
                        })?;

                    print_json(&json!({
                        "issue": issue,
                        "action": "transition",
                        "transition": {
                            "id": id,
                        },
                        "comment_added": comment_added,
                        "comment": normalized_comment,
                    }))?;
                }
                (Some(_), Some(_)) => unreachable!(
                    "clap enforces mutual exclusivity between status and transition_id"
                ),
            }
        }
        Commands::Keygen { .. } | Commands::SecretEncrypt { .. } => unreachable!(),
    }

    Ok(())
}

fn init_tracing(verbose: bool) {
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    let _ = tracing_subscriber::fmt().with_max_level(level).try_init();
}

fn build_config(cli: &Cli) -> Result<AtlassianConfig> {
    let mut config = AtlassianConfig::from_env_with_overrides(
        cli.base_url.clone(),
        cli.username.clone(),
        cli.api_token.clone(),
    )
    .context("failed to construct Atlassian config from environment and CLI arguments")?;

    if let Some(timeout) = cli.timeout {
        config.timeout = Duration::from_secs(timeout);
    }

    if let Some(agent) = &cli.user_agent {
        config.user_agent = agent.clone();
    }

    if cli.insecure {
        config.verify_ssl = false;
    }

    Ok(config)
}

fn handle_keygen(
    bits: usize,
    private_out: Option<PathBuf>,
    public_out: Option<PathBuf>,
    stdout: bool,
) -> Result<()> {
    if !stdout && private_out.is_none() && public_out.is_none() {
        bail!(
            "Provide --stdout or an output path via --private-out/--public-out to receive key material",
        );
    }

    let keypair =
        KeyPair::generate(bits).map_err(|err| anyhow!("failed to generate key pair: {err}"))?;
    let (public_key, private_key) = keypair.into_keys();
    let private_pem = private_key
        .to_pem()
        .map_err(|err| anyhow!("failed to encode private key as PEM: {err}"))?;
    let public_pem = public_key
        .to_pem()
        .map_err(|err| anyhow!("failed to encode public key as PEM: {err}"))?;

    if let Some(path) = private_out {
        write_new_file(&path, &private_pem, true)
            .with_context(|| format!("failed to write private key to {}", path.display()))?;
        println!("private key written to {}", path.display());
    }

    if let Some(path) = public_out {
        write_new_file(&path, &public_pem, false)
            .with_context(|| format!("failed to write public key to {}", path.display()))?;
        println!("public key written to {}", path.display());
    }

    if stdout {
        println!("# Private key (PEM, keep secret)");
        println!("{}", private_pem.trim_end());
        println!("# Public key (PEM)");
        println!("{}", public_pem.trim_end());
    }

    Ok(())
}

fn handle_secret_encrypt(
    public_key_path: Option<PathBuf>,
    public_key_inline: Option<String>,
    secret: Option<String>,
    secret_file: Option<PathBuf>,
    secret_env: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let public_pem = match (public_key_path, public_key_inline) {
        (Some(path), None) => read_text_file(&path, "public key")?,
        (None, Some(value)) => value,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicting public key arguments"),
        (None, None) => bail!("Provide --public-key-path or --public-key-inline"),
    };

    let public_key = parse_public_key_from_str(public_pem.trim())
        .map_err(|err| anyhow!("failed to parse public key: {err}"))?;

    let secret_value = resolve_secret(secret, secret_file, secret_env)?;
    let cipher = HybridCipher::new(FluxConfig::default());
    let ciphertext = cipher
        .encrypt(&public_key, secret_value.as_bytes())
        .map_err(|err| anyhow!("failed to encrypt secret: {err}"))?;

    let encoded = BASE64_ENGINE.encode(ciphertext);
    if let Some(path) = output {
        write_new_file(&path, &encoded, false)
            .with_context(|| format!("failed to write ciphertext to {}", path.display()))?;
        println!("ciphertext written to {}", path.display());
    } else {
        println!("{encoded}");
    }

    Ok(())
}

fn resolve_secret(
    secret: Option<String>,
    secret_file: Option<PathBuf>,
    secret_env: Option<String>,
) -> Result<String> {
    if let Some(value) = secret {
        return normalize_secret(value);
    }

    if let Some(path) = secret_file {
        let contents = read_text_file(&path, "secret")?;
        return normalize_secret(contents);
    }

    let env_name = secret_env.unwrap_or_else(|| "JIRA_API_TOKEN".to_string());
    let value = env::var(&env_name)
        .with_context(|| format!("failed to read secret from env {env_name}"))?;
    normalize_secret(value)
}

fn normalize_secret(value: String) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("Secret value cannot be empty");
    }
    Ok(trimmed.to_string())
}

fn normalize_comment(comment: &Option<String>) -> Option<String> {
    comment
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn read_text_file(path: &PathBuf, purpose: &str) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read {purpose} from {}", path.display()))
}

fn write_new_file(path: &PathBuf, contents: &str, restrict_permissions: bool) -> Result<()> {
    if path.exists() {
        bail!("refusing to overwrite existing file {}", path.display());
    }

    #[cfg(not(unix))]
    let _ = restrict_permissions;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        if restrict_permissions {
            options.mode(0o600);
        }
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    if !contents.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.flush()?;
    Ok(())
}

fn load_json_file<T>(path: &PathBuf) -> Result<T>
where
    T: DeserializeOwned,
{
    let contents = read_text_file(path, "JSON payload")?;
    let parsed = serde_json::from_str(&contents)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    Ok(parsed)
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_comment;

    #[test]
    fn normalize_comment_trims_and_keeps_content() {
        let comment = Some("  Ship it  ".to_string());
        assert_eq!(normalize_comment(&comment), Some("Ship it".to_string()));
    }

    #[test]
    fn normalize_comment_filters_empty_strings() {
        assert_eq!(normalize_comment(&Some("   ".to_string())), None);
        assert_eq!(normalize_comment(&None), None);
    }
}
