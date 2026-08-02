# SDK Configuration Reference

This reference describes the behavior implemented by `threatflux-atlassian-sdk` 0.4.2. It is intentionally narrower
than Atlassian's full platform: the supported path is direct Jira Cloud REST API v2 access with an account email and API
token.

This independent project is not affiliated with, endorsed by, or sponsored by Atlassian.

## Direct Client Defaults

`AtlassianConfig::new` and `AtlassianConfig::builder` produce the following defaults:

| Field | Default | Runtime effect |
| --- | --- | --- |
| `timeout` | 60 seconds | Passed to reqwest as the request timeout. |
| `cert_path` | `None` | Uses the transport's normal root store. |
| `verify_ssl` | `true` | Rejects invalid certificates and requires an HTTPS base URL during validation. |
| `max_retries` | `3` | Stored in the config; the request path does not consume it. |
| `retry_delay` | 1 second | Stored in the config; the request path does not consume it. |
| `user_agent` | `atlassian-rust-sdk/<crate-version>` | Sent with direct REST requests. |

`AtlassianClient::new` validates the configuration, builds one reqwest client, and reuses it for subsequent calls.

## Environment Variables

`AtlassianClient::from_env()` delegates to `AtlassianConfig::from_env()`.

| Variable | Required | Parsing and behavior |
| --- | --- | --- |
| `JIRA_URL` | Yes | Parsed as a URL. HTTPS is required when `JIRA_VERIFY_SSL` is enabled. |
| `JIRA_USERNAME` | Yes* | Trimmed account email. A present but empty value is an error. |
| `JIRA_API_TOKEN` | Yes* | Trimmed API token. A present but empty value is an error. |
| `JIRA_TIMEOUT` | No | Unsigned integer seconds; an invalid value is an error. |
| `JIRA_CERT_PATH` | No | File containing one PEM or DER certificate to add as a trust root. |
| `JIRA_VERIFY_SSL` | No | Only the case-insensitive string `false` disables verification; every other value enables it. |
| `JIRA_MAX_RETRIES` | No | Unsigned integer stored in the config. Invalid values are silently ignored. No automatic retry occurs. |

\* `JIRA_USERNAME` and `JIRA_API_TOKEN` can each be supplied through their encrypted alternatives below.

There is no environment variable for `retry_delay`. Set it with `AtlassianConfigBuilder::retries` or
`AtlassianConfig::with_retries`; this still does not enable automatic retries in 0.4.2.

## Source Precedence

`AtlassianConfig::from_env_with_overrides` resolves values in this order:

1. If configured, decrypt and load the encrypted env file. Its entries override existing process environment values.
2. Use a non-empty explicit override for `JIRA_URL`, `JIRA_USERNAME`, or `JIRA_API_TOKEN`.
3. Use the corresponding plaintext environment variable.
4. For username and token only, decrypt the corresponding `*_ENCRYPTED` variable.
5. Apply optional timeout, certificate, verification, and retry-count environment settings.

`ENV_FILE_ENCRYPTED_PATH` takes precedence over `ENV_FILE_ENCRYPTED`. If a plaintext username or token variable is
present but empty, loading fails instead of falling back to its encrypted equivalent.

## Encrypted Inputs

Encrypted values use FluxEncrypt-compatible hybrid-encryption ciphertext encoded with Base64.

### Individual credentials

For the username:

```text
JIRA_USERNAME_ENCRYPTED
JIRA_USERNAME_PRIVATE_KEY
JIRA_USERNAME_PRIVATE_KEY_PASSWORD   # optional
```

For the API token:

```text
JIRA_API_TOKEN_ENCRYPTED
JIRA_API_TOKEN_PRIVATE_KEY
JIRA_API_TOKEN_PRIVATE_KEY_PASSWORD  # optional
```

The private key may be a raw PEM string or a Base64-encoded PEM. The password variable is required only for an
encrypted private key.

### Whole env file

Provide the encrypted env-file ciphertext inline or by path:

```text
ENV_FILE_ENCRYPTED                    # Base64 ciphertext
ENV_FILE_ENCRYPTED_PATH               # path containing Base64 ciphertext; wins when both are set
ENV_FILE_PRIVATE_KEY                  # raw or Base64-encoded PEM
ENV_FILE_PRIVATE_KEY_PASSWORD         # optional
```

The decrypted UTF-8 content is parsed with dotenv syntax and loaded with override semantics. Treat that plaintext as
sensitive even though it is not written by the SDK.

Encryption does not make a committed secret safe when its private key or password is stored beside it. Prefer a secret
manager, restrict process-environment access, and separate ciphertext from decryption keys.

## Authentication Scope

The direct client builds `Authorization: Basic base64(email:api_token)` and sends it to Jira REST API v2 paths joined to
`JIRA_URL`. Use an Atlassian API token, not an account password. The account's Jira permissions determine what each call
can read or change.

Atlassian documents Basic auth for personal scripts, bots, and ad-hoc calls. Organizations building distributable
integrations should evaluate Atlassian's supported application and OAuth models:

- [Basic auth for Jira Cloud REST APIs](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/)
- [Jira Cloud REST API v2 overview](https://developer.atlassian.com/cloud/jira/platform/rest/v2/intro/)

## TLS and Proxy Behavior

The workspace compiles reqwest with default features disabled and the `rustls` feature enabled.

- Certificate verification is on by default.
- With verification enabled, configuration validation rejects a non-HTTPS base URL.
- `JIRA_CERT_PATH` accepts one PEM or DER certificate and adds it to the root store.
- `JIRA_VERIFY_SSL=false` enables reqwest's `danger_accept_invalid_certs` behavior. Use this only in controlled local
  testing; it permits interception and server impersonation.
- `AtlassianClient` calls `no_proxy()`. It does not discover or honor `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`.

If your network requires an outbound proxy, the public client constructor currently offers no proxy customization.
That limitation cannot be solved by setting proxy environment variables.

## Retries and Rate Limits

No direct or Remote MCP method automatically retries in 0.4.2. `max_retries` and `retry_delay` are configuration data
only. A `429` response becomes `AtlassianError::RateLimit`, but the SDK does not parse `Retry-After` or delay the caller.

Add retry policy in the application layer:

- cap attempts and total elapsed time;
- use exponential backoff with jitter;
- honor server guidance when available;
- retry reads more freely than mutations;
- establish an idempotency or reconciliation strategy before retrying issue creation, comments, transitions,
  attachments, or other writes.

`AtlassianError::is_retryable()` returns true for `RateLimit`, `Timeout`, and `Http` with a status of 500 or greater.
Most non-special Jira HTTP failures are converted to `JiraApi`, so a Jira 5xx represented by that variant is not marked
retryable by the helper.

## Errors and Logging

The client maps `401`, `403`, `404`, and `429` to dedicated error variants. Other Jira non-success responses become
`JiraApi` with the response body included in the message. The body is also emitted through an error-level tracing event.
Tenant responses can contain issue details or other sensitive content, so review log sinks and retention.

`AtlassianConfig` derives `Debug`, `Serialize`, and `Deserialize`, including the API token field. Remote OAuth token types
also derive `Debug` and/or `Serialize`. Do not format, log, or serialize these values into telemetry, crash reports, or
user-visible output.

## Legacy Remote MCP Configuration

The retained Remote MCP types accept a client ID and callback port directly. The example also reads
`ATLASSIAN_CLIENT_ID` and `ATLASSIAN_CALLBACK_PORT`, but the SDK constructor does not read these variables itself.

The module is not usable with Atlassian's current Rovo MCP service: it targets the `/v1/sse` URL that Atlassian stopped
supporting after June 30, 2026, does not implement Streamable HTTP, does not run the callback listener, and stores
tokens only in memory. See
[Atlassian's OAuth migration notice](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/configuring-oauth-2-1/)
and use a supported MCP client instead.
