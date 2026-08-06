# SDK Configuration Reference

This reference describes the behavior implemented by `threatflux-atlassian-sdk`. It is intentionally narrower than
Atlassian's full platform: the supported path is direct Jira Cloud REST API v2 access with an account email and API
token.

This independent project is not affiliated with, endorsed by, or sponsored by Atlassian.

## Direct Client Defaults

`AtlassianConfig::new` and `AtlassianConfig::builder` produce the following defaults:

| Field | Default | Runtime effect |
| --- | --- | --- |
| `timeout` | 60 seconds | Passed to reqwest as the request timeout. |
| `cert_path` | `None` | Uses the transport's normal root store. |
| `host_policy` | `HostPolicy::AtlassianCloud` | Decides which hosts may receive the credential, and the scheme they may receive it over. The default admits `atlassian.com`, `atlassian.net`, `jira.com`, and subdomains of them, over HTTPS only; an IP literal is refused. |
| `verify_ssl` | `true` | Certificate verification, and nothing else. It never gates the scheme. |
| `max_retries` | `3` | Stored in the config; the request path does not consume it. |
| `retry_delay` | 1 second | Stored in the config; the request path does not consume it. |
| `user_agent` | `atlassian-rust-sdk/<crate-version>` | Sent with direct REST requests. |

`AtlassianConfig::new` and `AtlassianConfig::from_env` parse the base URL but do not check the destination.
`AtlassianConfig::validate` runs `HostPolicy::check_destination`; `AtlassianConfigBuilder::build` calls `validate`, and
so does `AtlassianClient::new` before it builds the one reqwest client it reuses for subsequent calls. The transport
re-runs the destination check on the joined URL of every request, so assigning to the public `base_url` field after
construction cannot smuggle a destination past it.

## Environment Variables

`AtlassianClient::from_env()` delegates to `AtlassianConfig::from_env()`.

<!-- BEGIN ENV_VARS -->
| Variable | Required | Parsing and behavior |
| --- | --- | --- |
| `JIRA_URL` | Yes | Parsed as a URL. HTTPS is required unconditionally; `JIRA_VERIFY_SSL` does not gate the scheme, and no environment can select the one policy that admits `http://`. |
| `JIRA_USERNAME` | Yes* | Trimmed account email. A present but empty value is an error. |
| `JIRA_API_TOKEN` | Yes* | Trimmed API token. A present but empty value is an error. |
| `JIRA_TIMEOUT` | No | Unsigned integer seconds; an invalid value is an error. |
| `JIRA_HOST_POLICY` | No | `atlassian-cloud` (the default) or `allowlist:<host>[,<host>]`. The `loopback` token is refused. An empty or unrecognized value is an error. |
| `JIRA_VERIFY_SSL` | No | Read only in order to refuse a downgrade. A value meaning *disabled* is a hard configuration error; a value meaning *enabled* leaves the default in place. |
| `JIRA_MAX_RETRIES` | No | Unsigned integer stored in the config. Invalid values are silently ignored. No automatic retry occurs. |
<!-- END ENV_VARS -->

\* `JIRA_USERNAME` and `JIRA_API_TOKEN` can each be supplied through their encrypted alternatives below.

### What the environment may not relax

Neither the transport scheme requirement nor certificate verification is relaxable from the environment. Both are
relaxable only by an explicit code call, and the three variables that used to blur that line behave as follows.

`JIRA_VERIFY_SSL` is parsed strictly: the value is trimmed and lowercased, `1`, `true`, `yes`, and `on` mean enabled,
and `0`, `false`, `no`, and `off` mean disabled. A value meaning disabled is a hard `AtlassianError::Configuration`, not
a downgrade — the SDK refuses to start rather than send the credential to a certificate it did not verify. An empty or
unrecognized value (`maybe`, `2`, `enabled`) is also an error. The permissive parse this replaced was
`value.to_lowercase() != "false"`, under which `" false"`, `0`, and `no` all silently meant *enabled*. Certificate
verification is turned off only by `AtlassianConfigBuilder::verify_ssl(false)` or
`AtlassianConfig::with_ssl_verification(false)`, in code.

`JIRA_HOST_POLICY` accepts `atlassian-cloud` and `allowlist:<host>[,<host>]`, and refuses the `loopback` token outright.
`HostPolicy::Loopback` is therefore reachable only from a code call — `AtlassianConfigBuilder::host_policy` or
`AtlassianConfig::with_host_policy` — which is what keeps `AtlassianConfig::from_env` from ever producing a
configuration that talks cleartext, while still leaving the end-to-end suite a way to drive a real client against a
loopback mock. A refused value is never echoed into the error message, because the variable is attacker-settable under
the threat model it exists for and configuration errors reach workflow logs.

There is no `JIRA_CERT_PATH`. Adding a trust root is a code call — `AtlassianConfig::with_cert_path` or
`AtlassianConfigBuilder::cert_path` — because an extra root can vouch for whatever host the same environment selected
with `JIRA_URL`, which would be certificate verification relaxed from the environment. Unlike `JIRA_VERIFY_SSL` the
variable is not read at all, so a still-exported `JIRA_CERT_PATH` is ignored rather than refused and the client falls
back to the system roots. Ignoring downgrades nothing: the failure mode is a refused handshake, not a widened one.

`JIRA_URL` must not carry credentials in its authority, a query string, or a fragment. Userinfo would be a second
credential-bearing field in a struct that derives `Debug` and would be logged with every request URL, while the host
policy — matched against the URL host — could not see it. A query survives path resolution and would be attached to
every request the SDK makes.

There is no environment variable for `retry_delay`. Set it with `AtlassianConfigBuilder::retries` or
`AtlassianConfig::with_retries`; this still does not enable automatic retries.

## Source Precedence

`AtlassianConfig::from_env_with_overrides` resolves values in this order:

1. If configured, decrypt and load the encrypted env file. Its entries override existing process environment values.
2. Use a non-empty explicit override for `JIRA_URL`, `JIRA_USERNAME`, or `JIRA_API_TOKEN`.
3. Use the corresponding plaintext environment variable.
4. For username and token only, decrypt the corresponding `*_ENCRYPTED` variable.
5. Apply the optional timeout, host-policy, and retry-count environment settings, and refuse a `JIRA_VERIFY_SSL` that
   asks for a downgrade. No certificate path is applied here; the environment cannot install a trust anchor.

`ENV_FILE_ENCRYPTED_PATH` takes precedence over `ENV_FILE_ENCRYPTED`. If a plaintext username or token variable is
present but empty, loading fails instead of falling back to its encrypted equivalent.

## Encrypted Inputs

Encrypted values use FluxEncrypt-compatible hybrid-encryption ciphertext encoded with Base64.

### Individual credentials

<!-- BEGIN ENV_VARS -->
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
<!-- END ENV_VARS -->

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
- HTTPS is required, and `verify_ssl` has no bearing on that. `HostPolicy::check_destination` decides the scheme and the
  host together: it rejects any base URL that is not `https://`, whatever `verify_ssl` is set to. The single exception
  is a literal loopback address (`127.0.0.0/8`, `::1`) under `HostPolicy::Loopback`, which is settable only in code —
  `JIRA_HOST_POLICY` refuses the token — so `AtlassianConfig::from_env` can never yield a cleartext destination. No name
  is resolved for that check either, so a `localhost` or `localtest.me` host is refused even when it points at loopback.
- `AtlassianConfig::with_cert_path` / `AtlassianConfigBuilder::cert_path` accept one PEM or DER certificate and add it
  to the root store, alongside rather than instead of the built-in roots. This is a code call only; there is no
  environment variable for it. `AtlassianConfig::validate` rejects a path that does not exist.
- `JIRA_VERIFY_SSL=false` does **not** disable certificate verification. It is a hard configuration error, as is every
  other spelling of *disabled* (`0`, `no`, `off`, and any casing or surrounding whitespace of them).
- `AtlassianConfigBuilder::verify_ssl(false)` / `AtlassianConfig::with_ssl_verification(false)` is the code call that
  survives, and it reaches reqwest's `danger_accept_invalid_certs(true)` only on an `https://` base URL. Use it only in
  controlled local testing against a self-signed certificate; it permits interception and server impersonation. It
  cannot be used to reach an `http://` destination — the destination check refuses that first, and on an `http://` URL
  reqwest negotiates no TLS at all, so the flag never had an effect there.
- `AtlassianClient` calls `no_proxy()`. It does not discover or honor `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`.

If your network requires an outbound proxy, the public client constructor currently offers no proxy customization.
That limitation cannot be solved by setting proxy environment variables.

### What the host policy does not cover

`HostPolicy` bounds the **scheme**, not the set of hosts an environment can name. `JIRA_HOST_POLICY` refuses only the
literal `loopback` token; `allowlist:<any-host>` is accepted from the environment. A process whose environment an
attacker can set twice — `JIRA_HOST_POLICY=allowlist:evil.example` together with `JIRA_URL=https://evil.example` — will
send `Authorization: Basic` to `evil.example` over ordinary TLS, and the policy will permit it, because an operator's
own Data Center deployment is indistinguishable from an attacker's.

So the default policy is a safe default, not a containment boundary against a hostile environment. It cannot be made
into one here: a policy that could not be widened from configuration would make Data Center unusable. What it does
guarantee is that the credential never crosses the wire in cleartext, that the default admits only Atlassian Cloud
tenants, and that widening it requires the environment to be writable in the first place. Treat `JIRA_HOST_POLICY` as
part of the credential: pin it wherever the API token is pinned, and keep it out of workflow-settable inputs.

Allowlist entries are bare hosts — no scheme, port, path, or credentials — matched case-insensitively against the whole
host, with no wildcard. An entry carrying a port is rejected rather than accepted-and-never-matched, since the policy is
compared against the URL host, which excludes the port; the only `:` an entry may contain is an IPv6 literal's.

## Retries and Rate Limits

No direct or Remote MCP method automatically retries. `max_retries` and `retry_delay` are configuration data only. A
`429` response becomes `AtlassianError::RateLimit`, but the SDK does not parse `Retry-After` or delay the caller.

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
`JiraApi`.

How much of the response reaches you is governed by `DiagnosticsPolicy`, set with `AtlassianClient::with_diagnostics`:

| Policy | What the error carries | What the log carries |
| --- | --- | --- |
| `MetadataOnly` (default) | Status, operation, and `Retry-After` only. The body is never read. | The same metadata, plus the body's length. |
| `JiraErrorFields` | Jira's `errorMessages` and `errors`, each bounded. | Metadata only. |
| `IncludeBody` | The body, truncated to `BODY_LIMIT`. | Metadata only. |

A response body reaches a log under no policy, and reaches an error only when the caller opts in. That default matters
because tenant responses can contain issue details; opt in deliberately and review log sinks and retention when you do.

Transport failures (timeout, connection refused, body, decode) render as a failure kind plus the destination's scheme,
host, port, and path. The query string is never included — it carries JQL, which after reconciliation carries dedupe
labels and issue text.

`AtlassianConfig` derives `Debug` but deliberately derives neither `Serialize` nor `Deserialize`, so it cannot be
written into a log line, a cache file, or a diagnostic dump by a caller who never intended to. Its `api_token` is a
`SecretString`, which has no `Serialize` at all and whose hand-written `Debug` redacts the value, so the derived `Debug`
on the surrounding struct is redacted too. The Remote OAuth token types dropped `Serialize` as well, and their
credential fields are `SecretString`, so their `Debug` is redacted and serializing one is a compile error.

`AtlassianError` itself still derives `Serialize`. Under the default policy it carries only metadata, but a caller who
opted into `IncludeBody` and then serializes the error will write the response body wherever that goes.

## Legacy Remote MCP Configuration

The retained Remote MCP types accept a client ID and callback port directly. The example also reads
`ATLASSIAN_CLIENT_ID` and `ATLASSIAN_CALLBACK_PORT`, but the SDK constructor does not read these variables itself.

The module is not usable with Atlassian's current Rovo MCP service: it targets the `/v1/sse` URL that Atlassian stopped
supporting after June 30, 2026, does not implement Streamable HTTP, does not run the callback listener, and stores
tokens only in memory. See
[Atlassian's OAuth migration notice](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/configuring-oauth-2-1/)
and use a supported MCP client instead.
