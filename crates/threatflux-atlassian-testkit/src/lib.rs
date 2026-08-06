//! Dev-only test infrastructure for the `threatflux-atlassian` workspace.
//!
//! The crate is `publish = false` and is never a runtime dependency of the SDK,
//! the CLI or the Action. It also does not depend on `threatflux-atlassian-sdk`:
//! everything it exposes is `&'static str` or [`serde_json::Value`], which keeps
//! it usable from every member without a dev-dependency cycle and lets one
//! fixture file serve as both a mock response body and a golden comparison.
//!
//! ```
//! use threatflux_atlassian_testkit::fixtures;
//!
//! let event = fixtures::github_event_json("issues-opened-dependabot");
//! assert_eq!(event["issue"]["user"]["login"], "dependabot[bot]");
//! ```

pub mod env;
pub mod fixtures;
pub mod gha;
pub mod golden;
pub mod jira_mock;
pub mod logs;
pub mod net;
pub mod redaction;
pub mod sleeper;
