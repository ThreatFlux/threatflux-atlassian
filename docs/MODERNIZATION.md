# October 2026 modernization

Versions were verified on 2026-10-05 against official Rust distribution metadata,
crates.io, upstream action releases and container registry manifests. This update
starts from `f2a5637585d79b940b74aa6e017f98299901313f` on `main`.

## Rust and dependencies

| Surface | Before | Updated | Evidence |
| --- | --- | --- | --- |
| Development Rust | 1.97.1 | 1.99.0 | [Official stable distribution](https://static.rust-lang.org/dist/channel-rust-stable.toml), dated 2026-10-01 |
| Minimum supported Rust | 1.96.0 | 1.97.1 | [FluxEncrypt 0.7.5 manifest](https://docs.rs/crate/fluxencrypt/0.7.5/source/Cargo.toml) requires Rust 1.97.1 |
| FluxEncrypt | 0.7.2 requirement | 0.7.5 | [Published stable crate](https://crates.io/crates/fluxencrypt/0.7.5) |
| Development tools | Unversioned installs | Explicit stable versions | [Cargo tool registry](https://crates.io) and the `dev-setup` target |

All 26 unique direct registry dependencies were checked for the newest stable,
non-yanked release. Eighteen requirements were refreshed; ten distinct direct
crates changed their resolved version. The lockfile refresh updates 97 package
resolutions and resolves 298 packages, down from 299. There are no prerelease or
yanked registry packages in the resulting lockfile.

The tool versions are cargo-llvm-cov 0.9.1, cargo-audit 0.22.2, cargo-deny 0.20.2,
cargo-cyclonedx 0.5.9 and cargo-hack 0.6.45. `make dev-setup` installs these exact
versions with `--locked`.

## Compatibility

The minimum compiler rises to Rust 1.97.1 because the latest published stable
FluxEncrypt requires it. The development compiler remains separately pinned to
Rust 1.99.0. All four workspace members inherit the new minimum, and the Clippy
configuration and onboarding documentation agree with it.

Package versions remain 0.5.1 under the existing release automation. Jira APIs,
transport policies, public signatures, encrypted credential formats and SDK
feature implications remain compatible. New compiler lint fixes preserve the
async OAuth entrypoint and use equivalent emptiness assertions. The existing
forbidden Jira text-character helper becomes const at the new MSRV.

`encrypted-env` continues to make FluxEncrypt optional. The Action and SDK builds
without that feature exclude both FluxEncrypt and RSA; the CLI and the SDK's
default `full` features retain them. The resolved dependency guard verifies both
presence and absence cases so an empty graph cannot pass accidentally.

## Security

The existing [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
exception remains in the matching cargo-audit and cargo-deny policies. The latest
stable RSA 0.9.10 still has no patched version. FluxEncrypt performs private-key
operations, including decryption, so the advisory is applicable to the encrypted
credential path. A successful configured audit does not mean the vulnerability
is fixed. The no-ignore audit reports this one vulnerability.

The optional feature excludes that dependency path for consumers who do not need
encrypted credentials; it does not repair vulnerable RSA code for consumers who
enable the feature. No new advisory exceptions or broader lint suppressions are
introduced.

## GitHub Actions and containers

All six repository workflows and the consumer workflow are reviewed against
upstream stable action releases, with 82 uses across 20 immutable action or
reusable-workflow specifications and verified inputs. The consumer example pins
the compatible v0.5.1 Action release commit. Rust-toolchain's reviewed master
commit is pinned as required upstream when supplying an explicit toolchain input.
CI explicitly selects and logs the requested stable, beta, nightly or MSRV
compiler. Container builds use the updated Rust compiler and verified immutable
base-image digests. Existing release ownership remains with the pinned
ThreatFlux reusable automation; the update does not publish packages or images.

Required coverage generation also retains a nonempty LCOV artifact independently
of the existing optional Codecov delivery. Finding policies for informational
scanners remain as configured by the repository.

Geiger scans each of the four member manifests with the locked dependency graph
and native JSON output, using a separate build target. Unsafe counts and
unscanned inputs remain informational. JSON and stderr diagnostics are retained
in a required artifact; tool errors, missing reports, or invalid package
identity/version/path and metrics fail the job and security gate. Report
validation self-tests run in Quick Check and the local lint guard.

Manual release `source_ref` selection accepts repository branch names, tags or
full commit IDs only when the resolved commit belongs to fetched `origin/main`
history. Existing release tags and older main commits remain supported. Fork,
PR and unmerged branch commits are rejected before release preparation, builds,
SBOM generation or publication. A backport must first enter main history;
supporting another maintained release lineage requires a reviewed policy change.

The prepare job loads the guard from the trusted workflow revision, resolves and
checks ancestry, then passes only the vetted immutable `release_revision` to
downstream checkouts. A release tag that does not exist yet is created at that
revision, and an existing tag must already resolve to it, so the tag and the
uploaded artifacts always name the same commit. Compiler and tool setup precede the selected source
checkout, and checkout credentials are not persisted. The existing auto-release
owner merges its release PR into main before tagging and dispatches by that tag,
so its normal release flow meets this policy. Temporary Git self-tests run in
Quick Check and the local lint guard, including rejection and branch-movement
cases. No scanner finding is dismissed or excluded to implement this boundary.

## Validation

The repository's full `make all` gate passed: 43 Rust test suites and 2,525
passing test invocations, with zero failures or ignored tests. This count includes
repeated feature and coverage runs. Formatting, strict Clippy, feature guards,
strict rustdoc, configured audit/deny and benchmark compilation also passed.
The generated LCOV report contains 937,765 bytes.

The actual Rust 1.97.1 compiler passes all-feature/all-target workspace checking;
Rust 1.96.0 demonstrably rejects FluxEncrypt 0.7.5's compiler requirement. All
six workflows and the consumer example pass actionlint 1.7.12 (with ShellCheck)
and yamllint 1.38.0. Package-file inventories were checked for the SDK and CLI.
The full 23-combination feature powerset passed. CycloneDX 1.5 SBOM generation
passed for the SDK (205 components) and CLI (219 components), and cleanup includes
the dev-only testkit's generated outputs.

Tests use controlled local fixtures and mock servers. Live Atlassian requests and
release workflows are outside this validation. Hosted checks are reviewed on the
pushed PR commit before delivery.
