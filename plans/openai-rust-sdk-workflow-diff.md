# GitHub Actions Diff vs `ThreatFlux/openai_rust_sdk`

## Goal

Compare the current `threatflux-atlassian` CI/CD setup to `openai_rust_sdk`, identify the meaningful workflow gaps, and
recommend what should actually be adopted next.

## Scope

In scope:

- GitHub Actions workflow structure
- release flow
- crates.io publishing flow
- Docker publish/sign/SBOM flow
- security/quality checks that materially improve shipping confidence

Out of scope:

- SDK/runtime code changes
- repository settings outside what the workflows require
- replacing working hosted-runner choices with self-hosted runners

## Repos Reviewed

- `threatflux-atlassian`
  - `.github/workflows/ci.yml`
  - `.github/workflows/security.yml`
  - `.github/workflows/docker.yml`
  - `.github/workflows/release.yml`
  - `.github/workflows/auto-release.yml`
  - `Cargo.toml`
  - crate manifests under `crates/`
- `openai_rust_sdk`
  - `.github/workflows/ci.yml`
  - `.github/workflows/quality.yml`
  - `.github/workflows/security.yml`
  - `.github/workflows/docker.yml`
  - `.github/workflows/release.yml`
  - `.github/workflows/auto-release.yml`
  - `Cargo.toml`

## Current State Summary

`threatflux-atlassian` is already ahead of `openai_rust_sdk` in the places that matter most for reliable shipping:

- hosted-runner compatibility is working
- release gating is stricter
- SBOMs are generated and attached to releases
- crates.io publish already exists
- action pins are already in place

`openai_rust_sdk` is broader, but it is also noisier and less reliable operationally:

- it still depends heavily on `self-hosted`
- as of March 12, 2026, its latest visible `Docker` and `Code Quality` runs are queued
- as of March 12, 2026, its latest visible `Security` run is failing
- its `Auto Release` workflow is fan-out triggered from multiple workflows and creates duplicate queued runs

That means this should be a selective adoption exercise, not a template overwrite.

## Workflow Diff

### CI / Quality

`threatflux-atlassian`

- keeps formatting, clippy, test matrix, MSRV, feature checks, docs, bench, and coverage in one `CI` workflow
- uses `cargo-hack` for feature powerset validation
- uses hosted runners only

`openai_rust_sdk`

- splits extra quality checks into a separate `quality.yml`
- adds complexity reporting, TODO/FIXME scanning, docs quality, mutation testing, and a coverage threshold
- still relies on `self-hosted`

Recommendation

- keep the current consolidated `CI` model
- do not port `quality.yml` wholesale
- optionally adopt only two low-noise additions:
  - TODO/FIXME scan as a non-blocking or warning-only job
  - explicit coverage threshold once the repo has a stable target

Reasoning

- most of `quality.yml` is reporting-heavy and adds runner time without improving release correctness
- `cargo-hack` in `threatflux-atlassian` is stronger than `openai_rust_sdk`'s per-feature loop

### Security

`threatflux-atlassian`

- runs `cargo-audit`, `cargo-deny`, SBOM generation, TruffleHog, geiger, and OSSF Scorecard
- keeps a success gate around the required jobs

`openai_rust_sdk`

- adds CodeQL inside the workflow, Semgrep, Gitleaks, OWASP dependency check, container scanning, and more SARIF upload
- also has more secret dependencies and more failure/false-positive surface

Recommendation

- add Gitleaks to `threatflux-atlassian`
- keep Trivy-based container scanning in the Docker workflow as-is
- only add Semgrep or OWASP if there is a specific compliance requirement
- only add in-workflow CodeQL if org/repo-level CodeQL is not already configured

Reasoning

- Gitleaks is the cleanest missing addition
- Semgrep/OWASP create more operational load and tuning work than value for this repo right now

### Docker

`threatflux-atlassian`

- publishes to GHCR
- does PR image export for scanning
- signs the main-branch container
- generates a container SBOM
- restricts non-tag builds to `linux/amd64` to stay reliable on hosted runners

`openai_rust_sdk`

- publishes to Docker Hub and GHCR
- runs additional Docker runtime smoke tests
- pushes multi-arch more aggressively
- is still tied to `self-hosted`

Recommendation

- keep the current `threatflux-atlassian` Docker workflow shape
- add Docker runtime smoke tests only if the container becomes a supported distribution artifact
- do not copy the always-multi-arch/self-hosted pattern
- add Docker Hub publish only if there is a distribution requirement outside GHCR

Reasoning

- the hosted-runner fix in `threatflux-atlassian` solved a real reliability issue
- the `openai_rust_sdk` Docker workflow is broader but currently not operationally healthy

### Release

`threatflux-atlassian`

- creates GitHub releases
- builds cross-platform artifacts
- generates release SBOMs
- uploads assets after build
- publishes both crates to crates.io
- has a strict success gate

`openai_rust_sdk`

- creates GitHub releases
- builds cross-platform artifacts
- publishes one crate to crates.io
- builds/pushes Docker images as part of release
- has a placeholder artifact-signing step
- deploys docs to GitHub Pages
- allows crates.io publish failures without failing the release

Recommendation

- keep the current stricter `threatflux-atlassian` release gate
- do not loosen release success semantics to match `openai_rust_sdk`
- add package verification before publish:
  - `cargo package -p threatflux-atlassian-sdk --locked`
  - `cargo package -p threatflux-atlassian-cli --locked`
  - optional `cargo publish --dry-run` for both crates
- add an index propagation wait/retry between SDK publish and CLI publish

Reasoning

- the local workspace has an inter-crate dependency, so publish sequencing matters more than it does in the single-crate
  `openai_rust_sdk` repo
- validating package contents before publish will catch manifest/include/readme issues earlier

### Auto Release

`threatflux-atlassian`

- triggers from `CI` and `Security`
- already has the workspace version-sync fix for the SDK dependency pin

`openai_rust_sdk`

- triggers from `CI`, `Quality`, and `Security`
- latest visible runs show duplicate queued `Auto Release` jobs for the same branch state

Recommendation

- keep the narrower `threatflux-atlassian` trigger set
- do not copy the extra workflow fan-out trigger model

Reasoning

- more upstream workflow triggers here create duplicate release-evaluation runs without adding signal

## Crates.io Publishing Review

### What already exists

`threatflux-atlassian` already has crates.io publishing in `release.yml`.

Current behavior:

- publish only on non-prerelease versions
- token-gated with `CARGO_REGISTRY_TOKEN`
- publishes SDK first, then CLI

### What should be improved next

1. Add package verification before publish

- run `cargo package` for both crates before touching crates.io
- optionally run `cargo publish --dry-run` for both crates

2. Add propagation handling between workspace crate publishes

- the CLI depends on the SDK version
- crates.io index propagation can lag after the SDK publish
- add a retry loop or short wait before publishing the CLI

3. Move from static token auth to crates.io Trusted Publishing

- crates.io added Trusted Publishing for GitHub Actions in July 2025
- this removes the long-lived publish secret after the initial manual publish/bootstrap

4. Update release-facing documentation

- once crates.io publish is live, switch README install instructions from git-based installs to crates.io installs
- fix the current README example tag drift (`v0.3.2` vs workspace `0.4.0`)

Reference:

- Rust blog, July 11, 2025: https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07/
- docs link from that post: https://crates.io/docs/trusted-publishing

Recommendation order:

- first add package verification and propagation retry
- then migrate to Trusted Publishing

## Docs Publishing Review

`openai_rust_sdk` deploys docs to GitHub Pages during release.

Recommendation for `threatflux-atlassian`:

- do not copy that by default
- rely on docs.rs for the SDK crate docs after crates.io publish
- only add GitHub Pages if you want CLI/operator documentation or marketing-style docs outside API docs

Reasoning

- docs.rs automatically builds documentation for crates published to crates.io
- that is the standard Rust distribution path for library docs

Reference:

- Docs.rs build behavior: https://docs.rs/about/builds

## Proposed Implementation Order

### Phase 1: Worth doing immediately

1. Add package verification steps to `release.yml`
2. Add publish retry/wait logic between SDK and CLI crates.io publish steps
3. Add Gitleaks to `security.yml`

### Phase 2: Worth doing once release credentials are sorted

1. Switch crates.io publish from `CARGO_REGISTRY_TOKEN` to Trusted Publishing
2. Add the required `id-token: write` permission and auth step

### Phase 3: Optional

1. Add a coverage threshold once a target percentage is agreed
2. Add TODO/FIXME scanning as warning-only
3. Add Docker runtime smoke tests if the container becomes a first-class delivery target
4. Add Docker Hub publishing if external distribution requires it

## Files Most Likely to Change

- `.github/workflows/release.yml`
- `.github/workflows/security.yml`
- possibly `.github/workflows/ci.yml`
- possibly README/docs to explain crates.io install and release behavior

## Risks

- Trusted Publishing requires crates.io-side setup and at least one initial manual/bootstrap publish path
- adding too many scanners from `openai_rust_sdk` will likely recreate the same noisy/failing workflow behavior
- dual-crate publishing needs explicit ordering and retry behavior

## Open Questions

1. Do we want the CLI published to crates.io as a normal install target, or only the SDK?
2. Do we want GHCR-only container distribution, or GHCR plus Docker Hub?
3. Is repo/org-level CodeQL already considered sufficient, or do we want CodeQL explicitly in `security.yml`?
