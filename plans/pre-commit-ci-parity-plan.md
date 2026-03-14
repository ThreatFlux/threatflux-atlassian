# Pre-Commit CI Parity Plan

## Goal

Catch the same failures locally that GitHub Actions will reject in `CI`, `Security`, and workflow validation, with a fast default path for every commit and a slower path for pre-push or manual release readiness checks.

## Root Cause Observed

- PR `#8` failed in the `Quick Check` job, not in tests or security jobs.
- The specific failure was `cargo fmt --all -- --check` on `crates/threatflux-atlassian-action/src/lib.rs`.
- The branch had logic that compiled and tested cleanly, but a post-edit formatting drift remained.
- There is currently no single repo-standard pre-commit command that mirrors `Quick Check`, so this class of failure is easy to miss before push.

## Desired Outcome

Developers should be able to run one command before commit and one command before push:

- `pre-commit`
  - fast
  - deterministic
  - matches the CI fast gate
- `pre-push`
  - slower
  - catches workspace-wide breakage that PR CI will flag

## CI Jobs To Mirror

### Fast parity

Mirror the checks from `.github/workflows/ci.yml` `quick-check`:

- `cargo +1.94.0 fmt --all --check`
- `cargo +1.94.0 clippy --all-features --all-targets -- -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -A clippy::multiple_crate_versions -A clippy::module_name_repetitions -A clippy::missing_errors_doc -A clippy::missing_panics_doc -A clippy::must_use_candidate`
- `actionlint`

### Slow parity

Mirror the broader CI and security signal that commonly breaks PRs:

- `cargo +1.94.0 test --workspace --all-features`
- `cargo +1.94.0 test --doc --all-features`
- `cargo +1.94.0 check --workspace --no-default-features`
- `cargo +1.94.0 check --workspace --all-features`
- `cargo +1.94.0 deny check licenses advisories bans sources`

## Files To Add

- `scripts/pre-commit-ci.sh`
  - fast CI parity runner
- `scripts/pre-push-ci.sh`
  - slower workspace parity runner
- `.githooks/pre-commit`
  - optional thin wrapper to `scripts/pre-commit-ci.sh`
- `.githooks/pre-push`
  - optional thin wrapper to `scripts/pre-push-ci.sh`

## Files To Modify

- `Makefile`
  - add `pre-commit`, `pre-push`, and `ci-parity` targets
- `README.md`
  - add a short local quality gate section
- `docs/internal/MAINTAINER_GUIDE.md`
  - document expected local verification workflow

## Proposed Commands

### `make pre-commit`

Run:

```bash
cargo +1.94.0 fmt --all --check
cargo +1.94.0 clippy --all-features --all-targets -- \
  -D warnings \
  -D clippy::all \
  -D clippy::pedantic \
  -D clippy::nursery \
  -A clippy::multiple_crate_versions \
  -A clippy::module_name_repetitions \
  -A clippy::missing_errors_doc \
  -A clippy::missing_panics_doc \
  -A clippy::must_use_candidate
actionlint
```

### `make pre-push`

Run:

```bash
make pre-commit
cargo +1.94.0 test --workspace --all-features
cargo +1.94.0 test --doc --all-features
cargo +1.94.0 check --workspace --no-default-features
cargo +1.94.0 check --workspace --all-features
cargo +1.94.0 deny check licenses advisories bans sources
```

## Implementation Notes

1. Keep `pre-commit` fast.
   - Do not put Docker builds, release simulation, or coverage generation in the default pre-commit path.

2. Keep the commands identical to CI where possible.
   - Avoid “close enough” local variants.
   - Reuse the same toolchain version and the same clippy flag set.

3. Fail early and print the failing command.
   - The shell wrappers should use `set -euo pipefail`.
   - Each stage should echo a short header before execution.

4. Make hooks opt-in but easy.
   - Set `git config core.hooksPath .githooks` in maintainer setup docs.
   - Do not force-install hooks inside scripts.

5. Keep slow checks available for local release confidence.
   - `pre-push` should be the recommended gate before opening or updating a PR.

## Optional Follow-Ups

- Add changed-file awareness so docs-only changes can skip Rust-heavy checks.
- Add a `make fix` target that runs `cargo fmt --all` before `pre-commit`.
- Add a dedicated `cargo llvm-cov` target for action-crate coverage enforcement if we decide to gate minimum coverage in CI.
- Add `shellcheck` once the repo has more shell surface area.

## Validation Strategy

After implementation:

1. Intentionally introduce formatting drift and confirm `make pre-commit` fails.
2. Intentionally introduce a clippy lint and confirm `make pre-commit` fails.
3. Intentionally break a workflow file and confirm `actionlint` fails locally.
4. Run `make pre-push` and confirm it passes on a clean branch.
5. Verify the commands match the current CI workflow definitions after any workflow edits.

## Success Criteria

- A developer can run `make pre-commit` and catch the same failures that block `Quick Check`.
- A developer can run `make pre-push` and catch the common workspace-wide failures before opening or updating a PR.
- Maintainer docs clearly describe when to use each command and how they map to GitHub Actions.
