# Maintainer Guide

Internal maintainer notes for `threatflux-atlassian`.

## Branch Model

- `main` is the protected release branch.
- `dev` is the integration branch for ongoing work.
- feature branches should merge into `dev` first, then `dev` should merge into `main` through a pull request.

## Branch Protection

`main` is configured to require:

- a pull request before merge
- all required checks passing
- code-owner review
- at least one approving review
- stale review dismissal after new pushes
- last-push approval
- conversation resolution
- no direct pushes or force-pushes, including for admins

`dev` is protected from deletion so GitHub auto-delete will not remove it after a `dev -> main` merge.

## Code Ownership

The repository uses [`.github/CODEOWNERS`](../../.github/CODEOWNERS) to drive required code-owner review.

If ownership changes, update `CODEOWNERS` first and then confirm the required review policy still matches the intended
maintainer set.

## Required Checks

`main` protection is wired to the current CI and security check names. If a workflow job name changes, branch
protection must be updated to match or merges will block on a missing status.

Best practice:

- keep workflow job names stable
- treat job-name changes as an admin change, not a casual refactor
- update branch protection immediately after renaming a required check

## Secrets and Variables

Preferred GitHub Actions secret layout:

- `CRATES_IO_TOKEN` for crates.io publishing
- `CARGO_REGISTRY_TOKEN` only as a compatibility fallback

If release automation is updated to consume new secrets or variables, document them in
[Release Operations](./RELEASE_OPERATIONS.md) and in the top-level README.

## Documentation Expectations

When consumer-facing behavior changes:

- update [README.md](../../README.md)
- update [docs/USAGE.md](../USAGE.md)
- update maintainer docs if branch, release, or secret handling changed
