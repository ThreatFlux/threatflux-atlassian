# Template Adaptation

This repository started from the standard ThreatFlux Rust CI/CD template and was then adapted into a shared
workspace for Atlassian integrations.

## What Changed

| Area | Template Baseline | `threatflux-atlassian` |
| ---- | ----------------- | ---------------------- |
| Cargo layout | Single root crate | Virtual workspace with SDK and CLI crates |
| Source tree | `src/lib.rs` and `src/main.rs` at repo root | `crates/threatflux-atlassian-sdk` and `crates/threatflux-atlassian-cli` |
| CI feature checks | Root-crate feature checks | Workspace-wide feature checks |
| Release flow | Publish/build one root package | Build the CLI package and publish SDK before CLI |
| Docker build | Compile root binary | Compile `tflux-atlassian` from the CLI crate |
| Documentation | Generic template README | Repo-specific README plus usage docs |

## Concrete Repo Changes

1. The root [Cargo.toml](../Cargo.toml) was converted into a workspace manifest with shared dependency and release
   configuration.
2. Template root sources under `src/` were removed in favor of crate-specific sources under `crates/`.
3. The standard workflows under `.github/workflows/` were kept, but `ci.yml`, `docker.yml`, `release.yml`, and
   `security.yml` were adjusted for:
   - the `dev` branch
   - workspace-aware Cargo commands
   - CLI-specific binary packaging
   - ordered crates.io publish steps
4. The root [Makefile](../Makefile) was updated so local CI commands operate on the workspace rather than a single
   package.
5. Repo-specific documentation was added in [README.md](../README.md) and [USAGE.md](./USAGE.md).

## Reapplying This Pattern To Another Template Repo

If another ThreatFlux template repo needs the same treatment, the minimum steps are:

1. Replace the root package manifest with a workspace manifest.
2. Move code into crate directories under `crates/`.
3. Update CI and release workflows to use `cargo ... --workspace` where appropriate.
4. Update release packaging so the intended binary crate is built explicitly.
5. Update Docker layering to copy crate manifests and build the correct binary package.
6. Rewrite README, contributing, and security docs so they reference the actual repo instead of template placeholders.

## Why Keep The Template

The goal was to extract the Atlassian SDK/CLI from the monorepo without losing the standardized ThreatFlux delivery
pipeline. This keeps the repo aligned with the existing organization conventions while allowing the Atlassian crates
to evolve independently.
