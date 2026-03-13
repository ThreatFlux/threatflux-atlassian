# Release Operations

Internal release notes for `threatflux-atlassian`.

## Normal Release Flow

1. Merge feature work into `dev`.
2. Open a `dev -> main` pull request.
3. Let the protected `main` policy require green checks and code-owner approval.
4. Merge into `main`.
5. `Auto Release` computes the next version, creates the release commit and tag, and dispatches the dedicated
   `Release` workflow.
6. `Release` builds artifacts, generates SBOMs, attaches release assets, and publishes the crates.

## What the Release Workflow Produces

- Linux, macOS, and Windows CLI artifacts
- SHA256 files for Unix tarballs
- CycloneDX SBOMs for the SDK and CLI crates
- crates.io publish for `threatflux-atlassian-sdk`
- crates.io publish for `threatflux-atlassian-cli`

## crates.io Publishing

Preferred secret:

- `CRATES_IO_TOKEN`

Compatibility fallback:

- `CARGO_REGISTRY_TOKEN`

The workflow checks whether the target crate version already exists on crates.io. If it does, reruns skip publish
instead of failing.

## Manual Release Recovery

If a tag exists but assets or publish steps need to be repaired, rerun the workflow against the tag source:

```bash
gh workflow run Release \
  --repo ThreatFlux/threatflux-atlassian \
  --ref main \
  -f version="<x.y.z>" \
  -f source_ref="v<x.y.z>" \
  -f prerelease=false
```

## Stale Auto-Release Runs

`Auto Release` now targets a fixed `main` SHA and skips itself if `main` advances before the release commit is pushed.
That is intentional. A newer run should own the newer branch tip rather than replaying release logic from a stale
commit graph.

## Post-Release Verification

After each release:

- confirm the GitHub release has assets and SBOM attachments
- confirm both crates appear on crates.io
- confirm the release notes and version are correct
- confirm the `main` protection set still matches current required check names
