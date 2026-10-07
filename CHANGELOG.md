# Changelog

All notable changes to the ThreatFlux Atlassian workspace (`threatflux-atlassian-sdk`, `threatflux-atlassian-cli` and
the Jira GitHub Action) are documented in this file. Releases before 0.5.2 are described by their GitHub Releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The release workflow uses the section for a version as
the notes of its GitHub Release.

## [Unreleased]

## [0.5.2] - 2026-10-07

A maintenance release covering the toolchain, dependencies, container images and release automation. The SDK, CLI
and Action behavior is unchanged from 0.5.1.

### Changed

- The toolchain and the Docker builders use stable Rust 1.99.0. The MSRV rises from 1.96.0 to 1.97.1, which the
  latest stable FluxEncrypt (0.7.5) requires. Stable dependencies and the immutable GitHub Actions pins are refreshed.
- Both images, `Dockerfile` (the CLI) and `action.Dockerfile` (the Jira Action), build on `rust:1.99.0-trixie` and run
  on distroless `gcr.io/distroless/cc-debian13:nonroot`, both pinned by digest. The runtime has no shell or package
  manager and runs as uid/gid 65532 instead of the `app` user (uid 1000). The CLI image keeps `tini` as its
  entrypoint and `app` as its command; `tflux-atlassian` is a new link to the same binary.

### Security

- Both crates publish through crates.io trusted publishing: the release job exchanges its GitHub OIDC identity for a
  short-lived token, and no crates.io API token is stored in GitHub. A release whose manifest version differs from
  the release version fails instead of publishing.
- Release builds resolve their source to one commit in `main` history and reject unmerged, fork and pull request
  sources. Release images never read or write the shared build cache.
- Auto Release runs as the `threatflux-automation` GitHub App. Its release pull request runs CI like any other, and
  its tag push starts the release and container workflows.
- `release.yml` and `auto-release.yml` accept `dry_run` on a manual dispatch to rehearse a release without tagging,
  releasing, publishing or pushing anything.
