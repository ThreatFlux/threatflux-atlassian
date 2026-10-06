# ThreatFlux Jira Automation Docker action
#
# Same base images as the main Dockerfile: a Debian 13 (trixie) Rust builder and
# a distroless Debian 13 runtime with no shell or package manager. The action
# uses rustls, so it needs only glibc, libgcc_s and the CA bundle from
# distroless cc; tini is copied from the builder because distroless has no init.
#
# Base images are pinned by multi-arch index digest with the tag kept in front
# for Dependabot (scripts/check_image_pins.py). Refresh a digest with:
#   docker buildx imagetools inspect <image>:<tag> | awk '/^Digest:/{print $2}'

# rust 1.99.0 on Debian 13.7 (trixie), glibc 2.41.
FROM rust:1.99.0-trixie@sha256:15ad267e7a4cb2dce5905c90c76765adb6714945c5ea6d7c82673897a5e4067b AS rust-base

# Build-time packages only; nothing here reaches the runtime image except the
# tini binary copied out below. Exact Debian revisions follow the pinned base.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    libssl-dev \
    tini \
    && rm -rf /var/lib/apt/lists/*

FROM rust-base AS builder

ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

RUN useradd -m -u 1000 builder
USER builder
WORKDIR /build

COPY --chown=builder:builder . .

RUN cargo build --locked --release -p threatflux-atlassian-action

# distroless cc on Debian 13.7 (trixie): glibc 2.41, libgcc_s and the CA bundle,
# running as the built-in nonroot user (65532).
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime

LABEL org.opencontainers.image.title="ThreatFlux Jira Automation Action" \
      org.opencontainers.image.description="Config-driven GitHub Action for Jira automation" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/threatflux-atlassian"

# Root-owned and read-only to the runtime user.
COPY --from=builder /usr/bin/tini /usr/bin/tini
COPY --from=builder /build/target/release/threatflux-atlassian-action /usr/local/bin/threatflux-atlassian-action

USER 65532:65532
WORKDIR /home/nonroot

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/threatflux-atlassian-action"]
