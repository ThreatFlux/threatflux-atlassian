# ThreatFlux Atlassian Dockerfile
# Multi-stage build for the `tflux-atlassian` CLI.
#
# Follows ThreatFlux/rust-cicd-template: a Debian 13 (trixie) Rust builder and a
# distroless Debian 13 runtime. The runtime has no shell, package manager or
# coreutils. The CLI uses rustls rather than OpenSSL, so it needs only glibc,
# libgcc_s and the CA bundle, all of which distroless cc ships. Distroless has no
# init either, so tini is installed in the builder and copied across.
#
# Base images are pinned by multi-arch index digest. The tag stays in front of
# the digest so Dependabot can still bump both (scripts/check_image_pins.py).
# Refresh a digest with:
#   docker buildx imagetools inspect <image>:<tag> | awk '/^Digest:/{print $2}'

# rust 1.99.0 on Debian 13.7 (trixie), glibc 2.41.
FROM rust:1.99.0-trixie@sha256:15ad267e7a4cb2dce5905c90c76765adb6714945c5ea6d7c82673897a5e4067b AS rust-base

ARG VERSION=0.0.0
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=tflux-atlassian
ARG BINARY_PACKAGE=threatflux-atlassian-cli
ARG SBOM_MANIFEST_PATH=crates/threatflux-atlassian-cli/Cargo.toml
ARG OCI_IMAGE_TITLE="ThreatFlux Atlassian CLI"
ARG OCI_IMAGE_DESCRIPTION="ThreatFlux Atlassian Rust workspace"
ARG OCI_IMAGE_VENDOR=ThreatFlux
ARG OCI_IMAGE_SOURCE=https://github.com/ThreatFlux/threatflux-atlassian

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

ARG BINARY_NAME
ARG BINARY_PACKAGE
ARG SBOM_MANIFEST_PATH

RUN useradd -m -u 1000 builder
USER builder
WORKDIR /build

COPY --chown=builder:builder . .

RUN cargo build --locked --release -p "${BINARY_PACKAGE}" --bin "${BINARY_NAME}" --all-features

RUN cargo install cargo-cyclonedx --locked --version 0.5.9 && \
    cargo cyclonedx \
      --manifest-path "${SBOM_MANIFEST_PATH}" \
      --all-features \
      --format json \
      --spec-version 1.5 \
      --override-filename "${BINARY_NAME}-sbom" && \
    find /build -name "${BINARY_NAME}-sbom.json" -exec cp {} /build/sbom.cdx.json \; -quit && \
    test -s /build/sbom.cdx.json

# Stage the runtime filesystem here, because the distroless runtime has no
# shell to do it with. The binary keeps its fixed `app` path (HEALTHCHECK and
# existing `docker run <image> app ...` invocations use it), and a symlink adds
# the CLI's own name.
RUN mkdir -p /home/builder/out/bin /home/builder/out/doc && \
    cp "target/release/${BINARY_NAME}" /home/builder/out/bin/app && \
    if [ "${BINARY_NAME}" != "app" ]; then \
      ln -s app "/home/builder/out/bin/${BINARY_NAME}"; \
    fi && \
    cp /build/sbom.cdx.json /home/builder/out/doc/sbom.cdx.json

# distroless cc on Debian 13.7 (trixie): glibc 2.41, libgcc_s and the CA bundle,
# running as the built-in nonroot user (65532).
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime

ARG VERSION=0.0.0
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG OCI_IMAGE_TITLE="ThreatFlux Atlassian CLI"
ARG OCI_IMAGE_DESCRIPTION="ThreatFlux Atlassian Rust workspace"
ARG OCI_IMAGE_VENDOR=ThreatFlux
ARG OCI_IMAGE_SOURCE=https://github.com/ThreatFlux/threatflux-atlassian

LABEL org.opencontainers.image.title="${OCI_IMAGE_TITLE}" \
      org.opencontainers.image.description="${OCI_IMAGE_DESCRIPTION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="${OCI_IMAGE_VENDOR}" \
      org.opencontainers.image.source="${OCI_IMAGE_SOURCE}"

# Root-owned and read-only to the runtime user, which cannot replace its own
# binary, init or SBOM.
COPY --from=builder /usr/bin/tini /usr/bin/tini
COPY --from=builder /home/builder/out/bin/ /usr/local/bin/
COPY --from=builder /home/builder/out/doc/ /usr/share/doc/threatflux-atlassian/

USER 65532:65532
WORKDIR /home/nonroot

# Exec form: there is no shell. A nonzero exit means unhealthy.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/app", "--version"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/app"]
