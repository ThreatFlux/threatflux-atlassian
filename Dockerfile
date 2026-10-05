# ThreatFlux Atlassian Dockerfile
# Multi-stage build for the `tflux-atlassian` CLI.

FROM rust:1.99.0-bookworm@sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0 AS rust-base

ARG VERSION=0.0.0
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=tflux-atlassian
ARG BINARY_PACKAGE=threatflux-atlassian-cli
ARG SBOM_MANIFEST_PATH=crates/threatflux-atlassian-cli/Cargo.toml
ARG OCI_IMAGE_TITLE=ThreatFlux Atlassian CLI
ARG OCI_IMAGE_DESCRIPTION=ThreatFlux Atlassian Rust workspace
ARG OCI_IMAGE_VENDOR=ThreatFlux
ARG OCI_IMAGE_SOURCE=https://github.com/ThreatFlux/threatflux-atlassian

RUN apt-get update && apt-get install -y \
    ca-certificates \
    pkg-config \
    libssl-dev \
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

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime

ARG VERSION=0.0.0
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=tflux-atlassian
ARG OCI_IMAGE_TITLE=ThreatFlux Atlassian CLI
ARG OCI_IMAGE_DESCRIPTION=ThreatFlux Atlassian Rust workspace
ARG OCI_IMAGE_VENDOR=ThreatFlux
ARG OCI_IMAGE_SOURCE=https://github.com/ThreatFlux/threatflux-atlassian

LABEL org.opencontainers.image.title="${OCI_IMAGE_TITLE}" \
      org.opencontainers.image.description="${OCI_IMAGE_DESCRIPTION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="${OCI_IMAGE_VENDOR}" \
      org.opencontainers.image.source="${OCI_IMAGE_SOURCE}"

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/share/doc/threatflux-atlassian \
    && useradd -m -u 1000 app

COPY --from=builder /build/target/release/${BINARY_NAME} /usr/local/bin/app
COPY --from=builder /build/sbom.cdx.json /usr/share/doc/threatflux-atlassian/sbom.cdx.json

RUN chown -R app:app /usr/local/bin/app /usr/share/doc/threatflux-atlassian

USER app
WORKDIR /home/app

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/app", "--version"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/app"]
