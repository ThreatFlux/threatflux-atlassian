# ThreatFlux Atlassian Dockerfile
# Builds the `tflux-atlassian` CLI from the workspace.

# =============================================================================
# Build Stage
# =============================================================================
FROM rust:1.94-bookworm AS builder

# Build arguments
ARG VERSION=0.0.0
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=tflux-atlassian

RUN apt-get update && apt-get install -y ca-certificates pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Create build user
RUN useradd -m -u 1000 builder
USER builder

WORKDIR /build

COPY --chown=builder:builder Cargo.toml Cargo.lock ./
COPY --chown=builder:builder crates/threatflux-atlassian-sdk/Cargo.toml crates/threatflux-atlassian-sdk/Cargo.toml
COPY --chown=builder:builder crates/threatflux-atlassian-cli/Cargo.toml crates/threatflux-atlassian-cli/Cargo.toml

RUN mkdir -p crates/threatflux-atlassian-sdk/src crates/threatflux-atlassian-cli/src && \
    printf '%s\n' 'pub fn placeholder() {}' > crates/threatflux-atlassian-sdk/src/lib.rs && \
    printf '%s\n' 'fn main() {}' > crates/threatflux-atlassian-cli/src/main.rs && \
    cargo build --release -p threatflux-atlassian-cli --bin ${BINARY_NAME} --all-features || true && \
    rm -rf crates/threatflux-atlassian-sdk/src crates/threatflux-atlassian-cli/src

COPY --chown=builder:builder crates ./crates
COPY --chown=builder:builder README.md LICENSE CONTRIBUTING.md SECURITY.md ./

RUN cargo build --release -p threatflux-atlassian-cli --bin ${BINARY_NAME} --all-features

RUN cargo install cargo-cyclonedx --locked --version 0.5.8 && \
    cargo cyclonedx \
      --manifest-path crates/threatflux-atlassian-cli/Cargo.toml \
      --all-features \
      --format json \
      --spec-version 1.5 \
      --override-filename threatflux-atlassian-cli-sbom

# =============================================================================
# Runtime Stage
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Build arguments
ARG VERSION=0.0.0
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG BINARY_NAME=tflux-atlassian

# Labels
LABEL org.opencontainers.image.title="ThreatFlux Atlassian CLI" \
      org.opencontainers.image.description="ThreatFlux Atlassian Rust workspace" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/threatflux-atlassian"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/share/doc/threatflux-atlassian \
    && useradd -m -u 1000 app

# Copy binary from builder
COPY --from=builder /build/target/release/${BINARY_NAME} /usr/local/bin/app
COPY --from=builder /build/crates/threatflux-atlassian-cli/threatflux-atlassian-cli-sbom.json /usr/share/doc/threatflux-atlassian/sbom.cdx.json

# Set ownership
RUN chown -R app:app /usr/local/bin/app /usr/share/doc/threatflux-atlassian

# Switch to non-root user
USER app
WORKDIR /home/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/app", "--version"]

# Use tini as init
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command
CMD ["/usr/local/bin/app"]
