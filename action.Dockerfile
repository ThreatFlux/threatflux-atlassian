# ThreatFlux Jira Automation Docker action

FROM ghcr.io/threatflux/rust-cicd-template:base-rust-latest AS builder

USER root
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH
RUN apt-get update && apt-get install -y ca-certificates curl build-essential pkg-config libssl-dev && rm -rf /var/lib/apt/lists/* && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
      sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.95.0 && \
    chmod -R a+w "$CARGO_HOME" "$RUSTUP_HOME"

RUN id -u builder >/dev/null 2>&1 || useradd -m builder
USER builder
WORKDIR /build

COPY --chown=builder:builder Cargo.toml Cargo.lock ./
COPY --chown=builder:builder crates/threatflux-atlassian-sdk/Cargo.toml crates/threatflux-atlassian-sdk/Cargo.toml
COPY --chown=builder:builder crates/threatflux-atlassian-cli/Cargo.toml crates/threatflux-atlassian-cli/Cargo.toml
COPY --chown=builder:builder crates/threatflux-atlassian-action/Cargo.toml crates/threatflux-atlassian-action/Cargo.toml

RUN mkdir -p crates/threatflux-atlassian-sdk/src crates/threatflux-atlassian-cli/src crates/threatflux-atlassian-action/src && \
    printf '%s\n' 'pub fn placeholder() {}' > crates/threatflux-atlassian-sdk/src/lib.rs && \
    printf '%s\n' 'fn main() {}' > crates/threatflux-atlassian-cli/src/main.rs && \
    printf '%s\n' 'fn main() {}' > crates/threatflux-atlassian-action/src/main.rs && \
    cargo build --release -p threatflux-atlassian-action || true && \
    rm -rf crates/threatflux-atlassian-sdk/src crates/threatflux-atlassian-cli/src crates/threatflux-atlassian-action/src

COPY --chown=builder:builder crates ./crates
COPY --chown=builder:builder README.md LICENSE CONTRIBUTING.md SECURITY.md ./

RUN cargo build --release -p threatflux-atlassian-action

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="ThreatFlux Jira Automation Action" \
      org.opencontainers.image.description="Config-driven GitHub Action for Jira automation" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/threatflux-atlassian"

RUN apt-get update && apt-get install -y ca-certificates tini && rm -rf /var/lib/apt/lists/* && useradd -m -u 1000 app

COPY --from=builder /build/target/release/threatflux-atlassian-action /usr/local/bin/threatflux-atlassian-action

RUN chown app:app /usr/local/bin/threatflux-atlassian-action

USER app
WORKDIR /home/app

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/threatflux-atlassian-action"]
