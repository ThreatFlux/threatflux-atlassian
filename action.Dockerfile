# ThreatFlux Jira Automation Docker action

FROM rust:1.96.1-bookworm AS rust-base

RUN apt-get update && apt-get install -y \
    ca-certificates \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

FROM rust-base AS builder

RUN useradd -m -u 1000 builder
USER builder
WORKDIR /build

COPY --chown=builder:builder . .

RUN cargo build --release -p threatflux-atlassian-action

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="ThreatFlux Jira Automation Action" \
      org.opencontainers.image.description="Config-driven GitHub Action for Jira automation" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/threatflux-atlassian"

RUN apt-get update && apt-get install -y \
    ca-certificates \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 app

COPY --from=builder /build/target/release/threatflux-atlassian-action /usr/local/bin/threatflux-atlassian-action

RUN chown app:app /usr/local/bin/threatflux-atlassian-action

USER app
WORKDIR /home/app

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/threatflux-atlassian-action"]
