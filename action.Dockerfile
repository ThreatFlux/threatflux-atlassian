# ThreatFlux Jira Automation Docker action

FROM rust:1.97.1-bookworm@sha256:14bc9c5966e7b3a385794b3d5389a8765668342025fbcc7b2e3d2866ac4bd8c3 AS rust-base

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

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime

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
