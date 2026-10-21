# ThreatFlux Atlassian static-musl runtime.
# These Rustls-only binaries need no shell or shared native runtime libraries.
# Build checks require maintained system musl, static PIE and no dynamic loader.
# CA data and its Debian package record travel together from the same stage.
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS certificates
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20250419+deb13u1 \
    && dpkg-query -s ca-certificates > /ca-certificates.status \
    && rm -rf /var/lib/apt/lists/*

FROM rust:1.99.1-alpine3.24@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS builder
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
# hadolint ignore=DL3018
RUN apk add --no-cache build-base binutils cmake perl tini-static
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml README.md LICENSE ./
COPY crates/ crates/
COPY examples/ examples/
RUN build_target="$(rustc -vV | sed -n 's/^host: //p')" && \
    mkdir -p /native-unwind /out/bin /out/doc /out/etc /out/data && \
    cp "$(rustc --print sysroot)/lib/rustlib/${build_target}/lib/self-contained/libunwind.a" /native-unwind/ && \
    RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=no -C linker=cc -C relocation-model=pic -C link-arg=-static-pie -L native=/native-unwind -C link-arg=-Wl,-Map=/native-link.map" \
      cargo build --locked --release --target "${build_target}" -p threatflux-atlassian-action && \
    cp "target/${build_target}/release/threatflux-atlassian-action" /out/bin/app && \
    ln -s app /out/bin/threatflux-atlassian-action && \
    musl_archive="$(grep -oE '/[^[:space:](]+/libc\.a' /native-link.map | sort -u)" && \
    test "$(readlink -f "${musl_archive}")" = /usr/lib/libc.a && \
    readelf -h /out/bin/app | grep -q 'Type:.*DYN' && \
    for executable in /out/bin/app /sbin/tini-static; do \
      if readelf -l "${executable}" | grep -q INTERP || readelf -d "${executable}" | grep -q NEEDED; then \
        echo "Dynamic runtime dependency in ${executable}" >&2; exit 1; \
      fi; \
    done && \
    printf 'nonroot:x:65532:65532:nonroot:/data:/sbin/nologin\n' > /out/etc/passwd && \
    printf 'nonroot:x:65532:nonroot\n' > /out/etc/group && \
    { rustc -vV; cargo tree --locked -p aws-lc-sys --depth 0; apk list --installed musl musl-dev tini-static; \
       sha256sum /usr/lib/libc.a /sbin/tini-static /native-unwind/libunwind.a; \
       grep -oE '/[^[:space:](]+/libc\.a' /native-link.map | sort -u; } > /out/doc/native-build.txt

FROM scratch AS runtime
LABEL org.opencontainers.image.title="ThreatFlux Jira Automation Action" \
      org.opencontainers.image.description="Config-driven GitHub Action for Jira automation" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/threatflux-atlassian"

COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certificates /ca-certificates.status /var/lib/dpkg/status.d/ca-certificates
COPY --from=builder /out/bin/ /usr/local/bin/
COPY --from=builder /out/doc/ /usr/share/doc/app/
COPY --from=builder /out/etc/ /etc/
COPY --from=builder /sbin/tini-static /usr/bin/tini
COPY --from=builder --chown=65532:65532 /out/data/ /data/
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/app"]
