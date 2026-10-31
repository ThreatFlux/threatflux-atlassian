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

FROM rust:1.99.1-alpine3.24@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87 AS builder
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
# hadolint ignore=DL3018
RUN apk add --no-cache build-base binutils cmake perl tini-static
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml README.md LICENSE ./
COPY crates/ crates/
COPY examples/ examples/
ARG BINARY_NAME=tflux-atlassian
ARG BINARY_PACKAGE=threatflux-atlassian-cli
ARG SBOM_MANIFEST_PATH=crates/threatflux-atlassian-cli/Cargo.toml
RUN build_target="$(rustc -vV | sed -n 's/^host: //p')" && \
    mkdir -p /native-unwind /out/bin /out/doc /out/etc /out/data && \
    cp "$(rustc --print sysroot)/lib/rustlib/${build_target}/lib/self-contained/libunwind.a" /native-unwind/ && \
    RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=no -C linker=cc -C relocation-model=pic -C link-arg=-static-pie -L native=/native-unwind -C link-arg=-Wl,-Map=/native-link.map" \
      cargo build --locked --release --target "${build_target}" -p "${BINARY_PACKAGE}" --bin "${BINARY_NAME}" --all-features && \
    cp "target/${build_target}/release/${BINARY_NAME}" /out/bin/app && \
    if [ "${BINARY_NAME}" != app ]; then ln -s app "/out/bin/${BINARY_NAME}"; fi && \
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
RUN cargo install cargo-cyclonedx --locked --version 0.5.9 && \
    cargo cyclonedx --manifest-path "${SBOM_MANIFEST_PATH}" --all-features \
      --format json --spec-version 1.5 --override-filename cli-sbom && \
    find /build -name cli-sbom.json -exec cp {} /out/doc/sbom.cdx.json \; -quit && \
    test -s /out/doc/sbom.cdx.json

FROM scratch AS runtime
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

COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certificates /ca-certificates.status /var/lib/dpkg/status.d/ca-certificates
COPY --from=builder /out/bin/ /usr/local/bin/
COPY --from=builder /out/doc/ /usr/share/doc/threatflux-atlassian/
COPY --from=builder /out/etc/ /etc/
COPY --from=builder /sbin/tini-static /usr/bin/tini
COPY --from=builder --chown=65532:65532 /out/data/ /data/
USER 65532:65532
WORKDIR /data
ENV RUST_LOG=info
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/usr/local/bin/app", "--version"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/app"]
