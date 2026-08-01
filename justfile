set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

cargo := env_var_or_default("CARGO", "cargo")
rust_msrv := env_var_or_default("RUST_MSRV", "1.96.0")
rust_toolchain := env_var_or_default("RUST_TOOLCHAIN", "1.96.0")
docker_image := env_var_or_default("DOCKER_IMAGE", "threatflux-atlassian")
docker_tag := env_var_or_default("DOCKER_TAG", "latest")
docker_registry := env_var_or_default("DOCKER_REGISTRY", "ghcr.io/threatflux")
binary_package := env_var_or_default("BINARY_PACKAGE", "threatflux-atlassian-cli")
binary_name := env_var_or_default("BINARY_NAME", "tflux-atlassian")
sbom_manifest_path := env_var_or_default("SBOM_MANIFEST_PATH", "crates/threatflux-atlassian-cli/Cargo.toml")
publish_packages := env_var_or_default("PUBLISH_PACKAGES", "threatflux-atlassian-sdk threatflux-atlassian-cli")

# Display available recipes.
help:
    @just --list

# Install development tools.
dev-setup:
    @echo "Installing development tools..."
    @rustup toolchain install {{ rust_toolchain }} --profile minimal
    @rustup component add rustfmt clippy llvm-tools-preview --toolchain {{ rust_toolchain }}
    @{{ cargo }} install cargo-llvm-cov --locked
    @{{ cargo }} install cargo-audit --locked
    @{{ cargo }} install cargo-deny --locked
    @{{ cargo }} install cargo-cyclonedx --locked
    @{{ cargo }} install cargo-hack --locked
    @echo "Development tools installed!"

# Install the Git pre-commit hook.
install-hooks:
    @echo "Installing git hooks..."
    @mkdir -p .git/hooks
    @printf '#!/bin/sh\njust pre-commit\n' > .git/hooks/pre-commit
    @chmod +x .git/hooks/pre-commit
    @echo "Git hooks installed!"

# Build the project in debug mode.
build:
    @echo "Building project..."
    @{{ cargo }} build --all-features
    @echo "Build completed!"

# Build the project in release mode.
build-release:
    @echo "Building release..."
    @{{ cargo }} build --release --all-features
    @echo "Release build completed!"

# Check compilation without building.
check:
    @echo "Checking compilation..."
    @{{ cargo }} check --all-features --all-targets

# Format code.
fmt:
    @echo "Formatting code..."
    @{{ cargo }} fmt --all
    @echo "Formatting completed!"

# Check code formatting.
fmt-check:
    @echo "Checking code format..."
    @{{ cargo }} fmt --all -- --check
    @echo "Format check passed!"

# Run the standard Clippy checks.
lint:
    @echo "Running clippy..."
    @{{ cargo }} clippy --all-features --all-targets -- -D warnings
    @echo "Linting passed!"

# Run the strict Clippy checks.
lint-strict:
    @echo "Running strict clippy..."
    @{{ cargo }} clippy --all-features --all-targets -- \
        -D warnings \
        -D clippy::all \
        -D clippy::pedantic \
        -D clippy::nursery \
        -D clippy::cargo \
        -A clippy::multiple_crate_versions \
        -A clippy::module_name_repetitions \
        -A clippy::missing_errors_doc \
        -A clippy::missing_panics_doc \
        -A clippy::must_use_candidate
    @echo "Strict linting passed!"

# Apply Clippy fixes.
lint-fix:
    @echo "Applying clippy fixes..."
    @{{ cargo }} clippy --all-features --all-targets --fix --allow-dirty --allow-staged -- -D warnings
    @echo "Fixes applied!"

# Run all tests.
test:
    @echo "Running tests..."
    @{{ cargo }} test --all-features
    @echo "Tests passed!"

# Run tests with output.
test-verbose:
    @echo "Running tests (verbose)..."
    @{{ cargo }} test --all-features -- --nocapture

# Run documentation tests.
test-doc:
    @echo "Running doc tests..."
    @{{ cargo }} test --doc --all-features
    @echo "Doc tests passed!"

# Check supported feature combinations.
test-features:
    @echo "Testing feature combinations..."
    @echo "  No default features..."
    @{{ cargo }} check --workspace --no-default-features
    @echo "  All features..."
    @{{ cargo }} check --workspace --all-features
    @echo "  Default features only..."
    @{{ cargo }} check --workspace
    @echo "Feature checks passed!"

# Test the full feature powerset (requires cargo-hack).
test-features-full:
    @echo "Testing full feature powerset..."
    @cargo hack check --workspace --feature-powerset --no-dev-deps
    @echo "Feature powerset passed!"

# Generate an LCOV coverage report.
coverage:
    @echo "Generating coverage..."
    @cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
    @echo "Coverage report: lcov.info"

# Generate an HTML coverage report.
coverage-html:
    @echo "Generating HTML coverage..."
    @cargo llvm-cov --all-features --workspace --html
    @echo "Report: target/llvm-cov/html/index.html"

# Show the coverage summary.
coverage-summary:
    @echo "Coverage summary:"
    @cargo llvm-cov --all-features --workspace --summary-only

# Run the security audit.
audit:
    @echo "Running security audit..."
    @cargo audit --ignore RUSTSEC-2023-0071
    @echo "Security audit passed!"

# Check licenses and advisories.
deny:
    @echo "Running cargo-deny..."
    @cargo deny check
    @echo "Deny checks passed!"

# Generate CycloneDX SBOMs for the SDK and CLI.
sbom:
    @echo "Generating SBOMs..."
    @mkdir -p sbom
    @rm -f sbom/*.json crates/threatflux-atlassian-sdk/*-sbom.json crates/threatflux-atlassian-cli/*-sbom.json crates/threatflux-atlassian-action/*-sbom.json
    @cargo cyclonedx --manifest-path crates/threatflux-atlassian-sdk/Cargo.toml --all-features --format json --spec-version 1.5 --override-filename threatflux-atlassian-sdk-sbom
    @cargo cyclonedx --manifest-path crates/threatflux-atlassian-cli/Cargo.toml --all-features --format json --spec-version 1.5 --override-filename threatflux-atlassian-cli-sbom
    @cp crates/threatflux-atlassian-sdk/threatflux-atlassian-sdk-sbom.json sbom/
    @cp crates/threatflux-atlassian-cli/threatflux-atlassian-cli-sbom.json sbom/
    @rm -f crates/threatflux-atlassian-sdk/*-sbom.json crates/threatflux-atlassian-cli/*-sbom.json crates/threatflux-atlassian-action/*-sbom.json
    @echo "SBOMs written to sbom/"

# Run all security checks.
security: audit deny
    @echo "All security checks passed!"

# Build documentation.
docs:
    @echo "Building documentation..."
    @RUSTDOCFLAGS="-D warnings" {{ cargo }} doc --all-features --no-deps
    @echo "Documentation built!"

# Build and open documentation.
docs-open:
    @{{ cargo }} doc --all-features --no-deps --open

# Run benchmarks.
bench:
    @echo "Running benchmarks..."
    @{{ cargo }} bench --all-features

# Check that benchmarks compile.
bench-check:
    @echo "Checking benchmarks..."
    @{{ cargo }} bench --all-features --no-run
    @echo "Benchmarks compile!"

# Check the minimum supported Rust version.
msrv:
    @echo "Checking MSRV ({{ rust_msrv }})..."
    @rustup toolchain install {{ rust_msrv }} --profile minimal >/dev/null 2>&1 || true
    @rustup run {{ rust_msrv }} cargo check --workspace --all-features
    @echo "MSRV check passed!"

# Build the Docker image.
docker-build:
    @echo "Building Docker image..."
    @docker build --build-arg BINARY_NAME={{ binary_name }} --build-arg BINARY_PACKAGE={{ binary_package }} --build-arg SBOM_MANIFEST_PATH={{ sbom_manifest_path }} -t {{ docker_image }}:{{ docker_tag }} .
    @echo "Docker image built: {{ docker_image }}:{{ docker_tag }}"

# Push the Docker image.
docker-push:
    @echo "Pushing Docker image..."
    @docker tag {{ docker_image }}:{{ docker_tag }} {{ docker_registry }}/{{ docker_image }}:{{ docker_tag }}
    @docker push {{ docker_registry }}/{{ docker_image }}:{{ docker_tag }}
    @echo "Image pushed!"

# Run pre-commit checks.
pre-commit: fmt-check lint test-doc
    @echo "Pre-commit checks passed!"

# Run the full local CI suite.
ci: fmt-check lint test test-features docs security
    @echo "All CI checks passed!"

# Run quick CI checks.
ci-quick: fmt-check lint check
    @echo "Quick CI checks passed!"

# Run the full validation suite.
all: ci coverage bench-check
    @echo "Full validation passed!"

# Check release readiness.
release-check: ci msrv
    @for package in {{ publish_packages }}; do \
        echo "  cargo publish --dry-run -p $package"; \
        cargo publish --dry-run -p "$package"; \
    done
    @echo "Ready for release!"

# Remove build and coverage artifacts.
clean:
    @echo "Cleaning..."
    @{{ cargo }} clean
    @rm -f lcov.info
    @echo "Clean completed!"

alias f := fmt
alias l := lint
alias t := test
alias b := build
alias c := check
