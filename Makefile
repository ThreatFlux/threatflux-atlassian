# ThreatFlux Rust Project Makefile
# Standardized build, test, and development commands
# Version: 1.1.0

# =============================================================================
# Configuration
# =============================================================================

CARGO ?= cargo
RUST_MSRV ?= 1.96.0
RUST_TOOLCHAIN ?= 1.97.1

# Docker configuration
# NOTE: DOCKER_IMAGE is an explicit constant, deliberately NOT
# $(shell basename $(CURDIR)) -- deriving it from the checkout directory breaks
# in git worktrees, renamed clones, and CI checkout paths.
DOCKER_IMAGE ?= threatflux-atlassian
DOCKER_TAG ?= latest
DOCKER_REGISTRY ?= ghcr.io/threatflux
BINARY_PACKAGE ?= threatflux-atlassian-cli
BINARY_NAME ?= tflux-atlassian
SBOM_MANIFEST_PATH ?= crates/threatflux-atlassian-cli/Cargo.toml
PUBLISH_PACKAGES ?= threatflux-atlassian-sdk threatflux-atlassian-cli

# Clippy configuration - strict by default
CLIPPY_FLAGS := -D warnings \
	-D clippy::all \
	-D clippy::pedantic \
	-D clippy::nursery \
	-D clippy::cargo \
	-A clippy::multiple_crate_versions \
	-A clippy::module_name_repetitions \
	-A clippy::missing_errors_doc \
	-A clippy::missing_panics_doc \
	-A clippy::must_use_candidate

# Colors for output
# NOTE: these are emitted with printf, never `echo "...\n"`. POSIX leaves echo's
# backslash handling implementation-defined and /bin/bash prints a literal \033.
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
CYAN := \033[0;36m
NC := \033[0m

# Prerequisite lists here are ordering-sensitive (ci, all, security,
# release-check). Under -j make would fan them out into concurrent cargo
# invocations that then serialize on the cargo target-dir lock, producing slow,
# interleaved and unreadable output. Keep this file serial.
.NOTPARALLEL:

# =============================================================================
# Default Target
# =============================================================================

.DEFAULT_GOAL := help

# Every target below is phony. `docs`, `check`, `clean` and the single-letter
# aliases in particular MUST be listed: a real docs/ directory exists at the
# repo root, so without this make would consider `docs` up to date and silently
# skip rustdoc and docs-check (and therefore drop them from `ci`).
.PHONY: help dev-setup install-hooks build build-release check \
        fmt fmt-check lint lint-strict lint-fix \
        test test-verbose test-doc test-features test-features-full \
        coverage coverage-html coverage-summary \
        audit deny sbom security \
        docs-check docs docs-open bench bench-check msrv \
        docker-build docker-push \
        pre-commit ci ci-quick all release-check clean \
        f l t b c

help: ## Display this help message
	@printf '$(CYAN)ThreatFlux Rust Project - Available Commands$(NC)\n'
	@printf '\n'
	@printf '$(YELLOW)Quick Start:$(NC)\n'
	@printf '  $(GREEN)make dev-setup$(NC)    Install all development tools\n'
	@printf '  $(GREEN)make ci$(NC)           Run all CI checks locally\n'
	@printf '  $(GREEN)make all$(NC)          Run full validation suite\n'
	@printf '\n'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# =============================================================================
# Setup
# =============================================================================

dev-setup: ## Install development tools
	@printf '$(CYAN)Installing development tools...$(NC)\n'
	@rustup toolchain install $(RUST_TOOLCHAIN) --profile minimal
	@rustup component add rustfmt clippy llvm-tools-preview --toolchain $(RUST_TOOLCHAIN)
	@$(CARGO) install cargo-llvm-cov --locked
	@$(CARGO) install cargo-audit --locked
	@$(CARGO) install cargo-deny --locked
	@$(CARGO) install cargo-cyclonedx --locked
	@$(CARGO) install cargo-hack --locked
	@printf '$(GREEN)Development tools installed!$(NC)\n'

# The hook body is written with printf, not `echo '...\n...'`: /bin/bash emits a
# literal backslash-n there and the hook becomes one unrunnable line.
# The '#' below is passed through to the shell verbatim -- inside a recipe line
# it is not a makefile comment.
install-hooks: ## Install git pre-commit hooks
	@printf '$(CYAN)Installing git hooks...$(NC)\n'
	@mkdir -p .git/hooks
	@printf '#!/bin/sh\nmake pre-commit\n' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@printf '$(GREEN)Git hooks installed!$(NC)\n'

# =============================================================================
# Building
# =============================================================================

build: ## Build the project (debug)
	@printf '$(CYAN)Building project...$(NC)\n'
	@$(CARGO) build --all-features
	@printf '$(GREEN)Build completed!$(NC)\n'

build-release: ## Build the project (release)
	@printf '$(CYAN)Building release...$(NC)\n'
	@$(CARGO) build --release --all-features
	@printf '$(GREEN)Release build completed!$(NC)\n'

check: ## Check compilation without building
	@printf '$(CYAN)Checking compilation...$(NC)\n'
	@$(CARGO) check --all-features --all-targets

# =============================================================================
# Code Quality
# =============================================================================

fmt: ## Format code
	@printf '$(CYAN)Formatting code...$(NC)\n'
	@$(CARGO) fmt --all
	@printf '$(GREEN)Formatting completed!$(NC)\n'

fmt-check: ## Check code formatting
	@printf '$(CYAN)Checking code format...$(NC)\n'
	@$(CARGO) fmt --all -- --check
	@printf '$(GREEN)Format check passed!$(NC)\n'

lint: ## Run clippy linter (standard)
	@printf '$(CYAN)Running clippy...$(NC)\n'
	@$(CARGO) clippy --all-features --all-targets -- -D warnings
	@printf '$(GREEN)Linting passed!$(NC)\n'

lint-strict: ## Run clippy with strict flags
	@printf '$(CYAN)Running strict clippy...$(NC)\n'
	@$(CARGO) clippy --all-features --all-targets -- $(CLIPPY_FLAGS)
	@printf '$(GREEN)Strict linting passed!$(NC)\n'

lint-fix: ## Run clippy and apply fixes
	@printf '$(CYAN)Applying clippy fixes...$(NC)\n'
	@$(CARGO) clippy --all-features --all-targets --fix --allow-dirty --allow-staged -- -D warnings
	@printf '$(GREEN)Fixes applied!$(NC)\n'

# =============================================================================
# Testing
# =============================================================================

test: ## Run all tests
	@printf '$(CYAN)Running tests...$(NC)\n'
	@$(CARGO) test --all-features
	@printf '$(GREEN)Tests passed!$(NC)\n'

test-verbose: ## Run tests with output
	@printf '$(CYAN)Running tests (verbose)...$(NC)\n'
	@$(CARGO) test --all-features -- --nocapture

test-doc: ## Run documentation tests
	@printf '$(CYAN)Running doc tests...$(NC)\n'
	@$(CARGO) test --doc --all-features
	@printf '$(GREEN)Doc tests passed!$(NC)\n'

test-features: ## Test feature combinations
	@printf '$(CYAN)Testing feature combinations...$(NC)\n'
	@printf '$(BLUE)  No default features...$(NC)\n'
	@$(CARGO) check --workspace --no-default-features
	@printf '$(BLUE)  All features...$(NC)\n'
	@$(CARGO) check --workspace --all-features
	@printf '$(BLUE)  Default features only...$(NC)\n'
	@$(CARGO) check --workspace
	@printf '$(GREEN)Feature checks passed!$(NC)\n'

test-features-full: ## Test all feature powerset (requires cargo-hack)
	@printf '$(CYAN)Testing full feature powerset...$(NC)\n'
	@cargo hack check --workspace --feature-powerset --no-dev-deps
	@printf '$(GREEN)Feature powerset passed!$(NC)\n'

# =============================================================================
# Coverage
# =============================================================================

coverage: ## Generate code coverage report
	@printf '$(CYAN)Generating coverage...$(NC)\n'
	@cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	@printf '$(GREEN)Coverage report: lcov.info$(NC)\n'

coverage-html: ## Generate HTML coverage report
	@printf '$(CYAN)Generating HTML coverage...$(NC)\n'
	@cargo llvm-cov --all-features --workspace --html
	@printf '$(GREEN)Report: target/llvm-cov/html/index.html$(NC)\n'

coverage-summary: ## Show coverage summary
	@printf '$(CYAN)Coverage summary:$(NC)\n'
	@cargo llvm-cov --all-features --workspace --summary-only

# =============================================================================
# Security
# =============================================================================

audit: ## Run security audit
	@printf '$(CYAN)Running security audit...$(NC)\n'
	@cargo audit --ignore RUSTSEC-2023-0071
	@printf '$(GREEN)Security audit passed!$(NC)\n'

deny: ## Check licenses and advisories
	@printf '$(CYAN)Running cargo-deny...$(NC)\n'
	@cargo deny check
	@printf '$(GREEN)Deny checks passed!$(NC)\n'

sbom: ## Generate CycloneDX SBOMs for the SDK and CLI
	@printf '$(CYAN)Generating SBOMs...$(NC)\n'
	@mkdir -p sbom
	@rm -f sbom/*.json crates/threatflux-atlassian-sdk/*-sbom.json crates/threatflux-atlassian-cli/*-sbom.json crates/threatflux-atlassian-action/*-sbom.json
	@cargo cyclonedx --manifest-path crates/threatflux-atlassian-sdk/Cargo.toml --all-features --format json --spec-version 1.5 --override-filename threatflux-atlassian-sdk-sbom
	@cargo cyclonedx --manifest-path crates/threatflux-atlassian-cli/Cargo.toml --all-features --format json --spec-version 1.5 --override-filename threatflux-atlassian-cli-sbom
	@cp crates/threatflux-atlassian-sdk/threatflux-atlassian-sdk-sbom.json sbom/
	@cp crates/threatflux-atlassian-cli/threatflux-atlassian-cli-sbom.json sbom/
	@rm -f crates/threatflux-atlassian-sdk/*-sbom.json crates/threatflux-atlassian-cli/*-sbom.json crates/threatflux-atlassian-action/*-sbom.json
	@printf '$(GREEN)SBOMs written to sbom/$(NC)\n'

security: audit deny ## Run all security checks
	@printf '$(GREEN)All security checks passed!$(NC)\n'

# =============================================================================
# Documentation
# =============================================================================

docs-check: ## Check README metadata, synchronized examples, feature flags, and local links
	@python3 scripts/check_docs.py

docs: docs-check ## Build documentation
	@printf '$(CYAN)Building documentation...$(NC)\n'
	@RUSTDOCFLAGS="-D warnings" $(CARGO) doc --all-features --no-deps
	@printf '$(GREEN)Documentation built!$(NC)\n'

docs-open: ## Build and open documentation
	@$(CARGO) doc --all-features --no-deps --open

# =============================================================================
# Benchmarks
# =============================================================================

bench: ## Run benchmarks
	@printf '$(CYAN)Running benchmarks...$(NC)\n'
	@$(CARGO) bench --all-features

bench-check: ## Check benchmarks compile
	@printf '$(CYAN)Checking benchmarks...$(NC)\n'
	@$(CARGO) bench --all-features --no-run
	@printf '$(GREEN)Benchmarks compile!$(NC)\n'

# =============================================================================
# MSRV
# =============================================================================

# `|| true` is scoped to the install: the MSRV toolchain is usually already
# present, and the check below is what must fail.
msrv: ## Check minimum supported Rust version
	@printf '$(CYAN)Checking MSRV (%s)...$(NC)\n' '$(RUST_MSRV)'
	@rustup toolchain install $(RUST_MSRV) --profile minimal >/dev/null 2>&1 || true
	@rustup run $(RUST_MSRV) cargo check --workspace --all-features
	@printf '$(GREEN)MSRV check passed!$(NC)\n'

# =============================================================================
# Docker
# =============================================================================

docker-build: ## Build Docker image
	@printf '$(CYAN)Building Docker image...$(NC)\n'
	@docker build \
		--build-arg BINARY_NAME=$(BINARY_NAME) \
		--build-arg BINARY_PACKAGE=$(BINARY_PACKAGE) \
		--build-arg SBOM_MANIFEST_PATH=$(SBOM_MANIFEST_PATH) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@printf '$(GREEN)Docker image built: %s:%s$(NC)\n' '$(DOCKER_IMAGE)' '$(DOCKER_TAG)'

docker-push: ## Push Docker image to registry
	@printf '$(CYAN)Pushing Docker image...$(NC)\n'
	@docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	@printf '$(GREEN)Image pushed!$(NC)\n'

# =============================================================================
# CI Targets
# =============================================================================

pre-commit: fmt-check lint test-doc docs-check ## Pre-commit checks
	@printf '$(GREEN)Pre-commit checks passed!$(NC)\n'

ci: fmt-check lint test test-features docs security ## Full CI checks
	@printf '$(GREEN)All CI checks passed!$(NC)\n'

ci-quick: fmt-check lint check ## Quick CI checks
	@printf '$(GREEN)Quick CI checks passed!$(NC)\n'

all: ci coverage bench-check ## Full validation suite
	@printf '$(GREEN)Full validation passed!$(NC)\n'

# =============================================================================
# Release
# =============================================================================

# `|| exit 1` is load-bearing: a for loop exits with the status of its last
# iteration, so without it a failing sdk dry-run followed by a passing cli
# dry-run would report success. Publish order (sdk before cli) matters.
release-check: ## Check release readiness
	@printf '$(CYAN)Checking release readiness...$(NC)\n'
	@$(MAKE) ci
	@$(MAKE) msrv
	@for pkg in $(PUBLISH_PACKAGES); do \
		printf '$(BLUE)  cargo publish --dry-run -p %s$(NC)\n' "$$pkg"; \
		cargo publish --dry-run -p "$$pkg" || exit 1; \
	done
	@printf '$(GREEN)Ready for release!$(NC)\n'

# =============================================================================
# Cleanup
# =============================================================================

clean: ## Clean build artifacts
	@printf '$(CYAN)Cleaning...$(NC)\n'
	@$(CARGO) clean
	@rm -f lcov.info
	@printf '$(GREEN)Clean completed!$(NC)\n'

# =============================================================================
# Aliases
# =============================================================================

f: fmt        ## Alias: format
l: lint       ## Alias: lint
t: test       ## Alias: test
b: build      ## Alias: build
c: check      ## Alias: check
