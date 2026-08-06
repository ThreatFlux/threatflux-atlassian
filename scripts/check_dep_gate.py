#!/usr/bin/env python3
"""Check that the SDK's `encrypted-env` feature really gates its dependencies.

`encrypted-env` exists so that a consumer who does not use
`JIRA_API_TOKEN_ENCRYPTED`/`ENV_FILE_ENCRYPTED` does not link `fluxencrypt`, and
through it `rsa` 0.9.x -- RUSTSEC-2023-0071, which has no patched release. A
cfg-gate in `config.rs` alone does not achieve that: the dependency has to be
`optional` in the manifest, and every crate that must not link it has to reach
the SDK through an entry that does not enable the feature.

That second half is the fragile one. `default-features = false` on the
*workspace* dependency entry is what keeps the Action off `full`; the same words
written on the Action's own entry are dropped by cargo with a warning, and the
gate silently stops holding. This checker reads the resolved graph rather than
the manifests, so it fails whichever way the gate is broken.

The positive cases are not decoration. Without them a typo in a package name, or
a `cargo tree` invocation that quietly resolves nothing, would make every
negative case pass and the checker would assert nothing at all.

Dev-dependencies are excluded: they reach neither a published consumer nor the
Action's container image. Build-dependencies are included, because they do run
during that build.

Run `--self-test` to exercise the decision logic against synthetic graphs.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# The crate under the advisory, and the crate that is its only route into this
# workspace. Both are named so a future fluxencrypt release that swaps its RSA
# backend cannot make the check pass while the gate itself has rotted.
GATED_CRATES = ("fluxencrypt", "rsa")

# `(label, cargo tree selector args, crates that must be absent, crates that
# must be present)`.
CASES: tuple[tuple[str, list[str], tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "SDK without encrypted-env",
        [
            "-p",
            "threatflux-atlassian-sdk",
            "--no-default-features",
            "--features",
            "direct,remote",
        ],
        GATED_CRATES,
        (),
    ),
    (
        "SDK with encrypted-env",
        [
            "-p",
            "threatflux-atlassian-sdk",
            "--no-default-features",
            "--features",
            "encrypted-env",
        ],
        (),
        GATED_CRATES,
    ),
    (
        "Action (workspace default-features = false)",
        ["-p", "threatflux-atlassian-action"],
        GATED_CRATES,
        ("threatflux-atlassian-sdk",),
    ),
    # The CLI is the deliberate exception: it encrypts credentials itself, so it
    # keeps its own `fluxencrypt` dependency and takes the SDK's `full` set. It
    # is asserted rather than skipped, so that "the CLI still ships rsa" stays a
    # recorded decision instead of an oversight nobody notices.
    (
        "CLI (opts into full)",
        ["-p", "threatflux-atlassian-cli"],
        (),
        GATED_CRATES,
    ),
)


def parse_packages(output: str) -> set[str]:
    """Return the package names in `cargo tree --prefix none --format {p}` output."""
    names = set()
    for line in output.splitlines():
        fields = line.split()
        if fields:
            names.add(fields[0])
    return names


def evaluate(
    label: str,
    packages: set[str],
    forbidden: tuple[str, ...],
    required: tuple[str, ...],
) -> list[str]:
    """Return the problems with one resolved graph."""
    problems = []
    for crate in forbidden:
        if crate in packages:
            problems.append(f"{label}: {crate} is in the graph and must not be")
    for crate in required:
        if crate not in packages:
            problems.append(
                f"{label}: {crate} is absent, so this case proves nothing; "
                "the selector or the manifest changed"
            )
    return problems


def resolve(selector: list[str]) -> set[str]:
    result = subprocess.run(
        [
            "cargo",
            "tree",
            *selector,
            "--edges",
            "normal,build",
            "--target",
            "all",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return parse_packages(result.stdout)


def self_test() -> int:
    failures: list[str] = []
    cases = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal cases
        cases += 1
        if not condition:
            failures.append(label)

    tree = (
        "threatflux-atlassian-sdk v0.4.2 (/repo/crates/threatflux-atlassian-sdk)\n"
        "fluxencrypt v0.7.3\n"
        "rsa v0.9.10\n"
        "serde v1.0.228\n"
    )
    expect(
        parse_packages(tree)
        == {"threatflux-atlassian-sdk", "fluxencrypt", "rsa", "serde"},
        "a path suffix and a version must not become part of the name",
    )
    expect(
        parse_packages("") == set(),
        "empty output must parse to no packages",
    )
    expect(
        parse_packages("serde v1.0.228\n\nserde v1.0.228 (*)\n") == {"serde"},
        "blank lines and cargo's (*) repeat marker must not add packages",
    )

    gated = parse_packages(tree)
    clean = parse_packages("threatflux-atlassian-action v0.4.2 (/repo/a)\nserde v1\n")

    expect(
        evaluate("x", clean, GATED_CRATES, ()) == [],
        "a graph without the gated crates must pass a negative case",
    )
    expect(
        len(evaluate("x", gated, GATED_CRATES, ())) == 2,
        "both gated crates must be reported, not just the first",
    )
    expect(
        evaluate("x", gated, (), GATED_CRATES) == [],
        "a graph with the gated crates must pass a positive case",
    )
    expect(
        "proves nothing" in " ".join(evaluate("x", clean, (), GATED_CRATES)),
        "a positive case that finds nothing must fail loudly, not vacuously",
    )
    expect(
        evaluate("x", set(), GATED_CRATES, ("threatflux-atlassian-sdk",)) != [],
        "an empty graph must never satisfy a case",
    )

    if failures:
        print("Dependency gate self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Dependency gate self-test passed ({cases} cases).")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    errors: list[str] = []
    for label, selector, forbidden, required in CASES:
        try:
            packages = resolve(selector)
        except subprocess.CalledProcessError as err:
            errors.append(f"{label}: cargo tree failed: {err.stderr.strip()}")
            continue
        errors.extend(evaluate(label, packages, forbidden, required))

    if errors:
        print("Dependency gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Dependency gate passed ({len(CASES)} resolved graphs).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
