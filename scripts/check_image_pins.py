#!/usr/bin/env python3
"""Check that every container base image is pinned to a digest.

A tag is a mutable pointer: `rust:1.97.1-bookworm` resolves to whatever the
registry serves today, so a rebuild of an old commit is not the build that
commit was reviewed as. Every `FROM` that names a real image therefore carries
`@sha256:<digest>`.

The human-readable tag stays in front of the digest. Dependabot's Docker
ecosystem is declared at `/` in `.github/dependabot.yml`, and it bumps
`image:tag@sha256:...` while a bare `image@sha256:...` gives it nothing to
resolve a newer version from -- the pin would freeze instead of being
maintained.

Run `--self-test` to exercise the detectors against synthetic inputs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SKIPPED_DIRS = {"target", ".git"}

# dependabot-core's Docker fetcher matches any filename containing "dockerfile"
# case-insensitively, so discovery uses the same rule: a Dockerfile Dependabot
# would bump is a Dockerfile this checker must cover.
DOCKERFILE_NAME_FRAGMENT = "dockerfile"

# `FROM [--flag=value ...] <reference> [AS <stage>]`.
FROM_RE = re.compile(
    r"^\s*FROM\s+(?P<flags>(?:--\S+\s+)*)(?P<reference>\S+)"
    r"(?:\s+AS\s+(?P<stage>\S+))?\s*$",
    re.IGNORECASE,
)

# Lowercase hex only: registries emit lowercase, and an uppercase copy of the
# same digest is not the same string to any tool that compares pins textually.
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# A build-arg reference (`FROM ${BASE_IMAGE}`) cannot be checked here and can be
# overridden at build time, which is the pin defeated by another name.
INTERPOLATION_RE = re.compile(r"[$]")

# `scratch` is the empty base; there is no image to pin.
UNPINNABLE_REFERENCES = {"scratch"}


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Return `(line number, joined line)` pairs with comments and escapes resolved."""
    lines: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not pending and raw.lstrip().startswith("#"):
            continue
        stripped = raw.rstrip()
        if not pending:
            start = number
        if stripped.endswith("\\"):
            pending.append(stripped[:-1])
            continue
        pending.append(stripped)
        lines.append((start, " ".join(part.strip() for part in pending).strip()))
        pending = []
    if pending:
        lines.append((start, " ".join(part.strip() for part in pending).strip()))
    return lines


def parse_from_lines(text: str) -> list[tuple[int, str, str | None]]:
    """Return `(line number, reference, stage name)` for every FROM in `text`."""
    parsed = []
    for number, line in logical_lines(text):
        match = FROM_RE.match(line)
        if match is None:
            continue
        parsed.append((number, match.group("reference"), match.group("stage")))
    return parsed


def check_reference(reference: str, known_stages: set[str]) -> str | None:
    """Return why `reference` is not an acceptable base, or None if it is."""
    # Stage names are matched case-insensitively by the builder, so the checker
    # has to be case-insensitive too or a `FROM Rust-Base` would be read as an
    # unpinned image from a registry.
    if reference.lower() in known_stages:
        return None
    if reference.lower() in UNPINNABLE_REFERENCES:
        return None
    if INTERPOLATION_RE.search(reference):
        return (
            f"base image {reference} is a build-arg reference; it cannot be "
            "digest-pinned and is overridable at build time"
        )
    if "@" not in reference:
        return f"base image {reference} is tag-pinned only; add @sha256:<digest>"

    name, _, digest = reference.partition("@")
    if not DIGEST_RE.match(digest):
        return (
            f"base image {reference} has a malformed digest; expected "
            "@sha256: followed by 64 lowercase hex characters"
        )
    if ":" not in name.rsplit("/", 1)[-1]:
        return (
            f"base image {reference} drops the tag; keep image:tag@sha256:... "
            "so Dependabot can still bump it"
        )
    return None


def check_dockerfile(path: Path, errors: list[str]) -> int:
    relative = path.relative_to(ROOT)
    from_lines = parse_from_lines(path.read_text(encoding="utf-8"))
    if not from_lines:
        errors.append(f"{relative} contains no FROM line")
        return 0

    known_stages: set[str] = set()
    for number, reference, stage in from_lines:
        problem = check_reference(reference, known_stages)
        if problem is not None:
            errors.append(f"{relative}:{number} {problem}")
        if stage is not None:
            known_stages.add(stage.lower())
    return len(from_lines)


def find_dockerfiles() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and DOCKERFILE_NAME_FRAGMENT in path.name.lower()
        and not SKIPPED_DIRS.intersection(path.relative_to(ROOT).parts)
    )


def self_test() -> int:
    failures: list[str] = []
    cases = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal cases
        cases += 1
        if not condition:
            failures.append(label)

    digest = "sha256:" + "0" * 64
    stages = {"rust-base"}

    expect(
        check_reference(f"rust:1.97.1-bookworm@{digest}", set()) is None,
        "tag plus digest must be accepted",
    )
    expect(
        check_reference("rust:1.97.1-bookworm", set()) is not None,
        "a tag-only base must be rejected",
    )
    expect(
        check_reference("rust", set()) is not None,
        "a bare image name must be rejected",
    )
    expect(
        "Dependabot" in (check_reference(f"rust@{digest}", set()) or ""),
        "a digest without a tag must be rejected for Dependabot's sake",
    )
    expect(
        check_reference(f"ghcr.io/org/img:v1@{digest}", set()) is None,
        "a registry-qualified reference must be accepted",
    )
    expect(
        check_reference(f"localhost:5000/img@{digest}", set()) is not None,
        "a registry port must not be mistaken for a tag",
    )
    expect(
        check_reference("rust:1.97.1@sha256:abc", set()) is not None,
        "a truncated digest must be rejected",
    )
    expect(
        check_reference("rust:1.97.1@sha256:" + "A" * 64, set()) is not None,
        "an uppercase digest must be rejected",
    )
    expect(
        check_reference("rust:1.97.1@md5:" + "0" * 32, set()) is not None,
        "a non-sha256 digest must be rejected",
    )
    expect(
        check_reference("rust-base", stages) is None,
        "a previously declared stage is not an image",
    )
    expect(
        check_reference("Rust-Base", stages) is None,
        "stage references are case-insensitive",
    )
    expect(
        check_reference("runtime", stages) is not None,
        "a stage that has not been declared yet is not a stage",
    )
    expect(
        check_reference("scratch", set()) is None,
        "scratch has no image to pin",
    )
    expect(
        check_reference("${BASE_IMAGE}", set()) is not None,
        "a build-arg base must be rejected",
    )
    expect(
        parse_from_lines(f"FROM rust:1@{digest} AS builder")
        == [(1, f"rust:1@{digest}", "builder")],
        "a FROM with a stage must parse",
    )
    expect(
        parse_from_lines(f"FROM --platform=$BUILDPLATFORM rust:1@{digest} AS b")
        == [(1, f"rust:1@{digest}", "b")],
        "a --platform flag must not be read as the reference",
    )
    expect(
        parse_from_lines(f"from rust:1@{digest} as builder")
        == [(1, f"rust:1@{digest}", "builder")],
        "FROM and AS are case-insensitive",
    )
    expect(
        parse_from_lines("# FROM rust:1.97.1-bookworm") == [],
        "a commented-out FROM must be ignored",
    )
    expect(
        parse_from_lines("RUN echo FROM rust:1.97.1-bookworm") == [],
        "FROM inside another instruction must be ignored",
    )
    expect(
        parse_from_lines("FROM \\\n  rust:1.97.1-bookworm") == [
            (1, "rust:1.97.1-bookworm", None)
        ],
        "a continued FROM must be joined before matching",
    )
    expect(
        [number for number, _, _ in parse_from_lines("\n\nFROM scratch")] == [3],
        "line numbers must point at the FROM line",
    )

    body = f"FROM rust:1@{digest} AS base\nFROM base AS builder\nFROM debian:x\n"
    replayed: list[str] = []
    known: set[str] = set()
    for _, reference, stage in parse_from_lines(body):
        if check_reference(reference, known) is not None:
            replayed.append(reference)
        if stage is not None:
            known.add(stage.lower())
    expect(
        replayed == ["debian:x"],
        "only the unpinned base of a multi-stage file must be reported",
    )

    if failures:
        print("Image pin self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Image pin self-test passed ({cases} cases).")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    errors: list[str] = []
    dockerfiles = find_dockerfiles()
    if not dockerfiles:
        errors.append("no Dockerfile was found; the checker would pass vacuously")

    total_from_lines = 0
    for path in dockerfiles:
        total_from_lines += check_dockerfile(path, errors)

    if errors:
        print("Image pin contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Image pin contract passed ({len(dockerfiles)} Dockerfiles, "
        f"{total_from_lines} FROM lines)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
