#!/usr/bin/env python3
"""Check the small set of documentation facts that commonly drift."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROOT_README = ROOT / "README.md"
SDK_README = ROOT / "crates/threatflux-atlassian-sdk/README.md"
CLI_README = ROOT / "crates/threatflux-atlassian-cli/README.md"
ACTION_README = ROOT / "crates/threatflux-atlassian-action/README.md"
USAGE = ROOT / "docs/USAGE.md"
CONFIG_REFERENCE = ROOT / "docs/SDK_CONFIGURATION.md"
QUICKSTART = ROOT / "crates/threatflux-atlassian-sdk/examples/quickstart.rs"
RETIREMENT_NOTICE = (
    "https://support.atlassian.com/atlassian-rovo-mcp-server/docs/"
    "configuring-oauth-2-1/"
)
SDK_CRATE_URL = "https://crates.io/crates/threatflux-atlassian-sdk"
CLI_CRATE_URL = "https://crates.io/crates/threatflux-atlassian-cli"
RELEASES_URL = "https://github.com/ThreatFlux/threatflux-atlassian/releases"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def marked_block(text: str, name: str, path: Path, errors: list[str]) -> str:
    start = f"<!-- BEGIN {name} -->"
    end = f"<!-- END {name} -->"
    if text.count(start) != 1 or text.count(end) != 1:
        errors.append(f"{path.relative_to(ROOT)} must contain one {name} marker pair")
        return ""
    return text.split(start, 1)[1].split(end, 1)[0].strip()


def fenced_rust(block: str, path: Path, errors: list[str]) -> str:
    match = re.fullmatch(r"```rust\n(?P<source>.*)\n```", block, re.DOTALL)
    if match is None:
        errors.append(
            f"{path.relative_to(ROOT)} QUICKSTART must be one rust code fence"
        )
        return ""
    return match.group("source").strip()


def check_local_links(paths: list[Path], errors: list[str]) -> None:
    link_pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    for path in paths:
        for raw_target in link_pattern.findall(read(path)):
            target = raw_target.strip().strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                errors.append(
                    f"{path.relative_to(ROOT)} links to missing local path: {raw_target}"
                )


def load_metadata() -> tuple[dict, str]:
    root_manifest = tomllib.loads(read(ROOT / "Cargo.toml"))
    sdk_manifest = tomllib.loads(
        read(ROOT / "crates/threatflux-atlassian-sdk/Cargo.toml")
    )
    msrv = root_manifest["workspace"]["package"]["rust-version"]
    return sdk_manifest, msrv


def load_docs() -> dict[Path, str]:
    return {
        ROOT_README: read(ROOT_README),
        SDK_README: read(SDK_README),
        CLI_README: read(CLI_README),
        ACTION_README: read(ACTION_README),
        USAGE: read(USAGE),
        CONFIG_REFERENCE: read(CONFIG_REFERENCE),
    }


def check_sections(docs: dict[Path, str], errors: list[str]) -> None:
    required_sections = {
        ROOT_README: [
            "Installation",
            "Quickstart",
            "Features",
            "Security",
            "License",
            "Remote MCP Status",
            "Version and Release Channels",
        ],
        SDK_README: [
            "Features",
            "Installation",
            "Quickstart",
            "Configuration",
            "Feature Flags",
            "Security",
            "License",
            "Legacy Remote MCP",
        ],
    }
    for path, sections in required_sections.items():
        text = docs[path]
        if not text.startswith("# "):
            errors.append(f"{path.relative_to(ROOT)} must start with a title")
        lead_blocks = text.split("\n\n", 2)
        if len(lead_blocks) < 2 or "[![" not in lead_blocks[1]:
            errors.append(
                f"{path.relative_to(ROOT)} must include badges after the title"
            )
        for section in sections:
            if f"## {section}" not in text:
                errors.append(f"{path.relative_to(ROOT)} is missing section: {section}")


def check_msrv(docs: dict[Path, str], msrv: str, errors: list[str]) -> None:
    for path in (ROOT_README, SDK_README, USAGE):
        if msrv not in docs[path]:
            errors.append(
                f"{path.relative_to(ROOT)} must document the workspace MSRV {msrv}"
            )


def check_install_guidance(docs: dict[Path, str], errors: list[str]) -> None:
    required = {
        ROOT_README: [
            "cargo add threatflux-atlassian-sdk",
            "cargo install --locked threatflux-atlassian-cli",
            SDK_CRATE_URL,
            CLI_CRATE_URL,
            RELEASES_URL,
        ],
        SDK_README: ["cargo add threatflux-atlassian-sdk", SDK_CRATE_URL],
        CLI_README: [
            "cargo install --locked threatflux-atlassian-cli",
            CLI_CRATE_URL,
            RELEASES_URL,
        ],
        USAGE: [
            "cargo add threatflux-atlassian-sdk",
            "cargo install --locked threatflux-atlassian-cli",
            SDK_CRATE_URL,
            CLI_CRATE_URL,
            RELEASES_URL,
        ],
    }
    for path, snippets in required.items():
        text = docs[path]
        for snippet in snippets:
            if snippet not in text:
                errors.append(
                    f"{path.relative_to(ROOT)} is missing release-safe guidance: "
                    f"{snippet}"
                )
        if "cargo add threatflux-atlassian-sdk@" in text:
            errors.append(f"{path.relative_to(ROOT)} pins cargo add to a release")
        for line in text.splitlines():
            if "cargo install" in line and "--version" in line:
                errors.append(
                    f"{path.relative_to(ROOT)} pins cargo install to a release"
                )


def check_affiliation(docs: dict[Path, str], errors: list[str]) -> None:
    for path in (ROOT_README, SDK_README, USAGE):
        if not re.search(
            r"not\s+affiliated\s+with,\s+endorsed\s+by,\s+or\s+sponsored\s+by\s+Atlassian",
            docs[path],
        ):
            errors.append(
                f"{path.relative_to(ROOT)} is missing the affiliation disclosure"
            )


def check_remote_guidance(docs: dict[Path, str], errors: list[str]) -> None:
    for path in (ROOT_README, SDK_README, USAGE, CONFIG_REFERENCE):
        text = docs[path]
        if "June 30, 2026" not in text or RETIREMENT_NOTICE not in text:
            errors.append(
                f"{path.relative_to(ROOT)} must link the dated Remote MCP retirement notice"
            )
        if "v0.4.0" in text:
            errors.append(
                f"{path.relative_to(ROOT)} contains the stale v0.4.0 guidance"
            )


def check_quickstarts(docs: dict[Path, str], errors: list[str]) -> None:
    expected_quickstart = read(QUICKSTART).strip()
    for path in (ROOT_README, SDK_README):
        text = docs[path]
        documented = fenced_rust(
            marked_block(text, "QUICKSTART", path, errors), path, errors
        )
        if documented and documented != expected_quickstart:
            errors.append(
                f"{path.relative_to(ROOT)} QUICKSTART differs from "
                f"{QUICKSTART.relative_to(ROOT)}"
            )


def check_features(docs: dict[Path, str], sdk_manifest: dict, errors: list[str]) -> int:
    feature_block = marked_block(docs[SDK_README], "FEATURES", SDK_README, errors)
    documented_features = re.findall(r"^\| `([^`]+)` \|", feature_block, re.MULTILINE)
    manifest_features = list(sdk_manifest["features"])
    if documented_features != manifest_features:
        errors.append(
            "SDK feature table does not match Cargo.toml: "
            f"documented={documented_features}, manifest={manifest_features}"
        )
    return len(manifest_features)


def report(errors: list[str], msrv: str, feature_count: int) -> int:
    if errors:
        print("Documentation contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Documentation contract passed (MSRV {msrv}, {feature_count} feature flags)."
    )
    return 0


def main() -> int:
    errors: list[str] = []
    sdk_manifest, msrv = load_metadata()
    docs = load_docs()

    check_sections(docs, errors)
    check_msrv(docs, msrv, errors)
    check_install_guidance(docs, errors)
    check_affiliation(docs, errors)
    check_remote_guidance(docs, errors)
    check_quickstarts(docs, errors)
    feature_count = check_features(docs, sdk_manifest, errors)
    check_local_links(list(docs), errors)

    return report(errors, msrv, feature_count)


if __name__ == "__main__":
    raise SystemExit(main())
