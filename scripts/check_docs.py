#!/usr/bin/env python3
"""Check the small set of documentation facts that commonly drift.

The environment-variable half of this check exists because the rest of the file
did not have one. Every fact below was verified against the docs while
`JIRA_HOST_POLICY` -- the single variable that decides where credentials may be
sent -- was documented in no table at all, and while two of them still described
`JIRA_VERIFY_SSL=false` as a way to disable certificate verification long after
it had become a hard configuration error. A checker that inspects sections,
links, and feature flags but not the variable names is a gate that cannot see
the contradiction it was installed to prevent.

It closes only half of that: this is a NAME-level gate. It proves every variable
the code reads is documented and nothing documented is dead. It cannot tell that
a correctly-named variable is described as doing the wrong thing, so the stale
`JIRA_VERIFY_SSL=false` prose would still pass. Reviewing a semantic claim about
a variable's behavior is still a human's job.

So the documented `JIRA_*` names are compared against a surface scanned out of
the SDK's own source: every `env::var`/`env::var_os` argument, every credential
base a `{base}_ENCRYPTED` family is derived from, and every suffix in that
family. This is the approach
`crates/threatflux-atlassian-sdk/tests/env_transport_reachability.rs` already
takes, reused here so that a hand-written list cannot go stale in one place
while the other keeps passing. A documented variable the code does not read and
a variable the code reads that no table documents both fail.

Run `--self-test` to exercise the scanner and the comparison against synthetic
inputs. The self-test also runs as part of a normal invocation, so every call
site of this script gets it without a separate step.
"""

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
SECURITY_POLICY = ROOT / "SECURITY.md"
QUICKSTART = ROOT / "crates/threatflux-atlassian-sdk/examples/quickstart.rs"
RETIREMENT_NOTICE = (
    "https://support.atlassian.com/atlassian-rovo-mcp-server/docs/"
    "configuring-oauth-2-1/"
)
SDK_CRATE_URL = "https://crates.io/crates/threatflux-atlassian-sdk"
CLI_CRATE_URL = "https://crates.io/crates/threatflux-atlassian-cli"
RELEASES_URL = "https://github.com/ThreatFlux/threatflux-atlassian/releases"
ISSUE_SEARCH_REFERENCE = (
    "https://developer.atlassian.com/cloud/jira/platform/rest/v2/"
    "api-group-issue-search/"
)
PROJECT_DEPRECATION_NOTICE = (
    "https://developer.atlassian.com/cloud/jira/platform/"
    "deprecation-notice-removal-of-get-filters-and-get-all-projects/"
)

SDK_SRC = ROOT / "crates/threatflux-atlassian-sdk/src"

# The documents whose `<!-- BEGIN ENV_VARS -->` blocks must together account for
# the whole `JIRA_*` surface, and each of which must document all of it that is
# not part of an encrypted-credential family.
#
# The crate READMEs are absent, and nothing else checks them: they carry their
# own tables and are what crates.io and docs.rs render, so a name that drifts
# there drifts on the page most readers see first. Adding ENV_VARS markers to
# them and listing them here is the fix; it is not done yet.
ENV_VAR_DOCS = (ROOT_README, CONFIG_REFERENCE, USAGE)

# `env::var` arguments that are a binding rather than a literal name, each one
# resolved by the credential-base expansion instead: `base` is the credential
# base, the three `_var` bindings are that base plus a suffix, and `variable`
# iterates the encrypted-env-file names, which appear as literals elsewhere.
#
# An argument outside this set means the SDK grew a way to read the environment
# that the expansion does not model, so the scanned surface would be incomplete
# and every comparison below unsound. That fails rather than passing quietly.
RESOLVED_DYNAMIC_ENV_ARGUMENTS = frozenset(
    {"&encrypted_var", "&password_var", "&private_key_var", "base", "variable"}
)

JIRA_ENV_VAR = re.compile(r"JIRA_[A-Z0-9_]*[A-Z0-9]")

# Names the scan must find, or it found nothing and every assertion built on it
# is vacuous. `JIRA_HOST_POLICY` is here by name because its absence from the
# documentation is the defect this check was added for.
REQUIRED_CORE_ENV_VARS = frozenset(
    {"JIRA_URL", "JIRA_USERNAME", "JIRA_API_TOKEN", "JIRA_HOST_POLICY", "JIRA_VERIFY_SSL"}
)
REQUIRED_DERIVED_ENV_VARS = frozenset(
    {"JIRA_API_TOKEN_ENCRYPTED", "JIRA_USERNAME_PRIVATE_KEY_PASSWORD"}
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def rel_label(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return path.name


def marked_block(text: str, name: str, path: Path, errors: list[str]) -> str:
    start = f"<!-- BEGIN {name} -->"
    end = f"<!-- END {name} -->"
    if text.count(start) != 1 or text.count(end) != 1:
        errors.append(f"{path.relative_to(ROOT)} must contain one {name} marker pair")
        return ""
    return text.split(start, 1)[1].split(end, 1)[0].strip()


def marked_blocks(text: str, name: str, path: Path, errors: list[str]) -> list[str]:
    """Every `<!-- BEGIN name -->`/`<!-- END name -->` block, in order.

    `marked_block` insists on exactly one pair because a quickstart or a feature
    table is one thing. An env-var surface is not: a reference page documents the
    plain variables in a table and the encrypted families in fenced blocks under
    a different heading, and forcing those into one region would mean marking
    prose that legitimately names variables the SDK does not read.
    """
    start = f"<!-- BEGIN {name} -->"
    end = f"<!-- END {name} -->"
    opened = text.count(start)
    if opened != text.count(end):
        errors.append(
            f"{rel_label(path)} has {opened} BEGIN {name} markers and "
            f"{text.count(end)} END markers"
        )
        return []

    blocks: list[str] = []
    rest = text
    for _ in range(opened):
        _, _, rest = rest.partition(start)
        block, closed, rest = rest.partition(end)
        if not closed:
            errors.append(f"{rel_label(path)} opens a {name} block that is never closed")
            return []
        if start in block:
            errors.append(f"{rel_label(path)} nests a {name} block inside another")
            return []
        blocks.append(block.strip())
    return blocks


def library_half(text: str) -> str:
    """Everything before the first `#[cfg(test)]`.

    Test code reads the environment too, and the variables it invents are not
    part of the shipped surface.
    """
    return text.replace("\r\n", "\n").split("\n#[cfg(test)]", 1)[0]


def rust_call_arguments(text: str, callee: str) -> list[str]:
    """The argument text of every `callee(` occurrence, up to the first `)`.

    Every call this is pointed at passes plain bindings or string literals, with
    no nested call and no parenthesis inside an argument. A future call that
    breaks that shape yields text that parses as neither a literal nor a declared
    binding, which fails the surface check rather than passing silently.
    """
    arguments: list[str] = []
    rest = text
    while True:
        index = rest.find(callee)
        if index < 0:
            return arguments
        after = rest[index + len(callee) :]
        end = after.find(")")
        arguments.append(after[: len(after) if end < 0 else end].strip())
        rest = after


def rust_string_literal(text: str) -> str | None:
    """The contents of `text` when it is a plain string literal."""
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return None


def scan_env_surface(sources: list[str], errors: list[str]) -> tuple[set[str], set[str]]:
    """The environment surface the SDK's source says it reads.

    Returns `(surface, core)`. `core` is the names read under a literal or used
    as a credential base -- the ones an operator configures directly -- and
    `surface` adds the `{base}_ENCRYPTED`-style families derived from them.
    """
    literals: set[str] = set()
    dynamic: set[str] = set()
    bases: set[str] = set()
    suffixes: set[str] = set()

    for source in sources:
        for callee in ("env::var(", "env::var_os("):
            for argument in rust_call_arguments(source, callee):
                name = rust_string_literal(argument)
                if name is None:
                    dynamic.add(argument)
                else:
                    literals.add(name)

        for callee in (
            "load_required_secret(",
            "load_required_credential(",
            "decrypt_secret_for_base(",
        ):
            for argument in rust_call_arguments(source, callee):
                name = rust_string_literal(argument.split(",", 1)[0].strip())
                if name is not None:
                    bases.add(name)

        for argument in rust_call_arguments(source, "format!("):
            literal = rust_string_literal(argument)
            if literal is not None and literal.startswith("{base}_"):
                suffixes.add(literal[len("{base}_") :])

    unresolved = sorted(dynamic - RESOLVED_DYNAMIC_ENV_ARGUMENTS)
    if unresolved:
        errors.append(
            "the SDK reads the environment through argument(s) this check cannot "
            f"resolve to a name: {', '.join(unresolved)}. Resolve them to the "
            "names they can produce and add them to RESOLVED_DYNAMIC_ENV_ARGUMENTS"
        )

    core = literals | bases
    surface = set(core)
    for base in bases:
        for suffix in suffixes:
            surface.add(f"{base}_{suffix}")
    return surface, core


def sdk_sources(errors: list[str]) -> list[str]:
    if not SDK_SRC.is_dir():
        errors.append(f"{rel_label(SDK_SRC)} is missing; the env-var check would be vacuous")
        return []
    sources = [library_half(read(path)) for path in sorted(SDK_SRC.rglob("*.rs"))]
    if len(sources) <= 5:
        errors.append(
            f"{rel_label(SDK_SRC)} yielded only {len(sources)} source files; "
            "the env-var check would be vacuous"
        )
    return sources


def documented_env_vars(text: str, path: Path, errors: list[str]) -> set[str]:
    names: set[str] = set()
    for block in marked_blocks(text, "ENV_VARS", path, errors):
        names.update(JIRA_ENV_VAR.findall(block))
    return names


def compare_env_var_docs(
    documented: dict[Path, set[str]],
    surface: set[str],
    core: set[str],
    errors: list[str],
) -> None:
    """Both directions of the env-var contract.

    Per document: nothing it names may be unread by the SDK, and it must carry
    every core variable -- an operator reading one page must not have to know
    that the variable deciding where the credential goes is documented on
    another. Across documents: every name the SDK reads must appear somewhere.
    """
    union: set[str] = set()
    for path, names in documented.items():
        if not names:
            errors.append(
                f"{rel_label(path)} has no ENV_VARS block naming a JIRA_ variable; "
                "the environment-variable contract would not cover it"
            )
            continue
        for name in sorted(names - surface):
            errors.append(
                f"{rel_label(path)} documents {name}, which the SDK does not read"
            )
        for name in sorted(core - names):
            errors.append(
                f"{rel_label(path)} omits {name} from its environment-variable table"
            )
        union |= names

    for name in sorted(surface - union):
        errors.append(
            f"the SDK reads {name}, which no environment-variable table documents"
        )


def env_scan_is_sound(surface: set[str], core: set[str], errors: list[str]) -> bool:
    """Whether the scan found enough to make the comparison mean anything.

    A scan that silently found nothing would make every assertion below pass, so
    the names the comparison turns on are required to be in it.
    """
    missing = sorted((REQUIRED_CORE_ENV_VARS - core) | (REQUIRED_DERIVED_ENV_VARS - surface))
    if missing:
        errors.append(
            f"the env-var scan did not find {', '.join(missing)}; it is not "
            "reading the SDK source it thinks it is, so the comparison it feeds "
            "proves nothing"
        )
        return False
    return True


def check_env_vars(docs: dict[Path, str], errors: list[str]) -> int:
    surface, core = scan_env_surface(sdk_sources(errors), errors)
    surface = {name for name in surface if name.startswith("JIRA_")}
    core = {name for name in core if name.startswith("JIRA_")}

    if not env_scan_is_sound(surface, core, errors):
        return len(surface)

    compare_env_var_docs(
        {path: documented_env_vars(docs[path], path, errors) for path in ENV_VAR_DOCS},
        surface,
        core,
        errors,
    )
    return len(surface)


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
        SECURITY_POLICY: read(SECURITY_POLICY),
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
            "Legacy Jira Search and Project Listing",
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


def check_legacy_jira_guidance(docs: dict[Path, str], errors: list[str]) -> None:
    shared_snippets = (
        "/rest/api/2/search",
        "/rest/api/2/search/jql",
        "/rest/api/2/project",
        "/rest/api/2/project/search",
        ISSUE_SEARCH_REFERENCE,
        PROJECT_DEPRECATION_NOTICE,
    )
    for path in (ROOT_README, SDK_README, CLI_README, USAGE):
        for snippet in shared_snippets:
            if snippet not in docs[path]:
                errors.append(
                    f"{path.relative_to(ROOT)} is missing legacy Jira guidance: "
                    f"{snippet}"
                )

    for snippet in (
        "/rest/api/2/search",
        "/rest/api/2/search/jql",
        ISSUE_SEARCH_REFERENCE,
    ):
        if snippet not in docs[ACTION_README]:
            errors.append(
                f"Action README is missing its legacy Jira search caveat: {snippet}"
            )


def check_security_support_policy(docs: dict[Path, str], errors: list[str]) -> None:
    text = docs[SECURITY_POLICY]
    for label in ("Latest published release", "`main`", "Older releases"):
        if label not in text:
            errors.append(f"SECURITY.md is missing release-independent label: {label}")
    if re.search(r"\b\d+\.\d+\.x\b", text):
        errors.append("SECURITY.md pins support to a minor release line")


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


SYNTHETIC = ROOT / "self-test.md"
OTHER_SYNTHETIC = ROOT / "other-self-test.md"


def env_vars_block(*names: str) -> str:
    rows = "\n".join(f"| `{name}` | No | Something. |" for name in names)
    return f"# Doc\n\n<!-- BEGIN ENV_VARS -->\n{rows}\n<!-- END ENV_VARS -->\n"


def self_test() -> int:
    failures: list[str] = []
    cases = 0

    def expect(condition: bool, description: str) -> None:
        nonlocal cases
        cases += 1
        if not condition:
            failures.append(description)

    def errors_for(call) -> list[str]:
        collected: list[str] = []
        call(collected)
        return collected

    # --- the scanner ------------------------------------------------------
    source = (
        'let a = env::var("JIRA_URL");\n'
        'if env::var_os("ENV_FILE_ENCRYPTED").is_some() {}\n'
        'let b = load_required_secret("JIRA_USERNAME")?;\n'
        'let c = format!("{base}_ENCRYPTED");\n'
        "\n#[cfg(test)]\nmod tests {\n"
        '    let hidden = env::var("JIRA_ONLY_IN_TESTS");\n'
        "}\n"
    )
    scanned_errors: list[str] = []
    # `library_half` is applied here exactly as `sdk_sources` applies it, so the
    # test-module case below exercises the composition the real scan uses.
    surface, core = scan_env_surface([library_half(source)], scanned_errors)
    expect(scanned_errors == [], "a well-formed source must scan without complaint")
    expect("JIRA_URL" in core, "a literal env::var argument must reach the core set")
    expect(
        "ENV_FILE_ENCRYPTED" in core,
        "an env::var_os argument must reach the core set",
    )
    expect(
        "JIRA_USERNAME_ENCRYPTED" in surface,
        "a credential base plus a scanned suffix must expand into the surface",
    )
    expect(
        "JIRA_USERNAME_ENCRYPTED" not in core,
        "a derived family member is not a core variable",
    )
    expect(
        "JIRA_ONLY_IN_TESTS" not in surface,
        "a variable read only under #[cfg(test)] is not part of the shipped surface",
    )
    expect(
        scan_env_surface(['env::var("JIRA_URL")'], [])[0] == {"JIRA_URL"},
        "a base-less source expands to its literals alone",
    )
    expect(
        any(
            "RESOLVED_DYNAMIC_ENV_ARGUMENTS" in error
            for error in errors_for(
                lambda errors: scan_env_surface(["env::var(&some_new_binding)"], errors)
            )
        ),
        "an env::var argument that is neither a literal nor a declared binding must fail",
    )
    expect(
        errors_for(lambda errors: scan_env_surface(["env::var(base)"], errors)) == [],
        "a declared dynamic binding must not fail",
    )

    # The real SDK source, so the scan above is not the only thing proven to
    # work. `JIRA_CERT_PATH` is the variable M1 removed: it must not come back
    # into the surface without this check noticing.
    real_errors: list[str] = []
    real_surface, real_core = scan_env_surface(sdk_sources(real_errors), real_errors)
    expect(real_errors == [], f"the SDK source must scan cleanly: {real_errors}")
    expect(
        REQUIRED_CORE_ENV_VARS <= real_core,
        "the SDK scan must find every core variable this check names",
    )
    expect(
        REQUIRED_DERIVED_ENV_VARS <= real_surface,
        "the SDK scan must expand the encrypted credential families",
    )
    expect(
        "JIRA_CERT_PATH" not in real_surface,
        "JIRA_CERT_PATH must not be read from the environment again",
    )

    # --- block extraction -------------------------------------------------
    expect(
        documented_env_vars(env_vars_block("JIRA_URL", "JIRA_TIMEOUT"), SYNTHETIC, [])
        == {"JIRA_URL", "JIRA_TIMEOUT"},
        "a marked table must yield exactly its JIRA_ names",
    )
    expect(
        documented_env_vars(
            "Prose naming `JIRA_CERT_PATH` outside any block.\n", SYNTHETIC, []
        )
        == set(),
        "a name in unmarked prose is not a documented variable",
    )
    expect(
        documented_env_vars(
            "<!-- BEGIN ENV_VARS -->\n`JIRA_URL`\n<!-- END ENV_VARS -->\n"
            "Prose about `JIRA_CERT_PATH`.\n"
            "<!-- BEGIN ENV_VARS -->\nJIRA_USERNAME_ENCRYPTED\n<!-- END ENV_VARS -->\n",
            SYNTHETIC,
            [],
        )
        == {"JIRA_URL", "JIRA_USERNAME_ENCRYPTED"},
        "two blocks in one document must both be read, and the prose between them skipped",
    )
    expect(
        any(
            "END markers" in error
            for error in errors_for(
                lambda errors: marked_blocks(
                    "<!-- BEGIN ENV_VARS -->\n`JIRA_URL`\n", "ENV_VARS", SYNTHETIC, errors
                )
            )
        ),
        "an unbalanced marker pair must fail",
    )
    expect(
        any(
            "nests" in error
            for error in errors_for(
                lambda errors: marked_blocks(
                    "<!-- BEGIN ENV_VARS -->\n<!-- BEGIN ENV_VARS -->\n"
                    "<!-- END ENV_VARS -->\n<!-- END ENV_VARS -->\n",
                    "ENV_VARS",
                    SYNTHETIC,
                    errors,
                )
            )
        ),
        "a nested marker pair must fail",
    )
    expect(
        marked_blocks("no markers here", "ENV_VARS", SYNTHETIC, []) == [],
        "a document without markers yields no blocks and no crash",
    )

    # --- the comparison, both directions ----------------------------------
    full = {"JIRA_URL", "JIRA_HOST_POLICY", "JIRA_API_TOKEN", "JIRA_API_TOKEN_ENCRYPTED"}
    center = {"JIRA_URL", "JIRA_HOST_POLICY", "JIRA_API_TOKEN"}

    expect(
        errors_for(
            lambda errors: compare_env_var_docs(
                {SYNTHETIC: center, OTHER_SYNTHETIC: full}, full, center, errors
            )
        )
        == [],
        "documents that between them cover the surface must pass",
    )

    # Direction one: documented, but the code does not read it. This is the
    # `JIRA_VERIFY_SSL=false`/`JIRA_CERT_PATH` shape -- a variable that survived
    # in a table after the code stopped honoring it.
    undocumented_direction = errors_for(
        lambda errors: compare_env_var_docs(
            {SYNTHETIC: full | {"JIRA_CERT_PATH"}}, full, center, errors
        )
    )
    expect(
        any(
            "documents JIRA_CERT_PATH, which the SDK does not read" in error
            for error in undocumented_direction
        ),
        "a documented variable the SDK does not read must fail",
    )

    # Direction two: read, but no table names it. This is the `JIRA_HOST_POLICY`
    # shape -- the defect that shipped.
    unread_direction = errors_for(
        lambda errors: compare_env_var_docs(
            {SYNTHETIC: full - {"JIRA_HOST_POLICY"}}, full, center, errors
        )
    )
    expect(
        any(
            "the SDK reads JIRA_HOST_POLICY, which no environment-variable table "
            "documents" in error
            for error in unread_direction
        ),
        "a variable the SDK reads that no table documents must fail",
    )
    expect(
        any(
            "omits JIRA_HOST_POLICY" in error for error in unread_direction
        ),
        "the document that dropped a core variable must be named",
    )

    # A core variable documented on one page only is still a failure on the
    # other: an operator reads one page, not the union of them.
    expect(
        any(
            "omits JIRA_HOST_POLICY" in error
            for error in errors_for(
                lambda errors: compare_env_var_docs(
                    {SYNTHETIC: full, OTHER_SYNTHETIC: full - {"JIRA_HOST_POLICY"}},
                    full,
                    center,
                    errors,
                )
            )
        ),
        "a core variable must appear in every env-var document, not just one",
    )
    expect(
        any(
            "no ENV_VARS block" in error
            for error in errors_for(
                lambda errors: compare_env_var_docs(
                    {SYNTHETIC: set()}, full, center, errors
                )
            )
        ),
        "a document with no marked block at all must fail",
    )
    expect(
        errors_for(
            lambda errors: compare_env_var_docs(
                {SYNTHETIC: full}, full, center, errors
            )
        )
        == [],
        "a document covering the whole surface on its own must pass",
    )

    # --- the vacuity guard ------------------------------------------------
    expect(
        env_scan_is_sound(real_surface, real_core, []),
        "the real SDK scan must satisfy the vacuity guard",
    )
    expect(
        not env_scan_is_sound(set(), set(), []),
        "a scan that found nothing must not be treated as sound",
    )
    expect(
        any(
            "proves nothing" in error
            for error in errors_for(
                lambda errors: env_scan_is_sound(
                    real_surface - {"JIRA_API_TOKEN_ENCRYPTED"}, real_core, errors
                )
            )
        ),
        "a scan that lost a required derived name must fail loudly",
    )
    expect(
        any(
            "JIRA_HOST_POLICY" in error
            for error in errors_for(
                lambda errors: env_scan_is_sound(
                    real_surface, real_core - {"JIRA_HOST_POLICY"}, errors
                )
            )
        ),
        "the vacuity failure must name the variable it could not find",
    )

    if failures:
        print("Documentation self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Documentation self-test passed ({cases} cases).")
    return 0


def report(errors: list[str], msrv: str, feature_count: int, env_count: int) -> int:
    if errors:
        print("Documentation contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Documentation contract passed (MSRV {msrv}, {feature_count} feature "
        f"flags, {env_count} JIRA_ environment variables)."
    )
    return 0


def main(argv: list[str]) -> int:
    # The self-test runs on every invocation rather than behind a separate make
    # step, because this script is called from three places (the Makefile and two
    # workflows) and a gate that is only armed in one of them is not a gate.
    status = self_test()
    if status != 0 or "--self-test" in argv:
        return status

    errors: list[str] = []
    sdk_manifest, msrv = load_metadata()
    docs = load_docs()

    check_sections(docs, errors)
    check_msrv(docs, msrv, errors)
    check_install_guidance(docs, errors)
    check_affiliation(docs, errors)
    check_remote_guidance(docs, errors)
    check_legacy_jira_guidance(docs, errors)
    check_security_support_policy(docs, errors)
    check_quickstarts(docs, errors)
    feature_count = check_features(docs, sdk_manifest, errors)
    env_count = check_env_vars(docs, errors)
    check_local_links(list(docs), errors)

    return report(errors, msrv, feature_count, env_count)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
