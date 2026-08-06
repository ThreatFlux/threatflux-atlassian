#!/usr/bin/env python3
"""Check that the workspace Clippy configuration is the only Clippy configuration.

A crate-root `#![allow(clippy::...)]` outranks the `-D` flags passed on the
command line, so one reintroduced inner attribute silently makes the strict lint
job vacuous while still reporting success. Levels therefore live in
`[workspace.lints.clippy]`, every member opts in with `[lints] workspace = true`,
and this checker fails the build if either half is bypassed or duplicated.

Levels can also be set from outside the source: `cargo clippy -- -A clippy::all` on a
command line, and `rustflags` in a repo-local `.cargo/config.toml`, which needs no
command line at all because cargo picks it up on every invocation made from the repo.
Both routes are scanned as well.

The scans fail closed. An inner attribute whose body cannot be delimited, and a cargo
config that is not valid TOML, are reported rather than skipped: a guard that cannot
parse an input cannot rule out that the input is the blanket allow it exists to catch.

Two suppression routes are deliberately NOT covered, because catching either one needs
the module graph resolved -- following `mod` declarations to the files they name --
which is out of proportion for this guard:

  * `#[allow(clippy::all)] pub mod inner;` -- an OUTER attribute on a module
    declaration suppresses the whole of that module's file, and the attribute sits in
    the parent file where nothing marks it as crate-wide.
  * `#[path = "hidden.inc"] pub mod inner;` -- the module body lives in a file whose
    suffix is not `.rs`, so `check_sources` never opens it.

Both are real. Reviewers, not this script, are the backstop for them.

Run `--self-test` to exercise the detectors against synthetic inputs.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Group entries need a negative priority so the individual `allow` entries that
# follow them win; a group left at the default priority would be applied last and
# silently re-deny everything the table means to permit.
REQUIRED_GROUPS = ("all", "pedantic", "nursery", "cargo")

# Inner attributes are only legal at the top of a crate or a module block, so any
# hit is at least module-wide -- the exact failure mode this guard exists for.
# Nothing anchors `#!` to the start of a line: `pub mod m { #![allow(clippy::all)] }`
# and a crate root opening with `/* c */ #![allow(clippy::all)]` both put a real one
# mid-line. What keeps a quoted or commented-out attribute from matching is that
# comments and literals are blanked out first (see `_mask_comments_and_literals`).
# Only the attribute's opening is matched here: the body is delimited by balancing
# brackets rather than by a pattern, because a `cfg_attr` predicate may nest
# parentheses (`not(test)`, `all(...)`, `any(...)`) and any paren-free pattern for
# it would let those spellings through while still compiling.
# All three tokens are separated by `\s*`, because rustc lexes comments and newlines
# as trivia between any pair of them: `#  !  [allow(clippy::all)]`, a `#` with the
# `![...]` on the next line, and `#/*x*/![allow(clippy::all)]` all compile and all
# silence the lint. The last one is the dangerous one -- rustfmt normalizes the other
# two but leaves it alone, so it passes `cargo fmt --check` as well. Requiring `#` and
# `!` to be adjacent let every one of them through without even a warning. Comments
# need no pattern of their own here because the search runs on the masked text, where
# `/*x*/` has already become spaces (see `_mask_comments_and_literals`).
INNER_ATTRIBUTE_RE = re.compile(r"#\s*!\s*\[")
# The body is whitespace-stripped before these run, because rustc accepts
# `clippy :: all` and `allow ( ... )` as readily as the canonical spelling.
SUPPRESSION_RE = re.compile(r"(?<![\w:])(?:allow|expect)\(")
BLANKET_TARGET_RE = re.compile(r"\bclippy::|(?<![\w:])warnings\b")
WHITESPACE_RE = re.compile(r"\s+")

OPENING_BRACKETS = "([{"
CLOSING_BRACKETS = ")]}"

# Longest excerpt of an offending attribute quoted back in an error message.
EXCERPT_LIMIT = 120

# Cargo emits the [lints] flags first and appends whatever follows `cargo clippy --`
# after them, so a trailing group deny outranks an individual allow in the manifest:
# `-D clippy::nursery` on the command line re-denies derive_partial_eq_without_eq.
# A second copy of the levels is therefore not belt-and-braces, it is a silent
# override -- and one that can drift away from the manifest unnoticed.
# The lint is separated from its flag by `[\s=]*` because rustc accepts all three
# spellings: a separate argument (`-A clippy::all`), glued to the short flag
# (`-Aclippy::all`) and joined to the long flag with `=` (`--allow=clippy::all`).
# Requiring whitespace matched only the first two, so the `=` form suppressed silently.
# `--cap-lints` is matched whatever its argument: it caps every lint at the given
# level, so it overrides the manifest without ever naming a Clippy lint to match on.
COMMAND_LINE_LINT_RE = re.compile(
    r"-(?:-warn|-allow|-deny|-forbid|[WADF])[\s=]*clippy::[\w:]+"
    r"|--cap-lints[\s=]*[\w-]+"
)

# `[env]` spells it `RUSTFLAGS`, `[build]` and `[target.*]` spell it `rustflags`, and
# the doc variants carry lint flags just as well, so the key is matched case-folded.
RUSTFLAG_KEYS = frozenset({"rustflags", "rustdocflags"})

SCANNED_SUFFIXES = (".rs",)
SKIPPED_DIRS = {"target", ".git"}
# `**` also matches zero directories, so the workflow patterns still cover
# `.github/workflows/*.yml` while additionally reaching composite actions nested under
# `.github/actions/*/action.yml`, which run cargo just as CI jobs do.
COMMAND_LINE_SOURCES = ("Makefile", ".github/**/*.yml", ".github/**/*.yaml")
# Cargo reads these on every invocation made from the repo, CI included, so they set
# lint levels with no command line to inspect. `config` without the suffix is the
# pre-1.39 spelling, which cargo still honours.
CARGO_CONFIG_SOURCES = (".cargo/config.toml", ".cargo/config")


def _end_of_line_comment(source: str, index: int) -> int:
    """Return the index of the newline ending the `//` comment at `index`."""
    end = source.find("\n", index)
    return len(source) if end < 0 else end


def _end_of_block_comment(source: str, index: int) -> int:
    """Return the index just past the `*/` closing the comment at `index`.

    Rust nests block comments, so the closing marker is found by counting depth
    rather than by searching for the first `*/`.
    """
    depth = 0
    while index < len(source):
        if source.startswith("/*", index):
            depth += 1
            index += 2
        elif source.startswith("*/", index):
            depth -= 1
            index += 2
            if depth == 0:
                return index
        else:
            index += 1
    return len(source)


def _end_of_string(source: str, index: int) -> int:
    """Return the index just past the string literal opening at `index`."""
    index += 1
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index + 1
        index += 1
    return len(source)


def _end_of_raw_string(source: str, index: int) -> int | None:
    """Return the index just past the raw string opening at the `r` at `index`.

    `None` means the `r` is an ordinary identifier character. Raw strings have no
    escapes and end only at a quote followed by as many `#` as the opener carried,
    so `r#"a"]b"#` holds a quote and a bracket that a plain-string scanner reads as
    real source -- which is how a raw string could bracket-unbalance an attribute
    and get it waved through.
    """
    start = index
    if start and source[start - 1] in "bc":  # `br"..."`, `cr"..."`
        start -= 1
    if start and (source[start - 1].isalnum() or source[start - 1] == "_"):
        return None
    cursor = index + 1
    while cursor < len(source) and source[cursor] == "#":
        cursor += 1
    if not source.startswith('"', cursor):
        return None
    terminator = '"' + "#" * (cursor - index - 1)
    end = source.find(terminator, cursor + 1)
    return len(source) if end < 0 else end + len(terminator)


def _end_of_char_literal(source: str, index: int) -> int:
    """Return the index just past the char literal opening at `index`.

    A `'` is ambiguous in Rust: `'a'` is a literal but `'a` is a lifetime or a loop
    label. Only a real literal is consumed -- reading a lifetime as an unterminated
    literal would blank the rest of the file, and with it any attribute below.
    """
    if source.startswith("\\", index + 1):
        cursor = index + 3  # the quote, the backslash, and the escape's first char
        while cursor < len(source) and source[cursor] not in "'\n":
            cursor += 1
        return cursor + 1 if source.startswith("'", cursor) else index + 1
    if source.startswith("'", index + 2):
        return index + 3
    return index + 1


def _comment_or_literal_end(source: str, index: int) -> int | None:
    """Return the index just past the comment or literal starting at `index`.

    `None` means `index` is ordinary source text. An unterminated comment or
    literal runs to the end of the file, matching what rustc would make of it.
    """
    if source.startswith("//", index):
        return _end_of_line_comment(source, index)
    if source.startswith("/*", index):
        return _end_of_block_comment(source, index)
    char = source[index]
    if char == "r":
        return _end_of_raw_string(source, index)
    if char == '"':
        return _end_of_string(source, index)
    if char == "'":
        return _end_of_char_literal(source, index)
    return None


def _mask_comments_and_literals(source: str) -> str:
    """Return `source` with every comment and literal blanked out.

    Masked characters become spaces (newlines are kept), so the result has the
    same length as the input and indices carry back to the original text. Blanking
    instead of skipping is what lets the `#!` search run anywhere on a line: a
    bracket, a quote or a whole `#![allow(clippy::all)]` that lives inside a
    string, a raw string, a char literal or a comment is no longer there to be
    mistaken for source, and neither is a quote inside a block comment that used
    to send the string scanner to the end of the file.
    """
    masked = list(source)
    index = 0
    while index < len(source):
        end = _comment_or_literal_end(source, index)
        if end is None:
            index += 1
            continue
        for position in range(index, min(end, len(masked))):
            if masked[position] != "\n":
                masked[position] = " "
        index = max(end, index + 1)
    return "".join(masked)


def _bracketed_end(source: str, open_index: int) -> int | None:
    """Return the index of the `]` closing the bracket at `open_index`.

    `source` must be masked: comments and literals are blanked before this runs,
    so only real delimiters are counted and an arbitrarily nested `cfg_attr`
    predicate stays inside the body. `None` means the body could not be delimited,
    which callers must treat as a finding rather than as a licence to skip the
    attribute.
    """
    depth = 0
    index = open_index
    while index < len(source):
        char = source[index]
        if char in OPENING_BRACKETS:
            depth += 1
        elif char in CLOSING_BRACKETS:
            depth -= 1
            if depth <= 0:
                return index if char == "]" else None
        index += 1
    return None


def _excerpt(source: str, start: int, end: int | None) -> str:
    """Return a one-line, length-capped quote of `source[start:end]` for a message."""
    stop = len(source) if end is None else end + 1
    excerpt = " ".join(source[start:stop].split())
    if len(excerpt) > EXCERPT_LIMIT:
        excerpt = excerpt[: EXCERPT_LIMIT - 3] + "..."
    return excerpt


def scan_inner_attributes(source: str) -> tuple[list[str], list[str]]:
    """Return `(suppressions, unparsable)` for the inner attributes in `source`.

    The whole bracketed body is inspected, so it makes no difference how many
    `cfg_attr` layers or cfg predicates a suppression is buried under, and the
    body is whitespace-stripped first so `clippy :: all` reads as `clippy::all`.
    An attribute whose body cannot be delimited goes in `unparsable`: the guard
    fails closed, because an attribute it cannot parse may well be the blanket
    allow it exists to catch.
    """
    masked = _mask_comments_and_literals(source)
    suppressions: list[str] = []
    unparsable: list[str] = []
    position = 0
    while (match := INNER_ATTRIBUTE_RE.search(masked, position)) is not None:
        open_index = match.end() - 1
        end_index = _bracketed_end(masked, open_index)
        if end_index is None:
            unparsable.append(_excerpt(source, match.start(), None))
            position = match.end()
            continue
        body = WHITESPACE_RE.sub("", masked[open_index + 1 : end_index])
        if SUPPRESSION_RE.search(body) and BLANKET_TARGET_RE.search(body):
            suppressions.append(_excerpt(source, match.start(), end_index))
        position = end_index + 1
    return suppressions, unparsable


def find_crate_level_allows(source: str) -> list[str]:
    """Return the inner attributes in `source` that suppress Clippy lints."""
    return scan_inner_attributes(source)[0]


def find_unparsable_inner_attributes(source: str) -> list[str]:
    """Return the inner attributes in `source` whose body could not be delimited."""
    return scan_inner_attributes(source)[1]


def find_command_line_lint_flags(text: str) -> list[str]:
    """Return command-line Clippy lint level flags found in `text`.

    Matching runs per line so that the `[\\s=]*` separator cannot bridge a flag on one
    line to a lint path on the next. `#` starts a comment in every format scanned here
    -- Makefile, YAML and TOML alike -- so commented-out flags are skipped.
    """
    return [
        match.group(0)
        for line in text.splitlines()
        if not line.lstrip().startswith("#")
        for match in COMMAND_LINE_LINT_RE.finditer(line)
    ]


def _flag_strings(value: object) -> list[str]:
    """Return the flag strings held by one `rustflags`-like config value.

    Cargo accepts a list (`["-A", "clippy::all"]`), a single space-separated string,
    and -- under `[env]` -- a table whose `value` key holds the string.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, dict):
        inner = value.get("value")
        return [inner] if isinstance(inner, str) else []
    return []


def collect_rustflags(table: dict) -> list[str]:
    """Return every `rustflags`-like setting anywhere in a parsed cargo config.

    The whole document is walked rather than a fixed list of table names, so
    `[build]`, every `[target.<triple>]` and `[target.'cfg(...)']`, and the `[env]`
    table are all covered by one rule and a newly invented spelling cannot slip past
    by living under a table the guard was never told about.
    """
    found: list[str] = []
    for key, value in table.items():
        if key.lower() in RUSTFLAG_KEYS:
            found.extend(_flag_strings(value))
        elif isinstance(value, dict):
            found.extend(collect_rustflags(value))
    return found


def find_cargo_config_lint_flags(text: str) -> tuple[list[str], bool]:
    """Return `(flags, unparsable)` for the text of a cargo config file.

    Two passes, because neither alone is enough. The raw-text pass catches flags that
    appear verbatim, including ones in `[alias]` entries that no `rustflags` key would
    reveal. The parsed pass joins each `rustflags` list into a single line, which is
    the only way to see `["-A", "clippy::all"]`: split across two array elements, the
    flag and its lint never sit next to each other in the file's text.

    `unparsable` is set when the file is not valid TOML. That fails closed, like the
    source scan: rustflags that cannot be read cannot be ruled out as a suppression.
    """
    flags = find_command_line_lint_flags(text)
    unparsable = False
    try:
        config = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        unparsable = True
    else:
        joined = " ".join(collect_rustflags(config))
        flags.extend(match.group(0) for match in COMMAND_LINE_LINT_RE.finditer(joined))
    # A flag spelled `-Aclippy::all` is found by both passes; report it once.
    return list(dict.fromkeys(flags)), unparsable


def check_workspace_table(manifest: dict, errors: list[str]) -> None:
    lints = manifest.get("workspace", {}).get("lints", {}).get("clippy")
    if not lints:
        errors.append("Cargo.toml is missing the [workspace.lints.clippy] table")
        return

    for group in REQUIRED_GROUPS:
        entry = lints.get(group)
        if not isinstance(entry, dict):
            errors.append(
                f"[workspace.lints.clippy] {group} must be "
                '{ level = "deny", priority = -1 }'
            )
            continue
        if entry.get("level") != "deny":
            errors.append(f"[workspace.lints.clippy] {group} must be denied")
        if entry.get("priority", 0) >= 0:
            errors.append(
                f"[workspace.lints.clippy] {group} needs priority = -1 so the "
                "individual allows below it take effect"
            )

    if lints.get("derive_partial_eq_without_eq") != "allow":
        errors.append(
            "[workspace.lints.clippy] derive_partial_eq_without_eq must stay "
            "allowed: deriving Eq across the public types is a forward "
            "commitment that cannot be withdrawn without a breaking change"
        )


def check_member_opt_in(manifest: dict, errors: list[str]) -> list[Path]:
    members = manifest.get("workspace", {}).get("members", [])
    if not members:
        errors.append("Cargo.toml declares no workspace members")
    manifests = []
    for member in members:
        path = ROOT / member / "Cargo.toml"
        manifests.append(path)
        if not path.is_file():
            errors.append(f"{member}/Cargo.toml does not exist")
            continue
        with path.open("rb") as handle:
            member_manifest = tomllib.load(handle)
        if member_manifest.get("lints", {}).get("workspace") is not True:
            errors.append(
                f"{member}/Cargo.toml must declare [lints] workspace = true so "
                "the shared Clippy levels apply to all of its targets"
            )
    return manifests


def check_sources(errors: list[str]) -> int:
    scanned = 0
    for path in sorted(ROOT.rglob("*")):
        if path.suffix not in SCANNED_SUFFIXES or not path.is_file():
            continue
        if SKIPPED_DIRS.intersection(path.relative_to(ROOT).parts):
            continue
        scanned += 1
        relative = path.relative_to(ROOT)
        suppressions, unparsable = scan_inner_attributes(
            path.read_text(encoding="utf-8")
        )
        for attribute in suppressions:
            errors.append(
                f"{relative} reintroduces a crate-level Clippy "
                f"suppression ({attribute}); it would override the -D flags CI "
                "passes. Narrow it to the item it applies to, with a reason."
            )
        for attribute in unparsable:
            errors.append(
                f"{relative} has an inner attribute this checker cannot "
                f"parse ({attribute}): its brackets do not balance, so it cannot "
                "be ruled out as a crate-level Clippy suppression. Simplify it."
            )
    return scanned


def check_no_duplicate_flags(errors: list[str]) -> None:
    paths = sorted(
        {path for pattern in COMMAND_LINE_SOURCES for path in ROOT.glob(pattern)}
    )
    for path in paths:
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        for flag in find_command_line_lint_flags(path.read_text(encoding="utf-8")):
            errors.append(
                f"{relative} sets a Clippy lint level on the command line "
                f"({flag}); levels belong in [workspace.lints.clippy] only"
            )


def check_cargo_config(errors: list[str]) -> int:
    """Report Clippy lint levels set by a repo-local cargo config.

    This is the one route that needs no command line and no source edit: cargo reads
    `.cargo/config.toml` on every invocation made from the repo, so a single
    `rustflags = ["-Aclippy::all"]` there silences the workspace levels for developers
    and CI alike while every other check in this script still reports success.
    """
    paths = sorted(
        {
            path
            for name in CARGO_CONFIG_SOURCES
            for path in ROOT.rglob(name)
            if path.is_file()
            and not SKIPPED_DIRS.intersection(path.relative_to(ROOT).parts)
        }
    )
    for path in paths:
        relative = path.relative_to(ROOT)
        flags, unparsable = find_cargo_config_lint_flags(
            path.read_text(encoding="utf-8")
        )
        for flag in flags:
            errors.append(
                f"{relative} sets a Clippy lint level ({flag}); it would apply to "
                "every cargo invocation made from this repo, CI included, without "
                "appearing on any command line. Levels belong in "
                "[workspace.lints.clippy] only"
            )
        if unparsable:
            errors.append(
                f"{relative} is not valid TOML, so its rustflags cannot be ruled "
                "out as a Clippy suppression. Fix it or remove it"
            )
    return len(paths)


def self_test() -> int:
    failures: list[str] = []
    cases = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal cases
        cases += 1
        if not condition:
            failures.append(label)

    def expect_suppression(source: str, label: str) -> None:
        """The source holds exactly one suppression, and it parsed cleanly."""
        expect(
            len(find_crate_level_allows(source)) == 1
            and find_unparsable_inner_attributes(source) == [],
            label,
        )

    def expect_ignored(source: str, label: str) -> None:
        """The source holds nothing to report: no suppression, nothing unparsable."""
        expect(
            find_crate_level_allows(source) == []
            and find_unparsable_inner_attributes(source) == [],
            label,
        )

    def expect_unparsable(source: str, label: str) -> None:
        """The body could not be delimited, so the guard reports it rather than skip."""
        expect(
            len(find_unparsable_inner_attributes(source)) == 1
            and find_crate_level_allows(source) == [],
            label,
        )

    expect_suppression(
        "#![allow(clippy::all)]",
        "blanket crate allow must be detected",
    )
    expect_suppression(
        "#![allow(clippy::all, clippy::pedantic)]",
        "multi-lint crate allow must be detected",
    )
    expect_suppression(
        "#! [ allow ( clippy::pedantic ) ]",
        "whitespace inside the attribute must not hide it",
    )
    # rustc reads `clippy :: all` as `clippy::all`, so the body is whitespace-
    # stripped before the target is matched; a literal `clippy::` match missed this.
    expect_suppression(
        "#![allow(clippy :: all)]",
        "whitespace inside the lint path must not hide it",
    )
    # rustc lexes comments and newlines as trivia between `#`, `!` and `[`, so every
    # spelling below compiles and silences the lint crate-wide. Requiring `#!` to be
    # adjacent reported nothing at all for them -- not even "unparsable". The block
    # comment form is the worst of the three: rustfmt normalizes the other two, so
    # `cargo fmt --check` would have caught them, but it leaves this one alone.
    expect_suppression(
        "#/*x*/![allow(clippy::all)]",
        "a block comment between # and ! must not hide a crate allow",
    )
    expect_suppression(
        "#  !  [allow(clippy::all)]",
        "whitespace between #, ! and [ must not hide a crate allow",
    )
    expect_suppression(
        "#\n![allow(clippy::all)]",
        "a newline between # and ! must not hide a crate allow",
    )
    expect_suppression(
        "#/*a*/!/*b*/[allow(clippy::all)]",
        "comments on both sides of ! must not hide a crate allow",
    )
    expect_suppression(
        "# // c\n![allow(clippy::all)]",
        "a line comment between # and ! must not hide a crate allow",
    )
    expect_suppression(
        "pub mod m { #/*x*/![allow(clippy::all)] }",
        "a split # ! inside a module block must not hide a module-wide allow",
    )
    expect_suppression(
        "#![cfg_attr(test, allow(clippy::nursery))]",
        "cfg_attr-wrapped crate allow must be detected",
    )
    # A cfg predicate may nest parentheses. Matching the predicate with a
    # paren-free pattern let `not(...)`, `all(...)` and `any(...)` through, so the
    # attribute has to be delimited by balancing brackets instead.
    expect_suppression(
        "#![cfg_attr(not(test), allow(clippy::all))]",
        "cfg_attr(not(...)) must not hide a crate allow",
    )
    expect_suppression(
        '#![cfg_attr(all(test, feature = "x"), allow(clippy::nursery))]',
        "cfg_attr(all(...)) must not hide a crate allow",
    )
    expect_suppression(
        "#![cfg_attr(any(test, doc), expect(warnings))]",
        "cfg_attr(any(...)) must not hide a crate expect",
    )
    expect_suppression(
        "#![cfg_attr(not(any(test, doc)), allow(clippy::pedantic))]",
        "deeply nested cfg predicates must not hide a crate allow",
    )
    expect_suppression(
        "#![allow(\n    clippy::all,\n)]",
        "an attribute split across lines must be detected",
    )
    expect_suppression(
        '#![cfg_attr(feature = "a]b)c", allow(clippy::all))]',
        "brackets inside a string literal must not truncate the attribute",
    )
    # Raw strings take no escapes and end only at `"` plus as many `#` as they
    # opened with. Reading one as a plain string leaves the brackets unbalanced,
    # which used to mean the attribute was skipped without a word.
    expect_suppression(
        '#![cfg_attr(not(feature = r#"a"]b"#), allow(clippy::all))]',
        "a raw string holding a quote and a bracket must not truncate the attribute",
    )
    expect_suppression(
        '#![cfg_attr(not(feature = r#"a\\"]b"#), allow(clippy::all))]',
        "a backslash in a raw string does not escape its quote",
    )
    expect_suppression(
        '#![cfg_attr(not(feature = r##"a"#]b"##), allow(clippy::all))]',
        "a multi-hash raw string must not truncate the attribute",
    )
    expect_suppression(
        "#![allow(clippy::all /* \" */)]",
        "a quote inside a block comment must not truncate the attribute",
    )
    # Inner attributes are legal wherever a block opens, not only at line start.
    expect_suppression(
        "pub mod m { #![allow(clippy::all)] }",
        "a single-line module block must not hide a module-wide allow",
    )
    expect_suppression(
        "/* lead */ #![allow(clippy::all)]",
        "a leading block comment must not hide a crate-wide allow",
    )
    expect_suppression(
        "const Q: char = '\"';\npub mod m { #![allow(clippy::all)] }",
        "a quote in a char literal must not blank out the rest of the file",
    )
    expect_suppression(
        "pub fn f<'a>(s: &'a str) -> &'a str { s }\n"
        "pub mod m { #![allow(clippy::all)] }",
        "lifetimes must not be read as char literals",
    )
    expect_suppression(
        "#![allow(warnings)]",
        "blanket warnings allow must be detected",
    )
    expect_suppression(
        "#![expect(clippy::pedantic)]",
        "crate-level expect must be detected",
    )
    # Failing closed: a body the checker cannot delimit may be the blanket allow
    # this guard exists to catch, so it is reported instead of silently skipped.
    expect_unparsable(
        "#![allow(clippy::all)",
        "an unterminated attribute must be reported, not skipped",
    )
    expect_unparsable(
        "#![warn(missing_docs)",
        "an unterminated attribute is reported whatever it appears to say",
    )
    expect_unparsable(
        "#![allow(clippy::all)}",
        "an attribute closed by the wrong delimiter must be reported",
    )
    expect_ignored(
        "#![warn(missing_docs)]",
        "crate-level warn must be left alone",
    )
    expect_ignored(
        "#![allow(dead_code)]",
        "non-Clippy crate allow must be left alone",
    )
    expect_ignored(
        "#[allow(clippy::too_many_lines)]\nfn f() {}",
        "item-level allow is the sanctioned escape hatch",
    )
    expect_ignored(
        "#![deny(clippy::allow_attributes)]",
        "a lint whose name merely starts with `allow` must be left alone",
    )
    expect_ignored(
        "#![cfg_attr(not(test), deny(warnings))]",
        "a cfg_attr that tightens levels must be left alone",
    )
    expect_ignored(
        '#![cfg_attr(feature = "allow(clippy::all)", deny(warnings))]',
        "a suppression named inside a string is not a suppression",
    )
    expect_ignored(
        'let s = "#![allow(clippy::all)] in a string";',
        "an attribute inside a string literal is not an inner attribute",
    )
    expect_ignored(
        'let s = r#"#![allow(clippy::all)]"#;',
        "an attribute inside a raw string is not an inner attribute",
    )
    expect_ignored(
        "//! #![allow(clippy::all)]\n//! is documentation",
        "an attribute quoted in a doc comment is not an inner attribute",
    )
    expect_ignored(
        "// #![allow(clippy::all)]\nfn f() {}",
        "an attribute commented out with // is not an inner attribute",
    )
    expect_ignored(
        "/* #![allow(clippy::all)] */\nfn f() {}",
        "an attribute inside a block comment is not an inner attribute",
    )
    expect_ignored(
        "/* /* nested */ #![allow(clippy::all)] */\nfn f() {}",
        "nested block comments must be balanced before the search",
    )
    # Widening the separator to `\s*` must not turn an outer attribute into an inner
    # one. It cannot: in real Rust a `#` is only ever followed by `[` or `!`, so the
    # two cases below leave non-whitespace between the `#` and any later `!`.
    expect_ignored(
        "#[allow(clippy::all)]\nmacro_rules! m {\n    () => {};\n}",
        "an outer allow followed by a macro bang is still an outer attribute",
    )
    expect_ignored(
        "pub fn f() {\n    let r#type = vec![1];\n}",
        "a raw identifier's # must not pair with a later macro bang",
    )
    expect(
        find_command_line_lint_flags("cargo clippy -- -D clippy::pedantic") ==
        ["-D clippy::pedantic"],
        "command-line deny must be detected",
    )
    expect(
        find_command_line_lint_flags("cargo clippy -- -A clippy::cargo") ==
        ["-A clippy::cargo"],
        "command-line allow must be detected",
    )
    # rustc joins a long flag to its lint with `=` just as readily as with a space.
    # Requiring whitespace missed the `=` spelling, which suppresses just as fully.
    expect(
        find_command_line_lint_flags("cargo clippy -- --allow=clippy::all") ==
        ["--allow=clippy::all"],
        "the = spelling of a long allow flag must be detected",
    )
    expect(
        find_command_line_lint_flags("cargo clippy -- --deny=clippy::pedantic") ==
        ["--deny=clippy::pedantic"],
        "the = spelling of a long deny flag must be detected",
    )
    expect(
        find_command_line_lint_flags("cargo clippy -- -Aclippy::all") ==
        ["-Aclippy::all"],
        "a short flag glued to its lint must be detected",
    )
    # `--cap-lints` names no lint, so nothing in the old pattern could match it, yet
    # it caps every lint at the given level and neuters the whole [lints] table.
    expect(
        find_command_line_lint_flags("cargo clippy -- --cap-lints allow") ==
        ["--cap-lints allow"],
        "--cap-lints caps every lint and must be detected",
    )
    expect(
        find_command_line_lint_flags("cargo clippy -- --cap-lints=warn") ==
        ["--cap-lints=warn"],
        "the = spelling of --cap-lints must be detected",
    )
    expect(
        find_command_line_lint_flags("cargo clippy -- -D warnings") == [],
        "-D warnings is a rustc level, not a Clippy lint level",
    )
    expect(
        find_command_line_lint_flags("# -D clippy::pedantic") == [],
        "commented-out flags must be ignored",
    )
    # This one is in the repo's own Makefile: widening the separator must not make
    # `--allow-dirty` read as an allow flag.
    expect(
        find_command_line_lint_flags("cargo clippy --fix --allow-dirty --allow-staged")
        == [],
        "--allow-dirty is not a lint level flag",
    )
    expect(
        find_command_line_lint_flags("-A clippy::all\n-D clippy::pedantic") ==
        ["-A clippy::all", "-D clippy::pedantic"],
        "the separator must not bridge a flag to a lint path on the next line",
    )

    def expect_config(text: str, flags: list[str], label: str) -> None:
        """The cargo config yields exactly `flags`, and it parsed cleanly."""
        found, unparsable = find_cargo_config_lint_flags(text)
        expect(found == flags and not unparsable, label)

    # A repo-local cargo config needs no command line at all: cargo applies it to
    # every invocation made from the repo, so this silenced the lints for CI too
    # while sitting in the one file the guard never opened.
    expect_config(
        '[build]\nrustflags = ["-Aclippy::all"]\n',
        ["-Aclippy::all"],
        "a build.rustflags allow must be detected",
    )
    # Split across two array elements the flag and its lint are never adjacent in the
    # file's text, so only the parsed pass can see this one.
    expect_config(
        '[build]\nrustflags = ["-A", "clippy::all"]\n',
        ["-A clippy::all"],
        "a rustflags allow split across array elements must be detected",
    )
    expect_config(
        '[build]\nrustflags = "-Aclippy::all"\n',
        ["-Aclippy::all"],
        "the space-separated string form of rustflags must be detected",
    )
    expect_config(
        "[target.'cfg(all())']\nrustflags = [\"--allow=clippy::pedantic\"]\n",
        ["--allow=clippy::pedantic"],
        "a target-specific rustflags allow must be detected",
    )
    expect_config(
        '[env]\nRUSTFLAGS = { value = "-Aclippy::all", force = true }\n',
        ["-Aclippy::all"],
        "an [env] RUSTFLAGS allow must be detected",
    )
    expect_config(
        '[build]\nrustdocflags = ["-Aclippy::all"]\n',
        ["-Aclippy::all"],
        "rustdocflags carries lint levels too and must be scanned",
    )
    expect_config(
        '[build]\nrustflags = ["--cap-lints", "allow"]\n',
        ["--cap-lints allow"],
        "--cap-lints in rustflags must be detected",
    )
    # Only the raw-text pass can see this: no rustflags key is involved.
    expect_config(
        '[alias]\nlint = "clippy -- -A clippy::all"\n',
        ["-A clippy::all"],
        "a cargo alias hiding an allow must be detected",
    )
    expect_config(
        '[build]\nrustflags = ["-Dclippy::nursery"]\n',
        ["-Dclippy::nursery"],
        "a second copy of a deny is an override too and must be detected",
    )
    expect_config(
        '[build]\nrustflags = ["-Aclippy::all"]\n',
        ["-Aclippy::all"],
        "a flag both passes find must be reported once, not twice",
    )
    expect_config(
        '[build]\nrustflags = ["-D", "warnings"]\n',
        [],
        "-D warnings in rustflags is a rustc level, not a Clippy lint level",
    )
    expect_config(
        '[build]\ntarget = "x86_64-unknown-linux-gnu"\n',
        [],
        "a cargo config that sets no lint level must be left alone",
    )
    expect_config(
        '# rustflags = ["-Aclippy::all"]\n[build]\ntarget = "x"\n',
        [],
        "a commented-out rustflags line must be left alone",
    )
    # Failing closed again: rustflags that cannot be read cannot be ruled out.
    expect(
        find_cargo_config_lint_flags("[build\nrustflags = ") == ([], True),
        "a cargo config that is not valid TOML must be reported",
    )

    if failures:
        print("Lint configuration self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Lint configuration self-test passed ({cases} cases).")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    errors: list[str] = []
    with (ROOT / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)

    check_workspace_table(manifest, errors)
    members = check_member_opt_in(manifest, errors)
    scanned = check_sources(errors)
    check_no_duplicate_flags(errors)
    configs = check_cargo_config(errors)

    if errors:
        print("Lint configuration contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Lint configuration contract passed ({len(members)} members, "
        f"{scanned} source files, {configs} cargo configs)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
