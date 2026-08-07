#!/usr/bin/env python3
"""Check that the two advisory-ignore lists agree, and that there is no third.

`cargo audit` reads `.cargo/audit.toml`. `cargo deny` does not -- it reads its
own `[advisories] ignore` in `deny.toml`. Consolidating the `--ignore` flags that
used to sit in the Makefile and twice in `security.yml` into `.cargo/audit.toml`
therefore leaves two configuration files, not one, and an advisory dropped from
one of them keeps being suppressed by the other with no signal that the two have
diverged.

So the invariant is not "one list" but "two lists that are the same list", plus
"no `--ignore RUSTSEC-...` on any command line" -- because a flag beats a config
file and would reintroduce exactly the divergence this replaced. Both halves are
checked here.

Run `--self-test` to exercise the parsers and the comparison against synthetic
inputs.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT_CONFIG = ROOT / ".cargo/audit.toml"
DENY_CONFIG = ROOT / "deny.toml"

# Every file that may invoke cargo-audit or cargo-deny. A `--ignore` flag in any
# of them is a third source of truth that no config-file comparison can see.
COMMAND_SITES = (
    ROOT / "Makefile",
    *sorted((ROOT / ".github/workflows").glob("*.yml")),
)

IGNORE_FLAG_RE = re.compile(r"--ignore[= ]\s*(RUSTSEC-\d{4}-\d{4})")


def parse_audit_ignores(text: str) -> set[str]:
    """Return `[advisories] ignore` from a cargo-audit config."""
    return set(tomllib.loads(text).get("advisories", {}).get("ignore", []))


def parse_deny_ignores(text: str) -> set[str]:
    """Return `[advisories] ignore` from a cargo-deny config.

    cargo-deny accepts either a bare id or a table carrying a `reason`, and the
    two forms mean the same thing; a parser that handled only strings would read
    a documented ignore as no ignore at all and report a false divergence.
    """
    entries = tomllib.loads(text).get("advisories", {}).get("ignore", [])
    ids = set()
    for entry in entries:
        ids.add(entry["id"] if isinstance(entry, dict) else entry)
    return ids


def find_ignore_flags(text: str) -> list[tuple[int, str]]:
    """Return `(line number, advisory id)` for every `--ignore RUSTSEC-...`.

    Per occurrence rather than per file: `security.yml` carried the same flag on
    two separate lines, and a deduplicated report would send a reader to fix one
    of them and leave the other.
    """
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        for advisory in IGNORE_FLAG_RE.findall(line):
            found.append((number, advisory))
    return found


def compare(audit: set[str], deny: set[str]) -> list[str]:
    problems = []
    for advisory in sorted(audit - deny):
        problems.append(
            f"{advisory} is ignored in .cargo/audit.toml but not in deny.toml, "
            "so cargo-deny will still fail on it"
        )
    for advisory in sorted(deny - audit):
        problems.append(
            f"{advisory} is ignored in deny.toml but not in .cargo/audit.toml, "
            "so cargo-audit will still fail on it"
        )
    return problems


def self_test() -> int:
    failures: list[str] = []
    cases = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal cases
        cases += 1
        if not condition:
            failures.append(label)

    expect(
        parse_audit_ignores('[advisories]\nignore = ["RUSTSEC-2023-0071"]\n')
        == {"RUSTSEC-2023-0071"},
        "a cargo-audit ignore list must parse",
    )
    expect(
        parse_audit_ignores("[database]\nfetch = true\n") == set(),
        "a config with no advisories section must parse as no ignores",
    )
    expect(
        parse_deny_ignores('[advisories]\nignore = ["RUSTSEC-2023-0071"]\n')
        == {"RUSTSEC-2023-0071"},
        "a bare cargo-deny id must parse",
    )
    expect(
        parse_deny_ignores(
            '[advisories]\nignore = [{ id = "RUSTSEC-2023-0071", reason = "x" }]\n'
        )
        == {"RUSTSEC-2023-0071"},
        "a cargo-deny ignore table must parse to its id",
    )
    expect(
        parse_deny_ignores(
            '[advisories]\nignore = ["RUSTSEC-2020-0001",'
            ' { id = "RUSTSEC-2023-0071" }]\n'
        )
        == {"RUSTSEC-2020-0001", "RUSTSEC-2023-0071"},
        "the two cargo-deny forms must be readable side by side",
    )

    expect(
        compare({"RUSTSEC-2023-0071"}, {"RUSTSEC-2023-0071"}) == [],
        "identical lists must compare clean",
    )
    expect(
        len(compare({"RUSTSEC-2023-0071"}, set())) == 1,
        "an entry missing from deny.toml must be reported",
    )
    expect(
        "cargo-audit will still fail" in " ".join(compare(set(), {"RUSTSEC-2023-0071"})),
        "an entry missing from audit.toml must name the tool that breaks",
    )
    expect(
        len(compare({"RUSTSEC-2020-0001"}, {"RUSTSEC-2023-0071"})) == 2,
        "a disjoint pair must be reported in both directions",
    )
    expect(
        compare(set(), set()) == [],
        "two empty lists agree",
    )

    expect(
        find_ignore_flags("cargo audit --ignore RUSTSEC-2023-0071")
        == [(1, "RUSTSEC-2023-0071")],
        "a space-separated ignore flag must be found",
    )
    expect(
        find_ignore_flags("cargo audit --ignore=RUSTSEC-2023-0071")
        == [(1, "RUSTSEC-2023-0071")],
        "an equals-separated ignore flag must be found",
    )
    expect(
        find_ignore_flags("cargo audit --json > audit-report.json") == [],
        "an unrelated flag must not be reported",
    )
    expect(
        find_ignore_flags("# do not add --ignore RUSTSEC-2023-0071 here")
        == [(1, "RUSTSEC-2023-0071")],
        "a commented-out flag is still a second source of truth in the making",
    )
    expect(
        find_ignore_flags(
            "cargo audit --ignore RUSTSEC-2023-0071\n"
            "cargo audit --ignore RUSTSEC-2023-0071 --json\n"
        )
        == [(1, "RUSTSEC-2023-0071"), (2, "RUSTSEC-2023-0071")],
        "the same flag on two lines must be reported twice, with line numbers",
    )

    if failures:
        print("Advisory ignore self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Advisory ignore self-test passed ({cases} cases).")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    errors: list[str] = []

    for path in (AUDIT_CONFIG, DENY_CONFIG):
        if not path.is_file():
            errors.append(f"{path.relative_to(ROOT)} is missing")
    if errors:
        print("Advisory ignore contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    audit = parse_audit_ignores(AUDIT_CONFIG.read_text(encoding="utf-8"))
    deny = parse_deny_ignores(DENY_CONFIG.read_text(encoding="utf-8"))
    errors.extend(compare(audit, deny))

    for path in COMMAND_SITES:
        if not path.is_file():
            continue
        for number, advisory in find_ignore_flags(path.read_text(encoding="utf-8")):
            errors.append(
                f"{path.relative_to(ROOT)}:{number} passes --ignore {advisory} on a "
                "command line; a flag outranks the config files, so the entry "
                "belongs in .cargo/audit.toml and deny.toml instead"
            )

    if errors:
        print("Advisory ignore contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Advisory ignore contract passed ({len(audit)} advisories, "
        f"{len(COMMAND_SITES)} command sites clean)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
