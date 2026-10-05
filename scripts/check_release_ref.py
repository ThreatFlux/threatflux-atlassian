#!/usr/bin/env python3
"""Resolve a release source to an immutable commit in the repository's main history.

Run from the trusted workflow checkout, before checking out a requested release
source. Manual inputs cannot authorize a new release lineage. A future maintained
release branch requires a reviewed change to this policy.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

TRUSTED_LINEAGE = "refs/remotes/origin/main"
COMMIT_PATTERN = re.compile(r"[0-9a-fA-F]{40}")
# A Git hook exports these for its own repository. Every command here supplies
# an explicit repository cwd, so inheriting them can redirect even `git init`
# into the caller's repository instead of a temporary fixture. This is the set
# documented by `git rev-parse --local-env-vars`, plus worktree/discovery knobs.
GIT_REPOSITORY_ENV = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS", "GIT_DIR", "GIT_GRAFT_FILE", "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE", "GIT_INTERNAL_SUPER_PREFIX", "GIT_NAMESPACE",
    "GIT_NO_REPLACE_OBJECTS", "GIT_OBJECT_DIRECTORY", "GIT_PREFIX",
    "GIT_REPLACE_REF_BASE", "GIT_SHALLOW_FILE", "GIT_WORK_TREE",
    "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
}


class ReleaseRefError(ValueError):
    """The requested source has not passed the release trust boundary."""


def git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {
        key: value for key, value in os.environ.items()
        if key not in GIT_REPOSITORY_ENV and not key.startswith("GIT_CONFIG_")
    }
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def commit_at(repository: Path, reference: str) -> str | None:
    result = git(repository, "rev-parse", "--verify", "--end-of-options", f"{reference}^{{commit}}")
    if result.returncode:
        return None
    revision = result.stdout.strip()
    if not COMMIT_PATTERN.fullmatch(revision):
        raise ReleaseRefError("Git did not resolve an immutable 40-character commit")
    return revision.lower()


def resolve_release_revision(repository: Path, requested: str) -> str:
    trusted_tip = commit_at(repository, TRUSTED_LINEAGE)
    if trusted_tip is None:
        raise ReleaseRefError("Release validation requires fetched origin/main history")
    if not requested or requested.startswith("-") or requested != requested.strip():
        raise ReleaseRefError("Release source must be a repository branch, tag or full commit ID")

    if COMMIT_PATTERN.fullmatch(requested):
        references = [requested.lower()]
    else:
        # Never resolve PR refs, another remote, revision expressions or paths.
        # Prefixing names also keeps Git from interpreting them as options.
        if requested.startswith("refs/heads/"):
            references = ["refs/remotes/origin/" + requested.removeprefix("refs/heads/")]
        elif requested.startswith("refs/tags/"):
            references = [requested]
        elif requested.startswith("refs/"):
            raise ReleaseRefError("Only repository branch and tag namespaces are allowed")
        elif requested.startswith("origin/"):
            references = ["refs/remotes/" + requested]
        else:
            references = ["refs/remotes/origin/" + requested, "refs/tags/" + requested]
        if any(git(repository, "check-ref-format", reference).returncode for reference in references):
            raise ReleaseRefError("Release source is not a valid branch or tag name")

    revisions = {revision for ref in references if (revision := commit_at(repository, ref)) is not None}
    if len(revisions) != 1:
        raise ReleaseRefError("Release source is missing or ambiguous; use an explicit branch or tag")
    revision = revisions.pop()
    # Pin both endpoints to objects from this fetched snapshot. Branch movement
    # after validation cannot change the commit consumed by downstream jobs.
    ancestry = git(repository, "merge-base", "--is-ancestor", revision, trusted_tip)
    if ancestry.returncode:
        raise ReleaseRefError("Release source must belong to origin/main history; unmerged sources are rejected")
    return revision


class ReleaseRefTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="threatflux-release-ref-")
        self.addCleanup(self.directory.cleanup)
        self.repository = Path(self.directory.name)
        self.run_git("init", "--initial-branch=main")
        self.run_git("commit", "--allow-empty", "-m", "trusted initial commit")
        self.old = self.run_git("rev-parse", "HEAD")
        self.run_git("tag", "v0.5.1", self.old)
        self.run_git("tag", "-a", "v0.5.2", "-m", "annotated trusted tag", self.old)
        self.run_git("commit", "--allow-empty", "-m", "trusted main update")
        self.current = self.run_git("rev-parse", "HEAD")
        self.run_git("update-ref", TRUSTED_LINEAGE, self.current)
        self.run_git("checkout", "-b", "unmerged", self.old)
        self.run_git("commit", "--allow-empty", "-m", "untrusted unmerged change")
        self.unmerged = self.run_git("rev-parse", "HEAD")
        self.run_git("update-ref", "refs/remotes/origin/unmerged", self.unmerged)
        self.run_git("update-ref", "refs/remotes/fork/topic", self.unmerged)
        self.run_git("update-ref", "refs/pull/104/head", self.unmerged)
        self.run_git("tag", "unmerged-tag", self.unmerged)

    def run_git(self, *arguments: str) -> str:
        result = git(
            self.repository,
            "-c", "user.name=Release guard fixture",
            "-c", "user.email=release-guard@example.invalid",
            "-c", "commit.gpgsign=false",
            "-c", "tag.gpgsign=false",
            "-c", "core.hooksPath=/dev/null",
            *arguments,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_main_and_released_tags_and_old_commit_are_accepted(self) -> None:
        for reference, expected in [
            ("main", self.current), ("refs/heads/main", self.current), ("origin/main", self.current),
            ("v0.5.1", self.old), ("refs/tags/v0.5.1", self.old), ("v0.5.2", self.old),
            (self.old, self.old), (self.current, self.current),
        ]:
            with self.subTest(reference=reference):
                self.assertEqual(resolve_release_revision(self.repository, reference), expected)

    def test_unmerged_branch_and_tag_and_commit_are_rejected(self) -> None:
        for reference in ["unmerged", "refs/heads/unmerged", "unmerged-tag", self.unmerged]:
            with self.subTest(reference=reference), self.assertRaises(ReleaseRefError):
                resolve_release_revision(self.repository, reference)

    def test_pr_and_fork_and_option_and_revision_expression_are_rejected(self) -> None:
        for reference in [
            "refs/pull/104/head", "refs/remotes/fork/topic", "--help", "-b main", "main~1",
            "HEAD", "main^{commit}", "", " main", "main\n", "missing", "0123456789abcdef" * 2 + "01234567",
        ]:
            with self.subTest(reference=reference), self.assertRaises(ReleaseRefError):
                resolve_release_revision(self.repository, reference)

    def test_missing_main_fails_closed_even_for_a_released_tag(self) -> None:
        self.run_git("update-ref", "-d", TRUSTED_LINEAGE)
        with self.assertRaises(ReleaseRefError):
            resolve_release_revision(self.repository, "v0.5.1")

    def test_ambiguous_branch_and_tag_names_require_explicit_namespace(self) -> None:
        self.run_git("update-ref", "refs/remotes/origin/v0.5.1", self.current)
        with self.assertRaises(ReleaseRefError):
            resolve_release_revision(self.repository, "v0.5.1")
        self.assertEqual(resolve_release_revision(self.repository, "refs/tags/v0.5.1"), self.old)

    def test_hook_environment_cannot_redirect_git_outside_the_fixture(self) -> None:
        # Never point this regression at a real repository: the sentinel does
        # not contain Git metadata, and must remain byte-for-byte untouched.
        from unittest.mock import patch

        with tempfile.TemporaryDirectory(prefix="threatflux-hook-sentinel-") as directory:
            sentinel = Path(directory)
            marker = sentinel / "unchanged"
            marker.write_text("this is not a Git repository", encoding="utf-8")
            hook_environment = {
                "GIT_DIR": str(sentinel),
                "GIT_COMMON_DIR": str(sentinel),
                "GIT_WORK_TREE": str(sentinel),
                "GIT_INDEX_FILE": str(sentinel / "index"),
                "GIT_OBJECT_DIRECTORY": str(sentinel / "objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(sentinel / "alternate"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.bare",
                "GIT_CONFIG_VALUE_0": "true",
            }
            before = {p.name: p.read_bytes() for p in sentinel.iterdir()}
            with patch.dict(os.environ, hook_environment):
                with tempfile.TemporaryDirectory(prefix="threatflux-hook-fixture-") as fixture:
                    result = git(Path(fixture), "init", "--initial-branch=main")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue((Path(fixture) / ".git" / "config").is_file())
                self.assertEqual(resolve_release_revision(self.repository, "main"), self.current)
            self.assertEqual({p.name: p.read_bytes() for p in sentinel.iterdir()}, before)

    def test_a_moving_branch_cannot_change_the_validated_revision(self) -> None:
        validated = resolve_release_revision(self.repository, "main")
        self.run_git("update-ref", TRUSTED_LINEAGE, self.unmerged)
        self.assertEqual(validated, self.current)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReleaseRefTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        revision = resolve_release_revision(Path(__file__).resolve().parent.parent, os.environ.get("REQUESTED_RELEASE_SOURCE", ""))
    except ReleaseRefError as error:
        print(f"Release source rejected: {error}")
        return 1
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"value={revision}\n")
    print(f"Validated immutable release revision: {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
