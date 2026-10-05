#!/usr/bin/env python3
"""Validate native informational Geiger inventory for a local workspace member."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

import tomllib

ROOT = Path(__file__).resolve().parents[1]
COUNTERS = ("functions", "exprs", "item_impls", "item_traits", "methods")


def workspace_packages() -> dict[str, tuple[Path, str]]:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    packages = {}
    for member in manifest["workspace"]["members"]:
        directory = ROOT / member
        package = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))["package"]
        version = package["version"]
        if isinstance(version, dict) and version.get("workspace") is True:
            version = manifest["workspace"]["package"]["version"]
        if not isinstance(version, str):
            raise TypeError("Expected a package version string")
        packages[package["name"]] = (directory.resolve(), version)
    return packages


def validate_metrics(metrics: object, name: str) -> None:
    if not isinstance(metrics, dict) or not isinstance(metrics.get("forbids_unsafe"), bool):
        raise TypeError(f"Missing metrics for {name}")
    for scope in ("used", "unused"):
        counts = metrics.get(scope)
        if not isinstance(counts, dict):
            raise TypeError(f"Missing {scope} metrics for {name}")
        for counter in COUNTERS:
            values = counts.get(counter)
            if not isinstance(values, dict):
                raise TypeError(f"Missing {counter} metrics for {name}")
            for kind in ("safe", "unsafe_"):
                value = values.get(kind)
                if type(value) is not int:
                    raise TypeError(f"Invalid {counter} count for {name}")
                if value < 0:
                    raise ValueError(f"Negative {counter} count for {name}")


def member_entry(report: dict, package: str) -> dict:
    entries = []
    for entry in report["packages"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
            raise TypeError("Expected a native package report")
        identity = entry["package"].get("id")
        if not isinstance(identity, dict):
            raise TypeError("Expected a native package identity")
        if identity.get("name") == package:
            entries.append(entry)
    if len(entries) != 1:
        raise ValueError(f"Missing or duplicate metrics for {package}")
    return entries[0]


def validate_identity(identity: dict, package: str, directory: Path, version: str) -> None:
    if identity.get("version") != version:
        raise ValueError(f"Wrong package version for {package}")
    source = identity.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("Path"), str):
        raise TypeError(f"Expected a local path source for {package}")
    location = urlsplit(source["Path"])
    # The upstream package-id conversion may encode a version fragment in the
    # file URL path. Version is checked independently against the manifest.
    local_path = Path(unquote(location.path).split("#", 1)[0]).resolve()
    if location.scheme != "file" or location.netloc or local_path != directory:
        raise ValueError(f"Wrong local workspace source for {package}")


def validate_report(report: object, package: str) -> dict:
    packages = workspace_packages()
    if package not in packages:
        raise ValueError("Unexpected workspace package")
    if not isinstance(report, dict):
        raise TypeError("Expected a native report object")
    for key in ("packages", "packages_without_metrics", "used_but_not_scanned_files"):
        if not isinstance(report.get(key), list):
            raise TypeError(f"Expected native report array: {key}")
    entry = member_entry(report, package)
    directory, version = packages[package]
    validate_identity(entry["package"]["id"], package, directory, version)
    validate_metrics(entry.get("unsafety"), package)
    return report


def fixture(package: str) -> dict:
    directory, version = workspace_packages()[package]
    metrics = {
        scope: {counter: {"safe": 1, "unsafe_": 2} for counter in COUNTERS}
        for scope in ("used", "unused")
    }
    metrics["forbids_unsafe"] = False
    identity = {"name": package, "version": version, "source": {"Path": directory.as_uri()}}
    return {
        "packages": [{"package": {"id": identity}, "unsafety": metrics}],
        "packages_without_metrics": [],
        "used_but_not_scanned_files": ["generated/input.rs"],
    }


class GeigerReportTests(unittest.TestCase):
    package = "threatflux-atlassian-sdk"

    def test_accepts_all_members_with_informational_unsafe_counts_and_diagnostics(self) -> None:
        for package in workspace_packages():
            with self.subTest(package=package):
                report = fixture(package)
                self.assertIs(validate_report(report, package), report)

    def test_accepts_upstream_encoded_package_id_fragment(self) -> None:
        report = fixture(self.package)
        report["packages"][0]["package"]["id"]["source"]["Path"] += "%230.5.1"
        validate_report(report, self.package)

    def test_rejects_missing_duplicate_or_unrelated_member_metrics(self) -> None:
        for change in ("missing", "duplicate", "unrelated"):
            report = fixture(self.package)
            if change == "missing":
                report["packages"] = []
            elif change == "duplicate":
                report["packages"].append(copy.deepcopy(report["packages"][0]))
            else:
                report["packages"][0]["package"]["id"]["name"] = "unrelated"
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_report(report, self.package)

    def test_rejects_wrong_version_or_registry_or_other_local_source(self) -> None:
        for change in ("version", "registry", "directory", "remote_file"):
            report = fixture(self.package)
            identity = report["packages"][0]["package"]["id"]
            if change == "version":
                identity["version"] = "0.0.0"
            elif change == "registry":
                identity["source"] = {"Registry": {"name": "crates.io"}}
            elif change == "directory":
                identity["source"]["Path"] = ROOT.as_uri()
            else:
                identity["source"]["Path"] = "file://another-host" + ROOT.as_posix()
            with self.subTest(change=change), self.assertRaises((TypeError, ValueError)):
                validate_report(report, self.package)

    def test_rejects_missing_malformed_or_negative_metrics(self) -> None:
        for change in ("empty", "boolean", "negative", "counter", "scope"):
            report = fixture(self.package)
            metrics = report["packages"][0]["unsafety"]
            if change == "empty":
                report["packages"][0]["unsafety"] = {}
            elif change == "boolean":
                metrics["used"]["exprs"]["unsafe_"] = True
            elif change == "negative":
                metrics["unused"]["methods"]["safe"] = -1
            elif change == "counter":
                del metrics["used"]["functions"]
            else:
                del metrics["unused"]
            with self.subTest(change=change), self.assertRaises((TypeError, ValueError)):
                validate_report(report, self.package)

    def test_rejects_non_native_schema_and_unknown_workspace_package(self) -> None:
        for report in ([], {}, {"packages": []}, {"packages": "fabricated"}):
            with self.subTest(report=report), self.assertRaises(TypeError):
                validate_report(report, self.package)
        with self.assertRaises(ValueError):
            validate_report(fixture(self.package), "unrelated")

    def test_cli_rejects_missing_and_invalid_json_reports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="threatflux-geiger-report-") as directory:
            path = Path(directory) / "report.json"
            for content in (None, "not JSON", "{}"):
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(Path(__file__).resolve()), str(path), self.package],
                    text=True, capture_output=True, check=False,
                )
                with self.subTest(content=content):
                    self.assertNotEqual(result.returncode, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("package", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(GeigerReportTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if arguments.path is None or arguments.package is None:
        parser.error("A report path and workspace package are required")
    report = validate_report(json.loads(arguments.path.read_text(encoding="utf-8")), arguments.package)
    print(
        f"{arguments.package}: informational metrics for {len(report['packages'])} packages; "
        f"{len(report['used_but_not_scanned_files'])} unscanned input files retained"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
