#!/usr/bin/env python3
"""Do not publish an SDK whose security fix exists only in a root Cargo patch."""
from pathlib import Path
import re
import sys
import tomllib

root = Path(__file__).resolve().parents[1]
manifest = tomllib.loads((root / "Cargo.toml").read_text())
if "fluxencrypt" in manifest.get("patch", {}).get("crates-io", {}):
    sys.exit(
        "Registry release blocked: the private RSA remediation currently depends "
        "on a root FluxEncrypt git patch, which does not propagate to published "
        "SDK consumers. Require an authorized fixed stable FluxEncrypt registry "
        "release, remove this temporary patch, and revalidate package verification "
        "before releasing this workspace. See docs/security/dependency-security-rollup.md."
    )
dependency = manifest.get("workspace", {}).get("dependencies", {}).get("fluxencrypt", "")
requirement = dependency if isinstance(dependency, str) else dependency.get("version", "")
version = re.fullmatch(r"[=^~]?(\d+)\.(\d+)\.(\d+)", requirement)
if version is None or tuple(map(int, version.groups())) < (0, 7, 12):
    sys.exit("Registry release blocked: require stable FluxEncrypt 0.7.12 or newer with the AWS-LC private-operation fix")
print("No temporary FluxEncrypt security patch blocks registry release")
