#!/usr/bin/env python3
"""Do not publish an SDK whose security fix exists only in a root Cargo patch."""
from pathlib import Path
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
print("No temporary FluxEncrypt security patch blocks registry release")
