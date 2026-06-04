"""Software Bill of Materials generation (NFR-SEC-03).

Emits a CycloneDX 1.5 SBOM of the installed environment so released artifacts can
ship with one. Build provenance (SLSA) and cosign signing are performed in the
release CI workflow (.github/workflows/release.yml), which consumes this output.
"""

from __future__ import annotations

from importlib.metadata import distributions
from typing import Any, Dict

from . import __version__


def generate_cyclonedx() -> Dict[str, Any]:
    seen = {}
    for dist in distributions():
        name = (dist.metadata.get("Name") or "").strip()
        if not name or name.lower() in seen:
            continue
        version = dist.version
        seen[name.lower()] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
        }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "openwright",
                "version": __version__,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        },
        "components": sorted(seen.values(), key=lambda c: c["name"].lower()),
    }
