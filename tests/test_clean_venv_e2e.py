"""Clean-venv release gate (V15) — opt-in (slow: builds a wheel + fresh venv).

Enable with OPENWRIGHT_RUN_E2E=1 (CI/release). Skipped by default so the normal
suite stays fast. The underlying check is scripts/clean_venv_e2e.sh.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(
    os.environ.get("OPENWRIGHT_RUN_E2E") != "1",
    reason="set OPENWRIGHT_RUN_E2E=1 to run the clean-venv release gate (V15)",
)
def test_clean_venv_pip_install_and_demo_is_green():
    proc = subprocess.run(
        ["bash", str(REPO / "scripts" / "clean_venv_e2e.sh")],
        capture_output=True, text=True, timeout=900,
    )
    assert proc.returncode == 0, f"clean-venv E2E failed:\n{proc.stdout}\n{proc.stderr}"
    assert "CLEAN-VENV E2E: PASS" in proc.stdout
