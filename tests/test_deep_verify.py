"""Deep-verify suite (V7) + verifier minimal-deps re-check (V12).

V7: crosswalk version/content-hash-mismatch refusal and absence refusal (B9), and
explicit selective-disclosure semantics. (Forged-but-signed verdict rejection is
covered in test_report_verify.py.)

V12: the shallow verify path imports no network/heavy libs; deep mode's crosswalk
import stays lazy.
"""

from __future__ import annotations

import base64
import copy
import subprocess
import sys

import pytest

from openwright.canonical import canonical_bytes
from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.report import build_report
from openwright.verify import verify_report


@pytest.fixture
def report(populated_ledger, key):
    result = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    return build_report(
        populated_ledger, result, key, scope_description="test agent",
        report_id="rpt_test", generated_at="2026-05-28T12:00:00.000000000Z",
    )


def _resign(report, key):
    payload = canonical_bytes({k: v for k, v in report.items() if k != "signature"})
    report["signature"] = {
        "algorithm": "ed25519",
        "public_key_id": key.key_id(),
        "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
    }
    return report


def _checks(result):
    return {name: ok for name, ok, _ in result.checks}


# -- V7: crosswalk pin -------------------------------------------------------


def test_report_carries_crosswalk_content_hash(report):
    assert report["crosswalk"]["content_hash"].startswith("sha256:")


def test_deep_verify_refuses_on_hash_mismatch(report, key):
    forged = copy.deepcopy(report)
    forged["crosswalk"]["content_hash"] = "sha256:" + "00" * 32  # claim a different crosswalk
    _resign(forged, key)
    deep = verify_report(forged, trusted_public_key_raw=key.public_key_raw(), deep=True)
    assert not deep.valid
    assert _checks(deep).get("deep_verify_crosswalk_pin") is False


def test_deep_verify_refuses_on_missing_pin(report, key):
    forged = copy.deepcopy(report)
    forged["crosswalk"].pop("content_hash", None)
    _resign(forged, key)
    deep = verify_report(forged, trusted_public_key_raw=key.public_key_raw(), deep=True)
    assert not deep.valid
    assert _checks(deep).get("deep_verify_crosswalk_pin") is False


def test_deep_verify_accepts_matching_pin(report, key):
    deep = verify_report(report, trusted_public_key_raw=key.public_key_raw(), deep=True)
    assert deep.valid
    assert _checks(deep).get("deep_verify_crosswalk_pin") is True


def test_deep_verify_makes_selective_disclosure_explicit(report, key):
    # Disclose a subset of events (legitimate selective disclosure): drop one,
    # keeping the checkpoint (full tree_size) intact.
    partial = copy.deepcopy(report)
    assert len(partial["events"]) > 1
    partial["events"] = partial["events"][:-1]
    _resign(partial, key)
    deep = verify_report(partial, trusted_public_key_raw=key.public_key_raw(), deep=True)
    assert any("disclos" in w.lower() for w in deep.warnings), deep.warnings


# -- V12: minimal deps -------------------------------------------------------

_HEAVY = ["pydantic", "yaml", "reportlab", "requests", "httpx", "urllib.request", "socket", "boto3", "psycopg"]


def test_shallow_verify_imports_no_heavy_or_network_libs():
    """Importing openwright.verify and running a shallow verify must not pull in
    pydantic/yaml/reportlab or any networking lib (INV-2 / FR-VER-03)."""
    code = (
        "import sys\n"
        "import openwright.verify as v\n"
        "import openwright.canonical, openwright.merkle\n"
        f"heavy = {_HEAVY!r}\n"
        "leaked = [m for m in heavy if m in sys.modules]\n"
        "print('LEAKED:' + ','.join(leaked))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    leaked = out.stdout.strip().split("LEAKED:")[-1]
    assert leaked == "", f"shallow verify path leaked heavy/network imports: {leaked}"


def test_deep_mode_crosswalk_import_is_lazy():
    """The crosswalk engine (pydantic/yaml) must only be imported when deep=True
    is actually used — not at module import of openwright.verify."""
    code = (
        "import sys\n"
        "import openwright.verify\n"
        "print('before:' + str('openwright.crosswalk' in sys.modules))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert "before:False" in out.stdout, out.stdout
