"""Report building, verification, and tamper-evidence (FR-RPT, FR-VER, AC-02/03/04)."""

from __future__ import annotations

import copy
import sys

import jsonschema
import pytest

from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.report import BOUNDARY_STATEMENT, build_report, to_oscal, to_sarif
from openwright.spec import compliance_event_schema
from openwright.verify import verify_report


@pytest.fixture
def report(populated_ledger, key):
    result = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    return build_report(populated_ledger, result, key,
                        scope_description="test agent", report_id="rpt_test",
                        generated_at="2026-05-28T12:00:00.000000000Z")


def test_clean_report_verifies(report, key):
    vr = verify_report(report, trusted_public_key_raw=key.public_key_raw())
    assert vr.valid
    assert all(ok for _, ok, _ in vr.checks)


def test_tampered_event_fails(report, key):
    bad = copy.deepcopy(report)
    for item in bad["events"]:
        if item["event"]["kind"] == "agent_decision":
            item["event"]["io"]["output_ref"] = "sha256:00"
            break
    assert not verify_report(bad, trusted_public_key_raw=key.public_key_raw()).valid


def _resign(report, key):
    """Re-sign a (mutated) report so it passes signature + integrity checks —
    simulating a producer that signs an honest-looking but forged verdict."""
    import base64

    from openwright.canonical import canonical_bytes

    payload = canonical_bytes({k: v for k, v in report.items() if k != "signature"})
    report["signature"] = {
        "algorithm": "ed25519",
        "public_key_id": key.key_id(),
        "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
    }
    return report


def test_deep_verify_catches_forged_but_signed_verdict(report, key):
    """F3: signatures + Merkle integrity prove a verdict is authentic-to-producer,
    not that it's correct. Deep verify re-derives verdicts from the evidence."""
    forged = copy.deepcopy(report)
    flipped = None
    for c in forged["controls"]:
        if c["status"] != "satisfied":
            c["status"] = "satisfied"
            flipped = c["control_id"]
            break
    assert flipped, "fixture should contain a non-satisfied control to forge"
    _resign(forged, key)

    shallow = verify_report(forged, trusted_public_key_raw=key.public_key_raw())
    assert shallow.valid, "forged-but-resigned report should pass integrity checks"

    deep = verify_report(forged, trusted_public_key_raw=key.public_key_raw(), deep=True)
    assert not deep.valid
    assert any(name == "deep_verify_verdicts" and not ok for name, ok, _ in deep.checks)
    assert any(flipped in e for e in deep.errors)


def test_deep_verify_passes_on_honest_report(report, key):
    deep = verify_report(report, trusted_public_key_raw=key.public_key_raw(), deep=True)
    assert deep.valid
    assert any(name == "deep_verify_verdicts" and ok for name, ok, _ in deep.checks)


def test_tampered_control_result_fails(report, key):
    bad = copy.deepcopy(report)
    for c in bad["controls"]:
        if c["status"] != "satisfied":
            c["status"] = "satisfied"
    assert not verify_report(bad, trusted_public_key_raw=key.public_key_raw()).valid


def test_deleted_event_fails(report, key):
    bad = copy.deepcopy(report)
    bad["events"].pop()
    assert not verify_report(bad, trusted_public_key_raw=key.public_key_raw()).valid


def test_reordered_events_fail(report, key):
    bad = copy.deepcopy(report)
    bad["events"][0]["event"], bad["events"][1]["event"] = (
        bad["events"][1]["event"], bad["events"][0]["event"])
    assert not verify_report(bad, trusted_public_key_raw=key.public_key_raw()).valid


def test_wrong_key_fails(report):
    from openwright.signing import InMemoryKeySource

    assert not verify_report(report, trusted_public_key_raw=InMemoryKeySource().public_key_raw()).valid


def test_embedded_key_warns(report):
    vr = verify_report(report)  # no trusted key supplied
    assert vr.valid and any("embedded" in w for w in vr.warnings)


def test_boundary_statement_in_all_artifacts(report):
    # FR-RPT-07: EVERY generated artifact must carry the boundary statement.
    assert report["boundary_statement"] == BOUNDARY_STATEMENT
    assert BOUNDARY_STATEMENT in to_oscal(report)["assessment-results"]["metadata"]["remarks"]
    sarif = to_sarif(report)
    assert sarif["runs"][0]["properties"]["openwright_boundary_statement"] == BOUNDARY_STATEMENT
    assert sarif["runs"][0]["tool"]["driver"]["fullDescription"]["text"] == BOUNDARY_STATEMENT


def test_oscal_structure(report):
    osc = to_oscal(report)["assessment-results"]
    assert osc["uuid"] and osc["results"][0]["findings"]
    states = {f["target"]["status"]["state"] for f in osc["results"][0]["findings"]}
    assert states <= {"satisfied", "not-satisfied"}
    # tri-state is preserved in a prop even though OSCAL has only 2 states
    props = osc["results"][0]["findings"][0]["props"]
    assert any(p["name"] == "openwright-status" for p in props)


def test_sarif_structure(report):
    sar = to_sarif(report)
    assert sar["version"] == "2.1.0"
    assert all(r["level"] in ("error", "warning", "note", "none") for r in sar["runs"][0]["results"])


def test_compliance_event_validates_against_published_schema(report):
    schema = compliance_event_schema()
    for item in report["events"]:
        jsonschema.validate(item["event"], schema)


def test_verifier_imports_no_network_libs():
    # FR-VER-02/03: the verifier is a minimal root of trust. In a FRESH interpreter,
    # importing it must not pull pydantic/pyyaml/reportlab or any networking library.
    import subprocess

    code = (
        "import openwright.verify, sys; "
        "banned={'requests','grpc','urllib3','httpx','aiohttp','pydantic','yaml','reportlab','typer'}; "
        "leaked=banned & set(sys.modules); "
        "sys.exit('LEAKED:%s' % leaked if leaked else 0)"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout
