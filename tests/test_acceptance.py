"""Acceptance criteria AC-01..07 exercised end-to-end via the demo (§13)."""

from __future__ import annotations

import json
import os

import pytest

from openwright.demo import run_demo
from openwright.spec import compliance_event_schema, crosswalk_schema


@pytest.mark.timeout(60)
def test_demo_satisfies_acceptance_criteria(tmp_path):
    out = run_demo(tmp_path)

    # AC-01: fan-out preserved (downstream received spans) + evidence forked
    assert out["downstream_spans"] >= 4
    assert out["ledger_size"] >= 6

    # AC-02: signed report with all three control states
    assert out["summary"]["satisfied"] >= 1
    assert out["summary"]["not_satisfied"] >= 1
    assert out["summary"]["insufficient_evidence"] >= 1

    # AC-03: offline verification valid, hash-only (no raw payloads in report)
    assert out["verification"].valid
    report = json.loads(open(out["report_json"]).read())
    blob = json.dumps(report)
    assert "APPROVED loan" not in blob and "applicant #1 profile" not in blob  # only hashes

    # AC-04: tamper-evidence (and restoration verifies again)
    assert out["tamper_detected"]
    assert out["restore_valid"]

    # §6 value story: sits on top of a verified receipt primitive, and the
    # red→green human-oversight loop (Art. 14 insufficient → satisfied).
    assert out["receipt_format"] == "receipt/action-v1"
    assert out["art14_before"] == "insufficient_evidence"
    assert out["art14_after"] == "satisfied"

    # AC-05: self-hosted, key on disk not embedded in any artifact
    assert os.path.exists(out["public_key"])

    # AC-06: boundary statement present in JSON + PDF + OSCAL
    assert "does not" in report["boundary_statement"].lower() or "DOES NOT" in report["boundary_statement"]
    assert os.path.getsize(out["report_pdf"]) > 1000
    oscal = json.loads(open(out["oscal"]).read())
    assert "audit opinion" in oscal["assessment-results"]["metadata"]["remarks"].lower()

    # AC-07: published, versioned, standalone schemas
    ev_schema = compliance_event_schema()
    assert ev_schema["x-openwright-schema-version"] == "1.0.0"
    assert crosswalk_schema()["title"] == "OpenWright Crosswalk"


@pytest.mark.timeout(60)
def test_report_carries_only_references_not_payloads(tmp_path):
    out = run_demo(tmp_path)
    report = json.loads(open(out["report_json"]).read())
    for item in report["events"]:
        io = item["event"].get("io", {})
        for ref_field in ("input_ref", "output_ref", "arguments_ref"):
            if io.get(ref_field):
                assert io[ref_field].startswith("sha256:")  # DR-02: references only
