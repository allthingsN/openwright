"""AgentCard identity binding (FR-ATT-07) and CLI behavior."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from openwright.cli import app
from openwright.identity import make_identity_claim, verify_identity_claim
from openwright.signing import InMemoryKeySource

runner = CliRunner()

AGENT_CARD = {
    "protocolVersion": "0.3.0",
    "name": "loan-agent",
    "description": "decisions",
    "url": "https://agent.example/a2a",
    "version": "1.0.0",
    "capabilities": {"streaming": False},
    "defaultInputModes": ["text"],
    "defaultOutputModes": ["text"],
    "skills": [],
}


def test_identity_claim_round_trip():
    key = InMemoryKeySource()
    claim = make_identity_claim(AGENT_CARD, key)
    assert verify_identity_claim(claim, AGENT_CARD, key.public_key_raw())


def test_identity_claim_detects_card_tamper():
    key = InMemoryKeySource()
    claim = make_identity_claim(AGENT_CARD, key)
    tampered = dict(AGENT_CARD, url="https://evil.example/a2a")
    assert not verify_identity_claim(claim, tampered, key.public_key_raw())


def test_identity_claim_rejects_wrong_key():
    claim = make_identity_claim(AGENT_CARD, InMemoryKeySource())
    assert not verify_identity_claim(claim, AGENT_CARD, InMemoryKeySource().public_key_raw())


def test_signatures_field_excluded_from_signing():
    # Adding a signatures field must not invalidate the claim (A2A signing rule).
    key = InMemoryKeySource()
    claim = make_identity_claim(AGENT_CARD, key)
    with_sig = dict(AGENT_CARD, signatures=[{"protected": "x", "signature": "y"}])
    assert verify_identity_claim(claim, with_sig, key.public_key_raw())


def test_cli_version_and_crosswalks():
    assert runner.invoke(app, ["version"]).exit_code == 0
    out = runner.invoke(app, ["crosswalks"])
    assert out.exit_code == 0 and "eu-ai-act" in out.stdout


def test_cli_schema_emits_valid_json():
    out = runner.invoke(app, ["schema", "--kind", "event"])
    assert out.exit_code == 0
    doc = json.loads(out.stdout)
    assert doc["title"] == "OpenWright ComplianceEvent"


def test_cli_verify_and_gate(tmp_path, populated_ledger):
    from openwright.crosswalk import evaluate
    from openwright.crosswalk_loader import load_builtin
    from openwright.report import build_report
    from openwright.signing import FileKeySource, generate_private_key_pem, public_key_pem

    keyp = tmp_path / "k.pem"
    keyp.write_bytes(generate_private_key_pem())
    key = FileKeySource(str(keyp))
    pubp = tmp_path / "k.pub"
    pubp.write_bytes(public_key_pem(key.public_key_raw()))

    result = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    report = build_report(populated_ledger, result, key, scope_description="t")
    rp = tmp_path / "report.json"
    rp.write_text(json.dumps(report))

    assert runner.invoke(app, ["verify", str(rp), "--pubkey", str(pubp)]).exit_code == 0
    # gate on a satisfied control -> pass
    assert runner.invoke(app, ["gate", str(rp), "--pubkey", str(pubp), "-r", "art-12-record-keeping"]).exit_code == 0
    # gate on an unsatisfied control -> fail (UC-4)
    assert runner.invoke(app, ["gate", str(rp), "--pubkey", str(pubp), "-r", "art-14-human-oversight"]).exit_code == 1
