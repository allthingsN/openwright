"""Tests for the P1/P2 features: incremental tree, shard aggregation, pure
Ed25519/standalone verifier, SQL backend, checkpoint store, witness, vault,
authz, retry, policy adapter, new crosswalks, dashboard, SBOM."""

from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest

from openwright.crosswalk import ControlStatus, evaluate
from openwright.crosswalk_loader import available_builtins, load_builtin
from openwright.events import ComplianceEvent, EventKind
from openwright.ledger import InMemoryLedgerBackend, Ledger, SqlLedgerBackend
from openwright.merkle import (
    IncrementalMerkleTree,
    inclusion_proof,
    leaf_hash,
    shard_super_proof,
    shard_super_root,
    tree_hash,
    verify_sharded_inclusion,
)
from openwright.signing import InMemoryKeySource

REPO = Path(__file__).resolve().parent.parent


def _ev(i):
    return ComplianceEvent(timestamp="2026-05-29T00:00:00.000000000Z", kind=EventKind.GENERIC,
                           actor={"agent_id": "a"}, source={"format": "sdk"}, attributes={"i": i})


# -- incremental tree + shard aggregation (NFR-SCAL-01) ----------------------

def test_incremental_matches_recursive():
    leaves = [leaf_hash(bytes([i % 256])) for i in range(257)]
    for n in (0, 1, 2, 3, 5, 8, 100, 256, 257):
        assert IncrementalMerkleTree.from_leaves(leaves[:n]).root() == tree_hash(leaves[:n])


def test_shard_aggregation_verifies_and_detects_tamper():
    shards = [[leaf_hash(f"s{s}-{i}".encode()) for i in range(4 + s)] for s in range(3)]
    roots = [tree_hash(s) for s in shards]
    super_root = shard_super_root(roots)
    si, li = 1, 2
    ok = verify_sharded_inclusion(shards[si][li], li, len(shards[si]), inclusion_proof(shards[si], li),
                                  roots[si], si, len(roots), shard_super_proof(roots, si), super_root)
    assert ok
    bad = verify_sharded_inclusion(shards[si][li], li, len(shards[si]), inclusion_proof(shards[si], li),
                                   leaf_hash(b"evil"), si, len(roots), shard_super_proof(roots, si), super_root)
    assert not bad


# -- pure Ed25519 + standalone single-file verifier (FR-VER-04) --------------

def test_pure_ed25519_matches_cryptography():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from openwright._ed25519_pure import verify as pure_verify

    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    msg = b"payload"
    sig = sk.sign(msg)
    assert pure_verify(pub, sig, msg)
    assert not pure_verify(pub, sig, msg + b"x")


def test_standalone_web_verifier_agrees(populated_ledger, key):
    from openwright.report import build_report

    spec = importlib.util.spec_from_file_location("vt_pure", REPO / "web" / "openwright_verifier.py")
    pure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pure)

    result = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    report = build_report(populated_ledger, result, key, scope_description="t")
    valid, _ = pure.verify_report(report, key.public_key_raw())
    assert valid
    report["events"][0]["event"]["kind"] = "generic"  # tamper
    valid2, _ = pure.verify_report(report, key.public_key_raw())
    assert not valid2


# -- SQL ledger backend + checkpoint store (FR-LED-03) -----------------------

def test_sql_ledger_backend_roundtrip_and_root():
    conn = sqlite3.connect(":memory:")
    led = Ledger(SqlLedgerBackend(conn))
    for i in range(6):
        led.commit(_ev(i))
    assert led.size() == 6 and led.root() == tree_hash(led.leaf_hashes())
    # reopen on same connection -> reconstructs identical state
    led2 = Ledger(SqlLedgerBackend(conn))
    assert led2.size() == 6 and led2.root_hex() == led.root_hex()
    assert led2.get_event(3).attributes["i"] == 3


def test_local_checkpoint_store(tmp_path):
    from openwright.checkpoint_store import LocalCheckpointStore

    led = Ledger(InMemoryLedgerBackend())
    for i in range(3):
        led.commit(_ev(i))
    key = InMemoryKeySource()
    store = LocalCheckpointStore(str(tmp_path / "cps"))
    store.put(led.checkpoint(key))
    assert store.tree_sizes() == [3]
    assert store.latest().tree_size == 3 and store.latest().verify(key.public_key_raw())


# -- witness co-signing (FR-ATT-08) ------------------------------------------

def test_witness_cosign_and_verify():
    from openwright.witness import Witness, verify_cosignature

    producer = InMemoryKeySource()
    led = Ledger(InMemoryLedgerBackend())
    for i in range(4):
        led.commit(_ev(i))
    cp1 = led.checkpoint(producer)
    w = Witness(InMemoryKeySource())
    cosig = w.cosign(cp1, producer.public_key_raw())
    assert verify_cosignature(cp1, cosig, w.key.public_key_raw())
    # extend the log; witness verifies consistency before co-signing again
    old = led.size()
    led.commit(_ev(99))
    cp2 = led.checkpoint(producer)
    cosig2 = w.cosign(cp2, producer.public_key_raw(), consistency_proof_hex=led.consistency_proof_hex(old))
    assert verify_cosignature(cp2, cosig2, w.key.public_key_raw())


def test_witness_rejects_invalid_producer_signature():
    from openwright.witness import Witness, WitnessError

    led = Ledger(InMemoryLedgerBackend())
    led.commit(_ev(0))
    cp = led.checkpoint(InMemoryKeySource())
    with pytest.raises(WitnessError):
        Witness(InMemoryKeySource()).cosign(cp, InMemoryKeySource().public_key_raw())  # wrong producer key


# -- payload vault (NFR-PRIV-03) ---------------------------------------------

def test_vault_stores_raw_separately_ledger_has_only_ref(tmp_path):
    from openwright.sdk import EvidenceClient
    from openwright.vault import FileVault

    vault = FileVault(str(tmp_path / "vault"))
    led = Ledger(InMemoryLedgerBackend())
    client = EvidenceClient(led, agent_id="a", vault=vault)
    ev = client.record_decision(output="APPROVED secret loan", risk_classification="high")
    ref = ev.io.output_ref
    assert ref.startswith("sha256:")
    # ledger record carries only the ref, never the raw payload
    import json
    assert "APPROVED secret loan" not in json.dumps(led.get_event(0).model_dump())
    # the raw payload is retrievable from the separate vault
    assert vault.fetch(ref) == b"APPROVED secret loan"


# -- authz (NFR-SEC-04) ------------------------------------------------------

def test_authz_gates_evidence_write_and_report():
    from openwright.authz import AuthorizationError, Authorizer, Capability, Principal
    from openwright.report import build_report
    from openwright.sdk import EvidenceClient

    authorizer = Authorizer()
    reader = Principal("reader", frozenset())
    writer = Principal("writer", frozenset({Capability.WRITE_EVIDENCE}))

    led = Ledger(InMemoryLedgerBackend())
    blocked = EvidenceClient(led, agent_id="a", principal=reader, authorizer=authorizer)
    with pytest.raises(AuthorizationError):
        blocked.record_decision(output="x")
    allowed = EvidenceClient(led, agent_id="a", principal=writer, authorizer=authorizer)
    allowed.record_decision(output="x")
    assert led.size() == 1

    # report generation requires GENERATE_REPORT
    result = evaluate(load_builtin("soc2"), list(led.events()))
    with pytest.raises(AuthorizationError):
        build_report(led, result, InMemoryKeySource(), scope_description="t",
                     principal=writer, authorizer=authorizer)


def test_token_authority():
    from openwright.authz import Capability, Principal, TokenAuthority

    ta = TokenAuthority({"good": Principal("w", frozenset({Capability.WRITE_EVIDENCE}))})
    assert ta.authorize_bearer("Bearer good", Capability.WRITE_EVIDENCE)
    assert not ta.authorize_bearer("Bearer bad", Capability.WRITE_EVIDENCE)
    assert not ta.authorize_bearer(None, Capability.WRITE_EVIDENCE)


# -- pipeline retry-with-backoff (NFR-REL-03) --------------------------------

def test_pipeline_retries_transient_ledger_failure():
    from openwright.adapters.base import SpanData
    from openwright.ingest.pipeline import EvidencePipeline

    class FlakyBackend(InMemoryLedgerBackend):
        def __init__(self):
            super().__init__()
            self.fails_left = 2

        def append_record(self, record):
            if self.fails_left > 0:
                self.fails_left -= 1
                raise RuntimeError("ledger temporarily unavailable")
            super().append_record(record)

    led = Ledger(FlakyBackend())
    pipe = EvidencePipeline(led, agent_id="a", commit_retries=5, retry_backoff=0.001)
    pipe.submit([SpanData("chat", {"gen_ai.operation.name": "chat"})])
    pipe.flush()
    assert pipe.stats()["processed"] == 1 and pipe.stats()["retries"] >= 2 and pipe.stats()["errors"] == 0
    pipe.stop()


# -- policy adapter (FR-ING-09) ----------------------------------------------

def test_policy_adapter_opa_and_cedar():
    from openwright.adapters.policy import policy_decisions_to_events

    opa = policy_decisions_to_events(
        [{"decision_id": "d1", "path": "authz/allow", "result": {"allow": True}}],
        agent_id="a", timestamp="2026-05-29T00:00:00.000000000Z", engine="opa")
    assert opa[0].kind == "policy_decision" and opa[0].attributes["decision"] == "allow"
    cedar = policy_decisions_to_events(
        [{"decision": "Deny", "diagnostics": {"reason": ["policy0"]}}],
        agent_id="a", timestamp="2026-05-29T00:00:00.000000000Z", engine="cedar")
    assert cedar[0].attributes["decision"] == "deny"


# -- new crosswalks (FR-MAP-09) ----------------------------------------------

@pytest.mark.parametrize("name", ["nist-ai-rmf", "iso-42001", "gdpr"])
def test_new_crosswalks_load_and_evaluate(name, populated_ledger):
    assert name in available_builtins()
    cw = load_builtin(name)
    res = evaluate(cw, list(populated_ledger.events()))
    assert len(res.controls) >= 3
    assert all(isinstance(c.status, ControlStatus) for c in res.controls)
    for c in cw.controls:
        assert c.citation.instrument  # FR-MAP-04


def test_oversight_crosswalks_flag_unapproved_decision(populated_ledger):
    # populated_ledger has one approved + one UN-approved high-risk decision.
    for name, cid in [("nist-ai-rmf", "govern-3.2"), ("iso-42001", "a.9.2"),
                      ("gdpr", "art-22-human-intervention")]:
        res = evaluate(load_builtin(name), list(populated_ledger.events()))
        status = {c.control_id: c.status for c in res.controls}[cid]
        assert status == ControlStatus.NOT_SATISFIED


# -- dashboard (FR-RPT-06) ---------------------------------------------------

def test_dashboard_renders(populated_ledger, key):
    from openwright.dashboard import build_dashboard
    from openwright.report import build_report

    result = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    r1 = build_report(populated_ledger, result, key, scope_description="t", report_id="r1",
                      generated_at="2026-05-28T00:00:00.000000000Z")
    r2 = build_report(populated_ledger, result, key, scope_description="t", report_id="r2",
                      generated_at="2026-05-29T00:00:00.000000000Z")
    html = build_dashboard([r2, r1])  # unsorted on purpose
    assert "art-14-human-oversight" in html
    assert "coverage" in html.lower() and "DOES NOT constitute" in html
    assert html.index("r1") < html.index("r2")  # sorted by generated_at


# -- SBOM (NFR-SEC-03) -------------------------------------------------------

def test_sbom_generation():
    from openwright.sbom import generate_cyclonedx

    sbom = generate_cyclonedx()
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    names = {c["name"].lower() for c in sbom["components"]}
    assert "pydantic" in names and "cryptography" in names
    assert sbom["metadata"]["component"]["name"] == "openwright"
