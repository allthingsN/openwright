"""Receipt-ingest adapter: verify-before-ingest + normalization (proposal §A1).

OpenWright sits on top of an external receipt primitive: it verifies a signed
Ed25519 action receipt and turns it into a canonical tool_call event, which then
flows through the EU AI Act crosswalk like any other evidence.
"""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from openwright.adapters.receipt import (
    SignedActionReceiptSource,
    ReceiptVerificationError,
    receipt_to_event,
    sign_receipt,
)
from openwright.crosswalk import ControlStatus, evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.events import EventKind
from openwright.ledger import InMemoryLedgerBackend, Ledger
from openwright.signing import InMemoryKeySource
from tests.conftest import FIXED_TS

PARAMS_HASH = "sha256:" + "ab" * 32


def _valid_receipt(key: InMemoryKeySource):
    return sign_receipt(
        key,
        tool="credit_check",
        params_hash=PARAMS_HASH,
        target="experian-sandbox",
        signer_name="loan-decisioning-agent",
        owner="bank.example",
        ts=FIXED_TS,
        nonce="nonce-123",
        transport="https",
    )


def test_valid_receipt_normalizes_to_tool_call():
    key = InMemoryKeySource()
    ev = receipt_to_event(_valid_receipt(key))

    assert ev.kind == EventKind.TOOL_CALL
    assert ev.tool.name == "credit_check"
    assert ev.io.arguments_ref == PARAMS_HASH  # preserved sha256: ref, no PII
    assert ev.source.format == "receipt/action-v1"
    assert ev.actor.agent_id == "loan-decisioning-agent"  # from signer.name
    # signer pubkey/owner carried into the identity claim (verifiably)
    assert ev.actor.identity_claim.claim_type == "receipt-signer"
    assert ev.actor.identity_claim.public_key_id == key.key_id()
    assert ev.attributes["target"] == "experian-sandbox"
    assert ev.attributes["nonce"] == "nonce-123"
    assert ev.attributes["transport"] == "https"
    assert ev.attributes["receipt_verified"] is True


def test_tampered_field_is_rejected():
    key = InMemoryKeySource()
    receipt = _valid_receipt(key)
    tampered = copy.deepcopy(receipt)
    tampered["action"]["target"] = "evil-endpoint"  # signature no longer covers this
    with pytest.raises(ReceiptVerificationError):
        receipt_to_event(tampered)


def test_bad_signature_is_rejected():
    key = InMemoryKeySource()
    receipt = _valid_receipt(key)
    receipt["sig"] = receipt["sig"][:-4] + ("AAAA" if not receipt["sig"].endswith("AAAA") else "BBBB")
    with pytest.raises(ReceiptVerificationError):
        receipt_to_event(receipt)


def test_wrong_signer_key_is_rejected():
    # Signed by one key, but the receipt claims a different signer pubkey.
    real, impostor = InMemoryKeySource(), InMemoryKeySource()
    receipt = _valid_receipt(real)
    import base64

    receipt["signer"]["pubkey"] = base64.b64encode(impostor.public_key_raw()).decode("ascii")
    with pytest.raises(ReceiptVerificationError):
        receipt_to_event(receipt)


@pytest.mark.parametrize("missing", ["sig", "signer", "action"])
def test_structurally_malformed_is_rejected(missing):
    key = InMemoryKeySource()
    receipt = _valid_receipt(key)
    receipt.pop(missing)
    with pytest.raises(ReceiptVerificationError):
        receipt_to_event(receipt)


def test_non_dict_is_rejected():
    with pytest.raises(ReceiptVerificationError):
        receipt_to_event("not-a-receipt")  # type: ignore[arg-type]


def test_verified_receipt_flows_through_eu_ai_act_eval():
    key = InMemoryKeySource()
    led = Ledger(InMemoryLedgerBackend(), origin="openwright/test",
                 retention=timedelta(days=200), clock=lambda: FIXED_TS)
    committed = led.commit(receipt_to_event(_valid_receipt(key)))

    res = evaluate(load_builtin("eu-ai-act"), list(led.events()))
    art12 = next(c for c in res.controls if c.control_id == "art-12-record-keeping")
    # The receipt-derived tool_call is recorded → Art. 12 satisfied, and the
    # event itself is cited as evidence.
    assert art12.status == ControlStatus.SATISFIED
    assert committed.event_id in art12.evidence_event_ids


def test_receipt_source_is_pluggable():
    # The format tag is exposed on the source so other receipt formats can plug
    # in behind the same interface (interchangeable primitives).
    src = SignedActionReceiptSource()
    assert src.format == "receipt/action-v1"
    key = InMemoryKeySource()
    ev = src.verify_and_normalize(_valid_receipt(key), agent_id_default="fallback")
    assert ev.source.format == "receipt/action-v1"
