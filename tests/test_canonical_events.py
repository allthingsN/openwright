"""Determinism, canonicalization, and event-model invariants (FR-NRM, DR)."""

from __future__ import annotations

import pytest

from openwright.canonical import CanonicalizationError, canonical_bytes, content_hash, to_rfc3339
from openwright.events import ComplianceEvent, EventKind


def test_canonical_sorts_keys_and_omits_none():
    a = canonical_bytes({"b": 1, "a": None, "c": 2})
    assert a == b'{"b":1,"c":2}'


def test_canonical_rejects_floats():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": 1.5})


def test_canonical_stable_across_key_order():
    assert content_hash({"x": 1, "y": [2, 3]}) == content_hash({"y": [2, 3], "x": 1})


def test_rfc3339_normalizes_nanos_and_seconds():
    assert to_rfc3339(0) == "1970-01-01T00:00:00.000000000Z"
    assert to_rfc3339(1).endswith("Z") and "1970-01-01T00:00:01" in to_rfc3339(1)


def _event(**kw):
    base = dict(timestamp="2026-05-28T00:00:00.000000000Z", kind=EventKind.LLM_CALL,
                actor={"agent_id": "a"}, source={"format": "sdk"})
    base.update(kw)
    return ComplianceEvent(**base)


def test_event_id_is_deterministic():
    e1 = _event().finalize_id()
    e2 = _event().finalize_id()
    assert e1.event_id == e2.event_id and e1.event_id.startswith("evt_")


def test_event_id_independent_of_ledger_fields():
    e = _event()
    before = e.derive_event_id()
    e.finalize_id()
    # leaf content excludes ledger; assigning ledger must not change identity
    from openwright.events import LedgerFields

    e.ledger = LedgerFields(leaf_hash="sha256:00", leaf_index=0, committed_at="x")
    assert e.derive_event_id() == before


def test_leaf_content_excludes_ledger():
    e = _event().finalize_id()
    assert "ledger" not in e.leaf_content()


def test_forward_compatible_unknown_fields_preserved():
    # DR-04: a future field must round-trip through a v1.0 reader
    raw = _event().model_dump(mode="json", exclude_none=True)
    raw["future_field"] = {"new": "data"}
    back = ComplianceEvent.model_validate(raw)
    assert back.model_dump(exclude_none=True).get("future_field") == {"new": "data"}


def test_float_in_attributes_rejected_with_actionable_message():
    with pytest.raises(ValueError, match="float"):
        _event(attributes={"score": 0.5})
