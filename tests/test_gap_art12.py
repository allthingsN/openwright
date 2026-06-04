"""Gap-aware Art-12 record-keeping verdict (U1, V8).

An attested ``evidence_gap`` marker must influence the Art-12 result instead of
sitting out-of-scope as a GENERIC event: a period containing a gap yields
Art-12 != satisfied, and the signed report surfaces the gap.
"""

from __future__ import annotations

from openwright.crosswalk import ControlStatus, evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.events import ComplianceEvent, EventKind
from openwright.ledger import InMemoryLedgerBackend, Ledger
from openwright.report import build_report
from openwright.signing import InMemoryKeySource

TS = "2026-05-28T00:00:00.000000000Z"


def _evt(kind: EventKind, **attrs) -> ComplianceEvent:
    return ComplianceEvent(
        timestamp=TS, kind=kind, actor={"agent_id": "a"}, source={"format": "sdk"}, attributes=attrs
    )


def _gap(dropped: int) -> ComplianceEvent:
    return ComplianceEvent(
        timestamp=TS,
        kind=EventKind.GENERIC,
        actor={"agent_id": "openwright-collector"},
        source={"format": "openwright"},
        attributes={
            "marker": "evidence_gap",
            "dropped_events": dropped,
            "window_start": TS,
            "window_end": TS,
        },
    )


def _art12(result):
    return next(c for c in result.controls if c.control_id == "art-12-record-keeping")


def test_art12_satisfied_when_no_gap():
    led = Ledger(InMemoryLedgerBackend())
    for _ in range(3):
        led.commit(_evt(EventKind.LLM_CALL))
    res = evaluate(load_builtin("eu-ai-act"), list(led.events()))
    assert _art12(res).status == ControlStatus.SATISFIED


def test_art12_not_satisfied_when_gap_present():
    led = Ledger(InMemoryLedgerBackend())
    for _ in range(3):
        led.commit(_evt(EventKind.LLM_CALL))
    gap = led.commit(_gap(5))
    res = evaluate(load_builtin("eu-ai-act"), list(led.events()))
    art12 = _art12(res)
    assert art12.status == ControlStatus.NOT_SATISFIED
    assert gap.event_id in art12.gap_event_ids  # the marker is cited as the gap
    assert "evidence-gap" in art12.reason.lower() or "gap" in art12.reason.lower()


def test_report_surfaces_evidence_gap_in_signed_payload():
    led = Ledger(InMemoryLedgerBackend())
    for _ in range(2):
        led.commit(_evt(EventKind.LLM_CALL))
    led.commit(_gap(7))
    res = evaluate(load_builtin("eu-ai-act"), list(led.events()))
    rep = build_report(led, res, InMemoryKeySource(), scope_description="x")
    assert rep["evidence_gaps"], "report must surface the self-attested gap"
    assert rep["evidence_gaps"][0]["dropped_events"] == 7
    # The gap is part of the signed payload (tamper-evident completeness).
    from openwright.verify import verify_report

    vr = verify_report(rep)
    assert vr.valid
    # And Art-12 is reported not_satisfied.
    art12 = next(c for c in rep["controls"] if c["control_id"] == "art-12-record-keeping")
    assert art12["status"] == "not_satisfied"
