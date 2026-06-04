"""Crosswalk three-state semantics + adapters (FR-MAP, FR-ING, FR-NRM)."""

from __future__ import annotations

from openwright.adapters import (
    SpanData,
    apply_langfuse_precedence,
    reconstruct_provenance,
    sarif_to_events,
    span_to_event,
)
from openwright.crosswalk import ControlStatus, evaluate
from openwright.crosswalk_loader import load_builtin
from tests.conftest import FIXED_TS


def test_three_states_present(populated_ledger):
    res = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    statuses = {c.control_id: c.status for c in res.controls}
    assert statuses["art-14-human-oversight"] == ControlStatus.NOT_SATISFIED
    assert statuses["art-73-serious-incident"] == ControlStatus.INSUFFICIENT_EVIDENCE
    assert statuses["art-12-record-keeping"] == ControlStatus.SATISFIED


def test_insufficient_never_collapses_to_not_satisfied(populated_ledger):
    # Art 73 has no incidents in scope -> must be insufficient, NOT not_satisfied
    res = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    art73 = next(c for c in res.controls if c.control_id == "art-73-serious-incident")
    assert art73.status == ControlStatus.INSUFFICIENT_EVIDENCE
    assert art73.evaluated_count == 0


def test_empty_ledger_all_insufficient():
    res = evaluate(load_builtin("eu-ai-act"), [])
    assert all(c.status == ControlStatus.INSUFFICIENT_EVIDENCE for c in res.controls)


def test_citations_present():
    cw = load_builtin("eu-ai-act")
    for c in cw.controls:
        assert c.citation.instrument and c.citation.url


def test_otel_current_and_legacy_conventions():
    cur = span_to_event(SpanData("chat", {"gen_ai.operation.name": "chat",
        "gen_ai.provider.name": "anthropic", "gen_ai.usage.input_tokens": 10,
        "gen_ai.usage.output_tokens": 5}), timestamp=FIXED_TS)
    assert cur.kind == "llm_call" and cur.model.provider == "anthropic"
    assert cur.io.input_tokens == 10 and cur.attributes["semconv"] == "gen_ai/latest"

    leg = span_to_event(SpanData("chat", {"gen_ai.operation.name": "chat",
        "gen_ai.system": "openai", "gen_ai.usage.prompt_tokens": 3,
        "gen_ai.usage.completion_tokens": 7}), timestamp=FIXED_TS)
    assert leg.model.provider == "openai" and leg.io.input_tokens == 3
    assert leg.attributes["semconv"] == "gen_ai/legacy"


def test_langfuse_precedence_wins():
    span = SpanData("chat", {"gen_ai.request.model": "gpt-4",
        "langfuse.observation.model.name": "claude-3", "langfuse.session.id": "s1"})
    ev = span_to_event(span, timestamp=FIXED_TS)
    apply_langfuse_precedence(ev, span.attributes)
    assert ev.model.request_model == "claude-3"  # langfuse wins
    assert ev.provenance.context_id == "s1"


def test_a2a_provenance_reconstruction():
    known = {}
    p1 = reconstruct_provenance("t1", context_id="c1")
    known["t1"] = p1
    p2 = reconstruct_provenance("t2", context_id="c1", reference_task_ids=["t1"], known=known)
    assert p2.parent_task_id == "t1" and p2.root_task_id == "t1"
    assert p1.root_task_id == "t1"  # no parent -> own root


def test_sarif_ingest_is_safe_on_garbage():
    assert sarif_to_events({"runs": "not-a-list"}, agent_id="a", timestamp=FIXED_TS) == []
    evs = sarif_to_events(
        {"runs": [{"tool": {"driver": {"name": "scanner"}},
                   "results": [{"ruleId": "R1", "level": "error", "message": {"text": "bad"}}]}]},
        agent_id="a", timestamp=FIXED_TS)
    assert len(evs) == 1 and evs[0].attributes["rule_id"] == "R1"
