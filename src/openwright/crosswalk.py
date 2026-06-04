"""Declarative control crosswalks and the engine that evaluates them.

A *crosswalk* maps canonical events to regulatory controls. Per FR-MAP-01 the
mapping is **data, not code**: a crosswalk is a versioned YAML document and this
module is a generic interpreter — there is no per-article logic hard-coded in
Python. Per FR-MAP-06 each control states a *testable predicate over events*;
per FR-MAP-07 evaluation yields exactly one of **satisfied / not_satisfied /
insufficient_evidence** and never collapses "insufficient" into "not satisfied".
Per FR-MAP-04/05 every control cites its primary source and every crosswalk is
independently versioned.
"""

from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .canonical import canonical_bytes, sha256_hex
from .events import ComplianceEvent


class ControlStatus(str, enum.Enum):
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not_satisfied"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class EmptyScopePolicy(str, enum.Enum):
    """What to report when no events fall in a control's scope."""

    INSUFFICIENT = "insufficient_evidence"  # default and honest
    SATISFIED = "satisfied"  # vacuously true (use sparingly, document why)
    NOT_SATISFIED = "not_satisfied"


# -- declarative schema -------------------------------------------------------


class EventFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Optional[List[str]] = None
    risk_classification: Optional[List[str]] = None
    oversight_status: Optional[List[str]] = None
    source_format: Optional[List[str]] = None
    attribute_equals: Dict[str, Any] = Field(default_factory=dict)
    has: List[str] = Field(default_factory=list)  # dotted paths that must be non-null


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str  # committed | field | linked | any_of | all_of | not
    # field
    path: Optional[str] = None
    op: Optional[str] = None  # eq | ne | in | exists | gte | lte
    value: Any = None
    # linked
    link: Optional[str] = None  # approval_ref | same_task | same_context | references_root
    target: Optional[EventFilter] = None
    # composite
    conditions: List["Condition"] = Field(default_factory=list)


class Citation(BaseModel):
    model_config = ConfigDict(extra="allow")
    instrument: str
    article: Optional[str] = None
    clause: Optional[str] = None
    paragraphs: List[str] = Field(default_factory=list)
    url: Optional[str] = None
    quote: Optional[str] = None
    effective_date: Optional[str] = None
    notes: Optional[str] = None


class Control(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str
    requirement: str
    citation: Citation
    scope: EventFilter = Field(default_factory=EventFilter)
    condition: Condition
    empty_scope: EmptyScopePolicy = EmptyScopePolicy.INSUFFICIENT
    rationale: Optional[str] = None
    # When true, an attested ``evidence_gap`` marker anywhere in the evaluated set
    # forces this control to not_satisfied (U1): a record-keeping/completeness
    # obligation cannot be "satisfied" while the log itself attests lost events.
    completeness_sensitive: bool = False
    # Deployer-profile variants (B14). ``variant`` is an informational label
    # (e.g. "in_the_loop"/"on_the_loop"); ``applies_to_profiles`` gates the control
    # to a deployer profile — empty means it always applies. See ``select_profile``.
    variant: Optional[str] = None
    applies_to_profiles: List[str] = Field(default_factory=list)


class Crosswalk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str
    version: str
    source: str
    reviewed_as_of: str
    description: Optional[str] = None
    disclaimer: Optional[str] = None
    # Deployer profiles selected when a caller requests none (B14). A control with
    # no ``applies_to_profiles`` always applies; these defaults decide which
    # profile-gated controls (e.g. the in-the-loop Art-14 variant, FRIA-only Art-27)
    # are included by default, preserving the unprofiled behavior.
    default_profiles: List[str] = Field(default_factory=list)
    controls: List[Control]


Condition.model_rebuild()


def select_profile(crosswalk: "Crosswalk", profile: Optional[List[str]] = None) -> "Crosswalk":
    """Return the crosswalk with only the controls applicable to a deployer profile (B14).

    A control with no ``applies_to_profiles`` always applies; one that lists profiles
    applies iff the selected set intersects it. When ``profile`` is ``None`` the
    crosswalk's ``default_profiles`` are used (so unprofiled callers get a stable,
    backward-compatible control set). The returned crosswalk is a real variant — its
    content hash (B9) reflects exactly the controls evaluated under this profile.
    """
    selected = set(profile) if profile is not None else set(crosswalk.default_profiles)
    controls = [
        c for c in crosswalk.controls
        if not c.applies_to_profiles or (set(c.applies_to_profiles) & selected)
    ]
    return crosswalk.model_copy(update={"controls": controls})


# -- results ------------------------------------------------------------------


class ControlResult(BaseModel):
    control_id: str
    title: str
    status: ControlStatus
    requirement: str
    citation: Citation
    reason: str
    evaluated_count: int
    satisfied_count: int
    evidence_event_ids: List[str] = Field(default_factory=list)
    gap_event_ids: List[str] = Field(default_factory=list)


def crosswalk_content_hash(crosswalk: Crosswalk) -> str:
    """``sha256:<hex>`` over the canonical crosswalk definition (B9).

    Hashes the whole parsed crosswalk — id, version, every control's predicate and
    citation — so any change to what is evaluated changes the hash. It is computed
    over the model, not the YAML text, so formatting/comments don't affect it; a
    verifier that loads the same crosswalk reproduces the exact hash. This is what
    a report pins so deep-verify can refuse a mismatched/absent crosswalk.
    """
    return "sha256:" + sha256_hex(canonical_bytes(crosswalk.model_dump(mode="json", exclude_none=True)))


class CrosswalkResult(BaseModel):
    crosswalk_id: str
    crosswalk_title: str
    crosswalk_version: str
    crosswalk_content_hash: Optional[str] = None
    source: str
    reviewed_as_of: str
    disclaimer: Optional[str] = None
    controls: List[ControlResult]

    @property
    def satisfied(self) -> int:
        return sum(1 for c in self.controls if c.status == ControlStatus.SATISFIED)

    @property
    def not_satisfied(self) -> int:
        return sum(1 for c in self.controls if c.status == ControlStatus.NOT_SATISFIED)

    @property
    def insufficient(self) -> int:
        return sum(1 for c in self.controls if c.status == ControlStatus.INSUFFICIENT_EVIDENCE)


# -- evaluation ---------------------------------------------------------------

_MAX_IDS = 50  # cap evidence/gap id lists in results to keep reports bounded


def _get(d: dict, dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _matches(ev: dict, f: EventFilter) -> bool:
    if f.kind is not None and ev.get("kind") not in f.kind:
        return False
    if f.risk_classification is not None and _get(ev, "risk.classification") not in f.risk_classification:
        return False
    if f.oversight_status is not None and _get(ev, "oversight.status") not in f.oversight_status:
        return False
    if f.source_format is not None and _get(ev, "source.format") not in f.source_format:
        return False
    for path, val in f.attribute_equals.items():
        if _get(ev, path) != val:
            return False
    for path in f.has:
        if _get(ev, path) is None:
            return False
    return True


class _Index:
    def __init__(self, events: List[dict]) -> None:
        self.events = events
        self.by_id = {e["event_id"]: e for e in events if e.get("event_id")}


def _holds(ev: dict, cond: Condition, idx: _Index) -> bool:
    t = cond.type
    if t == "committed":
        # being present in the evaluated ledger snapshot is itself the evidence
        return bool(_get(ev, "ledger.leaf_hash"))
    if t == "field":
        actual = _get(ev, cond.path) if cond.path else None
        op = cond.op or "exists"
        if op == "exists":
            return actual is not None
        if op == "eq":
            return actual == cond.value
        if op == "ne":
            return actual != cond.value
        if op == "in":
            return actual in (cond.value or [])
        if op == "gte":
            return actual is not None and actual >= cond.value
        if op == "lte":
            return actual is not None and actual <= cond.value
        return False
    if t == "linked":
        return _linked(ev, cond, idx)
    if t == "any_of":
        return any(_holds(ev, c, idx) for c in cond.conditions)
    if t == "all_of":
        return all(_holds(ev, c, idx) for c in cond.conditions)
    if t == "not":
        return not all(_holds(ev, c, idx) for c in cond.conditions)
    raise ValueError(f"unknown condition type: {t!r}")


def _linked(ev: dict, cond: Condition, idx: _Index) -> bool:
    target = cond.target
    link = cond.link
    if link == "approval_ref":
        ref = _get(ev, "oversight.approval_ref")
        if not ref:
            return False
        cand = idx.by_id.get(ref)
        return cand is not None and (target is None or _matches(cand, target))
    if link in ("same_task", "same_context", "references_root"):
        key = {
            "same_task": "provenance.task_id",
            "same_context": "provenance.context_id",
            "references_root": "provenance.root_task_id",
        }[link]
        mine = _get(ev, key)
        if mine is None:
            return False
        for other in idx.events:
            if other is ev:
                continue
            if _get(other, key) == mine and (target is None or _matches(other, target)):
                return True
        return False
    raise ValueError(f"unknown link type: {link!r}")


def evaluate(crosswalk: Crosswalk, events: List[ComplianceEvent]) -> CrosswalkResult:
    """Evaluate every control against ``events`` with strict three-state results."""
    dicts = [e.model_dump(mode="json", exclude_none=True) for e in events]
    idx = _Index(dicts)
    results: List[ControlResult] = []

    # Attested evidence-gap markers (from the ingest pipeline's drop accounting)
    # make any completeness-sensitive control fail (U1). Collected once here.
    gap_markers = [e for e in dicts if (e.get("attributes") or {}).get("marker") == "evidence_gap"]
    gap_ids = [e["event_id"] for e in gap_markers if e.get("event_id")][:_MAX_IDS]
    gap_dropped = sum(int((e.get("attributes") or {}).get("dropped_events") or 0) for e in gap_markers)

    for ctrl in crosswalk.controls:
        scoped = [e for e in dicts if _matches(e, ctrl.scope)]
        if not scoped:
            status = ControlStatus(ctrl.empty_scope.value)
            reason = (
                "No events fell within this control's scope, so there is nothing to "
                "evaluate. Reported as insufficient evidence rather than a failure "
                "(FR-MAP-07)."
                if status == ControlStatus.INSUFFICIENT_EVIDENCE
                else f"No events in scope; control policy treats empty scope as {status.value}."
            )
            results.append(
                ControlResult(
                    control_id=ctrl.id,
                    title=ctrl.title,
                    status=status,
                    requirement=ctrl.requirement,
                    citation=ctrl.citation,
                    reason=reason,
                    evaluated_count=0,
                    satisfied_count=0,
                )
            )
            continue

        passed = [e for e in scoped if _holds(e, ctrl.condition, idx)]
        violators = [e for e in scoped if e not in passed]
        if violators:
            status = ControlStatus.NOT_SATISFIED
            reason = (
                f"{len(violators)} of {len(scoped)} in-scope event(s) did not satisfy the "
                f"required predicate."
            )
        else:
            status = ControlStatus.SATISFIED
            reason = f"All {len(scoped)} in-scope event(s) satisfied the required predicate."

        results.append(
            ControlResult(
                control_id=ctrl.id,
                title=ctrl.title,
                status=status,
                requirement=ctrl.requirement,
                citation=ctrl.citation,
                reason=reason,
                evaluated_count=len(scoped),
                satisfied_count=len(passed),
                evidence_event_ids=[e["event_id"] for e in passed][:_MAX_IDS],
                gap_event_ids=[e["event_id"] for e in violators][:_MAX_IDS],
            )
        )

    # Completeness override (U1): a self-attested gap forces completeness-sensitive
    # controls (e.g. EU AI Act Art. 12 record-keeping) to not_satisfied, rather
    # than letting the gap markers sit out-of-scope as GENERIC events.
    if gap_markers:
        sensitive = {c.id for c in crosswalk.controls if c.completeness_sensitive}
        for r in results:
            if r.control_id in sensitive and r.status != ControlStatus.NOT_SATISFIED:
                r.status = ControlStatus.NOT_SATISFIED
                r.reason = (
                    f"Record-keeping completeness fails: the log self-attests "
                    f"{len(gap_markers)} evidence-gap marker(s) (~{gap_dropped} dropped "
                    f"event(s)). " + r.reason
                )
                r.gap_event_ids = (list(r.gap_event_ids) + gap_ids)[:_MAX_IDS]

    return CrosswalkResult(
        crosswalk_id=crosswalk.id,
        crosswalk_title=crosswalk.title,
        crosswalk_version=crosswalk.version,
        crosswalk_content_hash=crosswalk_content_hash(crosswalk),
        source=crosswalk.source,
        reviewed_as_of=crosswalk.reviewed_as_of,
        disclaimer=crosswalk.disclaimer,
        controls=results,
    )
