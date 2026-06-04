"""Policy-engine decision ingest (FR-ING-09): OPA and Cedar → policy.decision events.

Consumes decision logs from Open Policy Agent (OPA) and Amazon Cedar and records
them as ``policy_decision`` events. We consume the engines' output; we do not
re-implement policy evaluation. All input is treated as untrusted (FR-ING-10):
parsing is defensive and malformed entries are skipped, not fatal.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..events import ComplianceEvent, EventKind


def _opa_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    result = entry.get("result")
    allowed = result.get("allow") if isinstance(result, dict) else result
    return {
        "engine": "opa",
        "decision_id": entry.get("decision_id"),
        "policy": entry.get("path"),
        "decision": "allow" if allowed else "deny",
        "result": result if not isinstance(result, dict) else None,
    }


def _cedar_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    decision = entry.get("decision")
    diagnostics = entry.get("diagnostics", {}) if isinstance(entry.get("diagnostics"), dict) else {}
    return {
        "engine": "cedar",
        "decision": str(decision).lower() if decision else None,
        "determining_policies": diagnostics.get("reason"),
        "errors": diagnostics.get("errors"),
    }


def policy_decisions_to_events(
    entries: List[Dict[str, Any]],
    *,
    agent_id: str,
    timestamp: str,
    engine: str = "opa",
    task_id: Optional[str] = None,
) -> List[ComplianceEvent]:
    parse = _opa_entry if engine == "opa" else _cedar_entry
    events: List[ComplianceEvent] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        attrs = {k: v for k, v in parse(entry).items() if v is not None}
        events.append(
            ComplianceEvent(
                timestamp=entry.get("timestamp") or timestamp,
                kind=EventKind.POLICY_DECISION,
                actor={"agent_id": agent_id},
                provenance={"task_id": task_id} if task_id else {},
                attributes=attrs,
                source={"format": f"policy-{engine}"},
            )
        )
    return events
