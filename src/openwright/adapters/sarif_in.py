"""SARIF side-channel ingest (FR-ING-07).

Consumes SARIF 2.1.0 findings from conformance/security scanners (e.g. a2a-tck,
Cisco a2a-scanner) and attaches them as ``conformance_finding`` events to an
agent. We *consume* scanner output; we do not re-implement scanning (OOS-03).
SARIF is treated as untrusted input (FR-ING-10, NFR-SEC-01): structure is
validated defensively and malformed entries are skipped, not crashed on.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..events import ComplianceEvent, EventKind


def sarif_to_events(
    sarif: Dict[str, Any],
    *,
    agent_id: str,
    timestamp: str,
    task_id: Optional[str] = None,
) -> List[ComplianceEvent]:
    """Convert a SARIF log into conformance-finding events (best-effort, safe)."""
    events: List[ComplianceEvent] = []
    if not isinstance(sarif, dict):
        return events
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        return events

    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = (((run.get("tool") or {}).get("driver")) or {})
        tool_name = driver.get("name") if isinstance(driver, dict) else None
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for res in results:
            if not isinstance(res, dict):
                continue
            message = ""
            if isinstance(res.get("message"), dict):
                message = str(res["message"].get("text", ""))
            locations = []
            for loc in res.get("locations", []) if isinstance(res.get("locations"), list) else []:
                phys = loc.get("physicalLocation", {}) if isinstance(loc, dict) else {}
                art = phys.get("artifactLocation", {}) if isinstance(phys, dict) else {}
                region = phys.get("region", {}) if isinstance(phys, dict) else {}
                locations.append({"uri": art.get("uri"), "startLine": region.get("startLine")})
            events.append(
                ComplianceEvent(
                    timestamp=timestamp,
                    kind=EventKind.CONFORMANCE_FINDING,
                    actor={"agent_id": agent_id},
                    provenance={"task_id": task_id} if task_id else {},
                    attributes={
                        "tool": tool_name,
                        "rule_id": res.get("ruleId"),
                        "level": res.get("level", "warning"),
                        "message": message,
                        "locations": locations,
                    },
                    source={"format": "sarif"},
                )
            )
    return events
