"""Report generation: signed JSON, PDF, OSCAL, SARIF (FR-RPT).

The signed JSON report (FR-RPT-02) is the authoritative artifact and is
self-contained for independent verification (FR-VER-05, FR-ATT-04): it carries
the signed checkpoint, every event (hash-only — no raw payloads), and an
inclusion proof per event. The whole report is *also* signed, because the
control results are computed (not Merkle leaves) and must be tamper-evident too.

Every artifact carries the evidence-not-certification boundary (FR-RPT-07).
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import __version__
from .canonical import canonical_bytes, to_rfc3339
from .crosswalk import CrosswalkResult
from .ledger import Ledger
from .signing import Checkpoint, KeySource, public_key_pem

REPORT_VERSION = "1.0.0"

BOUNDARY_STATEMENT = (
    "This report constitutes EVIDENCE that the listed controls were exercised at "
    "runtime, attested with a tamper-evident Merkle log and an Ed25519 signature. "
    "It DOES NOT constitute legal compliance, certification, conformity assessment, "
    "or an audit opinion. Determinations of compliance are reserved for qualified "
    "auditors, notified bodies, and counsel. Crosswalks are maintainer-authored, "
    "rigorously cited, and pending qualified legal/standards review."
)


def _signing_payload(report: Dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in report.items() if k != "signature"}
    return canonical_bytes(unsigned)


def build_report(
    ledger: Ledger,
    crosswalk_result: CrosswalkResult,
    key: KeySource,
    *,
    scope_description: str,
    agent_ids: Optional[List[str]] = None,
    period: Optional[Dict[str, str]] = None,
    checkpoint: Optional[Checkpoint] = None,
    report_id: Optional[str] = None,
    generated_at: Optional[str] = None,
    principal=None,
    authorizer=None,
) -> Dict[str, Any]:
    """Assemble and sign the JSON attestation report."""
    if authorizer is not None:
        from .authz import Capability

        authorizer.require(principal, Capability.GENERATE_REPORT)
    checkpoint = checkpoint or ledger.checkpoint(key)
    tree_size = checkpoint.tree_size

    events: List[Dict[str, Any]] = []
    timestamps: List[str] = []
    seen_agents = set()
    for i in range(tree_size):
        ev = ledger.get_event(i)
        timestamps.append(ev.timestamp)
        seen_agents.add(ev.actor.agent_id)
        events.append(
            {
                "event": ev.model_dump(mode="json", exclude_none=True),
                "leaf_index": i,
                "leaf_hash": ev.ledger.leaf_hash if ev.ledger else None,
                # Pin proofs to the checkpoint's tree_size so they verify against
                # the signed root even if the ledger grew during report build (F6).
                "inclusion_proof": ledger.inclusion_proof_hex(i, tree_size=tree_size),
            }
        )

    if period is None and timestamps:
        period = {"start": min(timestamps), "end": max(timestamps)}

    # Surface self-attested evidence gaps at the top level (U1): they are part of
    # the signed payload, so the completeness story is tamper-evident and visible
    # to a reader without re-deriving it from the event list.
    evidence_gaps: List[Dict[str, Any]] = []
    for item in events:
        ev = item["event"]
        attrs = ev.get("attributes") or {}
        if attrs.get("marker") == "evidence_gap":
            evidence_gaps.append(
                {
                    "event_id": ev.get("event_id"),
                    "leaf_index": item["leaf_index"],
                    "dropped_events": attrs.get("dropped_events"),
                    "window_start": attrs.get("window_start"),
                    "window_end": attrs.get("window_end"),
                }
            )

    cr = crosswalk_result
    report: Dict[str, Any] = {
        "report_version": REPORT_VERSION,
        "report_id": report_id or f"rpt_{uuid.uuid4().hex}",
        "generated_at": generated_at or to_rfc3339(datetime.now(timezone.utc)),
        "tool": {"name": "openwright", "version": __version__},
        "boundary_statement": BOUNDARY_STATEMENT,
        "scope": {
            "description": scope_description,
            "agent_ids": sorted(agent_ids or seen_agents),
        },
        "period": period or {},
        "crosswalk": {
            "id": cr.crosswalk_id,
            "title": cr.crosswalk_title,
            "version": cr.crosswalk_version,
            # Pin the exact crosswalk definition (B9/U2): deep-verify recomputes
            # this hash from the crosswalk it loads and refuses on absence/mismatch,
            # so a verdict can't be silently re-derived under a different crosswalk.
            "content_hash": cr.crosswalk_content_hash,
            "source": cr.source,
            "reviewed_as_of": cr.reviewed_as_of,
            "disclaimer": cr.disclaimer,
        },
        "summary": {
            "total": len(cr.controls),
            "satisfied": cr.satisfied,
            "not_satisfied": cr.not_satisfied,
            "insufficient_evidence": cr.insufficient,
        },
        "controls": [c.model_dump(mode="json", exclude_none=True) for c in cr.controls],
        "evidence_gaps": evidence_gaps,
        "checkpoint": checkpoint.model_dump(mode="json"),
        "events": events,
        "public_key_pem": public_key_pem(key.public_key_raw()).decode("ascii"),
    }

    signature = key.sign(_signing_payload(report))
    report["signature"] = {
        "algorithm": "ed25519",
        "public_key_id": key.key_id(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return report


# -- OSCAL assessment-results (FR-RPT-03) -------------------------------------

# OSCAL finding.target.status.state has only {satisfied, not-satisfied}; it has
# no "insufficient evidence" state. To honor FR-MAP-07 (never collapse the two)
# we map insufficient → not-satisfied with reason "other" AND a `openwright-status`
# prop carrying the exact tri-state, so the distinction is never lost.
_OSCAL_STATE = {
    "satisfied": ("satisfied", "pass"),
    "not_satisfied": ("not-satisfied", "fail"),
    "insufficient_evidence": ("not-satisfied", "other"),
}


def to_oscal(report: Dict[str, Any]) -> Dict[str, Any]:
    now = report["generated_at"]
    findings = []
    observations = []
    for c in report["controls"]:
        obs_uuid = str(uuid.uuid4())
        observations.append(
            {
                "uuid": obs_uuid,
                "description": f"{c['title']}: {c['reason']}",
                "methods": ["TEST"],
                "collected": now,
            }
        )
        state, reason = _OSCAL_STATE[c["status"]]
        findings.append(
            {
                "uuid": str(uuid.uuid4()),
                "title": c["title"],
                "description": c["requirement"],
                "props": [
                    {"name": "openwright-status", "value": c["status"], "ns": "https://github.com/allthingsN/openwright/ns"},
                ],
                "target": {
                    "type": "objective-id",
                    "target-id": c["control_id"],
                    "status": {"state": state, "reason": reason},
                },
                "related-observations": [{"observation-uuid": obs_uuid}],
            }
        )
    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"OpenWright evidence — {report['crosswalk']['title']}",
                "last-modified": now,
                "version": report["report_id"],
                "oscal-version": "1.1.3",
                "remarks": BOUNDARY_STATEMENT,
            },
            "import-ap": {"href": "#openwright-evidence"},
            "results": [
                {
                    "uuid": str(uuid.uuid4()),
                    "title": "Runtime control evidence",
                    "description": report["scope"]["description"],
                    "start": report.get("period", {}).get("start", now),
                    "reviewed-controls": {"control-selections": [{"include-all": {}}]},
                    "observations": observations,
                    "risks": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "title": "Control gaps",
                            "description": "Controls not satisfied or with insufficient evidence.",
                            "statement": BOUNDARY_STATEMENT,
                            "status": "open",
                        }
                    ],
                    "findings": findings,
                }
            ],
        }
    }


# -- SARIF gap findings (FR-RPT-04) -------------------------------------------

_SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
_SARIF_LEVEL = {"not_satisfied": "error", "insufficient_evidence": "warning"}


def to_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    rules = []
    results = []
    for c in report["controls"]:
        if c["status"] == "satisfied":
            continue
        rules.append(
            {
                "id": c["control_id"],
                "name": c["title"],
                "shortDescription": {"text": c["requirement"][:300]},
                "helpUri": (c.get("citation") or {}).get("url"),
            }
        )
        results.append(
            {
                "ruleId": c["control_id"],
                "level": _SARIF_LEVEL.get(c["status"], "warning"),
                "message": {"text": f"{c['status']}: {c['reason']}"},
                "locations": [
                    {
                        "logicalLocations": [
                            {"name": c["control_id"], "kind": "control"}
                        ]
                    }
                ],
            }
        )
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "openwright",
                        "version": __version__,
                        "informationUri": "https://github.com/allthingsN/openwright",
                        # The evidence-not-certification boundary travels with the
                        # SARIF artifact too (FR-RPT-07: every generated report).
                        "fullDescription": {"text": BOUNDARY_STATEMENT},
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"openwright_boundary_statement": BOUNDARY_STATEMENT},
            }
        ],
    }


# -- PDF (FR-RPT-01) ----------------------------------------------------------


def render_pdf(report: Dict[str, Any], path: str) -> None:
    """Render a human-readable attestation PDF."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, leading=10)
    boundary_style = ParagraphStyle(
        "boundary", parent=styles["Normal"], fontSize=9, leading=12,
        backColor=colors.HexColor("#fff3cd"), borderColor=colors.HexColor("#ffc107"),
        borderWidth=1, borderPadding=6,
    )
    story: List[Any] = []
    story.append(Paragraph("OpenWright — Agent Evidence Attestation", styles["Title"]))
    story.append(Paragraph("Evidence of controls exercised — NOT a compliance certification", styles["Italic"]))
    story.append(Spacer(1, 0.15 * inch))

    cw = report["crosswalk"]
    meta_rows = [
        ["Report ID", report["report_id"]],
        ["Generated", report["generated_at"]],
        ["Tool", f"{report['tool']['name']} {report['tool']['version']}"],
        ["Scope", report["scope"]["description"]],
        ["Agent(s)", ", ".join(report["scope"]["agent_ids"]) or "—"],
        ["Period", f"{report.get('period',{}).get('start','—')} → {report.get('period',{}).get('end','—')}"],
        ["Crosswalk", f"{cw['title']} (v{cw['version']})"],
        ["Source", cw["source"]],
        ["Crosswalk reviewed", cw["reviewed_as_of"]],
    ]
    t = Table(meta_rows, colWidths=[1.6 * inch, 4.9 * inch])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.15 * inch))

    s = report["summary"]
    story.append(Paragraph(
        f"<b>Summary:</b> {s['satisfied']} satisfied · {s['not_satisfied']} not satisfied · "
        f"{s['insufficient_evidence']} insufficient evidence · {s['total']} controls",
        styles["Normal"],
    ))
    story.append(Spacer(1, 0.1 * inch))

    status_color = {
        "satisfied": colors.HexColor("#d4edda"),
        "not_satisfied": colors.HexColor("#f8d7da"),
        "insufficient_evidence": colors.HexColor("#fff3cd"),
    }
    rows = [["Control", "Status", "Evidence / reason"]]
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#343a40")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
    ]
    for i, c in enumerate(report["controls"], start=1):
        cite = c.get("citation", {})
        art = f"Art. {cite.get('article')}" if cite.get("article") else cite.get("clause", "")
        rows.append([
            Paragraph(f"<b>{c['control_id']}</b><br/>{art}", small),
            Paragraph(c["status"].replace("_", " "), small),
            Paragraph(f"{c['reason']} (evaluated {c['evaluated_count']}, ok {c['satisfied_count']})", small),
        ])
        style_cmds.append(("BACKGROUND", (1, i), (1, i), status_color.get(c["status"], colors.white)))
    tbl = Table(rows, colWidths=[1.5 * inch, 1.2 * inch, 3.8 * inch], repeatRows=1)
    tbl.setStyle(TableStyle(style_cmds))
    story.append(tbl)
    story.append(Spacer(1, 0.15 * inch))

    cp = report["checkpoint"]
    story.append(Paragraph("<b>Attestation checkpoint (signed tree head)</b>", styles["Normal"]))
    cp_rows = [
        ["Origin", cp["origin"]],
        ["Tree size", str(cp["tree_size"])],
        ["Root hash", cp["root_hash"]],
        ["Timestamp", cp["timestamp"]],
        ["Signing key", cp["public_key_id"]],
    ]
    cpt = Table(cp_rows, colWidths=[1.3 * inch, 5.2 * inch])
    cpt.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(cpt)
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("<b>Boundary statement</b>", styles["Normal"]))
    story.append(Paragraph(report["boundary_statement"], boundary_style))

    SimpleDocTemplate(path, pagesize=letter, title="OpenWright Attestation").build(story)
