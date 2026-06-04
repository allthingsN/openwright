"""Continuous coverage dashboard (FR-RPT-06).

Renders a self-contained static HTML page (no JS, no external assets) showing
per-control status across a series of signed reports — coverage and gaps over
time. Takes the reports you already produce; stores nothing itself.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, List

from .report import BOUNDARY_STATEMENT

_COLOR = {
    "satisfied": "#2e7d32",
    "not_satisfied": "#c62828",
    "insufficient_evidence": "#f9a825",
    "absent": "#bdbdbd",
}
_SYMBOL = {"satisfied": "✓", "not_satisfied": "✗", "insufficient_evidence": "?", "absent": "·"}


def build_dashboard(reports: List[Dict[str, Any]]) -> str:
    """Return a static HTML coverage dashboard for a time-ordered list of reports."""
    reports = sorted(reports, key=lambda r: r.get("generated_at", ""))
    control_ids: List[str] = []
    titles: Dict[str, str] = {}
    for r in reports:
        for c in r.get("controls", []):
            if c["control_id"] not in titles:
                control_ids.append(c["control_id"])
                titles[c["control_id"]] = c.get("title", c["control_id"])

    def status_at(report: Dict[str, Any], cid: str) -> str:
        for c in report.get("controls", []):
            if c["control_id"] == cid:
                return c["status"]
        return "absent"

    head_cells = "".join(
        f'<th title="{html.escape(r.get("crosswalk",{}).get("title",""))}">'
        f'{html.escape(r.get("generated_at","")[:19])}<br/><small>{html.escape(r.get("report_id","")[:14])}</small></th>'
        for r in reports
    )
    rows = []
    for cid in control_ids:
        cells = []
        for r in reports:
            st = status_at(r, cid)
            cells.append(
                f'<td style="background:{_COLOR[st]};color:#fff;text-align:center" '
                f'title="{html.escape(st)}">{_SYMBOL[st]}</td>'
            )
        rows.append(
            f'<tr><th style="text-align:left">{html.escape(cid)}<br/>'
            f'<small>{html.escape(titles[cid])}</small></th>{"".join(cells)}</tr>'
        )

    # coverage trend (satisfied / total per report)
    trend = []
    for r in reports:
        s = r.get("summary", {})
        total = s.get("total", 0) or 1
        pct = round(100 * s.get("satisfied", 0) / total)
        trend.append(
            f'<div style="display:inline-block;text-align:center;margin:0 6px">'
            f'<div style="height:120px;width:30px;background:#eee;position:relative;border-radius:3px">'
            f'<div style="position:absolute;bottom:0;width:100%;height:{pct}%;background:#2e7d32;border-radius:3px"></div>'
            f'</div><small>{pct}%</small></div>'
        )

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>OpenWright coverage dashboard</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}} th,td{{border:1px solid #ddd;padding:6px;font-size:12px}}
.note{{background:#fff3cd;border:1px solid #ffc107;padding:.6rem;border-radius:6px;font-size:.85rem}}
.legend span{{display:inline-block;margin-right:1rem}}
</style></head><body>
<h1>OpenWright — control coverage over time</h1>
<p class="note">{html.escape(BOUNDARY_STATEMENT)}</p>
<div class="legend">
 <span style="color:{_COLOR['satisfied']}">&#9632; satisfied</span>
 <span style="color:{_COLOR['not_satisfied']}">&#9632; not satisfied</span>
 <span style="color:{_COLOR['insufficient_evidence']}">&#9632; insufficient evidence</span>
 <span style="color:{_COLOR['absent']}">&#9632; not in scope</span>
</div>
<h2>Coverage trend (% satisfied)</h2>
<div>{''.join(trend) or '<em>no reports</em>'}</div>
<h2>Per-control status</h2>
<table><thead><tr><th>Control</th>{head_cells}</tr></thead><tbody>{''.join(rows)}</tbody></table>
</body></html>"""


def write_dashboard(report_paths: List[str], out_path: str) -> str:
    reports = [json.loads(open(p, encoding="utf-8").read()) for p in report_paths]
    open(out_path, "w", encoding="utf-8").write(build_dashboard(reports))
    return out_path
