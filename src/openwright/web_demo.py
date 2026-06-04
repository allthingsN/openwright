"""Interactive in-browser demo page (`openwright demo` opens this).

Renders a single, self-contained HTML file that lets a person actually *see and
understand* what the demo did — and, crucially, **verify the real signed report
offline, in their own browser**, using the audited single-file pure-Python
verifier running inside WebAssembly (Pyodide). A "Tamper" button mutates the
report and re-verifies so the user watches verification fail, then restores it.

Everything is embedded inline (the report, the signer's public key, and the
verifier source), so the file works when opened directly (``file://``) with no
server and no calls back to the producer. The only network use is the one-time
Pyodide runtime, which loads from a CDN by default (override with
``?pyodide=<base-url>`` for fully offline use).
"""

from __future__ import annotations

import html
import json
from importlib import resources
from typing import Any, Dict, Optional

from .report import BOUNDARY_STATEMENT

_COLOR = {
    "satisfied": "#2e7d32",
    "not_satisfied": "#c62828",
    "insufficient_evidence": "#f9a825",
    "absent": "#9e9e9e",
}
_LABEL = {
    "satisfied": "satisfied",
    "not_satisfied": "not satisfied",
    "insufficient_evidence": "insufficient evidence",
    "absent": "not in scope",
}


def _browser_verifier_src() -> str:
    return resources.files("openwright").joinpath("browser_verifier.py").read_text(encoding="utf-8")


def _json_blob(value: Any) -> str:
    # Safe to drop inside a <script type="application/json"> tag.
    return json.dumps(value).replace("</", "<\\/")


def _step(n: int, title: str, body: str, tone: str = "") -> str:
    cls = f" step--{tone}" if tone else ""
    return (
        f'<li class="step{cls}"><span class="step__n">{n}</span>'
        f'<div><h3>{html.escape(title)}</h3><p>{body}</p></div></li>'
    )


def render_demo_html(
    report: Dict[str, Any],
    public_key_pem: str,
    *,
    narrative: Dict[str, Any],
) -> str:
    """Return a self-contained interactive HTML demo page for one signed report."""
    cw = report.get("crosswalk", {})
    cp = report.get("checkpoint", {})
    summary = report.get("summary", {})
    a14_before = narrative.get("art14_before", "insufficient_evidence")
    a14_after = narrative.get("art14_after", "satisfied")
    spans = narrative.get("downstream_spans", 0)
    n_events = len(report.get("events", []))
    receipt_fmt = narrative.get("receipt_format", "receipt")

    # -- story timeline -------------------------------------------------------
    steps = "".join([
        _step(1, "Telemetry forks, untouched",
              f"A real OpenTelemetry agent exported spans through the OpenWright collector. "
              f"Your downstream backend received <b>{spans} spans unchanged</b>; a copy was forked "
              f"into the evidence ledger. An OpenWright failure can never drop or alter your primary telemetry."),
        _step(2, "It sits on top of a signed receipt",
              f"The agent's tool call also produced a signed action receipt. OpenWright "
              f"verified its Ed25519 signature <i>before</i> ingest and turned it into a "
              f"<code>{html.escape(receipt_fmt)}</code> evidence event — it builds on receipt primitives, not against them."),
        _step(3, "It catches the real gap (red)",
              f"First evaluation: Art. 12 record-keeping <b>satisfied</b>, but Art. 14 human-oversight "
              f"= <span class=\"pill\" style=\"background:{_COLOR.get(a14_before)}\">{_LABEL.get(a14_before, a14_before)}</span> "
              f"— the high-risk decision wasn't yet proven to be overseen. This is the gap an auditor cares about.",
              tone="bad"),
        _step(4, "Remediate, and watch it flip (green)",
              f"A human approval was recorded via the SDK and the decision finalized. Re-evaluation flips "
              f"Art. 14 to <span class=\"pill\" style=\"background:{_COLOR.get(a14_after)}\">{_LABEL.get(a14_after, a14_after)}</span>. "
              f"<b>Find the missing control, fix it, prove it.</b>",
              tone="good"),
        _step(5, "Verify it yourself — offline, below",
              "The signed report carries only hashes (no prompts, no PII). The panel below runs the "
              "<b>audited verifier inside your browser</b> (WebAssembly) — no server, nothing sent anywhere — "
              "to check the signatures, every event's hash, the inclusion proofs, and the Merkle root."),
        _step(6, "Tamper-evident",
              "Change one field and verification fails; restore it and it passes again. That is the whole "
              "point: anyone can independently confirm the evidence wasn't altered."),
    ])

    # -- controls table -------------------------------------------------------
    rows = []
    for c in report.get("controls", []):
        st = c.get("status", "absent")
        cite = c.get("citation", {})
        art = f"Art. {cite.get('article')}" if cite.get("article") else cite.get("clause", "")
        rows.append(
            f'<tr><td><b>{html.escape(c.get("control_id",""))}</b><br>'
            f'<small>{html.escape(c.get("title",""))}</small></td>'
            f'<td><small>{html.escape(art)}</small></td>'
            f'<td><span class="pill" style="background:{_COLOR.get(st, _COLOR["absent"])}">{_LABEL.get(st, st)}</span></td>'
            f'<td><small>{html.escape((c.get("reason","") or "")[:200])}</small></td></tr>'
        )
    controls_table = "".join(rows)

    boundary = html.escape(BOUNDARY_STATEMENT)
    root = html.escape(str(cp.get("root_hash", "")))
    key_id = html.escape(str((report.get("signature", {}) or {}).get("public_key_id", "")))

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>OpenWright — interactive evidence demo</title>
<style>
:root{{--ok:#2e7d32;--bad:#c62828;--warn:#f9a825;--ink:#1c2530;--muted:#5b6673;--line:#e2e6ea}}
*{{box-sizing:border-box}}
body{{font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--ink);max-width:920px;margin:0 auto;padding:1.5rem 1.1rem 4rem}}
h1{{font-size:1.5rem;margin:.2rem 0}} h2{{font-size:1.15rem;margin:2rem 0 .6rem}} h3{{font-size:1rem;margin:0 0 .15rem}}
.sub{{color:var(--muted);margin:.1rem 0 1rem}}
.boundary{{background:#fff8e1;border:1px solid var(--warn);border-radius:8px;padding:.7rem .9rem;font-size:.85rem}}
.card{{border:1px solid var(--line);border-radius:10px;padding:1rem 1.1rem;margin:1rem 0;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.03)}}
ol.steps{{list-style:none;padding:0;margin:0}}
.step{{display:flex;gap:.8rem;padding:.7rem 0;border-bottom:1px solid var(--line)}} .step:last-child{{border:0}}
.step__n{{flex:0 0 28px;height:28px;border-radius:50%;background:var(--ink);color:#fff;display:flex;align-items:center;justify-content:center;font-size:.85rem;font-weight:600}}
.step--good .step__n{{background:var(--ok)}} .step--bad .step__n{{background:var(--bad)}}
.step p{{margin:.15rem 0;color:var(--muted)}}
.pill{{display:inline-block;color:#fff;border-radius:999px;padding:.05rem .55rem;font-size:.78rem;white-space:nowrap}}
.flip{{display:flex;align-items:center;gap:.6rem;font-size:1.05rem;margin:.3rem 0}}
.arrow{{color:var(--muted)}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}} td,th{{border:1px solid var(--line);padding:.45rem .55rem;vertical-align:top;text-align:left}}
button{{font:inherit;padding:.55rem 1rem;border-radius:8px;border:1px solid var(--ink);background:var(--ink);color:#fff;cursor:pointer}}
button.secondary{{background:#fff;color:var(--ink)}} button:disabled{{opacity:.5;cursor:default}}
.verify-head{{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center}}
.badge{{font-weight:700;padding:.1rem .6rem;border-radius:6px;color:#fff}}
.checks{{margin:.8rem 0 0;font-family:ui-monospace,Menlo,monospace;font-size:.85rem}}
.checks div{{padding:.12rem 0}} .ok{{color:var(--ok)}} .fail{{color:var(--bad)}}
.kv{{font-family:ui-monospace,Menlo,monospace;font-size:.8rem;color:var(--muted);word-break:break-all}}
.muted{{color:var(--muted);font-size:.85rem}}
</style></head><body>

<h1>OpenWright — what just happened</h1>
<p class="sub">A high-risk loan-decisioning agent (EU AI Act, Annex III), turned into signed, tamper-evident, control-mapped evidence — then verified, by you, right here.</p>
<div class="boundary"><b>Boundary:</b> {boundary}</div>

<h2>The story, in six beats</h2>
<div class="card"><ol class="steps">{steps}</ol></div>

<h2>The red&rarr;green moment</h2>
<div class="card">
  <div class="flip"><b>Art. 14 human oversight</b></div>
  <div class="flip">
    before <span class="pill" style="background:{_COLOR.get(a14_before)}">{_LABEL.get(a14_before, a14_before)}</span>
    <span class="arrow">&rarr;</span>
    after <span class="pill" style="background:{_COLOR.get(a14_after)}">{_LABEL.get(a14_after, a14_after)}</span>
  </div>
  <p class="muted">Summary: {summary.get('satisfied',0)} satisfied · {summary.get('not_satisfied',0)} not satisfied · {summary.get('insufficient_evidence',0)} insufficient · {summary.get('total',0)} controls.</p>
</div>

<h2>Control results — {html.escape(str(cw.get('title','')))}</h2>
<div class="card"><table>
<thead><tr><th>Control</th><th>Article</th><th>Status</th><th>Why</th></tr></thead>
<tbody>{controls_table}</tbody></table></div>

<h2>Verify it yourself — offline, in this browser</h2>
<div class="card">
  <div class="verify-head">
    <button id="go">Verify this report</button>
    <button id="tamper" class="secondary" disabled>Tamper with an event</button>
    <button id="restore" class="secondary" disabled>Restore</button>
    <span id="badge"></span>
  </div>
  <p class="muted" id="vstatus">Runs the audited single-file verifier inside WebAssembly (Pyodide). Your report and key never leave this page.</p>
  <div class="checks" id="checks"></div>
  <p class="muted">Signed tree head: tree_size <b>{cp.get('tree_size','?')}</b> · {n_events} event(s) · signer <span class="kv">{key_id}</span></p>
  <p class="kv">root {root}</p>
</div>

<h2>Or verify from the command line</h2>
<div class="card"><p class="muted">The same check, offline, from a terminal:</p>
<pre class="kv">openwright verify report.json --pubkey public_key.pem --deep</pre>
<p class="muted"><code>--deep</code> goes further: it re-derives every control verdict from the evidence against the pinned crosswalk and refuses on mismatch.</p></div>

<script type="application/json" id="report-data">{_json_blob(report)}</script>
<script type="application/json" id="pubkey-data">{_json_blob(public_key_pem)}</script>
<script type="application/json" id="verifier-src">{_json_blob(_browser_verifier_src())}</script>
<script>
  const PYODIDE_BASE = new URLSearchParams(location.search).get("pyodide") ||
    "https://cdn.jsdelivr.net/pyodide/v0.26.2/full/";
  const REPORT = JSON.parse(document.getElementById("report-data").textContent);
  const PUBKEY_PEM = JSON.parse(document.getElementById("pubkey-data").textContent);
  const VERIFIER_SRC = JSON.parse(document.getElementById("verifier-src").textContent);
</script>
<script src="https://cdn.jsdelivr.net/pyodide/v0.26.2/full/pyodide.js" onerror="document.getElementById('vstatus').textContent='Could not load the WebAssembly runtime (offline?). Self-host Pyodide and use ?pyodide=<base-url>.'"></script>
<script>
let pyodideReady = null;
const $ = (id) => document.getElementById(id);
function setStatus(t){{ $("vstatus").textContent = t; }}

async function getPyodide(){{
  if(!pyodideReady){{
    setStatus("Loading the WebAssembly runtime (one-time download)…");
    const py = await loadPyodide({{ indexURL: PYODIDE_BASE }});
    py.runPython('__name__ = "openwright_browser_verifier"\\n' + VERIFIER_SRC);
    pyodideReady = py;
  }}
  return pyodideReady;
}}

async function verify(reportObj){{
  const py = await getPyodide();
  py.globals.set("REPORT_JSON", JSON.stringify(reportObj));
  py.globals.set("PEM", PUBKEY_PEM);
  const res = py.runPython(`
import json as _j
_r = _j.loads(REPORT_JSON)
_pub = pubkey_raw_from_pem(PEM)
_valid, _checks = verify_report(_r, _pub)
[bool(_valid), [[str(n), bool(ok)] for (n,ok) in _checks]]
`);
  const out = res.toJs({{create_proxies:false}});
  if(res.destroy) res.destroy();
  return {{ valid: out[0], checks: out[1] }};
}}

function render(result){{
  const badge = $("badge");
  badge.className = "badge";
  badge.style.background = result.valid ? "var(--ok)" : "var(--bad)";
  badge.textContent = result.valid ? "VALID" : "INVALID";
  $("checks").innerHTML = result.checks.map(
    ([name, ok]) => `<div class="${{ok?'ok':'fail'}}">[${{ok?'OK':'FAIL'}}] ${{name}}</div>`
  ).join("");
}}

$("go").onclick = async () => {{
  $("go").disabled = true;
  try {{
    const r = await verify(REPORT);
    setStatus("Verified locally — signatures, every event hash, inclusion proofs, and the Merkle root.");
    render(r);
    $("tamper").disabled = false;
  }} catch(e) {{ setStatus("error: " + e); }}
  $("go").disabled = false;
}};

$("tamper").onclick = async () => {{
  const bad = JSON.parse(JSON.stringify(REPORT));
  let changed = false;
  for(const item of (bad.events||[])){{
    if(item.event && item.event.io && item.event.io.output_ref){{ item.event.io.output_ref = "sha256:" + "0".repeat(64); changed = true; break; }}
  }}
  if(!changed && (bad.events||[]).length){{ bad.events[0].event.timestamp = "1999-01-01T00:00:00.000000000Z"; }}
  const r = await verify(bad);
  setStatus("Tampered with one event field, then re-verified — the recomputed hash no longer matches, so verification fails.");
  render(r);
  $("restore").disabled = false;
}};

$("restore").onclick = async () => {{
  const r = await verify(REPORT);
  setStatus("Restored the original report — verification passes again.");
  render(r);
}};
</script>
</body></html>"""
