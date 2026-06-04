"""Interactive browser-demo HTML (story + in-browser WASM verify + tamper)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.report import build_report
from openwright.signing import public_key_pem, public_key_raw_from_pem
from openwright.verify import verify_report
from openwright.web_demo import render_demo_html

ROOT = Path(__file__).resolve().parent.parent


def test_browser_verifier_copies_stay_identical():
    """The pure verifier is bundled in 3 places; they must not drift."""
    web = (ROOT / "web" / "openwright_verifier.py").read_bytes()
    pkg = (ROOT / "src" / "openwright" / "browser_verifier.py").read_bytes()
    npm = (ROOT / "packages" / "npm" / "openwright" / "src" / "openwright_verifier.py").read_bytes()
    assert web == pkg == npm, "browser verifier copies drifted; resync from web/openwright_verifier.py"


def _demo_html(populated_ledger, key):
    report = build_report(
        populated_ledger,
        evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events())),
        key,
        scope_description="demo",
    )
    pem = public_key_pem(key.public_key_raw()).decode("ascii")
    html = render_demo_html(
        report, pem,
        narrative={"art14_before": "insufficient_evidence", "art14_after": "satisfied",
                   "downstream_spans": 4, "receipt_format": "receipt/action-v1"},
    )
    return report, pem, html


def test_demo_html_is_self_contained(populated_ledger, key):
    _, _, html = _demo_html(populated_ledger, key)
    # Embeds everything needed to run with no server and no producer contact.
    for needle in ('id="report-data"', 'id="pubkey-data"', 'id="verifier-src"',
                   "loadPyodide", "verify_report", "pubkey_raw_from_pem",
                   "Verify this report", "Tamper with an event"):
        assert needle in html, needle
    # Carries the evidence-not-compliance boundary.
    assert "Boundary:" in html


def test_demo_html_embeds_the_real_report_and_it_verifies(populated_ledger, key):
    report, pem, html = _demo_html(populated_ledger, key)
    m = re.search(r'id="report-data">(.*?)</script>', html, re.S)
    assert m, "report data block not found"
    embedded = json.loads(m.group(1))  # \/ is valid JSON for /, so this round-trips
    assert embedded == report
    # The embedded report is genuinely verifiable (the page lets a user confirm this in WASM).
    vr = verify_report(embedded, trusted_public_key_raw=public_key_raw_from_pem(pem.encode("ascii")))
    assert vr.valid


def test_run_demo_writes_demo_html(tmp_path):
    from openwright.demo import run_demo

    out = run_demo(tmp_path)
    page = Path(out["demo_html"])
    assert page.exists() and page.suffix == ".html"
    text = page.read_text(encoding="utf-8")
    assert "Verify this report" in text and 'id="verifier-src"' in text
