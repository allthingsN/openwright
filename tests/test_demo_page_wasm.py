"""The interactive demo page verifies (and catches tamper) in real WASM (Pyodide).

Skips when node / the Pyodide npm package aren't installed (one-time `npm install`
in web/wasm_test).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.report import build_report
from openwright.signing import public_key_pem
from openwright.web_demo import render_demo_html

WASM_DIR = Path(__file__).resolve().parent.parent / "web" / "wasm_test"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not (WASM_DIR / "node_modules" / "pyodide").exists(),
    reason="node + web/wasm_test/node_modules/pyodide required (run `npm install` in web/wasm_test)",
)


def test_demo_page_verifies_and_catches_tamper_in_wasm(populated_ledger, key):
    report = build_report(
        populated_ledger,
        evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events())),
        key,
        scope_description="wasm demo page",
    )
    html = render_demo_html(
        report,
        public_key_pem(key.public_key_raw()).decode("ascii"),
        narrative={"art14_before": "insufficient_evidence", "art14_after": "satisfied",
                   "downstream_spans": 4, "receipt_format": "receipt/action-v1"},
    )
    fixtures = WASM_DIR / "fixtures"
    fixtures.mkdir(exist_ok=True)
    page = fixtures / "demo.html"
    page.write_text(html, encoding="utf-8")

    proc = subprocess.run(
        ["node", "run_demo_page.mjs", str(page)],
        cwd=WASM_DIR, capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"demo-page WASM verify failed:\n{proc.stdout}\n{proc.stderr}"
    assert "OK:" in proc.stdout
