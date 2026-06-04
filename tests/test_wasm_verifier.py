"""In-browser/WASM verifier end-to-end test (B10/V5).

Runs the unchanged single-file ``web/openwright_verifier.py`` inside a real
WebAssembly Python (Pyodide, via the locally-installed npm package — the same
runtime the browser uses, and the no-CDN path) and confirms it verifies a real
signed report and rejects a tampered one. Skips cleanly when node/pyodide aren't
installed (the npm runtime is a one-time `npm install` under web/wasm_test).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.report import build_report
from openwright.signing import public_key_pem

WASM_DIR = Path(__file__).resolve().parent.parent / "web" / "wasm_test"


pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not (WASM_DIR / "node_modules" / "pyodide").exists(),
    reason="node + web/wasm_test/node_modules/pyodide required (run `npm install` in web/wasm_test)",
)


def test_wasm_pyodide_verifies_real_report_end_to_end(populated_ledger, key, tmp_path):
    result = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    report = build_report(populated_ledger, result, key, scope_description="wasm e2e")

    fixtures = WASM_DIR / "fixtures"
    fixtures.mkdir(exist_ok=True)
    report_path = fixtures / "report.json"
    pem_path = fixtures / "public_key.pem"
    report_path.write_text(json.dumps(report))
    pem_path.write_bytes(public_key_pem(key.public_key_raw()))

    proc = subprocess.run(
        ["node", "run_verify.mjs", str(report_path), str(pem_path)],
        cwd=WASM_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"WASM verify failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
    assert "OK:" in proc.stdout
