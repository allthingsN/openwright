// Headless WASM test of the interactive demo PAGE (openwright demo).
// Extracts the page's embedded report + public key + verifier source exactly as
// the page's own JS does, then runs the same Pyodide verify flow — proving the
// in-browser "Verify this report" / "Tamper" experience actually works in WASM.
//
// Usage: node run_demo_page.mjs <demo.html>

import { readFileSync } from "node:fs";
import { loadPyodide } from "pyodide";

const html = readFileSync(process.argv[2], "utf8");
const blob = (id) => {
  const m = html.match(new RegExp(`id="${id}">([\\s\\S]*?)</script>`));
  if (!m) throw new Error(`embedded block ${id} not found`);
  return JSON.parse(m[1]); // \/ is valid JSON for /
};
const REPORT = blob("report-data");
const PUBKEY_PEM = blob("pubkey-data");
const VERIFIER_SRC = blob("verifier-src");

const py = await loadPyodide();
py.runPython('__name__ = "openwright_browser_verifier"\n' + VERIFIER_SRC);

function verify(reportObj) {
  py.globals.set("REPORT_JSON", JSON.stringify(reportObj));
  py.globals.set("PEM", PUBKEY_PEM);
  return py.runPython(`
import json as _j
_r = _j.loads(REPORT_JSON)
_pub = pubkey_raw_from_pem(PEM)
_v, _c = verify_report(_r, _pub)
bool(_v)
`);
}

const honest = verify(REPORT);
const bad = JSON.parse(JSON.stringify(REPORT));
let changed = false;
for (const it of bad.events || []) {
  if (it.event?.io?.output_ref) { it.event.io.output_ref = "sha256:" + "0".repeat(64); changed = true; break; }
}
if (!changed && (bad.events || []).length) bad.events[0].event.timestamp = "1999-01-01T00:00:00.000000000Z";
const tampered = verify(bad);

if (honest === true && tampered === false) {
  console.log("OK: demo page verifies the honest report and rejects the tampered one in WASM");
  process.exit(0);
}
console.error("FAIL:", { honest, tampered });
process.exit(1);
