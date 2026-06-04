// Automated Pyodide (WASM CPython) end-to-end test of the single-file OpenWright
// verifier (B10/V5). Loads the *unchanged* web/openwright_verifier.py inside a real
// WebAssembly Python runtime, verifies a real signed report, and confirms tamper is
// caught. The Pyodide runtime is the locally-installed npm package (bundled, no CDN),
// which is exactly the "no network" path the browser verifier can also use.
//
// Usage: node run_verify.mjs <report.json> <public_key.pem>
// Exit 0 = honest report verified AND a tampered report rejected; non-zero otherwise.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadPyodide } from "pyodide";

const here = dirname(fileURLToPath(import.meta.url));

async function main() {
  const [, , reportPath, pemPath] = process.argv;
  if (!reportPath || !pemPath) {
    console.error("usage: node run_verify.mjs <report.json> <public_key.pem>");
    process.exit(2);
  }

  // Load the verifier as an imported module (not __main__) so its CLI guard
  // (`if __name__ == "__main__": sys.exit(main(...))`) does not fire here.
  const verifierSrc =
    '__name__ = "openwright_verifier_wasm"\n' +
    readFileSync(join(here, "..", "openwright_verifier.py"), "utf8");
  const reportJson = readFileSync(reportPath, "utf8");
  const pem = readFileSync(pemPath, "utf8");

  const pyodide = await loadPyodide();
  pyodide.runPython(verifierSrc);
  pyodide.globals.set("PEM", pem);

  function verify(jsonStr) {
    pyodide.globals.set("REPORT_JSON", jsonStr);
    return pyodide.runPython(`
import json as _json
_report = _json.loads(REPORT_JSON)
_pub = pubkey_raw_from_pem(PEM)
_valid, _checks = verify_report(_report, _pub)
bool(_valid)
`);
  }

  const honestOk = verify(reportJson);
  if (!honestOk) {
    console.error("FAIL: honest report did not verify under WASM Pyodide");
    process.exit(1);
  }

  // Tamper: flip an event's output reference without re-signing -> must be caught.
  const tampered = JSON.parse(reportJson);
  let mutated = false;
  for (const item of tampered.events || []) {
    const ev = item.event || {};
    if (ev.io && ev.io.output_ref) {
      ev.io.output_ref = "sha256:" + "00".repeat(32);
      mutated = true;
      break;
    }
  }
  if (!mutated && (tampered.events || []).length) {
    tampered.events[0].event.timestamp = "1999-01-01T00:00:00.000000000Z";
    mutated = true;
  }
  const tamperedRejected = !verify(JSON.stringify(tampered));
  if (!tamperedRejected) {
    console.error("FAIL: tampered report was NOT rejected under WASM Pyodide");
    process.exit(1);
  }

  console.log("OK: WASM Pyodide verified the honest report and rejected the tampered one");
  process.exit(0);
}

main().catch((e) => {
  console.error("ERROR:", e);
  process.exit(3);
});
