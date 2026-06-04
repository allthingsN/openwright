// OpenWright independent verifier (npm, B16).
//
// Runs the audited, zero-third-party-dependency single-file Python verifier
// (src/openwright_verifier.py) inside WebAssembly (Pyodide). Verification is fully
// local — the report and key are never sent anywhere, and no producer/server is
// contacted. The ONLY network use is Pyodide loading its runtime; pass a preloaded
// pyodide (or a self-hosted indexURL) for fully offline operation.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const VERIFIER_SRC =
  '__name__ = "openwright_verifier_wasm"\n' +
  readFileSync(join(here, "src", "openwright_verifier.py"), "utf8");

let _pyodidePromise = null;

async function getPyodide(opts = {}) {
  if (opts.pyodide) return opts.pyodide;
  if (!_pyodidePromise) {
    const { loadPyodide } = await import("pyodide");
    _pyodidePromise = loadPyodide(opts.indexURL ? { indexURL: opts.indexURL } : undefined).then((py) => {
      py.runPython(VERIFIER_SRC);
      return py;
    });
  }
  return _pyodidePromise;
}

/**
 * Verify a signed OpenWright report against the signer's public key.
 * @param {object} report                - the parsed report JSON
 * @param {string} publicKeyPem          - the signer's Ed25519 public key (PEM)
 * @param {object} [opts]                - { pyodide?, indexURL? }
 * @returns {Promise<{valid: boolean, checks: [string, boolean][]}>}
 */
export async function verifyReport(report, publicKeyPem, opts = {}) {
  const py = await getPyodide(opts);
  py.globals.set("REPORT_JSON", JSON.stringify(report));
  py.globals.set("PEM", publicKeyPem);
  const res = py.runPython(`
import json as _json
_report = _json.loads(REPORT_JSON)
_pub = pubkey_raw_from_pem(PEM)
_valid, _checks = verify_report(_report, _pub)
[bool(_valid), [[str(n), bool(ok)] for (n, ok) in _checks]]
`);
  const out = res.toJs({ create_proxies: false });
  res.destroy?.();
  return { valid: out[0], checks: out[1] };
}

export default { verifyReport };
