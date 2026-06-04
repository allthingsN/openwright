# OpenWright in-browser / WASM verifier

The single-file, zero-third-party-dependency verifier `openwright_verifier.py` is the
auditable root of trust in its purest form (FR-VER-03): pure Python, standard library
only, no `cryptography`, no network. It runs unchanged in CPython **and** inside a stock
WebAssembly Python (Pyodide) in the browser (FR-VER-04).

## What it proves

Given a signed report and the signer's public key (PEM):

- report + checkpoint Ed25519 signatures (pure-Python RFC 8032 verification),
- every event's leaf hash recomputes from hash-only content (no raw payloads),
- every inclusion proof against the signed root, plus the full-tree root,
- that cited evidence events are present.

## Run it in a browser

```bash
python -m http.server      # from this directory
# open http://localhost:8000/verifier.html
```

Paste a `report.json` and the signer's public key (PEM) and click **Verify**.

### Network claim (accurate)

Verification is **fully local** — your report and key are never sent anywhere, and the
page never contacts the report producer or any OpenWright server. The **only** network
fetch is the one-time WebAssembly runtime (Pyodide). By default it loads from a public
CDN. For a fully offline / air-gapped verifier, **self-host Pyodide**:

1. Download a Pyodide release (e.g. `pyodide-0.26.2.tar.bz2`) and serve its `full/`
   directory from your own origin, e.g. `https://verify.example.com/pyodide/`.
2. Open the verifier with `?pyodide=https://verify.example.com/pyodide/`.

Then there is no network dependency on any third party at all.

## Automated WASM test (V5)

`wasm_test/` runs the **unchanged** `openwright_verifier.py` inside a real Pyodide
(WebAssembly CPython) runtime — the locally-installed `pyodide` npm package, i.e. the
no-CDN path — verifies a real signed report end-to-end, and confirms a tampered report
is rejected.

```bash
cd web/wasm_test && npm install            # one-time: fetches the Pyodide runtime
# driven automatically by: pytest tests/test_wasm_verifier.py
node run_verify.mjs <report.json> <public_key.pem>
```

`tests/test_wasm_verifier.py` generates a fresh signed report from the current code,
then drives `run_verify.mjs`; it skips cleanly when node / the Pyodide package aren't
installed.
