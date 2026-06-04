# openwright (npm) — independent, offline report verifier

Verify a signed [OpenWright](https://github.com/allthingsN/openwright) evidence report
in Node or the browser. It runs the **audited, zero-third-party-dependency single-file
Python verifier** inside WebAssembly (Pyodide), so the same trust-critical code that
ships in the Python package and the in-browser verifier checks your report — no
reimplementation to drift, nothing sent over the network.

```bash
npm i openwright
```

```js
import { verifyReport } from "openwright";

const { valid, checks } = await verifyReport(report, publicKeyPem);
// valid: boolean; checks: [name, ok][] (report/checkpoint signatures, leaf hashes,
// inclusion proofs, full-tree root, evidence-events-present)
```

CLI:

```bash
npx openwright-verify report.json public_key.pem
```

## What it checks

- report + checkpoint Ed25519 signatures (pure-Python RFC 8032),
- every event's leaf hash recomputed from hash-only content (no raw payloads),
- every inclusion proof against the signed root, plus the full-tree root,
- that cited evidence events are present.

It checks **evidence integrity** — it does **not** assert legal compliance or
certification.

## Offline / air-gapped

The only network use is Pyodide loading its runtime. For fully offline operation pass
a preloaded Pyodide or a self-hosted `indexURL`:

```js
import { loadPyodide } from "pyodide";
const pyodide = await loadPyodide({ indexURL: "https://your-host/pyodide/" });
await verifyReport(report, pem, { pyodide });
```

## Build / test from source

```bash
npm install
# generate fixtures with the Python package, then:
npm test
```

> Publishing to npm under the `openwright` name is an outward step performed by the
> maintainers with registry credentials; this package is the functional artifact.
