# Contributing to OpenWright

Thanks for your interest in contributing! OpenWright is the open-source **agent evidence
layer**. The highest-leverage contributions are usually:

- **Connectors** — instrument a new agent framework, storage backend, or exporter
  (these live in [openwright-connectors](https://github.com/allthingsN/openwright-connectors)).
- **Crosswalks** — map evidence to a regulatory framework (EU AI Act, SOC 2, ISO 42001, …).
- **Core** — events, Merkle/ledger, signing, the verifier, the CLI, `instrument()`.

For anything non-trivial, please **open an issue first** to align on the approach.

## Dev setup

Requires Python 3.10–3.14 and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/allthingsN/openwright && cd openwright
poetry install
poetry run pytest            # the suite must be green
```

Backend tests (Postgres/S3) skip cleanly when no service is present, so the default suite
needs no infrastructure. Other checks:

```bash
poetry run pytest -q                              # unit + integration
OPENWRIGHT_RUN_E2E=1 poetry run pytest tests/test_clean_venv_e2e.py   # clean-venv release gate (slow)
# Go core + Python↔Go interop (if you touch core-go/):  cd core-go && go test ./...
```

## The non-negotiable invariants

These are what make the evidence trustworthy. A PR that breaks any of them won't be merged —
and several are guarded by tests:

1. **No behavior change to the cryptographic core.** Canonicalization, Merkle construction,
   signing, and crosswalk verdicts must stay byte-for-byte deterministic. If a change alters
   canonical bytes, Merkle output, signatures, or verdicts, it's a bug. The Go↔Python
   conformance vectors and RFC 6962 reference vectors are the oracle.
2. **Hashes only — never raw payloads or PII in the ledger.** I/O is stored as `sha256:`
   references (`hash_payload`); raw payloads, if retained at all, go to a separate vault.
3. **Append-only / tamper-evident.** The ledger is insert-only; gaps are surfaced as attested
   `evidence_gap` markers, never silent truncation.
4. **The offline verifier stays dependency-light.** `openwright.verify` must import only the
   stdlib + `cryptography` (a test enforces no `pydantic`/`pyyaml`/`reportlab`/`typer`/network
   libs leak in). The verifier is the root of trust — keep it auditable.
5. **The boundary is enforced in code.** Every artifact carries: *"OpenWright produces evidence
   that controls were exercised. It is not, and does not claim to be, a legal compliance
   certification."* Don't weaken or remove it. See [docs/COMPLIANCE_BOUNDARY.md](docs/COMPLIANCE_BOUNDARY.md).

## Adding a connector

Connectors are independently-publishable `openwright-<name>` packages discovered via entry
points; they never reimplement crypto and never import one another (a decoupling guard
enforces this). See the
[connectors contributing guide](https://github.com/allthingsN/openwright-connectors/blob/main/CONTRIBUTING.md)
and start from `packages/_template`. For one-line `instrument("<framework>")` support, expose
an `auto_instrument(runtime, **opts)` under the `openwright.instrumentors` entry-point group.

## Adding or changing a crosswalk

Crosswalks are published, content-hashed YAML mapping evidence predicates to controls. They
are maintainer-authored, **rigorously cited**, and carry **no normative authority** (pending
qualified legal/standards review). Every predicate must cite its source. See
[docs/CROSSWALK_GOVERNANCE.md](docs/CROSSWALK_GOVERNANCE.md). Crosswalks are versioned
independently of the package; bump the crosswalk version and changelog on any change.

## Code style & PRs

- Match the surrounding code — type hints, docstrings, and the existing idioms. Keep diffs
  small and focused; every changed line should trace to the change you're making.
- Add/extend tests for behavior changes; keep the suite green.
- Conventional-ish commit messages (`feat:`, `fix:`, `docs:`, `refactor:`) are appreciated.
- Open a PR against `main`; CI (tests + the decoupling guard) must pass.

## Security

Please report suspected vulnerabilities **privately** rather than in a public issue — see
[docs/SECURITY.md](docs/SECURITY.md).

## License

By contributing, you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.
