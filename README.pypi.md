# OpenWright — the Agent Evidence Layer

**Turn the runtime behavior of AI agents into signed, tamper-evident,
control-mapped audit evidence — verifiable by anyone, offline.**

OpenWright sits on top of your existing OpenTelemetry instrumentation, forks a
copy of your agent's runtime behavior, and turns it into signed, append-only,
tamper-evident records mapped to specific regulatory controls. The evidence is
verifiable by a third party **without** access to your data or infrastructure,
and the ledger holds only hashes — never prompts or PII.

It ships five built-in, primary-source-cited framework crosswalks — plus a
narrowed EU AI Act **v1** review subset (`eu-ai-act-v1`) and deployer-profile
variants of Art. 14 (in-the-loop / on-the-loop) and Art. 27 (FRIA-gated). You can
also write your own:

| Crosswalk | Covers | Controls |
|---|---|---|
| EU AI Act (Reg. 2024/1689) | Art. 12, 13, 14, 26, 27, 73 (high-risk subset) | 6 |
| NIST AI RMF 1.0 | Govern / Map / Measure / Manage subset | 7 |
| ISO/IEC 42001:2023 | Annex A AI-management-system subset | 6 |
| GDPR (Reg. 2016/679) | Art. 5, 22, 25, 30, 33, 35 (accountability + automated decisions) | 8 |
| SOC 2 | Trust Services Criteria — Common Criteria + Processing Integrity | 7 |

These crosswalks are **maintainer-authored and cited, but not yet legally
reviewed** — they produce *evidence*, not a compliance determination.

> **OpenWright produces _evidence that controls were exercised_. It does NOT
> assert legal compliance, certification, or an audit opinion** — those are for
> qualified auditors and counsel. Every artifact carries this boundary.

## Install

```bash
pip install openwright-core
```

The distribution is `openwright-core`; it imports as `openwright`. Requires Python 3.10+.

## Try it (one command)

```bash
openwright demo
```

Runs a complete, self-hosted, no-network demo: it instruments a sample high-risk
agent, forks the telemetry into an evidence ledger, records human approvals and
risk classifications, produces a **signed report** (JSON + PDF + OSCAL + SARIF)
against the EU AI Act crosswalk, verifies it offline, and shows that tampering
fails verification. It then **opens an interactive page in your browser** that
walks through what happened and lets you **verify the real signed report
yourself — offline, in-browser (WebAssembly)** — including a "Tamper" button to
watch verification fail and a "Restore" button to watch it pass again. (Use
`openwright demo --no-browser` for headless/CI.)

It also prints where the artifacts landed and a command to verify them yourself:

```bash
openwright verify <report.json> --pubkey <public_key.pem> --deep
```

## Use it in your code

```python
from datetime import timedelta
from openwright.ledger import FileLedgerBackend, Ledger
from openwright.sdk import EvidenceClient
from openwright.signing import InMemoryKeySource      # use FileKeySource in production
from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.report import build_report
from openwright.verify import verify_report

key = InMemoryKeySource()
ledger = Ledger(FileLedgerBackend("./ledger"), retention=timedelta(days=200))
client = EvidenceClient(ledger, agent_id="my-agent")

# Record the evidence telemetry can't infer — linked by task id.
with client.task("task-42", context_id="session-7"):
    approval = client.record_human_approval(reviewer="me@example.com", rationale="looks good")
    client.record_risk_classification("high", rationale="high-impact decision", fria="FRIA-1")
    client.record_decision(
        output="APPROVED",
        risk_classification="high",
        rationale="meets policy",
        approval_ref=approval.event_id,                # links the decision to the approval
        control="art-14-human-oversight",
    )

# Evaluate a crosswalk, build a signed report, verify it offline.
result = evaluate(load_builtin("eu-ai-act"), list(ledger.events()))
report = build_report(ledger, result, key, scope_description="my agent")
verdict = verify_report(report, trusted_public_key_raw=key.public_key_raw())

print({c["control_id"]: c["status"] for c in report["controls"]})
print("verified offline:", verdict.valid)
```

## Collect from a live agent

Point your app's OTLP exporter at the collector; your existing backend keeps
receiving telemetry unchanged while a copy is forked into the evidence ledger:

```bash
openwright collector --downstream http://your-existing-otlp-backend:4318
```

## CLI

```
openwright demo                       Run the full end-to-end demo.
openwright collector --downstream URL Run the OTLP collector (gRPC+HTTP); fan out + fork to ledger.
openwright report  LEDGER --key K     Build a signed report (JSON/PDF/OSCAL/SARIF) from a ledger.
openwright verify  REPORT --pubkey K  Verify a signed report offline (--deep re-checks verdicts).
openwright gate    REPORT -r CONTROL  CI/CD gate: non-zero exit if a required control is unsatisfied.
openwright crosswalks                 List built-in crosswalks.
openwright connectors list            List installed connectors (sources/forwarders/exporters/storage).
openwright export  REPORT --to NAME   Export a report to a sink (GRC/CI) via an installed exporter.
openwright keygen  --out key.pem      Generate an Ed25519 signing key you control.
openwright version
```

## Connectors

OpenWright exposes a small, versioned **connector contract** (`openwright.connectors`,
v1.0): framework-capture sources, downstream forwarders, report exporters, and
pluggable ledger/checkpoint storage backends. Connectors are independently
installable `openwright-<name>` packages discovered via entry points — **core never
depends on a connector**, so adding one needs zero core change. Resolve storage by
URI (`openwright collector --ledger-backend postgres://… --checkpoint-store s3://…`)
and see what's installed with `openwright connectors list`.

Run `openwright --help` for the full list.

## License

Apache-2.0.
