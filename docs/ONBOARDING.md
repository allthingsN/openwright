# OpenWright Onboarding Guide

This guide takes you from zero to a verified attestation, then through the two
integration tiers, report generation, independent verification, CI/CD gating,
and authoring a custom crosswalk.

> OpenWright produces **evidence that controls were exercised** — not legal
> compliance or certification. See [COMPLIANCE_BOUNDARY.md](COMPLIANCE_BOUNDARY.md).

---

## 0. Install (≈2 minutes)

```bash
poetry install
poetry run openwright version
```

Python 3.10–3.14 is supported (the reference environment is 3.13). Everything
needed for the demo, collector, SDK, and reports installs with one command.

---

## 1. Run the demo (≈1 minute, the fastest way to understand it)

```bash
poetry run openwright demo
```

This is fully self-hosted and uses no network or hosted service. It:

- generates an Ed25519 signing key **you control on disk** (never embedded);
- starts the OpenWright OTLP collector and a stand-in downstream "Langfuse";
- runs a high-risk loan-decisioning agent that emits **real** OpenTelemetry
  GenAI spans through the collector;
- forwards that telemetry to the downstream backend **unchanged**, while forking
  a copy into the evidence ledger;
- records human approvals, risk classifications, and FRIA references via the SDK
  (and leaves one decision deliberately un-approved);
- evaluates the EU AI Act crosswalk, writes a signed JSON/PDF/OSCAL/SARIF report,
  verifies it offline, and demonstrates that tampering fails.

At the end it prints the artifact paths and a command to verify the report
yourself. Inspect them:

```
<workdir>/artifacts/report.json        signed, machine-readable
<workdir>/artifacts/report.pdf         human-readable attestation
<workdir>/artifacts/report.oscal.json  OSCAL assessment-results
<workdir>/artifacts/report.sarif.json  SARIF gap findings
<workdir>/keys/public_key.pem          the signer's public key
```

---

## 2. Understand the report

The signed JSON report is the authoritative artifact and is **self-contained for
verification**:

- `checkpoint` — a signed tree head: `{origin, tree_size, root_hash, timestamp,
  public_key_id, signature}`.
- `events[]` — each committed event (hash-only — no raw payloads), its
  `leaf_index`, `leaf_hash`, and an `inclusion_proof` binding it to the
  checkpoint root.
- `controls[]` — per-control `status` (satisfied / not_satisfied /
  insufficient_evidence), the requirement, the **primary-source citation**, and
  the evidence/gap event ids.
- `summary`, `scope`, `period`, `crosswalk` (id + version + source).
- `boundary_statement` — the evidence-not-certification boundary.
- `signature` — an Ed25519 signature over the whole report, so the *computed*
  control results are tamper-evident too (they aren't Merkle leaves).

---

## 3. Tier 1 — zero-code onboarding (the adoption lever)

Point your existing OpenTelemetry pipeline at the OpenWright collector. The
collector forwards everything downstream unchanged and forks a copy into the
ledger — **no application code changes**.

```bash
# Generate a key you control (or wire a KMS — see SECURITY.md).
poetry run openwright keygen --out signing_key.pem

# Run the collector: OTLP/HTTP on :4318, fanning out to your real backend.
poetry run openwright collector \
  --ledger-dir ./openwright-ledger \
  --downstream https://cloud.langfuse.com/api/public/otel/v1/traces \
  --http-port 4318 --grpc-port 4317
```

Then set your agent's OTLP endpoint to the collector:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
# your agent runs unchanged; Langfuse still receives everything
```

The collector accepts OTLP over **both gRPC and HTTP**, parses the GenAI
`gen_ai.*` attributes (current names and their deprecated predecessors), and
reconstructs A2A task provenance from `a2a.task.id` / `a2a.context.id` /
`a2a.reference_task_ids` span attributes when present.

> Telemetry that can be *inferred* from spans is captured automatically. Human
> approvals, risk classifications, FRIA references, and incidents **cannot** be
> inferred — record those with the SDK (Tier 2).

### Already running an OpenTelemetry Collector?

You don't need to run the OpenWright collector *in front of* your pipeline. If you
already operate a Collector, run `openwright collector` as a **pure evidence sink**
(omit `--downstream`) and add one exporter to your existing traces pipeline —
the Collector fans out a copy to OpenWright and your real backend is untouched.
The full recipe, plus a script that proves it end-to-end against a real
`otelcol-contrib`, is in [`examples/otel_collector/`](../examples/otel_collector/).
A native, registry-listable Collector component is the next step on the roadmap
([docs/OTEL_PROCESSOR_SCOPE.md](OTEL_PROCESSOR_SCOPE.md), Option B).

---

## 4. Tier 2 — the SDK

Record the evidence telemetry can't infer, linked by A2A task id. You never
touch hashing, signing, or Merkle mechanics.

```python
from datetime import timedelta
from openwright.ledger import FileLedgerBackend, Ledger
from openwright.sdk import EvidenceClient
from openwright.signing import FileKeySource

ledger = Ledger(FileLedgerBackend("./openwright-ledger"),
                retention=timedelta(days=200))   # > 6 months (EU AI Act Art. 26(6))
client = EvidenceClient(ledger, agent_id="loan-agent")

with client.task("loan-123", context_id="session-7", root_task_id="loan-123"):
    approval = client.record_human_approval(reviewer="alice@bank.example",
                                            rationale="reviewed KYC + income")
    client.record_risk_classification("high", rationale="consumer credit decision",
                                      fria="FRIA-loan-2026")
    client.record_decision(
        output="APPROVED at 6.2% APR",          # hashed automatically
        input="applicant profile",              # hashed automatically
        risk_classification="high",
        rationale="score 742 above threshold",
        approval_ref=approval.event_id,          # links decision → approval (Art. 14)
        control="art-14-human-oversight",
    )
```

The ergonomic decorator ties a function to a named control automatically:

```python
from openwright.sdk import high_risk_decision

@high_risk_decision(client, control="art-14-human-oversight")
def decide_loan(application): ...
```

---

## 5. Generate a report

```bash
poetry run openwright report ./openwright-ledger \
  --key signing_key.pem \
  --crosswalk eu-ai-act \
  --scope "High-risk loan-decisioning agent" \
  --out ./out
```

Writes `report.json`, `report.pdf`, `report.oscal.json`, and
`report.sarif.json`. `--crosswalk` accepts a built-in id (`eu-ai-act`, `soc2`) or
a path to your own YAML.

---

## 6. Verify independently (offline, no infrastructure, no raw payloads)

Give the verifier the signer's public key **through a trusted channel** (not the
same file you're verifying):

```bash
poetry run openwright verify ./out/report.json --pubkey signing_key.pem.pub
```

It recomputes every leaf hash from the hash-only event content, verifies each
inclusion proof against the signed checkpoint root, recomputes the full tree
root, and checks both the report and checkpoint signatures. Exit code `0` =
valid, `1` = invalid.

The verifier has **zero network dependencies** and imports only the standard
library, `cryptography`, and OpenWright's two stdlib-only crypto modules — so it
is small enough to audit and run anywhere.

---

## 7. CI/CD gate (UC-4)

Fail a deploy when a required control isn't satisfied:

```bash
poetry run openwright gate ./out/report.json \
  --pubkey signing_key.pem.pub \
  -r art-12-record-keeping -r art-14-human-oversight \
  --sarif-out gaps.sarif
```

Exit `0` if all required controls are satisfied, `1` if any is unsatisfied, `2`
if the report fails to verify. `gaps.sarif` can be uploaded to GitHub code
scanning.

---

## 8. Author a custom crosswalk

Crosswalks are declarative YAML — no code. Each control states a testable
predicate over events and cites its primary source.

```yaml
crosswalk:
  id: my-policy
  title: "Internal AI governance policy"
  version: "1.0.0"
  source: "ACME AI Policy v3"
  reviewed_as_of: "2026-05-28"
  disclaimer: "Evidence of controls exercised; not a compliance determination."
  controls:
    - id: every-high-risk-decision-approved
      title: "High-risk decisions require human approval"
      requirement: "Each high-risk decision links to an approved human-approval event."
      citation: { instrument: "ACME AI Policy v3", clause: "4.2", url: "https://acme.example/policy" }
      scope: { kind: ["agent_decision"], risk_classification: ["high"] }
      condition:
        type: linked
        link: approval_ref
        target: { kind: ["human_approval"], oversight_status: ["approved"] }
      empty_scope: insufficient_evidence
```

Load and use it:

```bash
poetry run openwright report ./openwright-ledger --key signing_key.pem --crosswalk ./my-policy.yaml --out ./out
```

Predicate building blocks: filters (`kind`, `risk_classification`,
`oversight_status`, `source_format`, `attribute_equals`, `has`) and conditions
(`committed`, `field` with `eq/ne/in/exists/gte/lte`, `linked` with
`approval_ref/same_task/same_context/references_root`, and `any_of/all_of/not`).
See [CROSSWALK_GOVERNANCE.md](CROSSWALK_GOVERNANCE.md) for the full reference and
the citation/versioning requirements.

---

## Next steps

- [ARCHITECTURE.md](ARCHITECTURE.md) — how the pieces fit and why.
- [SECURITY.md](SECURITY.md) — the trust model and key management.
- [SCALABILITY.md](SCALABILITY.md) — running this beyond the demo.
