"""Minimal OpenWright SDK quickstart (Tier-2): ~30 lines to a verified attestation.

Run:  poetry run python examples/sdk_quickstart.py
"""

from __future__ import annotations

from datetime import timedelta

from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.ledger import FileLedgerBackend, Ledger
from openwright.report import build_report
from openwright.sdk import EvidenceClient
from openwright.signing import InMemoryKeySource  # use FileKeySource in production
from openwright.verify import verify_report

# 1. A signing key (in production: FileKeySource / EnvKeySource / KMS), a ledger, a client.
key = InMemoryKeySource()
ledger = Ledger(FileLedgerBackend("./quickstart-ledger"), retention=timedelta(days=200))
client = EvidenceClient(ledger, agent_id="my-agent")

# 2. Record the evidence telemetry can't infer — linked by task id.
with client.task("task-42", context_id="session-7"):
    approval = client.record_human_approval(reviewer="me@example.com", rationale="looks good")
    client.record_risk_classification("high", rationale="high-impact decision", fria="FRIA-1")
    client.record_decision(
        output="APPROVED",
        risk_classification="high",
        rationale="meets policy",
        approval_ref=approval.event_id,            # links the decision to the approval
        control="art-14-human-oversight",
    )

# 3. Evaluate a crosswalk, build a signed report, verify it offline.
result = evaluate(load_builtin("eu-ai-act"), list(ledger.events()))
report = build_report(ledger, result, key, scope_description="my agent")
verdict = verify_report(report, trusted_public_key_raw=key.public_key_raw())

print("Controls:", {c["control_id"]: c["status"] for c in report["controls"]})
print("Report verified offline:", verdict.valid)
print("\nNOTE: evidence of controls exercised — NOT a compliance certification.")
