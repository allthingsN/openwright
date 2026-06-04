"""OpenWright + LangGraph — a high-risk loan-decisioning agent (FR-SDK-05).

Runs fully offline (a deterministic scoring node stands in for an LLM, so no API
key is needed) and shows the value story on a real LangGraph StateGraph:

* the agent's credit-check tool call produces a Prismer-style signed receipt,
  which OpenWright VERIFIES and ingests — we sit on top of the receipt primitive;
* the EU AI Act evaluation first reports Art. 14 human-oversight as
  *insufficient-evidence* (the high-risk decision is not yet proven to have been
  overseen), then a human approval + the finalized decision are recorded and a
  re-run flips Art. 14 to *satisfied* — the red→green compliance loop.

Run:  poetry run python examples/langgraph_loan_agent.py
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from openwright.adapters.receipt import receipt_to_event, sign_receipt
from openwright.canonical import hash_payload, to_rfc3339
from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.ledger import InMemoryLedgerBackend, Ledger
from openwright.report import build_report
from openwright.sdk import EvidenceClient
from openwright.signing import InMemoryKeySource
from openwright.verify import verify_report

AGENT_ID = "langgraph-loan-agent"


class LoanState(TypedDict):
    applicant: str
    score: int
    threshold: int
    recommendation: str


def build_agent(client: EvidenceClient, agent_key: InMemoryKeySource):
    def assess(state: LoanState) -> LoanState:
        # deterministic "model" call — in a real agent this is an LLM/tool span
        score = 600 + (sum(map(ord, state["applicant"])) % 200)
        # The credit-check tool call produces a signed receipt; verify + ingest.
        receipt = sign_receipt(
            agent_key,
            tool="credit_check",
            params_hash=hash_payload({"applicant": state["applicant"]}),
            target="credit-bureau",
            signer_name=AGENT_ID,
            owner="bank.example",
            ts=to_rfc3339(datetime.now(timezone.utc)),
            nonce=f"rcpt-{state['applicant']}",
        )
        client.ledger.commit(receipt_to_event(receipt))
        return {**state, "score": score}

    def recommend(state: LoanState) -> LoanState:
        rec = "APPROVE" if state["score"] >= state["threshold"] else "DENY"
        # A high-risk classification + FRIA reference telemetry can't infer.
        client.record_risk_classification(
            "high", rationale=f"consumer credit decision for {state['applicant']}",
            fria="FRIA-loan-2026")
        return {**state, "recommendation": rec}

    g = StateGraph(LoanState)
    g.add_node("assess", assess)
    g.add_node("recommend", recommend)
    g.add_edge(START, "assess")
    g.add_edge("assess", "recommend")
    g.add_edge("recommend", END)
    return g.compile()


def _art14(result) -> str:
    return next(c.status.value for c in result.controls if c.control_id == "art-14-human-oversight")


def main() -> None:
    key = InMemoryKeySource()
    agent_key = InMemoryKeySource()  # the agent signs its own receipts (the producer)
    ledger = Ledger(InMemoryLedgerBackend(), origin="openwright/langgraph-demo",
                    retention=timedelta(days=200))
    client = EvidenceClient(ledger, agent_id=AGENT_ID)
    agent = build_agent(client, agent_key)
    crosswalk = load_builtin("eu-ai-act")

    with client.task("loan-1", context_id="ctx-1", root_task_id="loan-1"):
        result = agent.invoke({"applicant": "alice", "threshold": 700,
                               "score": 0, "recommendation": ""})
        print(f"  alice: recommendation={result['recommendation']} (score {result['score']})")

        # RED — the high-risk decision is not yet proven to be overseen.
        before = evaluate(crosswalk, list(ledger.events()))
        print(f"  Art. 14 human-oversight (before): {_art14(before)}")

        # Remediate: a human signs off, then the finalized decision is recorded.
        appr = client.record_human_approval(
            reviewer="loan-officer@bank.example", rationale=f"reviewed score {result['score']}")
        client.record_decision(
            output=f"{result['recommendation']} alice (score {result['score']})",
            input="alice", risk_classification="high",
            rationale=f"score {result['score']} vs threshold 700",
            approval_ref=appr.event_id, control="art-14-human-oversight")

    after = evaluate(crosswalk, list(ledger.events()))
    print(f"  Art. 14 human-oversight (after):  {_art14(after)}  (red→green)")

    report = build_report(ledger, after, key, scope_description="LangGraph loan-decisioning agent")
    vr = verify_report(report, trusted_public_key_raw=key.public_key_raw())
    s = report["summary"]
    print(f"\nEU AI Act crosswalk: {s['satisfied']} satisfied / {s['not_satisfied']} not / "
          f"{s['insufficient_evidence']} insufficient")
    print(f"Report verified offline: VALID={vr.valid}; gaps={[g['control_id'] for g in vr.gaps]}")
    print(json.dumps({"report_id": report["report_id"],
                      "checkpoint_root": report["checkpoint"]["root_hash"][:16] + "…",
                      "tree_size": report["checkpoint"]["tree_size"]}, indent=2))


if __name__ == "__main__":
    main()
