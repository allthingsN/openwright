"""End-to-end demo: a high-risk loan-decisioning agent, attested and verified.

`openwright demo` runs this. It tells the value story (§6 of the next-cycle proposal)
self-hosted with no hosted dependency and no embedded keys:

1. a real OpenTelemetry-instrumented agent exports OTLP/HTTP through the OpenWright
   collector, which fans telemetry out to a stand-in "Langfuse" backend
   UNCHANGED while forking a copy into the evidence ledger (AC-01);
2. the agent's tool call ALSO produces a signed action receipt; the
   receipt adapter verifies its Ed25519 signature and ingests it — we sit on top
   of the receipt primitive rather than reinventing it;
3. the EU AI Act evaluation first reports Art. 14 human-oversight as
   *insufficient-evidence* (the high-risk decision is not yet proven to have been
   overseen), then the SDK records a human approval and the finalized decision,
   and a re-run flips Art. 14 to *satisfied* — the red→green compliance loop;
4. a signed report (JSON + PDF + OSCAL + SARIF) is produced and independently
   verified offline with no raw payloads (AC-03); tampering is shown to fail and
   restoration to pass (AC-04); every artifact carries the
   evidence-not-certification boundary (AC-06).

A second application is left without a fundamental-rights impact assessment so the
final report honestly shows a remaining Art. 27 gap — the product reports what is
proven and what is not, which is what an auditor cares about.
"""

from __future__ import annotations

import copy
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

from .adapters.receipt import receipt_to_event, sign_receipt
from .canonical import hash_payload, to_rfc3339
from .crosswalk import CrosswalkResult, evaluate
from .crosswalk_loader import load_builtin
from .ingest.http_server import EvidenceCollector, MockOTLPBackend
from .ingest.pipeline import EvidencePipeline
from .ledger import FileLedgerBackend, Ledger
from .report import build_report, render_pdf, to_oscal, to_sarif
from .sdk import EvidenceClient
from .signing import FileKeySource, InMemoryKeySource, generate_private_key_pem, public_key_pem
from .verify import verify_report
from .web_demo import render_demo_html

AGENT_ID = "loan-decisioning-agent"
PRICING = {"default": {"input_per_1k": 0.003, "output_per_1k": 0.015}}


def _emit_llm_span(tracer, name: str, model: str, in_tok: int, out_tok: int) -> None:
    with tracer.start_as_current_span(name) as sp:
        sp.set_attribute("gen_ai.operation.name", "chat")
        sp.set_attribute("gen_ai.provider.name", "anthropic")
        sp.set_attribute("gen_ai.request.model", model)
        sp.set_attribute("gen_ai.response.model", model)
        sp.set_attribute("gen_ai.usage.input_tokens", in_tok)
        sp.set_attribute("gen_ai.usage.output_tokens", out_tok)
        sp.set_attribute("gen_ai.response.finish_reasons", ["stop"])


def _emit_tool_span(tracer, tool: str, task_id: str, context_id: str) -> None:
    with tracer.start_as_current_span(f"{tool}") as sp:
        sp.set_attribute("gen_ai.operation.name", "execute_tool")
        sp.set_attribute("gen_ai.tool.name", tool)
        sp.set_attribute("gen_ai.tool.call.id", f"call_{task_id}")
        sp.set_attribute("a2a.task.id", task_id)
        sp.set_attribute("a2a.context.id", context_id)


def _status_of(result: CrosswalkResult, control_id: str) -> str:
    return next(c.status.value for c in result.controls if c.control_id == control_id)


def run_demo(workdir: str | Path, *, log=print) -> Dict[str, Any]:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    work = Path(workdir)
    work.mkdir(parents=True, exist_ok=True)
    keys = work / "keys"
    keys.mkdir(exist_ok=True)
    artifacts = work / "artifacts"
    artifacts.mkdir(exist_ok=True)

    # --- 1. signing key the operator controls on disk (NFR-SEC-02, AC-05) ----
    key_path = keys / "signing_key.pem"
    pub_path = keys / "public_key.pem"
    key_path.write_bytes(generate_private_key_pem())
    key = FileKeySource(str(key_path))
    pub_path.write_bytes(public_key_pem(key.public_key_raw()))
    log(f"[1] Generated Ed25519 signing key (operator-controlled, on disk): {key.key_id()}")

    # --- 2. append-only file ledger, retention > 6 months (Art. 26(6)) -------
    ledger = Ledger(
        FileLedgerBackend(work / "ledger"),
        origin="openwright/demo-loan-agent",
        retention=timedelta(days=200),
    )
    log("[2] Opened append-only file ledger (retention 200 days).")

    # --- 3. collector + downstream backend (fan-out, AC-01) ------------------
    backend = MockOTLPBackend().start()
    pipeline = EvidencePipeline(ledger, agent_id=AGENT_ID, pricing=PRICING)
    collector = EvidenceCollector(pipeline, downstream_url=backend.url).start()
    log(f"[3] Started OTLP collector ({collector.traces_url}) → downstream backend ({backend.url}).")

    try:
        # --- 4. real OTel telemetry through the collector --------------------
        provider = TracerProvider(resource=Resource.create({"service.name": AGENT_ID}))
        provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=collector.traces_url)))
        tracer = provider.get_tracer("openwright.demo")
        _emit_llm_span(tracer, "assess applicant #1", "claude-opus-4-8", 420, 180)
        _emit_tool_span(tracer, "credit_check", "loan-1", "ctx-1")
        _emit_llm_span(tracer, "assess applicant #2", "claude-opus-4-8", 380, 95)
        _emit_tool_span(tracer, "credit_check", "loan-2", "ctx-2")
        provider.force_flush()
        time.sleep(0.2)
        pipeline.flush()
        downstream_spans = backend.span_count
        log(f"[4] Agent emitted telemetry; downstream received {downstream_spans} spans UNCHANGED, "
            f"evidence forked {pipeline.stats()['processed']} events.")
    finally:
        collector.stop()
        backend.stop()
        pipeline.stop()

    # --- 5. sit on top of the receipt primitive (verify, then ingest) --------
    # The tool call also produced a signed action receipt. The agent holds
    # its own key (the receipt producer); we VERIFY its signature before ingest.
    agent_key = InMemoryKeySource()
    receipt = sign_receipt(
        agent_key,
        tool="credit_check",
        params_hash=hash_payload({"applicant": "applicant #1 profile", "bureau": "experian"}),
        target="experian-sandbox",
        signer_name=AGENT_ID,
        owner="bank.example",
        ts=to_rfc3339(datetime.now(timezone.utc)),
        nonce="rcpt-loan-1",
        transport="https",
    )
    receipt_event = ledger.commit(receipt_to_event(receipt))
    log(f"[5] Verified an upstream signed action receipt (Ed25519) and ingested it as "
        f"{receipt_event.source.format} tool_call {receipt_event.event_id}.")

    # --- 6. SDK: risk classifications; NO decisions finalized yet ------------
    # The agent has reached recommendations, but the high-risk *decisions* are not
    # finalized until a human signs off — so there is not yet any proven oversight.
    client = EvidenceClient(ledger, agent_id=AGENT_ID)
    with client.task("loan-1", context_id="ctx-1", root_task_id="loan-1"):
        client.record_risk_classification("high", rationale="consumer credit decision", fria="FRIA-loan-2026-Q2")
    with client.task("loan-2", context_id="ctx-2", root_task_id="loan-2"):
        # Deliberately NO FRIA reference for application #2 (a real Art. 27 gap).
        client.record_risk_classification("high", rationale="consumer credit decision")
    log("[6] SDK recorded high-risk classifications + a FRIA ref for #1 (none for #2).")

    crosswalk = load_builtin("eu-ai-act")

    # --- 7. RED: evaluate before any decision is finalized -------------------
    result_before = evaluate(crosswalk, list(ledger.events()))
    art14_before = _status_of(result_before, "art-14-human-oversight")
    report_before = build_report(
        ledger, result_before, key,
        scope_description="High-risk consumer loan-decisioning agent (demo) — before human oversight",
    )
    report_before_json = artifacts / "report.before.json"
    report_before_json.write_text(json.dumps(report_before, indent=2))
    log(f"[7] EU AI Act eval (before): Art. 12 record-keeping="
        f"{_status_of(result_before, 'art-12-record-keeping')}, "
        f"Art. 14 human-oversight={art14_before} — the gap an auditor cares about.")

    # --- 8. REMEDIATE: record human approvals + finalized decisions ----------
    with client.task("loan-1", context_id="ctx-1", root_task_id="loan-1"):
        appr1 = client.record_human_approval(reviewer="alice@bank.example", rationale="reviewed KYC + income docs")
        client.record_decision(
            output="APPROVED loan application #1 at 6.2% APR",
            input="applicant #1 profile",
            risk_classification="high",
            rationale="credit score 742 above policy threshold; DTI within limits",
            approval_ref=appr1.event_id,
            control="art-14-human-oversight",
        )
    with client.task("loan-2", context_id="ctx-2", root_task_id="loan-2"):
        appr2 = client.record_human_approval(reviewer="alice@bank.example", rationale="reviewed application #2")
        client.record_decision(
            output="APPROVED loan application #2 at 7.1% APR",
            input="applicant #2 profile",
            risk_classification="high",
            rationale="credit score 705 above policy threshold",
            approval_ref=appr2.event_id,
            control="art-14-human-oversight",
        )
    log("[8] SDK recorded human approvals and the finalized high-risk decisions.")

    # --- 9. GREEN: re-evaluate + build the signed report ---------------------
    result = evaluate(crosswalk, list(ledger.events()))
    art14_after = _status_of(result, "art-14-human-oversight")
    report = build_report(
        ledger, result, key,
        scope_description="High-risk consumer loan-decisioning agent (demo)",
    )
    report_json = artifacts / "report.json"
    report_json.write_text(json.dumps(report, indent=2))
    render_pdf(report, str(artifacts / "report.pdf"))
    (artifacts / "report.oscal.json").write_text(json.dumps(to_oscal(report), indent=2))
    (artifacts / "report.sarif.json").write_text(json.dumps(to_sarif(report), indent=2))

    # Interactive, self-contained browser page: the story + an in-browser WASM
    # verifier so a person can verify (and tamper) the real report themselves.
    demo_html = artifacts / "demo.html"
    demo_html.write_text(
        render_demo_html(
            report,
            public_key_pem(key.public_key_raw()).decode("ascii"),
            narrative={
                "art14_before": art14_before,
                "art14_after": art14_after,
                "downstream_spans": downstream_spans,
                "receipt_format": receipt_event.source.format,
            },
        ),
        encoding="utf-8",
    )

    s = report["summary"]
    log(f"[9] EU AI Act eval (after): Art. 14 human-oversight={art14_after} (red→green). "
        f"{s['satisfied']} satisfied · {s['not_satisfied']} not satisfied · "
        f"{s['insufficient_evidence']} insufficient. Wrote JSON, PDF, OSCAL, SARIF.")

    # --- 10. independent offline verification with the trusted public key ----
    vr = verify_report(report, trusted_public_key_raw=key.public_key_raw())
    log(f"[10] Standalone verifier (offline, hash-only data): VALID={vr.valid}; "
        f"gaps={[g['control_id'] for g in vr.gaps]}")

    # --- 11. tamper → fail, then restore → pass ------------------------------
    tampered = copy.deepcopy(report)
    for c in tampered["controls"]:
        if c["status"] != "satisfied":
            c["status"] = "satisfied"
            break
    vr_t = verify_report(tampered, trusted_public_key_raw=key.public_key_raw())
    vr_restored = verify_report(report, trusted_public_key_raw=key.public_key_raw())
    log(f"[11] Tampered with a control result → VALID={vr_t.valid} (tamper detected); "
        f"restored → VALID={vr_restored.valid}.")

    return {
        "workdir": str(work),
        "report_json": str(report_json),
        "report_before_json": str(report_before_json),
        "demo_html": str(demo_html),
        "report_pdf": str(artifacts / "report.pdf"),
        "oscal": str(artifacts / "report.oscal.json"),
        "sarif": str(artifacts / "report.sarif.json"),
        "public_key": str(pub_path),
        "verification": vr,
        "tamper_detected": not vr_t.valid,
        "restore_valid": vr_restored.valid,
        "downstream_spans": downstream_spans,
        "ledger_size": ledger.size(),
        "summary": report["summary"],
        "summary_before": report_before["summary"],
        "art14_before": art14_before,
        "art14_after": art14_after,
        "receipt_event_id": receipt_event.event_id,
        "receipt_format": receipt_event.source.format,
    }
