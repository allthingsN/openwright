"""End-to-end proof of OpenWright's zero-code OpenTelemetry Collector integration.

This is Option A from docs/OTEL_PROCESSOR_SCOPE.md: a team already running an
OpenTelemetry Collector forks evidence to OpenWright with **no application code
changes** — the only change is collector config (one extra exporter).

The script boots a REAL collector (otelcol-contrib) with a fan-out pipeline:

    receivers: [otlp] -> exporters: [your backend (mock here), openwright]

then sends OTLP spans to the collector and asserts:

  1. the downstream backend received the spans (additive fan-out preserved);
  2. OpenWright forked a copy into its evidence ledger;
  3. a signed report built from that ledger verifies OFFLINE, hash-only.

Run it::

    OTELCOL_BIN=/path/to/otelcol-contrib \
        poetry run python examples/otel_collector/verify_fanout.py

If no collector binary is found (via $OTELCOL_BIN or PATH) the script prints
how to get one and exits 0 — it never fails a CI that lacks the binary.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.ingest.http_server import EvidenceCollector, MockOTLPBackend
from openwright.ingest.pipeline import EvidencePipeline
from openwright.ledger import FileLedgerBackend, Ledger
from openwright.report import build_report
from openwright.signing import FileKeySource, generate_private_key_pem
from openwright.verify import verify_report


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _otlp_spans(n: int = 3) -> bytes:
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )

    req = ExportTraceServiceRequest()
    rs = req.resource_spans.add()
    kv = rs.resource.attributes.add()
    kv.key = "service.name"
    kv.value.string_value = "loan-agent"
    ss = rs.scope_spans.add()
    for i in range(n):
        sp = ss.spans.add()
        sp.name = "chat"
        for k, v in [
            ("gen_ai.operation.name", "chat"),
            ("gen_ai.request.model", "gpt-4o"),
            ("gen_ai.system", "openai"),
        ]:
            a = sp.attributes.add()
            a.key = k
            a.value.string_value = v
    return req.SerializeToString()


def _post(url: str, body: bytes) -> int:
    r = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/x-protobuf"}
    )
    with urllib.request.urlopen(r, timeout=5) as resp:
        return resp.status


CONFIG_TEMPLATE = """\
# Generated fan-out config — see collector-config.yaml for the documented recipe.
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:{recv_port}

exporters:
  # Your existing backend (Langfuse / Phoenix / Datadog). A mock here.
  otlphttp/backend:
    endpoint: {backend_base}
    compression: none
    tls:
      insecure: true
  # The one line that adds OpenWright. Evidence is forked here.
  otlphttp/openwright:
    endpoint: {openwright_base}
    compression: none
    tls:
      insecure: true

service:
  telemetry:
    logs:
      level: warn
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp/backend, otlphttp/openwright]
"""


def main() -> int:
    otelcol = os.environ.get("OTELCOL_BIN") or shutil.which("otelcol-contrib") or shutil.which("otelcol")
    if not otelcol or not Path(otelcol).exists():
        print("No OpenTelemetry Collector binary found.")
        print("Set OTELCOL_BIN=/path/to/otelcol-contrib or put it on PATH.")
        print("Get one: https://github.com/open-telemetry/opentelemetry-collector-releases/releases")
        return 0  # skip, don't fail

    work = Path(tempfile.mkdtemp(prefix="openwright-otelcol-"))
    backend = MockOTLPBackend().start()
    key_path = work / "key.pem"
    pem = generate_private_key_pem()
    key_path.write_bytes(pem if isinstance(pem, bytes) else pem.encode())
    key = FileKeySource(str(key_path))
    ledger = Ledger(FileLedgerBackend(work / "ledger"))
    pipe = EvidencePipeline(ledger, agent_id="loan-agent")
    sink = EvidenceCollector(pipe).start()  # pure evidence sink: no --downstream

    recv_port = _free_port()
    # otlphttp exporters append /v1/traces, so give them the base URL.
    backend_base = backend.url.rsplit("/v1/traces", 1)[0]
    openwright_base = sink.traces_url.rsplit("/v1/traces", 1)[0]
    cfg = work / "config.yaml"
    cfg.write_text(
        CONFIG_TEMPLATE.format(
            recv_port=recv_port, backend_base=backend_base, openwright_base=openwright_base
        )
    )

    proc = subprocess.Popen(
        [otelcol, "--config", str(cfg)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        recv_url = f"http://127.0.0.1:{recv_port}/v1/traces"
        # Wait for the collector's receiver to come up.
        body = _otlp_spans(3)
        for _ in range(50):
            try:
                if _post(recv_url, body) == 200:
                    break
            except Exception:
                time.sleep(0.2)
        else:
            print("FAIL: collector receiver never came up")
            return 1

        # Send a few more batches through the real collector.
        for _ in range(2):
            _post(recv_url, _otlp_spans(3))
        time.sleep(1.0)
        pipe.flush()

        # 1. fan-out preserved: the downstream backend saw the spans
        assert backend.span_count >= 9, f"downstream got {backend.span_count} spans"
        # 2. evidence forked into OpenWright's ledger
        events = list(ledger.events())
        assert len(events) >= 9, f"ledger has {len(events)} events"
        # 3. a signed report built from that ledger verifies offline
        result = evaluate(load_builtin("eu-ai-act"), events)
        report = build_report(
            ledger, result, key, scope_description="OTel Collector fan-out example"
        )
        vr = verify_report(report, trusted_public_key_raw=key.public_key_raw())
        assert vr.valid, "offline verification failed"

        print("PASS — zero-code OpenTelemetry Collector fan-out")
        print(f"  collector           : {Path(otelcol).name}")
        print(f"  downstream spans     : {backend.span_count} (forwarded unchanged)")
        print(f"  evidence events      : {len(events)} (forked into the ledger)")
        print(f"  offline verification : VALID={vr.valid}")
        print("  application changes  : none (collector config only)")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        sink.stop()
        backend.stop()
        pipe.stop()


if __name__ == "__main__":
    sys.exit(main())
