"""End-to-end proof of the native OpenWright Collector exporter (Option B).

This is Option B from docs/OTEL_PROCESSOR_SCOPE.md: a native, registry-listable
OpenTelemetry Collector component (`openwright`) you add to a Collector you build
with the OpenTelemetry Collector Builder. It forwards a copy of traces to the
OpenWright evidence sink, keeping the cryptographic core a single byte-exact
Python implementation.

The script runs the custom `openwright-otelcol` distribution with a pipeline that
exports through the native `openwright` exporter, then asserts:

  1. evidence was forked into OpenWright's ledger via the Go component;
  2. a signed report built from that ledger verifies OFFLINE;
  3. CONFORMANCE: the evidence produced through the Go exporter path is
     **byte-identical** (same Merkle leaf hashes) to evidence produced by
     ingesting the very same spans directly through the Python core — proving
     the native component changes the transport, never the crypto.

Build the distribution first::

    builder --config otel/builder-config.yaml      # produces otel/_build/openwright-otelcol

Then run::

    OPENWRIGHT_OTELCOL=otel/_build/openwright-otelcol \
        poetry run python examples/otel_collector/verify_native_exporter.py

If the binary is absent the script prints how to build it and exits 0.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import load_builtin
from openwright.ingest.http_server import EvidenceCollector
from openwright.ingest.otlp_common import parse_request, request_to_spans
from openwright.ingest.pipeline import EvidencePipeline
from openwright.ledger import FileLedgerBackend, InMemoryLedgerBackend, Ledger
from openwright.report import build_report
from openwright.signing import FileKeySource, generate_private_key_pem
from openwright.verify import verify_report

FIXED_START_NS = 1_700_000_000_000_000_000


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _otlp_bytes(n: int = 9) -> bytes:
    """One OTLP request with n fully-determined spans (fixed ids + timestamps)."""
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
        sp.trace_id = (i + 1).to_bytes(16, "big")
        sp.span_id = (i + 1).to_bytes(8, "big")
        sp.start_time_unix_nano = FIXED_START_NS + i
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


CONFIG = """\
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:{recv_port}
exporters:
  openwright:
    endpoint: {openwright_base}
service:
  telemetry:
    logs:
      level: warn
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [openwright]
"""


def _leaf_hashes(ledger: Ledger) -> list:
    return sorted(ev.ledger.leaf_hash for ev in ledger.events() if ev.ledger)


def main() -> int:
    binary = os.environ.get("OPENWRIGHT_OTELCOL") or "otel/_build/openwright-otelcol"
    if not Path(binary).exists():
        print(f"OpenWright collector distribution not found at {binary}.")
        print("Build it:  builder --config otel/builder-config.yaml")
        return 0  # skip, don't fail

    work = Path(tempfile.mkdtemp(prefix="openwright-native-"))
    key_path = work / "key.pem"
    pem = generate_private_key_pem()
    key_path.write_bytes(pem if isinstance(pem, bytes) else pem.encode())
    key = FileKeySource(str(key_path))

    # Ledger A: fed through the native Go exporter -> OpenWright sink.
    ledger_a = Ledger(FileLedgerBackend(work / "ledger_a"))
    pipe_a = EvidencePipeline(ledger_a, agent_id="loan-agent")
    sink = EvidenceCollector(pipe_a).start()

    recv_port = _free_port()
    openwright_base = sink.traces_url.rsplit("/v1/traces", 1)[0]
    cfg = work / "config.yaml"
    cfg.write_text(CONFIG.format(recv_port=recv_port, openwright_base=openwright_base))

    payload = _otlp_bytes(9)
    proc = subprocess.Popen(
        [binary, "--config", str(cfg)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        recv_url = f"http://127.0.0.1:{recv_port}/v1/traces"
        for _ in range(50):
            try:
                if _post(recv_url, payload) == 200:
                    break
            except Exception:
                time.sleep(0.2)
        else:
            print("FAIL: openwright-otelcol receiver never came up")
            return 1
        time.sleep(1.0)
        pipe_a.flush()

        # 1. evidence forked through the Go component
        events_a = list(ledger_a.events())
        assert len(events_a) >= 9, f"ledger A has {len(events_a)} events"
        # 2. signed report verifies offline
        result = evaluate(load_builtin("eu-ai-act"), events_a)
        report = build_report(ledger_a, result, key, scope_description="native openwright exporter")
        vr = verify_report(report, trusted_public_key_raw=key.public_key_raw())
        assert vr.valid, "offline verification failed"

        # 3. CONFORMANCE: ingest the SAME spans directly through the Python core
        ledger_b = Ledger(InMemoryLedgerBackend())
        pipe_b = EvidencePipeline(ledger_b, agent_id="loan-agent")
        pipe_b.submit(request_to_spans(parse_request(payload)))
        pipe_b.flush()
        a_hashes, b_hashes = _leaf_hashes(ledger_a), _leaf_hashes(ledger_b)
        pipe_b.stop()
        assert a_hashes == b_hashes, "Go-path evidence diverged from Python-path evidence!"

        print("PASS — native OpenWright OpenTelemetry Collector exporter (Option B)")
        print(f"  distribution         : {Path(binary).name}")
        print(f"  evidence events      : {len(events_a)} (forked via the native `openwright` exporter)")
        print(f"  offline verification : VALID={vr.valid}")
        print(f"  byte-identical to Python core : {a_hashes == b_hashes} ({len(a_hashes)} leaf hashes match)")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        sink.stop()
        pipe_a.stop()


if __name__ == "__main__":
    sys.exit(main())
