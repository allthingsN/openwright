"""OTLP ingest, fan-out preservation, and failure isolation (FR-ING, NFR-REL)."""

from __future__ import annotations

import importlib.util
import time
import urllib.request

import pytest

_HAS_GRPC = importlib.util.find_spec("grpc") is not None

from openwright.ingest.http_server import EvidenceCollector, MockOTLPBackend
from openwright.ingest.pipeline import EvidencePipeline
from openwright.ledger import InMemoryLedgerBackend, Ledger


def _otlp_request_bytes():
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    req = ExportTraceServiceRequest()
    rs = req.resource_spans.add()
    kv = rs.resource.attributes.add()
    kv.key = "service.name"
    kv.value.string_value = "agent-x"
    ss = rs.scope_spans.add()
    sp = ss.spans.add()
    sp.name = "chat"
    for k, v in [("gen_ai.operation.name", "chat"), ("gen_ai.request.model", "m1")]:
        a = sp.attributes.add()
        a.key = k
        a.value.string_value = v
    return req.SerializeToString()


def _post(url, body, content_type="application/x-protobuf"):
    r = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": content_type})
    with urllib.request.urlopen(r, timeout=5) as resp:
        return resp.status, resp.read()


@pytest.fixture
def stack():
    backend = MockOTLPBackend().start()
    led = Ledger(InMemoryLedgerBackend())
    pipe = EvidencePipeline(led, agent_id="agent-x")
    coll = EvidenceCollector(pipe, downstream_url=backend.url).start()
    yield backend, led, pipe, coll
    coll.stop()
    backend.stop()
    pipe.stop()


def test_fanout_preserves_bytes_and_forks_evidence(stack):
    backend, led, pipe, coll = stack
    body = _otlp_request_bytes()
    status, _ = _post(coll.traces_url, body)
    assert status == 200
    pipe.flush()
    # downstream got the EXACT bytes unchanged (FR-ING-04)
    assert backend.request_count == 1
    assert backend.received_bodies[0] == body
    # and a copy was forked into evidence (NFR-REL-01)
    assert led.size() == 1
    assert led.get_event(0).model.request_model == "m1"


def test_malformed_body_does_not_crash_or_affect_telemetry(stack):
    backend, led, pipe, coll = stack
    # garbage body: evidence fork fails internally but request still succeeds
    status, _ = _post(coll.traces_url, b"not-a-protobuf")
    assert status == 200
    # collector still healthy for a subsequent valid request
    _post(coll.traces_url, _otlp_request_bytes())
    pipe.flush()
    assert led.size() == 1


def test_pipeline_processes_without_blocking():
    led = Ledger(InMemoryLedgerBackend())
    pipe = EvidencePipeline(led, agent_id="a")
    from openwright.adapters.base import SpanData

    spans = [SpanData("chat", {"gen_ai.operation.name": "chat"}) for _ in range(50)]
    pipe.submit(spans)
    pipe.flush()
    assert pipe.stats()["processed"] == 50
    pipe.stop()


def test_worker_survives_normalization_error_and_counts():
    """F1: a span that throws in _normalize must NOT kill the daemon worker —
    it is counted and skipped, and later spans still process."""
    from openwright.adapters.base import SpanData

    led = Ledger(InMemoryLedgerBackend())
    pipe = EvidencePipeline(led, agent_id="a")
    # A float unix-nano makes to_rfc3339 raise inside _normalize.
    pipe.submit([SpanData("chat", {"gen_ai.operation.name": "chat"}, start_time_unix_nano=1.5)])
    pipe.flush()
    assert pipe._thread.is_alive()  # worker survived the exception
    # A subsequent good span is still processed.
    pipe.submit([SpanData("chat", {"gen_ai.operation.name": "chat"})])
    pipe.flush()
    stats = pipe.stats()
    assert stats["errors"] == 1
    assert stats["processed"] == 1
    assert led.size() == 1
    pipe.stop()


def test_dropped_spans_recorded_as_tamper_evident_gap_marker():
    """F2: queue-full drops are attested in the ledger as an evidence_gap marker
    so the log self-attests the loss (completeness, not just integrity)."""
    import threading

    from openwright.adapters.base import SpanData

    led = Ledger(InMemoryLedgerBackend())
    release = threading.Event()
    real_commit = led.commit
    state = {"blocked_once": False}

    def slow_commit(ev):
        # Block the first commit so the (size-1) queue overflows and drops.
        if not state["blocked_once"]:
            state["blocked_once"] = True
            release.wait(3)
        return real_commit(ev)

    led.commit = slow_commit
    pipe = EvidencePipeline(led, agent_id="a", max_queue=1)
    pipe.submit([SpanData("chat", {"gen_ai.operation.name": "chat"}) for _ in range(12)])
    assert pipe.dropped >= 1  # some spans overflowed the bounded queue
    release.set()
    pipe.flush()
    pipe.stop()

    events = list(led.events())
    markers = [e for e in events if e.attributes.get("marker") == "evidence_gap"]
    assert markers, "expected at least one tamper-evident evidence_gap marker"
    assert sum(m.attributes["dropped_events"] for m in markers) == pipe.dropped
    assert pipe.stats()["drop_markers"] == len(markers)
    # the marker carries a time window of the loss
    assert markers[0].attributes["window_start"] is not None


@pytest.mark.skipif(not _HAS_GRPC, reason="grpcio not installed")
def test_grpc_receiver_accepts_export():
    import grpc
    from opentelemetry.proto.collector.trace.v1 import trace_service_pb2, trace_service_pb2_grpc

    led = Ledger(InMemoryLedgerBackend())
    pipe = EvidencePipeline(led, agent_id="a")
    from openwright.ingest.grpc_server import serve_grpc

    server = serve_grpc(pipe, port=4399)
    try:
        channel = grpc.insecure_channel("127.0.0.1:4399")
        stub = trace_service_pb2_grpc.TraceServiceStub(channel)
        req = trace_service_pb2.ExportTraceServiceRequest()
        rs = req.resource_spans.add()
        ss = rs.scope_spans.add()
        sp = ss.spans.add()
        sp.name = "chat"
        a = sp.attributes.add()
        a.key = "gen_ai.operation.name"
        a.value.string_value = "chat"
        stub.Export(req, timeout=5)
        time.sleep(0.2)
        pipe.flush()
        assert led.size() == 1
        channel.close()
    finally:
        server.stop(0)
        pipe.stop()
