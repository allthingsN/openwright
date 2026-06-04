"""OTLP/HTTP receiver with fan-out, plus a mock backend for the demo.

The receiver accepts ``POST /v1/traces`` (``application/x-protobuf``, an
``ExportTraceServiceRequest`` body — verified against the OTLP spec). It:

1. enqueues a copy of the spans for asynchronous evidence processing — wrapped
   so this can NEVER affect the next step (NFR-REL-01);
2. forwards the original request bytes to a downstream backend unchanged
   (FR-ING-04), returning that backend's response;
3. otherwise returns an empty ``ExportTraceServiceResponse`` with status 200.

Uses only the standard library plus the OTLP protobuf types.
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)

from .fanout import Forwarder, maybe_forward
from .otlp_common import parse_request, request_to_spans
from .pipeline import EvidencePipeline

log = logging.getLogger("openwright.ingest.http")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence default stderr logging
        return

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path.rstrip("/") != "/v1/traces":
            self.send_error(404, "only /v1/traces is supported")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "application/x-protobuf")

        # (0) Optional bearer-token authn for who may write evidence (NFR-SEC-04).
        authority = getattr(self.server, "token_authority", None)
        if authority is not None:
            from ..authz import Capability

            if not authority.authorize_bearer(self.headers.get("Authorization"), Capability.WRITE_EVIDENCE):
                self.send_error(401, "missing or insufficient bearer token")
                return

        # (1) Additive evidence fork — isolated so it can't affect telemetry.
        try:
            req = parse_request(body)
            self.server.pipeline.submit(request_to_spans(req))  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            log.exception("evidence fork failed (telemetry path unaffected)")

        # (2) Fan-out to downstream unchanged; (3) else acknowledge.
        status, resp_body = maybe_forward(self.server.forwarder, body, content_type)  # type: ignore[attr-defined]
        if self.server.forwarder is None:  # type: ignore[attr-defined]
            resp_body = ExportTraceServiceResponse().SerializeToString()
        self.send_response(status)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)


class EvidenceCollector:
    """A self-hosted OTLP/HTTP collector that forks telemetry into evidence."""

    def __init__(
        self,
        pipeline: EvidencePipeline,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        downstream_url: Optional[str] = None,
        token_authority=None,
    ) -> None:
        self.pipeline = pipeline
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.pipeline = pipeline  # type: ignore[attr-defined]
        self._server.forwarder = Forwarder(downstream_url) if downstream_url else None  # type: ignore[attr-defined]
        self._server.token_authority = token_authority  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def traces_url(self) -> str:
        return f"http://{self._server.server_address[0]}:{self.port}/v1/traces"

    def start(self) -> "EvidenceCollector":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class MockOTLPBackend:
    """A stand-in downstream backend (e.g. Langfuse) that records what it receives.

    Used by the demo/tests to prove telemetry is forwarded unchanged (AC-01).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.request_count = 0
        self.span_count = 0
        self.received_bodies: list[bytes] = []
        backend = self

        class _BackendHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                backend.request_count += 1
                backend.received_bodies.append(body)
                try:
                    req = ExportTraceServiceRequest()
                    req.ParseFromString(body)
                    backend.span_count += sum(
                        len(ss.spans) for rs in req.resource_spans for ss in rs.scope_spans
                    )
                except Exception:  # noqa: BLE001
                    pass
                resp = ExportTraceServiceResponse().SerializeToString()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        self._server = ThreadingHTTPServer((host, port), _BackendHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        addr = self._server.server_address
        return f"http://{addr[0]}:{addr[1]}/v1/traces"

    def start(self) -> "MockOTLPBackend":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
