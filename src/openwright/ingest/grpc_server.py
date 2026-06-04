"""OTLP/gRPC receiver (FR-ING-01). grpcio is imported lazily so the rest of
OpenWright works on platforms without a grpcio wheel."""

from __future__ import annotations

import logging
from concurrent import futures
from typing import Optional

from .pipeline import EvidencePipeline

log = logging.getLogger("openwright.ingest.grpc")


def serve_grpc(
    pipeline: EvidencePipeline,
    *,
    host: str = "127.0.0.1",
    port: int = 4317,
    max_workers: int = 8,
):
    """Start an OTLP/gRPC trace receiver. Returns the running grpc.Server."""
    import grpc
    from opentelemetry.proto.collector.trace.v1 import (
        trace_service_pb2,
        trace_service_pb2_grpc,
    )

    from .otlp_common import request_to_spans

    class _TraceService(trace_service_pb2_grpc.TraceServiceServicer):
        def Export(self, request, context):  # noqa: N802 (gRPC naming)
            try:
                pipeline.submit(request_to_spans(request))
            except Exception:  # noqa: BLE001 - additive; never fail the RPC
                log.exception("evidence fork failed (telemetry unaffected)")
            return trace_service_pb2.ExportTraceServiceResponse()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    trace_service_pb2_grpc.add_TraceServiceServicer_to_server(_TraceService(), server)
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    log.info("OTLP/gRPC receiver listening on %s:%d", host, port)
    return server
