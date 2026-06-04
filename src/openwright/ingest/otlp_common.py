"""Decode OTLP protobuf into proto-agnostic :class:`SpanData` (FR-ING-03).

This is the only module that imports the OpenTelemetry protobuf types, keeping
the adapters free of protobuf concerns (FR-NRM-03).
"""

from __future__ import annotations

from typing import Any, Dict, List

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)

from ..adapters.base import SpanData


def anyvalue_to_py(av: Any) -> Any:
    """Convert an OTLP ``AnyValue`` (oneof) to a plain Python value."""
    which = av.WhichOneof("value")
    if which is None:
        return None
    if which == "string_value":
        return av.string_value
    if which == "bool_value":
        return av.bool_value
    if which == "int_value":
        return av.int_value
    if which == "double_value":
        return av.double_value
    if which == "bytes_value":
        return av.bytes_value.hex()
    if which == "array_value":
        return [anyvalue_to_py(v) for v in av.array_value.values]
    if which == "kvlist_value":
        return {kv.key: anyvalue_to_py(kv.value) for kv in av.kvlist_value.values}
    return None


def attributes_to_dict(kv_list: Any) -> Dict[str, Any]:
    return {kv.key: anyvalue_to_py(kv.value) for kv in kv_list}


def parse_request(body: bytes) -> ExportTraceServiceRequest:
    req = ExportTraceServiceRequest()
    req.ParseFromString(body)
    return req


def request_to_spans(req: ExportTraceServiceRequest) -> List[SpanData]:
    """Flatten an OTLP trace export request into a list of :class:`SpanData`."""
    spans: List[SpanData] = []
    for rs in req.resource_spans:
        resource = attributes_to_dict(rs.resource.attributes) if rs.HasField("resource") else {}
        for ss in rs.scope_spans:
            for sp in ss.spans:
                spans.append(
                    SpanData(
                        name=sp.name,
                        attributes=attributes_to_dict(sp.attributes),
                        resource=resource,
                        trace_id=sp.trace_id.hex() or None,
                        span_id=sp.span_id.hex() or None,
                        parent_span_id=sp.parent_span_id.hex() or None,
                        start_time_unix_nano=sp.start_time_unix_nano or None,
                        status=str(sp.status.code) if sp.HasField("status") else None,
                    )
                )
    return spans
