"""Shared adapter input types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class SpanData:
    """A telemetry span reduced to plain Python (no protobuf types).

    The ingest layer fills this from OTLP; adapters consume it. Keeping adapters
    free of protobuf imports is what makes them swappable (FR-NRM-03).
    """

    name: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    resource: Dict[str, Any] = field(default_factory=dict)
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    start_time_unix_nano: Optional[int] = None
    status: Optional[str] = None
