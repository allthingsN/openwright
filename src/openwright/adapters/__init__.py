"""Source-format adapters (FR-NRM-03).

Each adapter isolates one upstream convention so that a change there (e.g. the
OTel GenAI conventions leaving experimental status — C-01) requires editing only
that adapter, never the core or the canonical event schema. Adapters are
deliberately proto-agnostic: they consume plain Python dicts, so the ingest
layer owns OTLP/protobuf decoding.
"""

from .base import SpanData
from .otel_genai import span_to_event
from .a2a import reconstruct_provenance
from .langfuse import apply_langfuse_precedence, has_langfuse_attributes
from .sarif_in import sarif_to_events
from .policy import policy_decisions_to_events
from .receipt import (
    SignedActionReceiptSource,
    ReceiptSource,
    ReceiptVerificationError,
    receipt_to_event,
    sign_receipt,
)

__all__ = [
    "SpanData",
    "span_to_event",
    "reconstruct_provenance",
    "apply_langfuse_precedence",
    "has_langfuse_attributes",
    "sarif_to_events",
    "policy_decisions_to_events",
    "SignedActionReceiptSource",
    "ReceiptSource",
    "ReceiptVerificationError",
    "receipt_to_event",
    "sign_receipt",
]
