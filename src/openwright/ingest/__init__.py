"""OTLP ingest: receive telemetry, fan out unchanged, fork a copy into evidence.

The evidence path is strictly additive (NFR-REL-01): the receiver forwards the
original OTLP request to any configured downstream backend (Langfuse, Phoenix,
Datadog, …) untouched, and only then enqueues a copy for asynchronous,
non-blocking evidence processing (NFR-PERF-02). A failure anywhere in the
evidence pipeline can never drop, delay, or alter the user's primary telemetry.
"""

from .otlp_common import request_to_spans, anyvalue_to_py, attributes_to_dict
from .pipeline import EvidencePipeline

__all__ = ["request_to_spans", "anyvalue_to_py", "attributes_to_dict", "EvidencePipeline"]
