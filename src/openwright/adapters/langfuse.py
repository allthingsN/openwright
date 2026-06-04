"""Langfuse ``langfuse.*`` attribute precedence (FR-ING-06).

Langfuse documents that its ``langfuse.*`` namespace "always take[s] precedence
over the generic OpenTelemetry conventions" (langfuse.com/integrations/native/
opentelemetry, verified 2026-05). This adapter overlays those values onto an
event already normalized from generic ``gen_ai.*`` attributes.
"""

from __future__ import annotations

from typing import Any, Dict

from ..canonical import hash_payload
from ..events import ComplianceEvent, IORef, ModelInfo

LF_SESSION_ID = "langfuse.session.id"
LF_USER_ID = "langfuse.user.id"
LF_ENVIRONMENT = "langfuse.environment"
LF_OBS_MODEL = "langfuse.observation.model.name"
LF_OBS_INPUT = "langfuse.observation.input"
LF_OBS_OUTPUT = "langfuse.observation.output"
LF_OBS_LEVEL = "langfuse.observation.level"
LF_OBS_TYPE = "langfuse.observation.type"
LF_TRACE_NAME = "langfuse.trace.name"


def has_langfuse_attributes(attrs: Dict[str, Any]) -> bool:
    return any(k.startswith("langfuse.") for k in attrs)


def apply_langfuse_precedence(event: ComplianceEvent, attrs: Dict[str, Any]) -> ComplianceEvent:
    """Mutate ``event`` so langfuse.* values win over generic OTel values."""
    if not has_langfuse_attributes(attrs):
        return event

    # Session id groups related observations → use as context if present.
    if attrs.get(LF_SESSION_ID):
        event.provenance.context_id = str(attrs[LF_SESSION_ID])

    if attrs.get(LF_OBS_MODEL):
        event.model = event.model or ModelInfo()
        event.model.request_model = str(attrs[LF_OBS_MODEL])

    if attrs.get(LF_OBS_INPUT) is not None or attrs.get(LF_OBS_OUTPUT) is not None:
        event.io = event.io or IORef()
        if attrs.get(LF_OBS_INPUT) is not None:
            event.io.input_ref = hash_payload(attrs[LF_OBS_INPUT])
        if attrs.get(LF_OBS_OUTPUT) is not None:
            event.io.output_ref = hash_payload(attrs[LF_OBS_OUTPUT])

    for key, label in ((LF_USER_ID, "user_id"), (LF_ENVIRONMENT, "environment"), (LF_OBS_LEVEL, "level"), (LF_OBS_TYPE, "observation_type"), (LF_TRACE_NAME, "trace_name")):
        if attrs.get(key) is not None:
            event.attributes[f"langfuse.{label}"] = str(attrs[key])

    event.attributes["langfuse_precedence_applied"] = True
    return event
