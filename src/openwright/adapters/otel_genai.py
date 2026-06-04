"""OpenTelemetry GenAI semantic-convention adapter (FR-ING-03, FR-NRM-01).

All attribute names live in this module so a future rename is a one-line change
(FR-NRM-03; the conventions are still Experimental/"Development" — C-01). Both
the current names and their deprecated predecessors are accepted, since
instrumentations that have not opted into ``gen_ai_latest_experimental`` still
emit the old names (verified against opentelemetry.io, 2026-05). When both are
present the current name wins.

There is NO ``gen_ai.usage.cost`` attribute in the conventions; cost is derived
downstream from token counts and an operator-supplied pricing table, or omitted.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..canonical import hash_payload
from ..events import ComplianceEvent, EventKind, IORef, ModelInfo, ToolInfo
from .base import SpanData

# -- attribute names (single source of truth) ---------------------------------
A_OPERATION = "gen_ai.operation.name"
A_PROVIDER = "gen_ai.provider.name"
A_PROVIDER_LEGACY = "gen_ai.system"
A_REQUEST_MODEL = "gen_ai.request.model"
A_RESPONSE_MODEL = "gen_ai.response.model"
A_INPUT_TOKENS = "gen_ai.usage.input_tokens"
A_INPUT_TOKENS_LEGACY = "gen_ai.usage.prompt_tokens"
A_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
A_OUTPUT_TOKENS_LEGACY = "gen_ai.usage.completion_tokens"
A_FINISH_REASONS = "gen_ai.response.finish_reasons"
A_TOOL_NAME = "gen_ai.tool.name"
A_TOOL_CALL_ID = "gen_ai.tool.call.id"
A_TOOL_TYPE = "gen_ai.tool.type"
A_CONVERSATION_ID = "gen_ai.conversation.id"
A_AGENT_NAME = "gen_ai.agent.name"
# Deprecated/removed content attributes — hashed if present, never stored raw.
A_PROMPT_LEGACY = "gen_ai.prompt"
A_COMPLETION_LEGACY = "gen_ai.completion"

_OPERATION_TO_KIND = {
    "chat": EventKind.LLM_CALL,
    "generate_content": EventKind.LLM_CALL,
    "text_completion": EventKind.LLM_CALL,
    "embeddings": EventKind.LLM_CALL,
    "execute_tool": EventKind.TOOL_CALL,
    "invoke_agent": EventKind.AGENT_DECISION,
    "create_agent": EventKind.AGENT_DECISION,
    "invoke_workflow": EventKind.AGENT_DECISION,
}


def _first(attrs: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in attrs and attrs[k] is not None:
            return attrs[k]
    return None


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_str_list(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]  # tolerate a scalar emitted instead of a 1-element array


def detected_semconv(attrs: Dict[str, Any]) -> str:
    """Best-effort tag of which convention generation a span follows."""
    if A_PROVIDER in attrs or A_INPUT_TOKENS in attrs:
        return "gen_ai/latest"
    if A_PROVIDER_LEGACY in attrs or A_INPUT_TOKENS_LEGACY in attrs:
        return "gen_ai/legacy"
    return "gen_ai/unknown"


def span_to_event(
    span: SpanData,
    *,
    timestamp: str,
    agent_id: Optional[str] = None,
    pricing: Optional[Dict[str, Any]] = None,
) -> ComplianceEvent:
    """Normalize one GenAI span into a canonical :class:`ComplianceEvent`."""
    attrs = span.attributes or {}
    operation = attrs.get(A_OPERATION)
    kind = _OPERATION_TO_KIND.get(operation, EventKind.GENERIC)

    resolved_agent = (
        agent_id
        or attrs.get(A_AGENT_NAME)
        or span.resource.get("service.name")
        or "unknown-agent"
    )

    input_tokens = _coerce_int(_first(attrs, A_INPUT_TOKENS, A_INPUT_TOKENS_LEGACY))
    output_tokens = _coerce_int(_first(attrs, A_OUTPUT_TOKENS, A_OUTPUT_TOKENS_LEGACY))
    total_tokens = (input_tokens or 0) + (output_tokens or 0) if (input_tokens or output_tokens) else None

    # Legacy raw content, if present, is hashed — never stored inline (FR-LED-06).
    prompt = attrs.get(A_PROMPT_LEGACY)
    completion = attrs.get(A_COMPLETION_LEGACY)

    cost = None
    if pricing and (input_tokens is not None or output_tokens is not None):
        cost = _compute_cost(pricing, _first(attrs, A_REQUEST_MODEL, A_RESPONSE_MODEL), input_tokens, output_tokens)

    io = IORef(
        input_ref=hash_payload(prompt) if prompt is not None else None,
        output_ref=hash_payload(completion) if completion is not None else None,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        cost=cost,
        cost_currency="USD" if cost else None,
    )
    model = ModelInfo(
        provider=_first(attrs, A_PROVIDER, A_PROVIDER_LEGACY),
        request_model=attrs.get(A_REQUEST_MODEL),
        response_model=attrs.get(A_RESPONSE_MODEL),
    )
    tool = None
    if attrs.get(A_TOOL_NAME) or attrs.get(A_TOOL_CALL_ID):
        tool = ToolInfo(name=attrs.get(A_TOOL_NAME), call_id=attrs.get(A_TOOL_CALL_ID))

    extra: Dict[str, Any] = {}
    if operation:
        extra["operation"] = operation
    finish = _coerce_str_list(attrs.get(A_FINISH_REASONS))
    if finish:
        extra["finish_reasons"] = finish
    if attrs.get(A_TOOL_TYPE):
        extra["tool_type"] = attrs[A_TOOL_TYPE]
    extra["semconv"] = detected_semconv(attrs)

    conversation_id = attrs.get(A_CONVERSATION_ID)

    return ComplianceEvent(
        timestamp=timestamp,
        kind=kind,
        actor={"agent_id": resolved_agent},
        provenance={"context_id": conversation_id} if conversation_id else {},
        io=io if any(v is not None for v in io.model_dump().values()) else None,
        model=model if any(model.model_dump().values()) else None,
        tool=tool,
        attributes=extra,
        source={
            "format": "otel-genai",
            "span_id": span.span_id,
            "trace_id": span.trace_id,
        },
    )


def _compute_cost(
    pricing: Dict[str, Any], model: Optional[str], in_tok: Optional[int], out_tok: Optional[int]
) -> Optional[str]:
    """Derive a cost as a decimal string (no floats in the event — FR-NRM-04)."""
    from decimal import Decimal

    rates = pricing.get(model) if model else None
    rates = rates or pricing.get("default")
    if not rates:
        return None
    cost = Decimal(0)
    if in_tok:
        cost += Decimal(str(rates.get("input_per_1k", 0))) * Decimal(in_tok) / Decimal(1000)
    if out_tok:
        cost += Decimal(str(rates.get("output_per_1k", 0))) * Decimal(out_tok) / Decimal(1000)
    return f"{cost:.6f}"
