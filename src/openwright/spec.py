"""Published, standalone, versioned schemas (FR-NRM-02, FR-MAP-01, AC-07).

The ``ComplianceEvent`` JSON Schema is independent of any source format, and the
crosswalk format is itself a published schema. Both are generated from the
Pydantic models so they can never drift from the code.
"""

from __future__ import annotations

from typing import Any, Dict

from . import COMPLIANCE_EVENT_SCHEMA_VERSION
from .crosswalk import Crosswalk
from .events import ComplianceEvent


# Stable, owned-domain base for published schema $id (U3). Repointed off the
# private-repo GitHub placeholder (which would 404) to an owned domain before any
# public schema commitment; the version path is preserved. The DNS/hosting for
# this domain is provisioned as part of going public.
SCHEMA_ID_BASE = "https://schemas.openwright.dev"


def compliance_event_schema() -> Dict[str, Any]:
    schema = ComplianceEvent.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"{SCHEMA_ID_BASE}/compliance_event/{COMPLIANCE_EVENT_SCHEMA_VERSION}"
    schema["title"] = "OpenWright ComplianceEvent"
    schema["x-openwright-schema-version"] = COMPLIANCE_EVENT_SCHEMA_VERSION
    return schema


def crosswalk_schema() -> Dict[str, Any]:
    schema = Crosswalk.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"{SCHEMA_ID_BASE}/crosswalk/1.0.0"
    schema["title"] = "OpenWright Crosswalk"
    return schema


def report_schema() -> Dict[str, Any]:
    """Published JSON Schema for the signed report envelope (FR-RPT-02, V13).

    Hand-authored (the report is an assembled dict, not a single pydantic model).
    ``additionalProperties`` is allowed for forward-compatible fields; each embedded
    event is governed by :func:`compliance_event_schema`.
    """
    from .report import REPORT_VERSION

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{SCHEMA_ID_BASE}/report/{REPORT_VERSION}",
        "title": "OpenWright Report",
        "type": "object",
        "required": [
            "report_version", "report_id", "generated_at", "tool", "boundary_statement",
            "scope", "crosswalk", "summary", "controls", "checkpoint", "events",
            "public_key_pem", "signature",
        ],
        "properties": {
            "report_version": {"type": "string"},
            "report_id": {"type": "string"},
            "generated_at": {"type": "string"},
            "tool": {"type": "object", "required": ["name", "version"]},
            "boundary_statement": {"type": "string"},
            "scope": {
                "type": "object",
                "required": ["description", "agent_ids"],
                "properties": {"agent_ids": {"type": "array", "items": {"type": "string"}}},
            },
            "period": {"type": "object"},
            "crosswalk": {
                "type": "object",
                "required": ["id", "version", "content_hash"],
                "properties": {
                    "id": {"type": "string"},
                    "version": {"type": "string"},
                    "content_hash": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                },
            },
            "summary": {
                "type": "object",
                "required": ["total", "satisfied", "not_satisfied", "insufficient_evidence"],
            },
            "controls": {"type": "array"},
            "evidence_gaps": {"type": "array"},
            "checkpoint": {
                "type": "object",
                "required": ["origin", "tree_size", "root_hash", "timestamp", "public_key_id", "signature"],
            },
            "events": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["event", "leaf_index", "inclusion_proof"],
                    "properties": {
                        "event": {"type": "object"},
                        "leaf_index": {"type": "integer", "minimum": 0},
                        "inclusion_proof": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            "public_key_pem": {"type": "string"},
            "signature": {
                "type": "object",
                "required": ["algorithm", "public_key_id", "signature"],
            },
        },
    }
