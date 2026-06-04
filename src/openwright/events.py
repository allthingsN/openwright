"""The canonical ``ComplianceEvent`` — the single record every signal becomes.

Per FR-NRM-01/02 this is the format-independent canonical model. Per DR-01 it
carries actor, provenance, I/O references, model/tool metadata, oversight,
risk, source metadata, and ledger fields. Per DR-02 I/O is referenced by hash
or vault pointer — never inline raw payloads. Per DR-04 the schema is
forward-versioned and unknown future fields are preserved (``extra="allow"``).

Determinism (FR-NRM-04): two helpers define the bytes that get hashed —
:meth:`ComplianceEvent.content_for_id` (everything except ``event_id`` and
``ledger``) derives the deterministic event id, and
:meth:`ComplianceEvent.leaf_content` (everything except ``ledger``) is the
Merkle leaf payload. Ledger fields are assigned at commit time and are
therefore excluded from both.
"""

from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import COMPLIANCE_EVENT_SCHEMA_VERSION
from .canonical import canonical_bytes, sha256_hex


class EventKind(str, enum.Enum):
    """The category of an evidence event."""

    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    AGENT_DECISION = "agent_decision"
    HUMAN_APPROVAL = "human_approval"
    RISK_CLASSIFICATION = "risk_classification"
    POLICY_DECISION = "policy_decision"
    INCIDENT = "incident"
    CONFORMANCE_FINDING = "conformance_finding"
    IDENTITY_CLAIM = "identity_claim"
    TASK_STATUS = "task_status"
    CORRECTION = "correction"
    GENERIC = "generic"


class OversightStatus(str, enum.Enum):
    """Human-oversight state for an event (EU AI Act Art. 14)."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class _Model(BaseModel):
    # extra="allow" so a newer producer can add fields a v1.0 reader still
    # round-trips and preserves (DR-04). Enums serialize to their string value.
    model_config = ConfigDict(extra="allow", use_enum_values=True)


class IdentityClaim(_Model):
    """A cryptographic binding of an event to an agent's A2A AgentCard.

    Addresses the gap (FR-ATT-07) that AgentCard fields are descriptive but not
    cryptographically bound: the claim signs a hash of the AgentCard with a key
    the agent controls, so a verifier can confirm the asserted identity.
    """

    claim_type: str = "agentcard-binding"
    public_key_id: Optional[str] = None
    agent_card_hash: Optional[str] = None
    signature_b64: Optional[str] = None


class Actor(_Model):
    agent_id: str
    agent_card_ref: Optional[str] = None  # URL or sha256: hash of the AgentCard
    identity_claim: Optional[IdentityClaim] = None


class Provenance(_Model):
    """A2A task provenance (FR-ING-05). Absent A2A, degrades to single events."""

    task_id: Optional[str] = None
    context_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    root_task_id: Optional[str] = None


class IORef(_Model):
    """References to I/O — never raw payloads (DR-02). Costs are decimal strings."""

    input_ref: Optional[str] = None
    output_ref: Optional[str] = None
    arguments_ref: Optional[str] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    cost: Optional[str] = None  # decimal string, e.g. "0.00231" (no floats)
    cost_currency: Optional[str] = None


class ModelInfo(_Model):
    provider: Optional[str] = None
    request_model: Optional[str] = None
    response_model: Optional[str] = None


class ToolInfo(_Model):
    name: Optional[str] = None
    call_id: Optional[str] = None


class Oversight(_Model):
    status: OversightStatus = OversightStatus.UNKNOWN
    approval_ref: Optional[str] = None  # event id of a linked human_approval, or external ref
    reviewer: Optional[str] = None


class Risk(_Model):
    classification: Optional[str] = None  # e.g. "high", "limited", "minimal"
    rationale_ref: Optional[str] = None
    framework: Optional[str] = None  # e.g. "eu-ai-act"


class SourceMeta(_Model):
    format: str  # "otel-genai" | "a2a" | "sdk" | "sarif" | "langfuse" | ...
    span_id: Optional[str] = None
    trace_id: Optional[str] = None
    collector_version: Optional[str] = None
    ingested_at: Optional[str] = None


class LedgerFields(_Model):
    """Assigned at commit time; excluded from id/leaf derivation."""

    leaf_hash: Optional[str] = None
    leaf_index: Optional[int] = None
    checkpoint_id: Optional[str] = None
    committed_at: Optional[str] = None
    retention_until: Optional[str] = None


class ComplianceEvent(_Model):
    schema_version: str = COMPLIANCE_EVENT_SCHEMA_VERSION
    event_id: str = ""
    timestamp: str  # RFC 3339, normalized via canonical.to_rfc3339
    kind: EventKind
    actor: Actor
    provenance: Provenance = Field(default_factory=Provenance)
    io: Optional[IORef] = None
    model: Optional[ModelInfo] = None
    tool: Optional[ToolInfo] = None
    oversight: Optional[Oversight] = None
    risk: Optional[Risk] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)
    source: SourceMeta
    ledger: Optional[LedgerFields] = None

    @field_validator("attributes")
    @classmethod
    def _no_floats_in_attributes(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        # Fail fast with an actionable message (NFR-USE-02) rather than at hash
        # time: floats would break deterministic hashing (FR-NRM-04).
        def check(obj: Any, path: str) -> None:
            if isinstance(obj, float):
                raise ValueError(
                    f"attributes.{path} is a float ({obj!r}); use an int or a decimal string "
                    "so events hash deterministically"
                )
            if isinstance(obj, dict):
                for k, val in obj.items():
                    check(val, f"{path}.{k}" if path else str(k))
            elif isinstance(obj, list):
                for i, val in enumerate(obj):
                    check(val, f"{path}[{i}]")

        check(v, "")
        return v

    # -- determinism helpers ------------------------------------------------

    def _dump(self, *, exclude_top: tuple = ()) -> dict:
        data = self.model_dump(mode="json", exclude_none=True)
        for key in exclude_top:
            data.pop(key, None)
        return data

    def content_for_id(self) -> dict:
        """Everything except ``event_id`` and ``ledger`` — drives the id."""
        return self._dump(exclude_top=("event_id", "ledger"))

    def leaf_content(self) -> dict:
        """Everything except ``ledger`` — the Merkle leaf payload."""
        return self._dump(exclude_top=("ledger",))

    def derive_event_id(self) -> str:
        """Deterministic id: ``evt_<40 hex>`` over the content (FR-NRM-04)."""
        digest = sha256_hex(canonical_bytes(self.content_for_id()))
        return "evt_" + digest[:40]

    def finalize_id(self) -> "ComplianceEvent":
        """Return a copy with a deterministic ``event_id`` filled in."""
        self.event_id = self.derive_event_id()
        return self

    def leaf_content_bytes(self) -> bytes:
        """Canonical bytes of the Merkle leaf payload (id included, ledger excluded)."""
        return canonical_bytes(self.leaf_content())
