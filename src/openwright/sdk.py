"""Python SDK for recording explicit evidence events (FR-SDK).

Telemetry can't infer human approvals, risk classifications, or policy
decisions — the SDK records those out-of-band (FR-SDK-02), linked by task ID.
The developer never touches hashing, signing, or Merkle mechanics (FR-SDK-04):
raw inputs/outputs are hashed into references automatically and committed to the
ledger, which handles attestation.

It is framework-agnostic; ``examples/`` demonstrates it standalone and against
LangGraph (FR-SDK-05).
"""

from __future__ import annotations

import contextlib
import contextvars
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional

from .canonical import hash_payload, to_rfc3339
from .events import (
    Actor,
    ComplianceEvent,
    EventKind,
    IdentityClaim,
    IORef,
    ModelInfo,
    Oversight,
    OversightStatus,
    Provenance,
    Risk,
)
from .ledger import Ledger

_current_scope: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "openwright_task_scope", default={}
)


def _now() -> str:
    return to_rfc3339(datetime.now(timezone.utc))


class EvidenceClient:
    """Records explicit evidence events into a :class:`~openwright.ledger.Ledger`."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        agent_id: str,
        agent_card_ref: Optional[str] = None,
        identity_claim: Optional[IdentityClaim] = None,
        clock: Callable[[], str] = _now,
        vault=None,
        principal=None,
        authorizer=None,
    ) -> None:
        self.ledger = ledger
        self.agent_id = agent_id
        self.agent_card_ref = agent_card_ref
        self.identity_claim = identity_claim
        self._clock = clock
        # Optional payload vault (NFR-PRIV-03): stores raw payloads separately,
        # referenced by the same hash. Default None → hash only, nothing stored.
        self._vault = vault
        # Optional authorization (NFR-SEC-04): gate evidence writes.
        self._principal = principal
        self._authorizer = authorizer

    def _ref(self, payload):
        """Hash a payload into a ledger reference, vaulting the raw if configured."""
        if self._vault is not None:
            return self._vault.store(payload)
        return hash_payload(payload)

    # -- provenance scope ---------------------------------------------------

    @contextlib.contextmanager
    def task(
        self,
        task_id: str,
        *,
        context_id: Optional[str] = None,
        parent_task_id: Optional[str] = None,
        root_task_id: Optional[str] = None,
    ):
        """Set the ambient A2A provenance for events recorded inside the block."""
        scope = {
            "task_id": task_id,
            "context_id": context_id or task_id,
            "parent_task_id": parent_task_id,
            "root_task_id": root_task_id or task_id,
        }
        token = _current_scope.set(scope)
        try:
            yield self
        finally:
            _current_scope.reset(token)

    def _provenance(self, overrides: Dict[str, Any]) -> Provenance:
        merged = dict(_current_scope.get())
        merged.update({k: v for k, v in overrides.items() if v is not None})
        return Provenance(**merged) if merged else Provenance()

    def _actor(self) -> Actor:
        return Actor(
            agent_id=self.agent_id,
            agent_card_ref=self.agent_card_ref,
            identity_claim=self.identity_claim,
        )

    # -- generic + specific recorders --------------------------------------

    def record(self, event: ComplianceEvent) -> ComplianceEvent:
        if self._authorizer is not None:
            from .authz import Capability

            self._authorizer.require(self._principal, Capability.WRITE_EVIDENCE)
        return self.ledger.commit(event)

    def record_decision(
        self,
        *,
        output: Any = None,
        input: Any = None,
        risk_classification: Optional[str] = None,
        rationale: Any = None,
        approval_ref: Optional[str] = None,
        model: Optional[Dict[str, Any]] = None,
        control: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        context_id: Optional[str] = None,
        root_task_id: Optional[str] = None,
    ) -> ComplianceEvent:
        attrs = dict(attributes or {})
        if control:
            attrs["control"] = control
        ev = ComplianceEvent(
            timestamp=self._clock(),
            kind=EventKind.AGENT_DECISION,
            actor=self._actor(),
            provenance=self._provenance(
                {"task_id": task_id, "context_id": context_id, "root_task_id": root_task_id}
            ),
            io=IORef(
                input_ref=self._ref(input) if input is not None else None,
                output_ref=self._ref(output) if output is not None else None,
            ),
            model=ModelInfo(**model) if model else None,
            risk=Risk(
                classification=risk_classification,
                rationale_ref=self._ref(rationale) if rationale is not None else None,
                framework="eu-ai-act" if risk_classification else None,
            )
            if risk_classification or rationale is not None
            else None,
            oversight=Oversight(status=OversightStatus.APPROVED, approval_ref=approval_ref)
            if approval_ref
            else None,
            attributes=attrs,
            source={"format": "sdk"},
        )
        return self.record(ev)

    def record_human_approval(
        self,
        *,
        reviewer: str,
        approved: bool = True,
        rationale: Any = None,
        task_id: Optional[str] = None,
        context_id: Optional[str] = None,
        root_task_id: Optional[str] = None,
    ) -> ComplianceEvent:
        ev = ComplianceEvent(
            timestamp=self._clock(),
            kind=EventKind.HUMAN_APPROVAL,
            actor=self._actor(),
            provenance=self._provenance(
                {"task_id": task_id, "context_id": context_id, "root_task_id": root_task_id}
            ),
            oversight=Oversight(
                status=OversightStatus.APPROVED if approved else OversightStatus.REJECTED,
                reviewer=reviewer,
            ),
            io=IORef(input_ref=self._ref(rationale)) if rationale is not None else None,
            source={"format": "sdk"},
        )
        return self.record(ev)

    def record_risk_classification(
        self,
        classification: str,
        *,
        rationale: Any = None,
        fria: Any = None,
        framework: str = "eu-ai-act",
        task_id: Optional[str] = None,
        context_id: Optional[str] = None,
        root_task_id: Optional[str] = None,
    ) -> ComplianceEvent:
        attrs: Dict[str, Any] = {}
        if fria is not None:
            attrs["fria_ref"] = self._ref(fria)
        ev = ComplianceEvent(
            timestamp=self._clock(),
            kind=EventKind.RISK_CLASSIFICATION,
            actor=self._actor(),
            provenance=self._provenance(
                {"task_id": task_id, "context_id": context_id, "root_task_id": root_task_id}
            ),
            risk=Risk(
                classification=classification,
                rationale_ref=self._ref(rationale) if rationale is not None else None,
                framework=framework,
            ),
            attributes=attrs,
            source={"format": "sdk"},
        )
        return self.record(ev)

    def record_policy_decision(
        self,
        *,
        decision: str,
        policy: str,
        task_id: Optional[str] = None,
        context_id: Optional[str] = None,
        root_task_id: Optional[str] = None,
    ) -> ComplianceEvent:
        ev = ComplianceEvent(
            timestamp=self._clock(),
            kind=EventKind.POLICY_DECISION,
            actor=self._actor(),
            provenance=self._provenance(
                {"task_id": task_id, "context_id": context_id, "root_task_id": root_task_id}
            ),
            attributes={"decision": decision, "policy": policy},
            source={"format": "sdk"},
        )
        return self.record(ev)

    def record_incident(
        self,
        *,
        severity: str,
        report_deadline_days: int,
        description: Any = None,
        task_id: Optional[str] = None,
        context_id: Optional[str] = None,
        root_task_id: Optional[str] = None,
    ) -> ComplianceEvent:
        ev = ComplianceEvent(
            timestamp=self._clock(),
            kind=EventKind.INCIDENT,
            actor=self._actor(),
            provenance=self._provenance(
                {"task_id": task_id, "context_id": context_id, "root_task_id": root_task_id}
            ),
            io=IORef(input_ref=self._ref(description)) if description is not None else None,
            attributes={"severity": severity, "report_deadline_days": report_deadline_days},
            source={"format": "sdk"},
        )
        return self.record(ev)


def high_risk_decision(
    client: EvidenceClient,
    *,
    control: str,
    risk_classification: str = "high",
    approval_ref: Optional[str] = None,
    capture_io: bool = True,
) -> Callable:
    """Decorator that records a function call as a high-risk decision tied to a
    named control (FR-SDK-03). Hashing of args/result is automatic."""

    def decorate(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            client.record_decision(
                output=repr(result) if capture_io else None,
                input=repr({"args": args, "kwargs": kwargs}) if capture_io else None,
                rationale=f"decision produced by {fn.__name__}",
                risk_classification=risk_classification,
                approval_ref=approval_ref,
                control=control,
            )
            return result

        return wrapper

    return decorate
