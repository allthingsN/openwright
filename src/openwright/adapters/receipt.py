"""External receipt-primitive ingest — the "sit on top of receipts" adapter.

(Proposal §A1; adapter isolation FR-NRM-03; untrusted input FR-ING-10.)

OpenWright does not reinvent cryptographic action receipts — it *consumes* them and
turns them into compliance evidence. This adapter verifies a signed receipt's
Ed25519 signature **before** ingesting it, then normalizes it into a canonical
``ComplianceEvent(kind=tool_call)``. We attest events ourselves with the in-house
Merkle stack *or* anchor on receipts produced upstream; this is the layer above
the receipt primitive, not a competitor to any one producer.

Other receipt formats (sigstore-style, a first-party format) plug in behind the
same :class:`ReceiptSource` interface — the receipt primitive is interchangeable.

A receipt is untrusted input (FR-ING-10, NFR-SEC-01): an unsigned, malformed, or
tampered receipt is rejected with :class:`ReceiptVerificationError` and never
enters the ledger as a normal event. Verification precedes ingestion.
"""

from __future__ import annotations

import abc
import base64
from typing import Any, Dict, Optional

from ..canonical import canonical_bytes, to_rfc3339
from ..events import Actor, ComplianceEvent, EventKind, IdentityClaim, IORef, ToolInfo
from ..signing import KeySource, key_id_for, verify_signature


class ReceiptVerificationError(Exception):
    """A receipt's signature was missing, malformed, or did not verify.

    The receipt is NOT turned into a tool_call event — verification precedes
    ingestion.
    """


def receipt_signing_bytes(receipt: Dict[str, Any]) -> bytes:
    """The exact bytes a receipt signs over: its canonical form minus ``sig``.

    Deterministic and verifier-reproducible (the same JCS canonicalization the
    rest of OpenWright uses), so any party holding the signer's public key can
    re-derive these bytes and check the signature independently.
    """
    return canonical_bytes({k: v for k, v in receipt.items() if k != "sig"})


class ReceiptSource(abc.ABC):
    """Interchangeable receipt-primitive adapter.

    Implement :meth:`verify_and_normalize` to teach OpenWright a new signed-receipt
    format. Every source verifies its own signature scheme and emits the same
    canonical :class:`ComplianceEvent`, so receipt primitives are swappable
    behind one interface.
    """

    #: ``source.format`` tag stamped on events produced by this source.
    format: str

    @abc.abstractmethod
    def verify_and_normalize(
        self, receipt: Dict[str, Any], *, agent_id_default: Optional[str] = None
    ) -> ComplianceEvent:
        """Verify ``receipt``'s signature and return a canonical event, or raise."""


class SignedActionReceiptSource(ReceiptSource):
    """Consumes a signed Ed25519 **action receipt** — the commoditizing receipt
    primitive several crypto-audit tools emit. This adapter targets the generic,
    public shape of such a receipt so OpenWright can verify + ingest it; it is not
    tied to any one producer (other formats plug in behind :class:`ReceiptSource`).

    Receipt shape (all values JSON; ``signer.pubkey`` is base64 of the raw
    32-byte Ed25519 key and ``sig`` is base64 of the signature)::

        {"action": {"tool": ..., "params_hash": "sha256:...", "target": ...},
         "signer": {"pubkey": "<b64>", "name": ..., "owner": ...},
         "ts": <rfc3339|unix>, "nonce": ..., "transport": ..., "sig": "<b64>"}

    Mapping → ``ComplianceEvent(kind=tool_call)``: ``tool.name`` ← action.tool;
    ``io.arguments_ref`` ← action.params_hash (already a ``sha256:`` ref — fits
    cleanly with no PII); ``actor.agent_id`` ← signer.name; signer pubkey/owner →
    ``actor.identity_claim``; nonce/target/transport → ``attributes``.
    """

    format = "receipt/action-v1"

    def verify_and_normalize(
        self, receipt: Dict[str, Any], *, agent_id_default: Optional[str] = None
    ) -> ComplianceEvent:
        if not isinstance(receipt, dict):
            raise ReceiptVerificationError("receipt must be a JSON object")
        action = receipt.get("action")
        signer = receipt.get("signer")
        if not isinstance(action, dict) or not isinstance(signer, dict):
            raise ReceiptVerificationError("receipt missing action/signer object")

        sig_b64 = receipt.get("sig")
        pubkey_b64 = signer.get("pubkey")
        if not sig_b64 or not pubkey_b64:
            raise ReceiptVerificationError("receipt missing signature or signer pubkey")
        try:
            sig = base64.b64decode(sig_b64)
            pub_raw = base64.b64decode(pubkey_b64)
        except (ValueError, TypeError) as exc:
            raise ReceiptVerificationError(f"malformed base64 in receipt: {exc}") from exc

        # Verify BEFORE ingest. The signed bytes are the canonical receipt minus
        # the signature itself, so any tampered field flips this to False.
        if not verify_signature(pub_raw, sig, receipt_signing_bytes(receipt)):
            raise ReceiptVerificationError("receipt Ed25519 signature did not verify")

        ts = receipt.get("ts")
        if ts is None:
            raise ReceiptVerificationError("receipt missing ts")

        # The signer pubkey/owner are carried (verifiably) into the identity
        # claim; extra="allow" on IdentityClaim preserves the non-AgentCard fields.
        identity_extra: Dict[str, Any] = {"public_key_b64": pubkey_b64}
        if signer.get("owner") is not None:
            identity_extra["owner"] = signer["owner"]
        identity = IdentityClaim(
            claim_type="receipt-signer",
            public_key_id=key_id_for(pub_raw),
            signature_b64=sig_b64,
            **identity_extra,
        )

        attributes: Dict[str, Any] = {"receipt_verified": True}
        if receipt.get("nonce") is not None:
            attributes["nonce"] = receipt["nonce"]
        if action.get("target") is not None:
            attributes["target"] = action["target"]
        if receipt.get("transport") is not None:
            attributes["transport"] = receipt["transport"]

        params_hash = action.get("params_hash")
        return ComplianceEvent(
            timestamp=to_rfc3339(ts),
            kind=EventKind.TOOL_CALL,
            actor=Actor(
                agent_id=signer.get("name") or agent_id_default or "unknown-agent",
                identity_claim=identity,
            ),
            io=IORef(arguments_ref=params_hash) if params_hash else None,
            tool=ToolInfo(name=action.get("tool")) if action.get("tool") else None,
            attributes=attributes,
            source={"format": self.format},
        )


_DEFAULT_SOURCE = SignedActionReceiptSource()


def receipt_to_event(
    receipt: Dict[str, Any], *, agent_id_default: Optional[str] = None
) -> ComplianceEvent:
    """Verify + normalize a signed action receipt via the default receipt source."""
    return _DEFAULT_SOURCE.verify_and_normalize(receipt, agent_id_default=agent_id_default)


def sign_receipt(
    key: KeySource,
    *,
    tool: str,
    params_hash: str,
    signer_name: str,
    ts: str,
    nonce: str,
    target: Optional[str] = None,
    owner: Optional[str] = None,
    transport: Optional[str] = None,
) -> Dict[str, Any]:
    """Produce a signed Ed25519 action receipt.

    Stands in for an upstream receipt producer in the demo and tests, and defines
    the canonical signing bytes once so producer and verifier agree.
    ``signer.pubkey`` and ``sig`` are base64.
    """
    receipt: Dict[str, Any] = {
        "action": {"tool": tool, "params_hash": params_hash},
        "signer": {
            "pubkey": base64.b64encode(key.public_key_raw()).decode("ascii"),
            "name": signer_name,
        },
        "ts": ts,
        "nonce": nonce,
    }
    if target is not None:
        receipt["action"]["target"] = target
    if owner is not None:
        receipt["signer"]["owner"] = owner
    if transport is not None:
        receipt["transport"] = transport
    sig = key.sign(receipt_signing_bytes(receipt))
    receipt["sig"] = base64.b64encode(sig).decode("ascii")
    return receipt
