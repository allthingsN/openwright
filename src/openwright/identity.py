"""Cryptographic binding of events to an A2A AgentCard identity (FR-ATT-07).

The A2A spec (v0.3.0) makes AgentCard ``signatures`` *optional* — cards are
descriptive by default and not cryptographically bound. OpenWright closes that
gap with an Ed25519 claim over the JCS-canonicalized card (RFC 8785), with the
``signatures`` field excluded from the signed content exactly as the A2A signing
guidance specifies. The result is a portable :class:`IdentityClaim` a verifier
can check offline (UC-5: counterparty vetting).

All AgentCard input is treated as untrusted (FR-ING-10): only the canonical
bytes are hashed; no field is interpreted or executed.
"""

from __future__ import annotations

import base64
from typing import Any, Dict

from .canonical import canonical_bytes, sha256_hex
from .events import IdentityClaim
from .signing import KeySource, key_id_for, verify_signature


def _card_signing_bytes(agent_card: Dict[str, Any]) -> bytes:
    # Exclude the 'signatures' field to avoid a circular dependency, per A2A.
    card = {k: v for k, v in agent_card.items() if k != "signatures"}
    return canonical_bytes(card)


def agent_card_hash(agent_card: Dict[str, Any]) -> str:
    return "sha256:" + sha256_hex(_card_signing_bytes(agent_card))


def make_identity_claim(agent_card: Dict[str, Any], key: KeySource) -> IdentityClaim:
    """Sign an AgentCard, producing a claim bindable to events."""
    signed = _card_signing_bytes(agent_card)
    sig = key.sign(signed)
    return IdentityClaim(
        claim_type="agentcard-binding",
        public_key_id=key.key_id(),
        agent_card_hash="sha256:" + sha256_hex(signed),
        signature_b64=base64.b64encode(sig).decode("ascii"),
    )


def verify_identity_claim(
    claim: IdentityClaim, agent_card: Dict[str, Any], public_key_raw: bytes
) -> bool:
    """Verify a claim binds ``public_key_raw`` to ``agent_card``."""
    if claim.public_key_id and claim.public_key_id != key_id_for(public_key_raw):
        return False
    signed = _card_signing_bytes(agent_card)
    if claim.agent_card_hash and claim.agent_card_hash != "sha256:" + sha256_hex(signed):
        return False
    if not claim.signature_b64:
        return False
    try:
        sig = base64.b64decode(claim.signature_b64)
    except (ValueError, TypeError):
        return False
    return verify_signature(public_key_raw, sig, signed)
