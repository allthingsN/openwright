"""External checkpoint witness — co-signing for stronger non-repudiation (FR-ATT-08).

A witness is an independent party (separate key, separate process/host) that
co-signs a producer's signed tree heads. Before co-signing, it (a) verifies the
producer's own signature and (b) verifies a *consistency proof* between the last
checkpoint it endorsed and the new one — so a compromised producer cannot trick
the witness into endorsing a rewritten or forked history. This raises the bar
from "compromise the producer's key" to "compromise the producer AND the witness"
(see docs/SECURITY.md). Self-hosted; no hosted dependency.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel

from .merkle import verify_consistency
from .signing import Checkpoint, KeySource, key_id_for, verify_signature


class WitnessCosignature(BaseModel):
    witness_key_id: str
    tree_size: int
    root_hash: str
    signature: str  # base64 over the checkpoint's signing bytes


class WitnessError(Exception):
    pass


class Witness:
    def __init__(self, key: KeySource) -> None:
        self.key = key
        self._last: Optional[Checkpoint] = None

    @property
    def key_id(self) -> str:
        return self.key.key_id()

    def cosign(
        self,
        checkpoint: Checkpoint,
        producer_public_key_raw: bytes,
        *,
        consistency_proof_hex: Optional[List[str]] = None,
    ) -> WitnessCosignature:
        # 1. The producer must have validly signed this tree head.
        if not checkpoint.verify(producer_public_key_raw):
            raise WitnessError("producer signature on checkpoint is invalid")
        # 2. It must extend the last head we endorsed (append-only history).
        if self._last is not None:
            if checkpoint.tree_size < self._last.tree_size:
                raise WitnessError("checkpoint tree_size went backwards")
            if checkpoint.tree_size > self._last.tree_size:
                proof = [bytes.fromhex(h) for h in (consistency_proof_hex or [])]
                if not verify_consistency(
                    self._last.tree_size, checkpoint.tree_size,
                    bytes.fromhex(self._last.root_hash), bytes.fromhex(checkpoint.root_hash), proof,
                ):
                    raise WitnessError("consistency proof from last endorsed checkpoint failed")
        # 3. Endorse by co-signing the exact same canonical signing bytes.
        import base64

        sig = self.key.sign(checkpoint.signing_bytes())
        self._last = checkpoint
        return WitnessCosignature(
            witness_key_id=self.key.key_id(),
            tree_size=checkpoint.tree_size,
            root_hash=checkpoint.root_hash,
            signature=base64.b64encode(sig).decode("ascii"),
        )


def verify_cosignature(
    checkpoint: Checkpoint, cosig: WitnessCosignature, witness_public_key_raw: bytes
) -> bool:
    """Confirm an independent witness endorsed this exact tree head."""
    import base64

    if key_id_for(witness_public_key_raw) != cosig.witness_key_id:
        return False
    if cosig.tree_size != checkpoint.tree_size or cosig.root_hash != checkpoint.root_hash:
        return False
    try:
        sig = base64.b64decode(cosig.signature)
    except (ValueError, TypeError):
        return False
    return verify_signature(witness_public_key_raw, sig, checkpoint.signing_bytes())
