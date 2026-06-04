"""External anchoring + non-equivocation detection (B7, FR-ATT-08, V14).

A single producer can *equivocate*: show one validly-signed history to party A
and a divergent one to party B (a "split view"). Signatures alone don't prevent
this — both views are signed by the producer's own key. The defense is to anchor
every signed checkpoint to an **external append-only mechanism** that independent
monitors read, so two inconsistent histories become simultaneously visible and a
third party can *prove* the equivocation.

This module provides:

* :class:`TransparencyAnchor` — an append-only log of published checkpoints (a
  stand-in for a public transparency-log gossip endpoint / witness network). The
  producer publishes every checkpoint; monitors read all of them. A file-backed
  variant persists across processes so independent observers share one view.
* :func:`detect_equivocation` — given checkpoints gathered from the anchor and/or
  different parties, returns an :class:`EquivocationProof` if the producer signed
  two inconsistent tree heads, else ``None``.

Two inconsistencies are caught:

1. **Same ``tree_size``, different roots** — both validly signed: a direct fork.
2. **Non-extension** — for sizes ``m < n``, a supplied consistency proof between
   the two signed roots fails to verify (the larger tree does not extend the
   smaller), i.e. history was rewritten.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .merkle import verify_consistency
from .signing import Checkpoint


@dataclass
class EquivocationProof:
    """Self-contained evidence that a producer presented divergent histories."""

    reason: str
    tree_size: int
    checkpoint_a: dict
    checkpoint_b: dict


class TransparencyAnchor:
    """Append-only anchor of published checkpoints (in-memory or file-backed).

    A file-backed anchor persists across processes, so independent observers
    (producer + monitors) share exactly one append-only view.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self._mem: List[dict] = []
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch(exist_ok=True)

    def publish(self, checkpoint: Checkpoint) -> None:
        if self.path is None:
            self._mem.append(checkpoint.model_dump())
            return
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(checkpoint.model_dump(), separators=(",", ":")) + "\n")

    def checkpoints(self) -> List[dict]:
        if self.path is None:
            return list(self._mem)
        with open(self.path, "r", encoding="utf-8") as fh:
            return [json.loads(ln) for ln in fh if ln.strip()]


def _is_validly_signed(cp: dict, public_key_raw: bytes) -> bool:
    try:
        return Checkpoint.model_validate(cp).verify(public_key_raw)
    except Exception:  # noqa: BLE001
        return False


def detect_equivocation(
    checkpoints: List[dict],
    public_key_raw: bytes,
    *,
    consistency_proofs: Optional[Dict[Tuple[int, int], List[str]]] = None,
) -> Optional[EquivocationProof]:
    """Return proof of a split view among ``checkpoints``, or ``None`` if consistent.

    Only checkpoints validly signed by ``public_key_raw`` are considered (a forged
    checkpoint is not the producer equivocating). ``consistency_proofs`` maps
    ``(smaller_size, larger_size)`` to the producer-supplied proof hex; any pair
    whose proof fails to verify is an equivocation.
    """
    valid = [cp for cp in checkpoints if _is_validly_signed(cp, public_key_raw)]

    # 1. Two signed checkpoints at the same size with different roots = a fork.
    by_size: Dict[int, dict] = {}
    for cp in valid:
        sz = int(cp["tree_size"])
        prev = by_size.get(sz)
        if prev is not None and prev["root_hash"] != cp["root_hash"]:
            return EquivocationProof(
                "two signed checkpoints at the same tree_size have different roots",
                sz,
                prev,
                cp,
            )
        by_size[sz] = cp

    # 2. A supplied consistency proof that fails = a rewritten (non-extending) history.
    if consistency_proofs:
        for (m, n), proof in consistency_proofs.items():
            a, b = by_size.get(m), by_size.get(n)
            if a is None or b is None or m >= n:
                continue
            ok = verify_consistency(
                m,
                n,
                bytes.fromhex(a["root_hash"]),
                bytes.fromhex(b["root_hash"]),
                [bytes.fromhex(h) for h in proof],
            )
            if not ok:
                return EquivocationProof(
                    "consistency proof between two signed checkpoints does not verify "
                    "(history was rewritten, not extended)",
                    n,
                    a,
                    b,
                )
    return None
