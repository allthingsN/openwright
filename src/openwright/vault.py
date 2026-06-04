"""Payload vault — raw payloads stored separately from the ledger (NFR-PRIV-03).

By default OpenWright never stores raw payloads at all (the ledger holds only
``sha256:`` references — NFR-PRIV-01/02). When an operator *does* need to retain
raw prompts/responses (for debugging, redress, or DSARs), a vault stores them in
a separate location with independent access control and retention, keyed by the
exact same hash that appears in the ledger. The ledger and verification never
depend on the vault; deleting the vault leaves the evidence chain fully intact.
"""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Optional

from .canonical import hash_payload


def _to_bytes(payload) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    from .canonical import canonical_bytes

    return canonical_bytes(payload)


class PayloadVault(abc.ABC):
    @abc.abstractmethod
    def store(self, payload) -> str:
        """Persist a raw payload; return its ``sha256:`` reference for the ledger."""

    @abc.abstractmethod
    def fetch(self, ref: str) -> Optional[bytes]: ...


class FileVault(PayloadVault):
    def __init__(self, directory: str) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, ref: str) -> Path:
        return self.dir / (ref.split(":")[-1] + ".bin")

    def store(self, payload) -> str:
        data = _to_bytes(payload)
        ref = hash_payload(data)
        self._path(ref).write_bytes(data)  # content-addressed; idempotent
        return ref

    def fetch(self, ref: str) -> Optional[bytes]:
        path = self._path(ref)
        return path.read_bytes() if path.exists() else None
