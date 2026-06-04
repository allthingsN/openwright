"""Core's reference storage backends, exposed as discoverable connectors.

These are core's *own* backends (not third-party connectors) registered in-process
so ``--ledger-backend`` / ``--checkpoint-store`` URI resolution works out of the
box and the discovery mechanism is testable without the connectors repo. Heavy
drivers (``psycopg``, ``boto3``) are imported lazily inside ``from_uri`` so
importing this module stays light (INV-2).

Schemes:

* ledger backends: ``sqlite://``, ``postgres://`` / ``postgresql://``, ``file://``
* checkpoint stores: ``local://`` / ``file://``, ``s3://bucket/prefix``
"""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlparse

from ..checkpoint_store import LocalCheckpointStore
from ..ledger import FileLedgerBackend, SqlLedgerBackend
from . import CONTRACT_VERSION, register


def _path_of(uri: str) -> str:
    p = urlparse(uri)
    return (p.netloc + p.path) if p.scheme else uri


def _sqlite_ledger(uri: str) -> SqlLedgerBackend:
    import sqlite3

    path = uri.split("://", 1)[1] if "://" in uri else uri
    conn = sqlite3.connect(path or ":memory:", check_same_thread=False)
    return SqlLedgerBackend(conn, paramstyle="qmark")


def _postgres_ledger(uri: str) -> SqlLedgerBackend:
    import psycopg  # lazy: optional `postgres` extra

    conn = psycopg.connect(uri)
    return SqlLedgerBackend(conn, paramstyle="pyformat")


def _file_ledger(uri: str) -> FileLedgerBackend:
    return FileLedgerBackend(_path_of(uri))


def _local_checkpoints(uri: str) -> LocalCheckpointStore:
    return LocalCheckpointStore(_path_of(uri))


def _s3_checkpoints(uri: str):
    from ..checkpoint_store import S3CheckpointStore  # lazy: optional `s3` extra

    p = urlparse(uri)  # s3://bucket/prefix
    return S3CheckpointStore(p.netloc, p.path.lstrip("/") or "openwright/checkpoints")


class _Factory:
    """A named backend factory: ``from_uri(uri) -> backend``."""

    CONTRACT_VERSION = CONTRACT_VERSION

    def __init__(self, name: str, fn: Callable[[str], Any]) -> None:
        self.name = name
        self._fn = fn

    def from_uri(self, uri: str) -> Any:
        return self._fn(uri)


_LEDGERS = {
    "sqlite": _sqlite_ledger,
    "postgres": _postgres_ledger,
    "postgresql": _postgres_ledger,
    "file": _file_ledger,
}
_STORES = {
    "local": _local_checkpoints,
    "file": _local_checkpoints,
    "s3": _s3_checkpoints,
}

for _name, _fn in _LEDGERS.items():
    register("openwright.ledger_backends", _name, _Factory(_name, _fn))
for _name, _fn in _STORES.items():
    register("openwright.checkpoint_stores", _name, _Factory(_name, _fn))
