"""Append-only evidence ledger and the attestor that proves things about it.

Design choices that satisfy the hard requirements:

* **Append-only (FR-LED-01).** Backends expose no edit or delete operation.
  Corrections are new ``CORRECTION`` events (see :meth:`Ledger.correct`).
* **Atomic attestation (NFR-REL-02).** A record's Merkle leaf hash is a pure
  function of the event's content, so writing the record *is* including the
  leaf — there is no second step that a crash could skip. We fsync each append
  and truncate any torn trailing line on load.
* **Hashes/pointers only (FR-LED-06, DR-02).** The event model already carries
  I/O as references, so the ledger never needs raw payloads or PII.
* **Pluggable (FR-LED-04).** Storage lives behind :class:`LedgerBackend`; a
  file backend ships for the zero-dependency demo path (FR-LED-02), plus an
  append-only SQL backend (FR-LED-03, :class:`SqlLedgerBackend`) that runs on
  sqlite and PostgreSQL with a DB-assigned identity column. Both paths are
  covered by the test suite: sqlite always, and PostgreSQL via real ``psycopg``
  whenever a DSN is provided (``OPENWRIGHT_TEST_PG_DSN``; a CI service container
  otherwise) — see ``tests/test_ledger_concurrency.py`` and docs/SCALABILITY.md.
* **Multi-writer (B3, NFR-SCAL-01).** A single :class:`Ledger` is in-process
  single-writer (a lock serializes commits). For N concurrent collector replicas
  on one logical ledger, :class:`ShardedLedger` runs one single-writer shard per
  replica and aggregates the per-shard Merkle roots under a signed *super-tree*,
  so global verifiability and gap-free per-shard ordering both hold under
  concurrency (proven in ``tests/test_ledger_concurrency.py``).
* **Retention (FR-LED-05).** Each record carries an immutable, attested
  ``retention_until``; because the record is tamper-evident, so is the
  retention commitment.
"""

from __future__ import annotations

import abc
import hashlib
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from .canonical import to_rfc3339
from .events import ComplianceEvent, EventKind, LedgerFields
from .merkle import (
    IncrementalMerkleTree,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    shard_super_proof,
    shard_super_root,
    tree_hash,
)
from .signing import Checkpoint, KeySource, sign_checkpoint


def _now_rfc3339() -> str:
    return to_rfc3339(datetime.now(timezone.utc))


class LedgerBackend(abc.ABC):
    """Stable storage contract. Implementations MUST be append-only."""

    @abc.abstractmethod
    def append_record(self, record: dict) -> None:
        """Durably append one committed-event record. MUST NOT overwrite."""

    @abc.abstractmethod
    def size(self) -> int: ...

    @abc.abstractmethod
    def iter_records(self) -> Iterator[dict]: ...

    @abc.abstractmethod
    def get_record(self, index: int) -> dict: ...


class InMemoryLedgerBackend(LedgerBackend):
    def __init__(self) -> None:
        self._records: List[dict] = []

    def append_record(self, record: dict) -> None:
        self._records.append(record)

    def size(self) -> int:
        return len(self._records)

    def iter_records(self) -> Iterator[dict]:
        return iter(list(self._records))

    def get_record(self, index: int) -> dict:
        return self._records[index]


class FileLedgerBackend(LedgerBackend):
    """JSON-Lines append-only file backend (zero external dependencies)."""

    def __init__(self, directory: str | os.PathLike) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.dir / "events.jsonl"
        if not self.events_path.exists():
            self.events_path.touch()
        else:
            self._heal_torn_tail()
        self._offsets: List[int] = self._index_offsets()

    def _heal_torn_tail(self) -> None:
        """Drop a trailing partial line left by a crash mid-append."""
        data = self.events_path.read_bytes()
        if data and not data.endswith(b"\n"):
            last_nl = data.rfind(b"\n")
            truncated = data[: last_nl + 1] if last_nl >= 0 else b""
            self.events_path.write_bytes(truncated)

    def _index_offsets(self) -> List[int]:
        offsets, pos = [], 0
        with self.events_path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    offsets.append(pos)
                pos += len(line)
        return offsets

    def append_record(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self.events_path.open("ab") as fh:
            offset = fh.tell()
            fh.write(line.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        self._offsets.append(offset)

    def size(self) -> int:
        return len(self._offsets)

    def iter_records(self) -> Iterator[dict]:
        with self.events_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def get_record(self, index: int) -> dict:
        if not 0 <= index < len(self._offsets):
            raise IndexError(index)
        with self.events_path.open("rb") as fh:
            fh.seek(self._offsets[index])
            return json.loads(fh.readline())


class SqlLedgerBackend(LedgerBackend):
    """Append-only SQL backend (FR-LED-03). Works on sqlite3 (stdlib) and
    PostgreSQL (via psycopg) — pass the appropriate DB-API connection and
    ``paramstyle``. Both are exercised by the test suite (sqlite always,
    PostgreSQL when ``OPENWRIGHT_TEST_PG_DSN`` is set; V2). Insert-only: it
    exposes no UPDATE/DELETE, and a production deployment should additionally
    revoke those grants.

    The primary key ``idx`` is a **DB-assigned identity** (sqlite AUTOINCREMENT /
    PostgreSQL IDENTITY), not application-computed. The old ``SELECT MAX(idx)+1``
    pattern was safe only because :class:`Ledger` serializes writers in-process;
    across processes/replicas two writers could read the same MAX and collide on
    the PK. Letting the DB assign the identity removes that race. Leaf ORDER (not
    contiguity of ``idx``) is what the Merkle log relies on, and reads use
    ``ORDER BY idx``.

    **Positional reads are O(1)+indexed (U4).** ``idx`` is DB-assigned and so is
    *not* dense-from-zero, which made the old ``ORDER BY idx LIMIT 1 OFFSET n``
    an O(n) scan per fetch (and O(n²) to iterate). Instead the backend keeps the
    ordered list of assigned ``idx`` values in memory — exactly like
    :class:`FileLedgerBackend`'s byte-offset list — built once at open and
    extended on each append from the value the DB returns. ``get_record(n)`` then
    maps position → ``idx`` and does a primary-key lookup ``WHERE idx = ?``. If a
    reader has fallen behind a concurrent writer (position past the cached list),
    it lazily reloads the list once.
    """

    def __init__(self, connection, *, table: str = "openwright_events", paramstyle: str = "qmark") -> None:
        self._conn = connection
        self._table = table
        self._qmark = paramstyle == "qmark"
        self._ph = "?" if self._qmark else "%s"
        idcol = (
            "INTEGER PRIMARY KEY AUTOINCREMENT"
            if self._qmark
            else "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"
        )
        cur = self._conn.cursor()
        cur.execute(f"CREATE TABLE IF NOT EXISTS {self._table} (idx {idcol}, record TEXT NOT NULL)")
        self._conn.commit()
        self._idx: List[int] = self._load_idx()  # position -> DB-assigned idx

    def _load_idx(self) -> List[int]:
        cur = self._conn.cursor()
        cur.execute(f"SELECT idx FROM {self._table} ORDER BY idx")
        return [row[0] for row in cur.fetchall()]

    def append_record(self, record: dict) -> None:
        payload = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
        cur = self._conn.cursor()
        if self._qmark:  # sqlite: lastrowid is the assigned identity
            cur.execute(f"INSERT INTO {self._table} (record) VALUES (?)", (payload,))
            self._conn.commit()
            self._idx.append(cur.lastrowid)
        else:  # postgres: ask the DB for the identity it assigned
            cur.execute(f"INSERT INTO {self._table} (record) VALUES (%s) RETURNING idx", (payload,))
            new_idx = cur.fetchone()[0]
            self._conn.commit()
            self._idx.append(new_idx)

    def size(self) -> int:
        # Authoritative count from the DB so a reader sees a concurrent writer's
        # rows; the cached idx list is a fast position->idx map, not the source
        # of truth for size.
        cur = self._conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {self._table}")
        return cur.fetchone()[0]

    def iter_records(self) -> Iterator[dict]:
        cur = self._conn.cursor()
        cur.execute(f"SELECT record FROM {self._table} ORDER BY idx")
        for (rec,) in cur.fetchall():
            yield json.loads(rec)

    def get_record(self, index: int) -> dict:
        if index < 0:
            raise IndexError(index)
        if index >= len(self._idx):
            self._idx = self._load_idx()  # a concurrent writer may have advanced
        if index >= len(self._idx):
            raise IndexError(index)
        cur = self._conn.cursor()
        cur.execute(f"SELECT record FROM {self._table} WHERE idx = {self._ph}", (self._idx[index],))
        row = cur.fetchone()
        if row is None:
            raise IndexError(index)
        return json.loads(row[0])


def _leaf_bytes_from_record(record: dict) -> bytes:
    ref = record.get("ledger", {}).get("leaf_hash", "")
    return bytes.fromhex(ref.split(":")[-1])


class Ledger:
    """Orchestrates commitment, leaf-hash tracking, proofs, and checkpoints."""

    def __init__(
        self,
        backend: LedgerBackend,
        *,
        origin: str = "openwright/ledger",
        retention: Optional[timedelta] = None,
        clock: Callable[[], str] = _now_rfc3339,
    ) -> None:
        self.backend = backend
        self.origin = origin
        self.retention = retention
        self._clock = clock
        self._lock = threading.Lock()
        # Reconstruct the leaf-hash list from durable storage on open.
        self._leaves: List[bytes] = [_leaf_bytes_from_record(r) for r in backend.iter_records()]
        # Incremental frontier tree gives O(log n) root on the checkpoint hot
        # path (NFR-SCAL-01); kept in lock-step with _leaves.
        self._tree = IncrementalMerkleTree.from_leaves(self._leaves)

    # -- commitment ---------------------------------------------------------

    def commit(self, event: ComplianceEvent) -> ComplianceEvent:
        """Assign id + ledger fields, append durably, include the leaf.

        Holds a lock so concurrent writers (the async ingest worker and the SDK)
        commit serially, preserving append-order and the leaf-list invariant.
        """
        event.finalize_id()
        h = leaf_hash(event.leaf_content_bytes())
        committed_at = self._clock()
        retention_until = None
        if self.retention is not None:
            base = datetime.fromisoformat(committed_at.replace("Z", "+00:00"))
            retention_until = to_rfc3339(base + self.retention)
        with self._lock:
            event.ledger = LedgerFields(
                leaf_hash="sha256:" + h.hex(),
                leaf_index=self.backend.size(),
                committed_at=committed_at,
                retention_until=retention_until,
            )
            self.backend.append_record(event.model_dump(mode="json", exclude_none=True))
            self._leaves.append(h)
            self._tree.append(h)
        return event

    def correct(self, target_event_id: str, reason: str, actor_id: str) -> ComplianceEvent:
        """Record a correction as a NEW event (FR-LED-01); never mutate history."""
        ev = ComplianceEvent(
            timestamp=self._clock(),
            kind=EventKind.CORRECTION,
            actor={"agent_id": actor_id},
            source={"format": "sdk"},
            attributes={"corrects_event_id": target_event_id, "reason": reason},
        )
        return self.commit(ev)

    # -- reads / proofs -----------------------------------------------------

    # Reads that touch the mutable ``_leaves``/``_tree`` take the same lock as
    # ``commit`` so a report generated while ingest is live can never observe a
    # frontier tree mid-append (F6). The lock is non-reentrant, so locked methods
    # must not call one another.

    def size(self) -> int:
        with self._lock:
            return len(self._leaves)

    def leaf_hashes(self) -> List[bytes]:
        with self._lock:
            return list(self._leaves)

    def get_event(self, index: int) -> ComplianceEvent:
        return ComplianceEvent.model_validate(self.backend.get_record(index))

    def events(self) -> Iterator[ComplianceEvent]:
        for r in self.backend.iter_records():
            yield ComplianceEvent.model_validate(r)

    def root(self) -> bytes:
        with self._lock:
            return self._tree.root()  # O(log n) via the incremental frontier tree

    def root_hex(self) -> str:
        return self.root().hex()

    def inclusion_proof_hex(self, index: int, tree_size: Optional[int] = None) -> List[str]:
        """Inclusion proof for ``index``. Pin ``tree_size`` to prove against a
        fixed checkpoint even if the log has grown since (race-free reports)."""
        with self._lock:
            leaves = self._leaves[:tree_size] if tree_size is not None else list(self._leaves)
        return [h.hex() for h in inclusion_proof(leaves, index)]

    def consistency_proof_hex(self, old_size: int, tree_size: Optional[int] = None) -> List[str]:
        with self._lock:
            leaves = self._leaves[:tree_size] if tree_size is not None else list(self._leaves)
        return [h.hex() for h in consistency_proof(leaves, old_size)]

    def prove_retention(self, index: int) -> dict:
        """Return the immutable, attested retention commitment for a record."""
        ev = self.get_event(index)
        led = ev.ledger
        return {
            "event_id": ev.event_id,
            "committed_at": led.committed_at if led else None,
            "retention_until": led.retention_until if led else None,
            "leaf_index": index,
            "inclusion_proof": self.inclusion_proof_hex(index),
        }

    # -- checkpoints --------------------------------------------------------

    def checkpoint(self, key: KeySource, timestamp: Optional[str] = None) -> Checkpoint:
        # Snapshot size + root under a single lock so the signed tree head is
        # internally consistent even if a commit interleaves (F6).
        with self._lock:
            tree_size = len(self._leaves)
            root_hex = self._tree.root().hex()
        return sign_checkpoint(
            key,
            origin=self.origin,
            tree_size=tree_size,
            root_hash_hex=root_hex,
            timestamp=timestamp or self._clock(),
        )


class ShardedLedger:
    """Multi-writer logical ledger: single-writer shards under a signed super-tree (B3).

    A single :class:`Ledger` is in-process single-writer — fine for one collector,
    but N collector replicas writing one logical ledger would either contend on a
    single writer or (across processes) each compute a root over only the events
    they saw. The fix the catalog calls for is *sharded single-writer-per-shard
    using the existing super-tree aggregation*: each shard is an independent
    :class:`Ledger` with its own lock/backend (so per-shard indices stay gap-free
    and ordered), and the per-shard Merkle roots are themselves the leaves of a
    *super-tree* (:func:`merkle.shard_super_root`). One signed checkpoint over the
    super-root binds every shard, and an event is proven globally by combining its
    in-shard inclusion proof with the shard's inclusion proof in the super-tree
    (:func:`merkle.verify_sharded_inclusion`).

    Routing is by a stable hash of the actor's ``agent_id`` so one agent's events
    stay on one shard (cheap, monotonic per-shard order); callers may also pin a
    shard explicitly (e.g. one shard per replica).
    """

    def __init__(
        self,
        shards: List[Ledger],
        *,
        origin: str = "openwright/sharded-ledger",
        route: Optional[Callable[[ComplianceEvent], int]] = None,
    ) -> None:
        if not shards:
            raise ValueError("ShardedLedger needs at least one shard")
        self.shards = shards
        self.origin = origin
        self._route = route or self._default_route

    def _default_route(self, event: ComplianceEvent) -> int:
        key = event.actor.agent_id if event.actor else ""
        digest = hashlib.sha256(key.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") % len(self.shards)

    def commit(self, event: ComplianceEvent, *, shard: Optional[int] = None) -> Tuple[int, ComplianceEvent]:
        """Commit to the routed (or pinned) shard; returns ``(shard_index, event)``."""
        s = shard if shard is not None else self._route(event)
        return s, self.shards[s].commit(event)

    def shard_roots(self) -> List[bytes]:
        return [s.root() for s in self.shards]

    def super_root(self) -> bytes:
        """Root of the super-tree over the per-shard roots (the one logical root)."""
        return shard_super_root(self.shard_roots())

    def super_root_hex(self) -> str:
        return self.super_root().hex()

    def total_size(self) -> int:
        return sum(s.size() for s in self.shards)

    def checkpoint(self, key: KeySource, timestamp: Optional[str] = None) -> Checkpoint:
        """Sign one checkpoint over the super-root, pinning each shard's size+root.

        Each shard's ``(size, root)`` is snapshotted so the signed super-root is
        internally consistent; commits that land after the snapshot belong to the
        next checkpoint. The per-shard snapshot travels in the checkpoint's
        ``shards`` field (the model allows extras) so a verifier can rebuild the
        super-tree and check any shard's inclusion against the signed super-root.
        """
        snap = [(s.size(), s.root()) for s in self.shards]
        roots = [r for _, r in snap]
        super_root = shard_super_root(roots)
        total = sum(sz for sz, _ in snap)
        cp = sign_checkpoint(
            key,
            origin=self.origin,
            tree_size=total,
            root_hash_hex=super_root.hex(),
            timestamp=timestamp or _now_rfc3339(),
        )
        cp.shards = [
            {"index": i, "size": sz, "root": r.hex()} for i, (sz, r) in enumerate(snap)
        ]
        return cp

    def sharded_inclusion_proof(
        self, shard: int, index: int, *, checkpoint: Optional[Checkpoint] = None
    ) -> dict:
        """Everything needed to prove one event under the (optionally pinned) super-root.

        Pass a ``checkpoint`` to pin the proof to a signed super-root even if the
        shards have grown since — the per-shard size and roots are read from the
        checkpoint snapshot. The result feeds :func:`merkle.verify_sharded_inclusion`.
        """
        if checkpoint is not None:
            meta = {s["index"]: s for s in checkpoint.shards}
            roots = [bytes.fromhex(meta[i]["root"]) for i in range(len(self.shards))]
            shard_size = meta[shard]["size"]
        else:
            roots = self.shard_roots()
            shard_size = self.shards[shard].size()
        return {
            "shard_index": shard,
            "num_shards": len(self.shards),
            "leaf_index": index,
            "shard_size": shard_size,
            "shard_root": roots[shard].hex(),
            "shard_proof": self.shards[shard].inclusion_proof_hex(index, tree_size=shard_size),
            "super_proof": [h.hex() for h in shard_super_proof(roots, shard)],
        }
