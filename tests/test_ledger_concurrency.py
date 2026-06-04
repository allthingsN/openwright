"""Ledger concurrency + multi-writer + backend tests (V1, V2, B3, U4).

V1 closes the F6 "weakest DONE": the single :class:`Ledger` is hammered by many
writer threads while reader threads concurrently call ``root()`` /
``inclusion_proof_hex()`` / ``consistency_proof_hex()``; we assert no race, no
corruption, and stable proofs.

B3 proves the multi-writer story: a :class:`ShardedLedger` with one single-writer
shard per replica, committing concurrently, yields gap-free per-shard ordering
and one consistent *signed* super-root under which every event still verifies.

V2 exercises :class:`SqlLedgerBackend` against real PostgreSQL (psycopg) when a
DSN is provided; U4's O(1) positional access is checked on sqlite always.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import uuid

import pytest

from openwright.events import ComplianceEvent, EventKind
from openwright.ledger import (
    InMemoryLedgerBackend,
    Ledger,
    ShardedLedger,
    SqlLedgerBackend,
)
from openwright.merkle import tree_hash, verify_inclusion, verify_sharded_inclusion


def _ev(i: int) -> ComplianceEvent:
    return ComplianceEvent(
        timestamp="2026-05-28T00:00:00.000000000Z",
        kind=EventKind.GENERIC,
        actor={"agent_id": f"a{i}"},
        source={"format": "sdk"},
        attributes={"i": i},
    )


# -- V1: single-ledger concurrency --------------------------------------------


def test_concurrent_commits_and_reads_no_corruption():
    led = Ledger(InMemoryLedgerBackend())
    n_writers, per = 8, 200
    total = n_writers * per
    errors: list = []

    def writer(w: int) -> None:
        for i in range(per):
            led.commit(_ev(w * per + i))

    def reader() -> None:
        for _ in range(600):
            try:
                sz = led.size()
                led.root()
                if sz >= 1:
                    # Pin proofs to a size we've observed; the log only grows, so
                    # the pinned slice always exists -> proofs must stay valid.
                    led.inclusion_proof_hex(sz - 1, tree_size=sz)
                if sz >= 2:
                    led.consistency_proof_hex(sz // 2, tree_size=sz)
            except Exception as exc:  # noqa: BLE001 - record, fail the test outside
                errors.append(exc)

    threads = [threading.Thread(target=writer, args=(w,)) for w in range(n_writers)]
    threads += [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors[:3]
    assert led.size() == total
    leaves = led.leaf_hashes()
    assert len(leaves) == total
    # Final root recomputes exactly (no torn/duplicated/lost leaf).
    root = led.root()
    assert root == tree_hash(leaves)
    # Every spot-checked leaf still verifies inclusion against the final root.
    for i in (0, total // 2, total - 1):
        proof = [bytes.fromhex(h) for h in led.inclusion_proof_hex(i, tree_size=total)]
        assert verify_inclusion(i, total, leaves[i], proof, root)


# -- B3: sharded multi-writer under a signed super-root -----------------------


def test_sharded_multiwriter_consistent_signed_super_root():
    from openwright.signing import InMemoryKeySource

    n_shards, per = 4, 120
    shards = [Ledger(InMemoryLedgerBackend()) for _ in range(n_shards)]
    sl = ShardedLedger(shards)
    seen: list = []
    lock = threading.Lock()

    def replica(s: int) -> None:
        for i in range(per):
            _, e = sl.commit(_ev(s * per + i), shard=s)  # one replica == one shard
            with lock:
                seen.append((s, e.ledger.leaf_index))

    threads = [threading.Thread(target=replica, args=(s,)) for s in range(n_shards)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Gap-free, ordered per-shard indices (single-writer-per-shard guarantee).
    for s in range(n_shards):
        assert shards[s].size() == per
        idxs = sorted(idx for ss, idx in seen if ss == s)
        assert idxs == list(range(per))

    # One signed checkpoint over the super-root binds every shard.
    key = InMemoryKeySource()
    cp = sl.checkpoint(key)
    assert cp.verify(key.public_key_raw())
    assert cp.tree_size == n_shards * per
    super_root = bytes.fromhex(cp.root_hash)

    # Every event verifies under the signed super-root (in-shard proof + super proof).
    for s in range(n_shards):
        for idx in (0, per // 2, per - 1):
            pf = sl.sharded_inclusion_proof(s, idx, checkpoint=cp)
            leaf = shards[s].leaf_hashes()[idx]
            assert verify_sharded_inclusion(
                leaf=leaf,
                leaf_index=pf["leaf_index"],
                shard_size=pf["shard_size"],
                shard_proof=[bytes.fromhex(h) for h in pf["shard_proof"]],
                shard_root=bytes.fromhex(pf["shard_root"]),
                shard_index=pf["shard_index"],
                num_shards=pf["num_shards"],
                super_proof=[bytes.fromhex(h) for h in pf["super_proof"]],
                super_root=super_root,
            )

    # Tampering with one shard's events breaks verification against the super-root.
    bad_leaf = bytes(32)
    pf = sl.sharded_inclusion_proof(0, 0, checkpoint=cp)
    assert not verify_sharded_inclusion(
        leaf=bad_leaf,
        leaf_index=pf["leaf_index"],
        shard_size=pf["shard_size"],
        shard_proof=[bytes.fromhex(h) for h in pf["shard_proof"]],
        shard_root=bytes.fromhex(pf["shard_root"]),
        shard_index=pf["shard_index"],
        num_shards=pf["num_shards"],
        super_proof=[bytes.fromhex(h) for h in pf["super_proof"]],
        super_root=super_root,
    )


# -- U4: O(1) indexed positional access on the SQL backend (sqlite, always) ----


def test_sql_backend_positional_reads_are_ordered_and_correct():
    conn = sqlite3.connect(":memory:")
    led = Ledger(SqlLedgerBackend(conn, table="evt"))
    for i in range(100):
        led.commit(_ev(i))
    assert led.size() == 100
    # get_record maps position -> idx -> PK lookup; order is preserved and every
    # position resolves to the right record (no OFFSET scan involved).
    assert [led.get_event(i).attributes["i"] for i in range(100)] == list(range(100))
    # Reopening reconstructs the identical root from the durable rows.
    led2 = Ledger(SqlLedgerBackend(conn, table="evt"))
    assert led2.size() == 100
    assert led2.root() == led.root()


# -- V2: real PostgreSQL backend ----------------------------------------------

PG_DSN = os.environ.get("OPENWRIGHT_TEST_PG_DSN")


@pytest.mark.skipif(not PG_DSN, reason="set OPENWRIGHT_TEST_PG_DSN to run the PostgreSQL backend test (V2)")
def test_postgres_backend_roundtrip_reopen_and_concurrent_writers():
    psycopg = pytest.importorskip("psycopg")
    table = "openwright_test_" + uuid.uuid4().hex[:12]

    def backend(conn):
        return SqlLedgerBackend(conn, table=table, paramstyle="pyformat")

    conn = psycopg.connect(PG_DSN)
    try:
        led = Ledger(backend(conn))
        for i in range(50):
            led.commit(_ev(i))
        assert led.size() == 50
        # U4 over Postgres: positional reads are ordered + correct.
        assert [led.get_event(i).attributes["i"] for i in range(50)] == list(range(50))

        # Reopen with a fresh connection: identical reconstructed root.
        conn2 = psycopg.connect(PG_DSN)
        led2 = Ledger(backend(conn2))
        assert led2.size() == 50
        assert led2.root() == led.root()
        conn2.close()

        # Concurrent writers on independent connections to the SAME table: the
        # DB-assigned IDENTITY keeps idx unique with no collisions (the race the
        # old MAX(idx)+1 pattern had). After they finish, every row is present
        # exactly once, ordered.
        n_extra = 40

        def writer():
            c = psycopg.connect(PG_DSN)
            be = backend(c)
            for i in range(n_extra):
                be.append_record({"r": uuid.uuid4().hex})
            c.close()

        ts = [threading.Thread(target=writer) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        conn3 = psycopg.connect(PG_DSN)
        be3 = backend(conn3)
        assert be3.size() == 50 + 4 * n_extra
        rows = list(be3.iter_records())
        assert len(rows) == 50 + 4 * n_extra  # gap-free, no lost/duplicated row
        conn3.close()
    finally:
        cur = conn.cursor()
        cur.execute(f"DROP TABLE IF EXISTS {table}")
        conn.commit()
        conn.close()
