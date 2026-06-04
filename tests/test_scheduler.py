"""Scheduled checkpoint signing (B6)."""

from __future__ import annotations

import threading
import time

from openwright.checkpoint_store import LocalCheckpointStore
from openwright.events import ComplianceEvent, EventKind
from openwright.ledger import InMemoryLedgerBackend, Ledger
from openwright.scheduler import CheckpointScheduler
from openwright.signing import InMemoryKeySource


def _ev(i: int) -> ComplianceEvent:
    return ComplianceEvent(
        timestamp="2026-05-28T00:00:00.000000000Z",
        kind=EventKind.GENERIC,
        actor={"agent_id": f"a{i}"},
        source={"format": "sdk"},
        attributes={"i": i},
    )


def test_scheduler_emits_periodic_signed_checkpoints(tmp_path):
    led = Ledger(InMemoryLedgerBackend())
    key = InMemoryKeySource()
    store = LocalCheckpointStore(str(tmp_path / "cps"))
    seen: list = []
    got_three = threading.Event()

    def on_cp(cp):
        seen.append(cp)
        if len(seen) >= 3:
            got_three.set()

    sched = CheckpointScheduler(
        led, key, store, interval=0.02, skip_if_unchanged=False, on_checkpoint=on_cp
    )
    sched.start()
    try:
        for i in range(5):
            led.commit(_ev(i))
            time.sleep(0.02)
        assert got_three.wait(timeout=5), "scheduler did not emit checkpoints on its cadence"
    finally:
        sched.stop()

    # Persisted checkpoints verify under the signer's key.
    assert store.tree_sizes()
    latest = store.latest()
    assert latest is not None and latest.verify(key.public_key_raw())


def test_scheduler_skips_unchanged_tree(tmp_path):
    led = Ledger(InMemoryLedgerBackend())
    key = InMemoryKeySource()
    store = LocalCheckpointStore(str(tmp_path / "cps"))
    # Long interval so only manual ticks happen; assert skip-if-unchanged logic.
    sched = CheckpointScheduler(led, key, store, interval=999, skip_if_unchanged=True)

    led.commit(_ev(0))
    assert sched.tick() is not None  # tree grew -> checkpoint
    assert sched.tick() is None  # unchanged -> skipped
    led.commit(_ev(1))
    assert sched.tick() is not None  # grew again -> checkpoint
    assert sched.count == 2
