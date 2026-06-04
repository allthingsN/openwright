"""Durable evidence-loss handling (B1/V9, B2/V10)."""

from __future__ import annotations

import threading
import time

from openwright.adapters.base import SpanData
from openwright.ingest.durable import DropJournal
from openwright.ingest.pipeline import EvidencePipeline
from openwright.ledger import FileLedgerBackend, InMemoryLedgerBackend, Ledger


def _span(i: int) -> SpanData:
    return SpanData("chat", {"gen_ai.operation.name": "chat", "i": i})


# -- B1 / V9: durable drop-intent survives a crash before the marker is emitted -


def test_drop_intent_is_durable_and_recovered_on_restart(tmp_path):
    durable_dir = tmp_path / "durable"

    # Phase 1: a "process" drops spans but crashes before the gap marker commits.
    # Its ledger is in-memory (so it never writes the shared ledger file); only
    # the durable drop journal in durable_dir is meant to survive.
    led1 = Ledger(InMemoryLedgerBackend())
    block = threading.Event()
    real_commit = led1.commit

    def blocking_commit(ev):
        block.wait()  # worker is stuck here -> it can never emit the gap marker
        return real_commit(ev)

    led1.commit = blocking_commit
    pipe1 = EvidencePipeline(
        led1, agent_id="a", max_queue=1, durable_dir=durable_dir, spill=False
    )
    pipe1.submit([_span(i) for i in range(30)])
    assert pipe1.dropped >= 5, pipe1.stats()

    # The drop intent is durable on disk *at drop time* (B1), not only in memory.
    pending = DropJournal(durable_dir / "drop_intent.json").load()
    assert pending is not None
    assert pending["count"] == pipe1.dropped
    assert pending["window_start"] is not None

    # Phase 2: "restart" on the same durable dir with a real file ledger. The
    # worker recovers the pending drops and emits the gap marker (V9).
    led2 = Ledger(FileLedgerBackend(durable_dir / "ledger"))
    pipe2 = EvidencePipeline(led2, agent_id="a", durable_dir=durable_dir, spill=False)
    try:
        assert pipe2.recovered_drops == pipe1.dropped
        pipe2.flush()
        markers = [e for e in led2.events() if e.attributes.get("marker") == "evidence_gap"]
        assert markers, "restart did not produce a recovery gap marker"
        assert sum(m.attributes["dropped_events"] for m in markers) == pipe1.dropped
        # Journal cleared once the recovery marker is durably committed.
        assert DropJournal(durable_dir / "drop_intent.json").load() is None
    finally:
        pipe2.stop()
        block.set()
        pipe1.stop()


# -- B2 / V10: sustained overload buffers durably instead of dropping ----------


def test_durable_spillover_loses_nothing_under_overload(tmp_path):
    led = Ledger(FileLedgerBackend(tmp_path / "led"))
    gate = threading.Event()
    real_commit = led.commit

    def gated_commit(ev):
        gate.wait(10)  # hold the worker so a burst overflows into the spill buffer
        return real_commit(ev)

    led.commit = gated_commit
    # Durability auto-enables for a file-backed ledger; tiny queue forces overflow.
    pipe = EvidencePipeline(led, agent_id="a", max_queue=4)
    n = 200
    pipe.submit([_span(i) for i in range(n)])

    # While the worker is gated, everything past the queue spilled durably — not
    # dropped.
    assert pipe.stats()["spilled"] >= n - 5, pipe.stats()
    assert pipe.dropped == 0

    gate.set()  # release: worker drains the queue and the durable spill buffer
    pipe.flush()
    pipe.stop()

    stats = pipe.stats()
    assert stats["dropped"] == 0, stats
    assert stats["spilled"] >= n - 5, stats
    assert stats["processed"] == n, stats
    # No payload-span loss, and no gap marker (nothing was unrecoverable).
    events = list(led.events())
    assert not [e for e in events if e.attributes.get("marker") == "evidence_gap"]
    assert led.size() == n


def test_in_memory_ledger_has_no_durability_and_still_drops(tmp_path):
    """Regression: an in-memory ledger has nowhere durable to write, so overflow
    still falls back to the in-memory drop path (unchanged default behavior)."""
    led = Ledger(InMemoryLedgerBackend())
    block = threading.Event()
    real_commit = led.commit

    def blocking_commit(ev):
        block.wait(5)
        return real_commit(ev)

    led.commit = blocking_commit
    pipe = EvidencePipeline(led, agent_id="a", max_queue=1)
    assert pipe._spill is None and pipe._journal is None  # no durable dir derivable
    pipe.submit([_span(i) for i in range(10)])
    assert pipe.dropped >= 1
    block.set()
    pipe.flush()
    pipe.stop()
    markers = [e for e in led.events() if e.attributes.get("marker") == "evidence_gap"]
    assert markers and sum(m.attributes["dropped_events"] for m in markers) == pipe.dropped
