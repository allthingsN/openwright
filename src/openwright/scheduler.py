"""Scheduled checkpoint signing (B6).

Today a checkpoint (signed tree head) is produced only on demand — typically
when a report is generated. A transparency log wants *periodic* signed tree
heads regardless of report activity, so that:

* a verifier always has a recent signed root to anchor inclusion/consistency
  proofs against, and
* gaps between checkpoints (the window in which equivocation could hide) are
  bounded by a known cadence, not by whenever someone asks for a report.

:class:`CheckpointScheduler` runs a daemon thread that, every ``interval``
seconds, snapshots the ledger, signs a checkpoint, persists it to a
:class:`~openwright.checkpoint_store.CheckpointStore`, and (optionally) has a
witness co-sign it. It works with either a :class:`~openwright.ledger.Ledger`
or a :class:`~openwright.ledger.ShardedLedger` — both expose ``checkpoint(key)``.

The cadence is configurable and independent of report generation. Signing only
touches the public tree head, never raw payloads (INV-3), and never blocks or
alters the evidence path (INV-6).
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

from .checkpoint_store import CheckpointStore
from .signing import Checkpoint, KeySource

log = logging.getLogger("openwright.scheduler")


class CheckpointScheduler:
    def __init__(
        self,
        ledger,
        key: KeySource,
        store: CheckpointStore,
        *,
        interval: float = 300.0,
        skip_if_unchanged: bool = True,
        on_checkpoint: Optional[Callable[[Checkpoint], None]] = None,
    ) -> None:
        self.ledger = ledger
        self.key = key
        self.store = store
        self.interval = interval
        self.skip_if_unchanged = skip_if_unchanged
        self.on_checkpoint = on_checkpoint
        self.count = 0
        self._last_size: Optional[int] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def tick(self) -> Optional[Checkpoint]:
        """Sign + persist one checkpoint now. Returns it, or ``None`` if skipped.

        Skips (when ``skip_if_unchanged``) if the tree has not grown since the
        last checkpoint, so an idle log does not accumulate identical tree heads.
        """
        cp = self.ledger.checkpoint(self.key)
        if self.skip_if_unchanged and cp.tree_size == self._last_size:
            return None
        self.store.put(cp)
        self._last_size = cp.tree_size
        self.count += 1
        if self.on_checkpoint is not None:
            try:
                self.on_checkpoint(cp)
            except Exception:  # noqa: BLE001 - a bad callback must not stop the scheduler
                log.exception("on_checkpoint callback failed")
        return cp

    def _run(self) -> None:
        # Sign immediately on start, then every interval, until stopped. Using
        # Event.wait as the sleep makes stop() responsive (no lingering thread).
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - never let a transient failure kill the loop
                log.exception("scheduled checkpoint failed (will retry next tick)")
            self._stop.wait(self.interval)

    def start(self) -> "CheckpointScheduler":
        if self._thread is not None:
            raise RuntimeError("scheduler already started")
        self._thread = threading.Thread(target=self._run, name="openwright-checkpoint", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
