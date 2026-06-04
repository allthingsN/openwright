"""Asynchronous evidence pipeline: SpanData → ComplianceEvent → ledger.

Runs on a single background worker thread so ledger commits are serialized
without locking, and so evidence work never blocks the receiving request
(NFR-PERF-02). Malformed spans are caught and counted, never fatal
(NFR-SEC-01). The queue is bounded; overflow is handled durably (B1/B2):

* a :class:`~openwright.ingest.durable.SpillBuffer` catches overflow spans on
  disk and the worker drains them back when capacity returns, so sustained
  overload buffers instead of dropping; and
* on genuinely unrecoverable loss, a :class:`~openwright.ingest.durable.DropJournal`
  persists the drop count + window at drop time (no silent cap — NFR-REL-03),
  so a crash before the lazy ``evidence_gap`` marker commits still yields the gap
  on restart.

Durability is automatic for a directory-backed ledger and a no-op for in-memory
ledgers (nowhere durable to write); it can be tuned/disabled per pipeline.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..adapters.a2a import provenance_from_attributes
from ..adapters.base import SpanData
from ..adapters.langfuse import apply_langfuse_precedence, has_langfuse_attributes
from ..adapters.otel_genai import span_to_event
from ..canonical import to_rfc3339
from ..events import ComplianceEvent, EventKind, Provenance
from ..ledger import Ledger
from .durable import DropJournal, SpillBuffer

log = logging.getLogger("openwright.ingest")

_SENTINEL = object()


class EvidencePipeline:
    def __init__(
        self,
        ledger: Ledger,
        *,
        agent_id: Optional[str] = None,
        pricing: Optional[Dict[str, Any]] = None,
        max_queue: int = 10000,
        commit_retries: int = 3,
        retry_backoff: float = 0.05,
        durable: bool = True,
        durable_dir: Optional[str | os.PathLike] = None,
        spill: bool = True,
        journal: bool = True,
    ) -> None:
        self.ledger = ledger
        self.agent_id = agent_id
        self.pricing = pricing
        self.commit_retries = commit_retries
        self.retry_backoff = retry_backoff
        self._q: "queue.Queue[Any]" = queue.Queue(maxsize=max_queue)
        self._known: Dict[str, Provenance] = {}
        self.processed = 0
        self.dropped = 0
        self.errors = 0
        self.retries = 0
        self.drop_markers = 0
        self.spilled = 0
        self.spill_recovered = 0
        self.recovered_drops = 0
        # Durable loss-handling (B1/B2). Default to the ledger's own directory so
        # a file-backed collector gets durability for free; in-memory ledgers have
        # nowhere durable to write, so spill/journal stay None and overflow falls
        # back to the in-memory drop accounting (still attested via a gap marker).
        dd = durable_dir if durable_dir is not None else (_derive_durable_dir(ledger) if durable else None)
        self._spill: Optional[SpillBuffer] = SpillBuffer(Path(dd) / "spill.jsonl") if (dd and spill) else None
        self._journal: Optional[DropJournal] = DropJournal(Path(dd) / "drop_intent.json") if (dd and journal) else None
        # Drops are recorded into the ledger as a tamper-evident gap marker so the
        # log self-attests the loss (completeness, not just integrity). The marker
        # is committed only from the worker thread, keeping the ledger single-writer.
        self._drop_lock = threading.Lock()
        # Serializes marker emission so two callers (worker idle pass + flush)
        # can't each emit a marker for the same pending drops (double-count).
        self._emit_lock = threading.Lock()
        self._undeclared_drops = 0
        self._drop_window: List[Optional[str]] = [None, None]  # [first_ts, last_ts]
        # Recover drop intent persisted before a crash (B1): a marker for these is
        # emitted by the worker on its first pass. Set before the worker starts.
        if self._journal is not None:
            pending = self._journal.load()
            if pending:
                self._undeclared_drops = int(pending["count"])
                self._drop_window = [pending.get("window_start"), pending.get("window_end")]
                self.recovered_drops = self._undeclared_drops
        # How often the idle worker wakes to flush a pending gap marker.
        self._drain_interval = 0.5
        self._thread = threading.Thread(target=self._run, name="openwright-evidence", daemon=True)
        self._thread.start()

    def submit(self, spans: List[SpanData]) -> None:
        """Enqueue spans for evidence processing. Never blocks the caller."""
        for sp in spans:
            try:
                self._q.put_nowait(sp)
            except queue.Full:
                # Overflow: prefer durable spillover (B2) so nothing is lost; only
                # a spill-write failure (or no spill configured) is a real drop.
                if self._spill is not None:
                    try:
                        self._spill.append(sp)
                        self.spilled += 1
                        continue
                    except Exception:  # noqa: BLE001 - spill failed; fall through to drop
                        log.exception("spill write failed; recording unrecoverable drop")
                now = to_rfc3339(datetime.now(timezone.utc))
                with self._drop_lock:
                    self.dropped += 1
                    self._undeclared_drops += 1
                    if self._drop_window[0] is None:
                        self._drop_window[0] = now
                    self._drop_window[1] = now
                    self._persist_drop_intent_locked()  # durable at drop time (B1)
                log.warning("evidence queue full; dropped 1 span (total dropped=%d)", self.dropped)

    def _persist_drop_intent_locked(self) -> None:
        """Persist current pending drop intent; caller holds ``_drop_lock``."""
        if self._journal is None:
            return
        try:
            self._journal.record(self._undeclared_drops, self._drop_window[0], self._drop_window[1])
        except Exception:  # noqa: BLE001 - durability is best-effort; never crash ingest
            log.exception("failed to persist drop intent")

    def _refill_from_spill(self) -> None:
        """Pull durably-spilled spans back into the queue as capacity frees up."""
        if self._spill is None:
            return

        def accept(span: SpanData) -> bool:
            try:
                self._q.put_nowait(span)
                return True
            except queue.Full:
                return False

        self.spill_recovered += self._spill.drain(accept)

    def _normalize(self, span: SpanData) -> ComplianceEvent:
        ts = to_rfc3339(span.start_time_unix_nano) if span.start_time_unix_nano else to_rfc3339(
            datetime.now(timezone.utc)
        )
        ev = span_to_event(span, timestamp=ts, agent_id=self.agent_id, pricing=self.pricing)
        if has_langfuse_attributes(span.attributes):
            apply_langfuse_precedence(ev, span.attributes)
        prov = provenance_from_attributes(span.attributes, known=self._known)
        if prov is not None:
            ev.provenance = prov
            if prov.task_id:
                self._known[prov.task_id] = prov
        return ev

    def _emit_drop_marker_if_pending(self) -> None:
        """Commit one tamper-evident gap marker covering any undeclared drops.

        Records the count and time window of dropped spans into the ledger so a
        verifier can see the log self-attests the loss.

        Crash-safe (B1): the pending count is **not** cleared until the marker
        commit succeeds. While the commit is in flight the count still stands, so
        new drops keep accumulating onto it and the durable journal always
        reflects the full uncommitted total — a crash mid-commit therefore loses
        nothing (the whole count is recovered on restart). On success exactly the
        committed batch is subtracted, so drops that arrived during the commit are
        carried into the next marker (every drop is attested once, never twice).
        The ``_emit_lock`` serializes emission so two callers can't both claim the
        same pending batch.
        """
        with self._emit_lock:
            with self._drop_lock:
                n = self._undeclared_drops
                if n == 0:
                    return
                window_start, window_end = self._drop_window
            marker = ComplianceEvent(
                timestamp=to_rfc3339(datetime.now(timezone.utc)),
                kind=EventKind.GENERIC,
                actor={"agent_id": self.agent_id or "openwright-collector"},
                attributes={
                    "marker": "evidence_gap",
                    "dropped_events": n,
                    "window_start": window_start,
                    "window_end": window_end,
                },
                source={"format": "openwright"},
            )
            try:
                self.ledger.commit(marker)
                self.drop_markers += 1
                with self._drop_lock:
                    # Subtract exactly the committed batch; new drops since the
                    # snapshot remain pending for the next marker.
                    self._undeclared_drops -= n
                    if self._undeclared_drops <= 0:
                        self._undeclared_drops = 0
                        self._drop_window = [None, None]
                        if self._journal is not None:
                            self._journal.clear()
                    else:
                        self._persist_drop_intent_locked()
            except Exception:  # noqa: BLE001 - never crash the additive path
                # Nothing was reset, so the count + durable journal still stand;
                # the next pass retries.
                log.exception("failed to commit evidence-gap marker (will retry)")

    def _run(self) -> None:
        while True:
            try:
                # Wake periodically even when idle so a pending gap marker still
                # lands promptly after a drop burst with no further traffic.
                item = self._q.get(timeout=self._drain_interval)
            except queue.Empty:
                # Queue drained — pull any durably-spilled spans back in (B2),
                # then attest any genuinely-dropped spans.
                self._refill_from_spill()
                self._emit_drop_marker_if_pending()
                continue
            try:
                if item is _SENTINEL:
                    self._emit_drop_marker_if_pending()
                    return
                # A drop seen before this span is attested before the span commits,
                # so the marker's position in the log precedes later evidence.
                self._emit_drop_marker_if_pending()
                # Normalization is fallible (bad attribute types, unparseable
                # timestamps). It MUST NOT kill the worker — count and move on,
                # or all evidence collection silently stops (NFR-SEC-01).
                try:
                    event = self._normalize(item)
                except Exception:  # noqa: BLE001
                    self.errors += 1
                    log.exception("failed to normalize span (telemetry unaffected)")
                    continue
                # Bounded retry-with-backoff on transient ledger unavailability
                # (NFR-REL-03); the additive path must never crash regardless.
                for attempt in range(self.commit_retries + 1):
                    try:
                        self.ledger.commit(event)
                        self.processed += 1
                        break
                    except Exception:  # noqa: BLE001
                        if attempt < self.commit_retries:
                            self.retries += 1
                            time.sleep(self.retry_backoff * (2**attempt))
                        else:
                            self.errors += 1
                            log.exception("failed to commit evidence after retries (telemetry unaffected)")
            finally:
                self._q.task_done()
                # A slot just freed — keep durable spillover flowing back in.
                self._refill_from_spill()

    def flush(self) -> None:
        # Drain durable spillover all the way back through the queue before
        # declaring the pipeline flushed, so no buffered span is left behind (B2).
        # Assumes no concurrent submit() (callers flush when done submitting).
        while True:
            self._refill_from_spill()
            self._q.join()
            if self._spill is None:
                break
            if self._spill.pending() == 0:
                # The worker may have refilled the queue from the spill's tail
                # between our join() and this check; spill is empty now, so one
                # more join drains that remainder and cannot be outrun.
                self._q.join()
                if self._spill.pending() == 0:
                    break
        # Ensure any drop that happened during/after draining is attested too.
        self._emit_drop_marker_if_pending()

    def stop(self) -> None:
        self._q.put(_SENTINEL)
        self._thread.join(timeout=5)

    def stats(self) -> Dict[str, int]:
        return {
            "processed": self.processed,
            "dropped": self.dropped,
            "errors": self.errors,
            "retries": self.retries,
            "drop_markers": self.drop_markers,
            "spilled": self.spilled,
            "spill_recovered": self.spill_recovered,
            "recovered_drops": self.recovered_drops,
        }


def _derive_durable_dir(ledger: Ledger) -> Optional[Path]:
    """The ledger's own storage directory, if it is a directory-backed file
    ledger — used as the default location for the spill buffer + drop journal."""
    backend = getattr(ledger, "backend", None)
    directory = getattr(backend, "dir", None)
    return Path(directory) if directory is not None else None
