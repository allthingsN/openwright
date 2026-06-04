"""Durable evidence-loss handling: drop-intent journal (B1) + spillover buffer (B2).

Both add durability to OpenWright's *own* copy of the spans only; neither ever
touches, delays, or alters the customer's primary telemetry (INV-6), and neither
stores raw payloads beyond the span the collector already received in memory.

* :class:`DropJournal` — persists the undeclared-drop count + time window at drop
  time (atomic write + fsync), so a crash *after* a drop but *before* the lazy
  ``evidence_gap`` marker is committed still yields the gap on restart (B1/V9).
* :class:`SpillBuffer` — on queue overflow, spans are appended to a durable,
  fsync'd file and drained back into the pipeline when capacity returns, so
  sustained overload buffers instead of dropping; only a spill-write failure is
  genuinely unrecoverable (B2/V10).
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Optional

from ..adapters.base import SpanData


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)  # atomic on POSIX


class DropJournal:
    """Durable record of *pending* (uncommitted) undeclared-drop intent."""

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, count: int, window_start: Optional[str], window_end: Optional[str]) -> None:
        _atomic_write(
            self.path,
            json.dumps(
                {"count": count, "window_start": window_start, "window_end": window_end}
            ).encode("utf-8"),
        )

    def load(self) -> Optional[dict]:
        """Return pending drop intent, or ``None`` if absent/empty/corrupt."""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return None
        return data if int(data.get("count", 0)) > 0 else None

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class SpillBuffer:
    """Durable FIFO overflow buffer of raw spans (append-only file + read cursor).

    Spans are appended (fsync'd) to an append-only file; draining advances a
    durable byte *cursor* rather than rewriting the file, so a drain is
    O(spans-consumed-this-call) instead of O(whole-file) — overflow handling stays
    cheap even under a large backlog. When the cursor reaches end-of-file the file
    is compacted (truncated) so it does not grow without bound. On restart the
    cursor is reloaded, so un-consumed spilled spans are recovered.

    Note: a span is considered consumed once it is *re-enqueued* into the in-memory
    queue (cursor advances then), matching the volatile-queue model — the spill
    protects against overflow drops, not against a crash with spans still in the
    (inherently volatile) queue.
    """

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.cursor_path = self.path.with_name(self.path.name + ".cursor")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._lock = threading.Lock()
        self._consumed = self._load_cursor()

    def _load_cursor(self) -> int:
        try:
            return int(self.cursor_path.read_text())
        except (FileNotFoundError, ValueError):
            return 0

    def append(self, span: SpanData) -> None:
        line = json.dumps(asdict(span), separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            with open(self.path, "ab") as fh:
                fh.write(line.encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())

    def pending(self) -> int:
        with self._lock:
            if not self.path.exists():
                return 0
            with open(self.path, "rb") as fh:
                fh.seek(self._consumed)
                return sum(1 for ln in fh if ln.strip())

    def drain(self, accept: Callable[[SpanData], bool]) -> int:
        """Feed buffered spans to ``accept`` in FIFO order from the cursor until it
        declines one (capacity exhausted) or the file ends. Advances the durable
        cursor over accepted spans; compacts the file once fully drained. Returns
        the number accepted."""
        with self._lock:
            if not self.path.exists():
                return 0
            accepted = 0
            with open(self.path, "rb") as fh:
                fh.seek(self._consumed)
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    if not line.strip():
                        self._consumed = fh.tell()
                        continue
                    if accept(SpanData(**json.loads(line))):
                        accepted += 1
                        self._consumed = fh.tell()
                    else:
                        break  # capacity full; leave cursor at this line for next drain
                fh.seek(0, os.SEEK_END)
                eof = fh.tell()
            if self._consumed >= eof:
                # Everything is consumed — compact so the file can't grow unbounded.
                # Safe to discard: consumed spans are already re-enqueued/committed.
                open(self.path, "wb").close()
                self._consumed = 0
            _atomic_write(self.cursor_path, str(self._consumed).encode("ascii"))
            return accepted
