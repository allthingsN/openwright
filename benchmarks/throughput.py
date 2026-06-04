"""Evidence-pipeline throughput + backpressure benchmark (NFR-PERF-03, V11).

Supersedes the dev-only in-memory figure with a fuller picture:

* ``ledger.commit`` (in-memory)         — the raw upper-bound ceiling.
* ``ledger.commit`` (file, fsync'd)     — the realistic *durable* ceiling, which
                                           is what a single collector sustains.
* ``pipeline normalize+commit``         — end-to-end normalize -> commit ceiling.
* backpressure / spill threshold        — under sustained overload, the durable
                                           spill buffer (B2) engages instead of
                                           dropping; we measure where it engages
                                           (≈ the durable drain rate) and confirm
                                           zero payload loss.

Run:  poetry run python benchmarks/throughput.py [N]
The numbers are machine-dependent; docs/BENCHMARKS.md records a representative run.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

from openwright.adapters.base import SpanData
from openwright.events import ComplianceEvent, EventKind
from openwright.ingest.pipeline import EvidencePipeline
from openwright.ledger import FileLedgerBackend, InMemoryLedgerBackend, Ledger


def _events(n: int):
    return [
        ComplianceEvent(timestamp="2026-05-29T00:00:00.000000000Z", kind=EventKind.AGENT_DECISION,
                        actor={"agent_id": "a"}, source={"format": "sdk"}, attributes={"i": i})
        for i in range(n)
    ]


def _spans(n: int):
    return [SpanData("chat", {"gen_ai.operation.name": "chat", "gen_ai.request.model": "m",
                              "gen_ai.usage.input_tokens": 10, "gen_ai.usage.output_tokens": 5})
            for _ in range(n)]


def bench_commit(n: int) -> float:
    led = Ledger(InMemoryLedgerBackend())
    events = _events(n)
    t0 = time.perf_counter()
    for e in events:
        led.commit(e)
    return n / (time.perf_counter() - t0)


def bench_commit_file(n: int) -> float:
    with tempfile.TemporaryDirectory() as d:
        led = Ledger(FileLedgerBackend(Path(d) / "led"))
        events = _events(n)
        t0 = time.perf_counter()
        for e in events:
            led.commit(e)
        return n / (time.perf_counter() - t0)


def bench_pipeline(n: int) -> float:
    led = Ledger(InMemoryLedgerBackend())
    pipe = EvidencePipeline(led, agent_id="a", max_queue=n + 10, durable=False)
    spans = _spans(n)
    t0 = time.perf_counter()
    pipe.submit(spans)
    pipe.flush()
    dt = time.perf_counter() - t0
    pipe.stop()
    return n / dt


def bench_backpressure(n: int, max_queue: int = 1000):
    """Sustained overload onto a file-backed ledger with a small bounded queue.

    Returns (accept_rate, drain_rate, spilled, lost). ``accept_rate`` is how fast
    the non-blocking ingest path absorbs spans (never blocks the caller);
    ``drain_rate`` is the durable end-to-end rate; ``spilled``>0 shows the spill
    buffer engaged; ``lost`` must be 0 (no payload loss)."""
    with tempfile.TemporaryDirectory() as d:
        led = Ledger(FileLedgerBackend(Path(d) / "led"))
        pipe = EvidencePipeline(led, agent_id="a", max_queue=max_queue, durable_dir=Path(d) / "durable")
        spans = _spans(n)
        t0 = time.perf_counter()
        pipe.submit(spans)  # never blocks; overflow spills durably
        accept_dt = time.perf_counter() - t0
        pipe.flush()
        drain_dt = time.perf_counter() - t0
        stats = pipe.stats()
        pipe.stop()
        committed = led.size() - stats["drop_markers"]
        return (n / accept_dt, committed / drain_dt, stats["spilled"], stats["dropped"])


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
    commit_rate = bench_commit(n)
    file_rate = bench_commit_file(min(n, 20_000))
    pipe_rate = bench_pipeline(n)
    accept_rate, drain_rate, spilled, lost = bench_backpressure(min(n, 20_000), max_queue=1000)

    print(f"ledger.commit (in-memory):      {commit_rate:>12,.0f} events/sec   (raw ceiling)")
    print(f"ledger.commit (file, fsync'd):  {file_rate:>12,.0f} events/sec   (durable ceiling)")
    print(f"pipeline normalize+commit:      {pipe_rate:>12,.0f} events/sec")
    print("backpressure (bounded queue + durable spill, file ledger):")
    print(f"  ingest accept rate:           {accept_rate:>12,.0f} events/sec   (non-blocking; never drops the caller)")
    print(f"  durable drain rate:           {drain_rate:>12,.0f} events/sec   (≈ the spill threshold: sustained input above this spills)")
    print(f"  spilled to disk:              {spilled:>12,}      lost: {lost}")
    target = 5000
    ok = commit_rate >= target and pipe_rate >= target and lost == 0
    print(f"target >= {target:,}/sec (and zero loss) : {'MET' if ok else 'NOT MET'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
