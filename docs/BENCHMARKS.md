# OpenWright — throughput & backpressure benchmark (V11)

This supersedes the earlier dev-only "13k–23k ev/s" in-memory figure with a fuller
picture: the **durable** ceiling (what a single collector actually sustains), the
end-to-end pipeline rate, and the **drop/spill threshold** — the sustained input
rate above which the durable spill buffer (B2) engages.

Numbers are machine-dependent. Reproduce with:

```bash
poetry run python benchmarks/throughput.py [N]
```

## Representative run

Single node, Apple Silicon (darwin), local SSD, Python 3.11, `N = 30,000`:

| Path | Rate | Meaning |
|------|------|---------|
| `ledger.commit` (in-memory) | ~18,000–23,000 ev/s | Raw upper bound; no durability. |
| `ledger.commit` (file, fsync'd) | **~8,000 ev/s** | **Realistic durable ceiling** — one fsync per commit. |
| pipeline normalize+commit | ~12,000 ev/s | End-to-end span → `ComplianceEvent` → commit. |
| ingest *accept* rate (overload) | ~4,000 ev/s | Non-blocking; the caller is never blocked or dropped (each spilled span is fsync'd). |
| durable *drain* rate (overload backlog) | ~2,000 ev/s | Draining a large spill backlog (double-fsync per span: spill append + commit). |
| payload spans lost | **0** | Spillover is durable; nothing is dropped. |

## The drop/spill threshold

The collector's bounded in-memory queue drains at roughly the **durable commit
ceiling (~8,000 ev/s)** on this hardware. That rate is the threshold:

- **Sustained input ≤ ~8,000 ev/s:** the queue keeps up; no spill, no drop.
- **Sustained input > ~8,000 ev/s, or a burst exceeding the queue depth:** the
  excess is written to the **durable spill buffer** (B2) — fsync'd to disk, not
  dropped — and drained back when input subsides. The non-blocking `submit()`
  path still accepts spans (it never blocks the customer's request path, INV-6);
  it just absorbs the overflow durably.
- **Only genuinely unrecoverable loss** (e.g. the spill device itself fails)
  produces a tamper-evident `evidence_gap` marker (B1), so the log self-attests
  the loss rather than hiding it.

So the prior "we drop on overflow" behavior is gone: the ceiling is the durable
commit rate, and beyond it the system trades latency (spill-and-drain) for
**zero payload loss**, with any true loss self-attested.

## Scaling past one node

Horizontal scale uses `ShardedLedger` (B3): one single-writer shard per collector
replica, aggregated under a signed super-tree, so N replicas multiply the durable
ceiling while preserving one consistent signed root (see docs/SCALABILITY.md).
