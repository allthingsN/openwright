# OpenWright Scalability

This document is honest about what v0.1 implements versus what it designs for.
v0.1 prioritizes **correctness and verifiability** over raw scale: the file
ledger and the recursive proof functions are exact (validated against RFC 6962
reference vectors) and are well suited to the demo and moderate production
volumes. Where a component is not yet optimized for scale, this document says so
and describes the concrete path — without pretending it is already built.

Legend: **[Implemented]** ships in v0.1 · **[Designed]** interface/path defined,
implementation is future work.

---

## 1. Ingest throughput **[Implemented]**

The collector → evidence path is asynchronous and strictly additive (FR-ING-04,
NFR-REL-01, NFR-PERF-02):

- The OTLP receiver forks a copy of each request for evidence and forwards the
  **original bytes unchanged** to the downstream backend. The fork happens in an
  isolated `try/except`, so evidence-side failure cannot affect telemetry.
- `EvidencePipeline` runs a single daemon worker thread draining a bounded
  `queue.Queue(maxsize=10000)`. `submit()` uses `put_nowait` and **never blocks
  the caller**; on overflow it increments a `dropped` counter and logs (no silent
  truncation — NFR-REL-03). Malformed spans increment `errors` and are skipped,
  never fatal (NFR-SEC-01).
- Per-span instrumentation overhead on the agent's hot path is OTel's own span
  overhead (sub-millisecond); OpenWright adds nothing synchronous to the agent
  (NFR-PERF-01).

**Scaling ingest horizontally:** the collector is stateless. Run N collectors
behind a load balancer, each forwarding to the same downstream and each feeding
its own ledger shard (see §4). The single-writer constraint is per-ledger, not
per-collector.

Throughput target: **≥ 5,000 events/sec on a single commodity node** (NFR-PERF-03).
The bottleneck at that rate is the ledger writer (fsync per append + leaf
append), addressed in §2 and §3.

---

## 2. The Merkle tree at scale — incremental frontier tree **[Implemented]**

`merkle.IncrementalMerkleTree` is now implemented and wired into the `Ledger`, so
`root()` is `O(log n)` on the checkpoint hot path (not `O(n)`). It is verified
**byte-identical** to the recursive `tree_hash` across `n = 0..300`, a 1,000-event
fuzz, and the Google CT vectors (`test_incremental_matches_recursive`) — a drop-in
that never changes a single proof. v0.1 still keeps the full leaf-hash list
resident to *serve* inclusion/consistency proofs; paging those from durable
storage (RAM = only the `O(log n)` frontier) is the remaining step.

How it works: an incremental ("compact range" /
"frontier") Merkle tree. Instead of recomputing from all leaves, store the
hashes along the tree's right edge (the frontier) — at most `⌈log₂ n⌉` nodes.
Appending a leaf updates the frontier in `O(log n)`; the root is derived from the
frontier in `O(log n)`; inclusion and consistency proofs are served from cached
subtree hashes in `O(log n)`. Crucially, **the output hashes are byte-identical**
to the recursive implementation, so the existing CT reference-vector tests and
the `verify.py` verifier act as a conformance oracle for the optimized
implementation — you can swap it in without changing the report format or
breaking any existing proof.

Until then, operators with very large logs should checkpoint and roll ledgers
(see §4) to keep any single tree bounded.

---

## 3. Storage backends **[Implemented]**

`SqlLedgerBackend` (append-only, insert-only) is implemented and tested on
sqlite3; the identical SQL runs on PostgreSQL via psycopg (pass the connection +
`paramstyle="format"`). `checkpoint_store.py` ships `LocalCheckpointStore` and an
S3-compatible `S3CheckpointStore`. All behind the `LedgerBackend` / `CheckpointStore`
interfaces.


Storage lives behind the `LedgerBackend` ABC (FR-LED-04) with a deliberately tiny
contract: `append_record`, `size`, `iter_records`, `get_record`. v0.1 ships:

- `InMemoryLedgerBackend` — tests and ephemeral use.
- `FileLedgerBackend` — append-only JSON-Lines, `fsync` on every append, and
  torn-trailing-line healing on open (a crash mid-append can never leave a
  half-written record visible). Zero external dependencies (FR-LED-02).

The production backends (FR-LED-03) implement the same ABC:

- **PostgreSQL ledger** — an append-only `events` table (insert-only; no UPDATE/
  DELETE grants), the leaf hash stored alongside each row, and a serializable or
  single-writer commit path so leaf indices are gap-free. Read replicas serve
  reporting/verification (read scale) while one primary owns writes.
- **Object-store checkpoints** — signed checkpoints (and, with the incremental
  tree, periodic frontier snapshots) written to an S3-compatible bucket with
  object-lock/WORM for the retention window.

Because the leaf hash is a pure function of event content, a backend only has to
durably store records in order; it never needs to understand attestation.

---

## 4. Sharding while preserving **global** verifiability **[Implemented core]**

The shard super-tree primitives are implemented: `merkle.shard_super_root`,
`shard_super_proof`, and `verify_sharded_inclusion` build a super-tree over
per-shard roots and verify an event via shard-inclusion + super-inclusion
(`test_shard_aggregation_verifies_and_detects_tamper`). Consistency proofs across
rolled epochs are likewise implemented (`verify_consistency_between`). The
remaining work is operational orchestration (running the shards + aggregator),
not new cryptography.


NFR-SCAL-01 requires that sharding/batching must not break global verifiability.
Two composable strategies, both of which the existing primitives already support:

1. **Per-shard logs + an aggregator super-tree.** Each shard is an independent
   append-only Merkle log producing its own signed checkpoints. A periodic
   **aggregator** builds a tree whose leaves are the shard checkpoint roots and
   signs a super-checkpoint. A verifier then checks: (a) an event's inclusion in
   its shard (existing inclusion proof), and (b) that shard root's inclusion in
   the super-tree (a second inclusion proof). Global tamper-evidence is preserved
   because altering any event invalidates its shard root, which invalidates the
   super-root.

2. **Time/size-rolled ledgers + consistency proofs.** Roll to a fresh ledger on a
   size or time boundary; link consecutive epochs with a `consistency_proof`
   (already implemented and verified — `verify_consistency_between`) so a verifier
   can confirm each new epoch is an append-only extension and that no history was
   rewritten across the roll.

An optional **external witness** (FR-ATT-08) co-signing super-checkpoints adds
non-repudiation against a compromised producer (see [SECURITY.md](SECURITY.md)).
The report format does not change for any of this.

---

## 5. Horizontal scale of stateless components **[Implemented design]**

- **Collectors** (OTLP receive + fan-out + enqueue): stateless → scale out freely.
- **Report generation** and **verification**: read-only over a ledger snapshot →
  run anywhere, including on read replicas; verification needs no infrastructure
  at all (it operates on the report file plus a public key).
- **The ledger writer**: single-writer per shard for gap-free indices. Scale by
  sharding (§4), not by adding writers to one log.

---

## 6. Privacy and payload vaulting at scale **[Implemented + Designed]**

The ledger stores I/O as `sha256:` references, never raw payloads or PII
(DR-02, NFR-PRIV-01/02) — implemented today. A complete, verifiable report is
producible with no payloads in the ledger (the demo proves this: the report
contains only hashes). When raw payloads must be retained for other reasons,
store them in a **separate vault** with independent access control and retention
(NFR-PRIV-03), keyed by the same `sha256:` reference; the ledger and the vault
scale independently, and the vault can be smaller/colder because it is never
needed for verification.

---

## 7. Retention and storage growth (EU AI Act Art. 12 "lifetime" logging)

Each record carries an immutable, attested `retention_until` (FR-LED-05); because
records are tamper-evident, so is the retention commitment. EU AI Act Art. 26(6)
sets a **≥ 6-month** floor for deployer logs; Art. 12 frames logging as
**lifetime**, so plan for indefinite/long retention with cold tiering.

Rough capacity math (order-of-magnitude):

| Quantity | Estimate |
|---|---|
| Canonical event record (hash-only) | ~1 KB |
| Merkle leaf hash | 32 bytes |
| 5,000 ev/s for 1 hour | 18M events ≈ **~18 GB** records, ~576 MB leaf hashes |
| 1 year at a sustained 100 ev/s | ~3.15B events ≈ **~3 TB** records |
| Checkpoint | a few hundred bytes, regardless of tree size |

Leaf hashes (32 B each) are cheap; the record bodies dominate. With the
incremental tree (§2) the in-memory working set is only the `O(log n)` frontier,
not the full leaf list, so memory stays flat as the log grows. Cold-tier old
records to object storage; serve proofs from cached subtree hashes.

---

## 8. Failure modes & availability — the ledger is never a SPOF for the agent

OpenWright is built so that **evidence capture can never break or block the agent**,
and so that a storage outage degrades to a *visible, attested gap* — never silent loss.

**The agent is decoupled from the ledger.** Capture is additive and asynchronous; the
customer's primary work/telemetry is never touched or delayed (INV-6). "Postgres is down"
means *evidence completeness* is degraded for the outage window — **not** that the agent is
down.

**Two capture paths, with an explicit durability trade-off:**

| Path | Guarantee | Use when |
|---|---|---|
| **In-process** (`openwright.instrument(...)`, the one-liner) | Best-effort. A hard ledger-write failure is caught and dropped rather than allowed to affect the agent. Lowest friction. | dev, single-service, low-stakes capture |
| **Out-of-process collector** (`EvidencePipeline` + `ingest/durable.py`) | At-least-once with durable spillover + attested gaps; runs on separate infra/credentials (tamper-domain separation). | audit-grade / production |

**What happens when writes fail (collector path):**
1. **Transient / backpressure** — the bounded queue overflows to a durable, `fsync`'d
   `SpillBuffer` on disk and drains back when capacity/DB returns. A Postgres blip loses nothing.
2. **Genuinely unrecoverable** (the spill write itself fails) — the event is counted and an
   **attested `evidence_gap` marker** (drop count + time window) is committed via a crash-safe
   `DropJournal` (atomic write + `fsync`, survives restarts).

So the worst case is a **signed, visible gap** ("N events dropped in window W"), never silent
missing data (NFR-REL-03, no silent truncation). An auditor sees the gap and its bounds.

**Postgres is not required and not a SPOF:**
- **Optional backend** — `FileLedgerBackend` (fsync, zero deps) or SQLite work for single-node /
  moderate volume; Postgres is the HA/scale choice, behind the same `LedgerBackend` ABC.
- **Tamper-evidence is DB-independent** — it comes from Ed25519 signatures + WORM S3 checkpoints;
  what was recorded stays verifiable even mid-outage.
- **Availability** — run Postgres HA (managed Multi-AZ / Patroni: primary + sync replica +
  auto-failover); the spill buffer covers the failover window; read replicas serve reporting/verify.
- **The single writer is per *shard*, for gap-free Merkle indices (correctness), not a global
  bottleneck** — scale and remove the SPOF by sharding (per tenant/agent/time), each shard an
  independent log tied together by a super-tree / consistency proofs (§4). Add shards, not writers.

---

## Summary

| Concern | v0.1 status | Path at scale |
|---|---|---|
| Ingest throughput | **Implemented** (async, non-blocking, additive; ~13k–23k ev/s measured) | scale collectors horizontally |
| Merkle root | **Implemented** — `IncrementalMerkleTree`, O(log n), identical hashes | page proof-serving leaves from storage |
| Storage | **Implemented** — file, in-memory, **SQL (sqlite/Postgres)**, **checkpoint store (local/S3)** | tune Postgres/object-store for volume |
| Sharding | **Implemented core** — super-tree + consistency proofs | operational orchestration of shards |
| Read scale | **Implemented** (stateless report/verify) | read replicas |
| Privacy/vaulting | **Implemented** (hash-only) | separate payload vault |
| Retention | **Implemented** (attested `retention_until`) | cold tiering |
| Availability / write failures | **Implemented** — agent decoupled; durable spill + attested `evidence_gap` (collector path); pluggable backend | HA Postgres (Multi-AZ) + shard per writer |

> The EU AI Act high-risk effective date (2 August 2026) stands as enacted; the
> pending "Digital Omnibus" deferral is not yet adopted. None of the scaling
> choices above change OpenWright's boundary: it produces **evidence of controls
> exercised**, not a compliance or audit determination.
