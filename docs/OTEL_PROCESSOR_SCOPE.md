# Scope: Native OpenTelemetry Collector Integration

**Status:** all three options are now IMPLEMENTED and verified (A: `examples/otel_collector/`; B: `otel/`; C: `core-go/`). C ships the cryptographic primitives plus the byte-identity conformance gate and cross-language interop — a full Go ledger/report pipeline remains deferred per §4 until a concrete Go-only requirement. This document remains the rationale and the staging recommendation.
**Date:** 31 May 2026
**Driver:** [openwright-diligence-and-plan.md](../openwright-diligence-and-plan.md) §5.4 — the OTel-telemetry-native, zero-code ingest path is OpenWright's clearest differentiator vs. the SDK/MCP-per-action crypto-audit crowd (Merkleon, DCL, Prismer). This document scopes what "native OTel Collector processor" actually means, the options, and the recommended path.

---

## 1. What we have today

`openwright collector` is already an OTLP-native receiver. Concretely (in `src/openwright/ingest/`):

- **`http_server.py` / `grpc_server.py`** — receive OTLP/HTTP + OTLP/gRPC, decode to `SpanData`.
- **`fanout.py`** — forward the *original request bytes unchanged* to a downstream backend (Langfuse/Phoenix/Datadog) when `--downstream` is set.
- **`pipeline.py`** — `EvidencePipeline`: a single background worker pulls `SpanData` off a bounded queue, normalizes via the adapters, and calls `ledger.commit()`. The evidence path is **strictly additive** and never blocks or alters the telemetry path.

So OpenWright is *already* an OTLP endpoint. The gap the diligence memo points at is narrower and specific: a team that **already runs an OpenTelemetry Collector** should be able to fork evidence to OpenWright **without standing up a second OpenWright process or changing application code** — "drop a component into the collector I already operate."

---

## 2. The hard constraint that shapes every option

The product's entire value is *third-party-verifiable evidence*. That verifiability rests on **one byte-exact implementation** of: RFC 8785/JCS canonical JSON (floats forbidden), `leaf = SHA256(0x00 ‖ canonical(event))`, the RFC 6962/9162 Merkle tree, and Ed25519 signing. The Python implementation is byte-verified against Google CT test vectors.

> **A second, independent re-implementation of that core (e.g. in Go) is a direct threat to the trust model.** If the Go and Python canonicalizers ever disagree by one byte, evidence produced by one path fails verification by the other. Any "native Go" option must therefore either (a) reuse the Python core over a process boundary, or (b) accept the cost of a second implementation kept byte-identical by a **shared conformance-vector suite** — and that cost is ongoing, not one-time.

The OpenTelemetry Collector is written in Go. Custom components are Go, built into a distribution with the **OpenTelemetry Collector Builder (`ocb`)**. There is no supported in-process Python component. This is the crux of the options below.

### Which OTel component type fits?

A Collector pipeline is `receivers → processors → exporters`, and the Collector **natively fans out to multiple exporters in one pipeline**. So the natural shape for "fork a copy to OpenWright" is an **additional exporter** (not a processor — processors transform in-place and aren't sinks). "Processor" in the memo is colloquial; the right primitive is an OpenWright **exporter** (or a routing **connector** into a second pipeline). This matters because the Collector's own fan-out gives us the additive guarantee for free.

---

## 3. The three options

| | **A — Config recipe (zero new code)** | **B — Thin Go exporter → Python core** | **C — Full Go evidence core** |
|---|---|---|---|
| What it is | Document a Collector config: add an `otlp/openwright` exporter to the user's existing pipeline, pointing at a `openwright collector` running as a pure evidence sink | A custom OpenWright exporter compiled into an `ocb` distribution; it forwards normalized/raw OTLP to the Python evidence service over gRPC/HTTP | Re-implement canonical+Merkle+Ed25519+ledger in Go; the collector component is self-contained, no Python at runtime |
| New code | **None** (maybe a 1-line confirmation that `--downstream` is optional) | ~200–500 LOC Go + a distribution build + CI | A full second crypto/ledger stack in Go + shared conformance vectors |
| Delivers the GTM line "drop into your existing Collector" | Yes (config) | Yes — *and* "it's a native OTel component" (registry-listable) | Yes — *and* "single Go binary, no Python" |
| Single byte-exact evidence impl preserved | **Yes** | **Yes** (Python remains the only core) | **No** — two impls, divergence risk |
| Removes the Python process from the deployment | No (OpenWright sink still runs) | No (still forwards to the Python service) | **Yes** |
| Effort (rough, assumptions in §6) | **~1–3 days** | **~1–2 weeks** | **~4–8+ weeks + ongoing dual-maintenance** |
| Risk | Low | Low–medium (build/release plumbing, version skew) | **High** (trust-model divergence is the worst failure mode this product can have) |

**Reading of the options.** Option A delivers ~80% of the differentiator's *demo and design-partner value* immediately, with no Go. Option B adds the credible "OpenWright is a native OTel component you configure like any other exporter" story (discoverability + operating model), while keeping Python as the single source of cryptographic truth. Option C is the only one that yields a true single-binary, Python-free deployment — and it is also the only one that endangers the trust model. C should not be built on spec.

---

## 4. Recommendation

A staged path, each stage independently shippable:

1. **Now (this cycle): ship Option A.** It makes the OTel-native, zero-code story real for the design-partner demo with essentially no engineering risk, and it's the honest centerpiece the diligence memo asks for.
2. **Next (the real "native component" deliverable): build Option B.** A thin, registry-listable OpenWright exporter that forwards to the Python core. This is what lets us truthfully say "OpenWright is a native OpenTelemetry Collector component" without forking the cryptographic core.
3. **Deferred, with an explicit trigger: Option C.** Build only if a design partner *mandates* a Go-only / single-binary deployment with no sidecar. Triggered by a real requirement, never speculatively — and only behind a shared conformance-vector suite that holds Go and Python byte-identical.

---

## 5. Task breakdown

### Option A — Collector config recipe (do now)
- [ ] Confirm `openwright collector` runs as a **pure evidence sink** (no `--downstream`): receive OTLP, fork to ledger, forward nothing. (`--downstream` is already optional; verify the no-downstream path end-to-end.)
- [ ] Write a documented Collector config snippet: user's existing pipeline gets a second exporter `otlp/openwright` → the OpenWright sink endpoint. Their real backend exporter is untouched; the Collector fans out to both.
- [ ] Add a smoke test / example under `examples/` that boots a stock `otelcol` with this config, sends spans, and shows evidence committed + verifiable — proving "no app code, existing collector."
- [ ] Document the additive guarantee in this topology (the second exporter cannot affect the primary path; a failing OpenWright sink degrades only the evidence fork).
- [ ] Add an ONBOARDING section: "Already running an OpenTelemetry Collector?"

### Option B — Native Go exporter (next, on a go-decision)
- [ ] Stand up an `ocb` (OpenTelemetry Collector Builder) manifest producing an `openwright-otelcol` distribution.
- [ ] Implement `openwrightexporter` (Go): batches spans, forwards as OTLP (or a thin normalized envelope) to the Python evidence service; honors retry/queue semantics mirroring `EvidencePipeline`; never blocks the pipeline.
- [ ] Define the wire contract between the Go exporter and the Python core (prefer **raw OTLP** so the Python adapters remain the single normalization point — do not normalize in Go).
- [ ] CI to build + release the distribution binary (this is where the deferred SLSA/cosign/SBOM release pipeline becomes relevant).
- [ ] Conformance test: evidence produced via the Go-exporter path is **byte-identical** to evidence produced via direct Python ingest for the same spans.
- [ ] Submit/document for the OpenTelemetry registry listing (the GTM payoff).

### Option C — Full Go core (deferred; trigger = Go-only mandate)
- [ ] Port canonical JSON (RFC 8785), leaf/Merkle (RFC 6962), Ed25519, and a ledger backend to Go.
- [ ] **Shared conformance-vector suite** run in both languages in CI; any divergence fails the build. This is the gate that protects the trust model and must exist *before* C ships.
- [ ] Independent-verifier interop test: Python verifier validates Go-produced evidence and vice-versa.

---

## 6. Effort estimates & assumptions

Estimates are engineering-days for one engineer fluent in Go + OTel; treat as ranges, not commitments.

- **A:** 1–3 days. Assumes the no-downstream sink path works as written (likely) and the example uses a stock `otelcol-contrib` binary.
- **B:** 5–10 days. Dominated by `ocb` distribution build + release CI and the byte-identical conformance test, not the exporter logic itself (~a few hundred LOC).
- **C:** 20–40+ days, plus **ongoing** dual-maintenance on every change to canonicalization, the event schema, or the Merkle/signature format. The recurring cost is the real story, not the initial port.

---

## 7. Open decisions (need lead/founder input)

1. **Is "native OTel component" a GTM requirement, or is the config recipe (A) enough for the design-partner demo?** If A suffices for the next two milestones, B can wait.
2. **Go expertise.** B and C assume Go fluency on the team; if absent, that's a hiring/contractor input that changes the estimate and the build/maintain risk.
3. **Wire contract for B** — raw OTLP forward (recommended; keeps Python as the only normalizer) vs. a normalized envelope (more work, splits normalization across languages).
4. **C's trigger** — agree explicitly that C is built only on a customer mandate for a Python-free single binary, and never before the shared conformance-vector suite exists.

---

## 8. Non-goals / out of scope

- Reimplementing the verifier in Go (the existing pure-Python verifier already runs dependency-free, including in-browser via WASM).
- Replacing the Python `openwright collector` (it remains the reference receiver and the Tier-1 zero-code path for teams *not* already running a Collector).
- Any change to the on-the-wire report or checkpoint format — all options above produce the identical evidence artifacts a third party verifies today.
