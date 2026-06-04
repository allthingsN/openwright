# OpenWright Security Model and Threat Model

This document describes the security guarantees OpenWright v0.1 provides, the precise limits of those guarantees, and the threats it does and does not defend against. It is written for operators deploying the evidence collector, developers integrating the SDK, and auditors or third parties verifying reports.

## Scope and the Hard Boundary

OpenWright produces **evidence that controls were exercised**. It does not assert legal compliance, certification, or an audit opinion. Every signed report carries an explicit `BOUNDARY_STATEMENT` to this effect.

This distinction is also the central security boundary. OpenWright provides **integrity and non-repudiation of what was recorded** — not **truthfulness of the recorder**. A correctly functioning OpenWright deployment can prove, to anyone holding the signer's public key, that a specific set of events was committed to an append-only log at a specific tree size, that no committed event was later altered, reordered, inserted, or removed, and that the control evaluation in a report is computed over exactly those events. It cannot prove that the events themselves describe reality. The threats below are organized around this boundary.

## 1. Tamper-Evidence Guarantee

### Mechanism

OpenWright commits each `ComplianceEvent` as a leaf in an append-only Merkle tree (`merkle.py`) following RFC 6962 / RFC 9162:

- `leaf_hash = SHA256(0x00 || data)`
- `node_hash = SHA256(0x01 || left || right)`
- empty tree hash = `SHA256("")`

The tree algorithms are validated in the test suite against the Google Certificate Transparency reference vectors (roots for n=0..8, plus inclusion and consistency proofs). The implementation is stdlib-only (`hashlib`).

At commit time (`ledger.py`), the leaf hash is computed from the event's content. Committing an event *is* attesting to it; there is no separate "seal" step that could diverge from the committed bytes. This is what makes the atomicity property (NFR-REL-02) hold: an event is either committed-and-attested or not present.

A **Checkpoint** (`signing.py`) is an Ed25519 signature over the canonical serialization of `{origin, root_hash, timestamp, tree_size}`. This is the signed tree head. The signature binds a specific root hash to a specific tree size at a specific time under a specific signing key.

### What the proofs actually prove

Given a signed checkpoint and the proofs OpenWright emits, a verifier can establish the following, with the listed tamper classes all detectable:

- **Inclusion proof** (`verify_inclusion`, RFC 9162 §2.1.3.2): recomputes the root hash from a leaf hash, its index, and the audit path. If the recomputed root does not equal the root in the signed checkpoint, the event was not in the tree at that size, or its content differs from what is claimed. **Modification** of a past event changes its leaf hash and therefore breaks its inclusion proof against the signed root.

- **Consistency proof** (`verify_consistency`, RFC 9162 §2.1.4.2): proves that a tree of size `m` is a prefix of a tree of size `n` (`m <= n`) — that the first `m` leaves are unchanged and only appends occurred. **Deletion**, **reordering**, or **insertion** before the current end of the log all change the historical leaves and therefore fail the consistency proof between any earlier signed checkpoint and the current one.

- **Full-tree root recomputation**: the standalone verifier (`verify.py`) recomputes the entire tree root from the hash-only event content in the report and checks it against the signed checkpoint root, independent of any individual inclusion proof.

In summary, against the signed checkpoint(s): modification breaks inclusion; insertion, deletion, and reordering of past events break consistency. None of these can be performed on already-checkpointed events without producing a verifiably broken proof or a different root that does not match a previously distributed signature.

### Precise limits

The guarantee is conditional and bounded. It does **not** cover:

- **Anything not yet checkpointed.** Tamper-evidence applies to events covered by a signed checkpoint that a verifier holds or can compare against. Events appended but not yet checkpointed, or a checkpoint never distributed to anyone, are not protected against an actor who controls the log and the signing key — that actor can simply rebuild the tree and re-sign. The strength of the guarantee depends on the signed root being **witnessed externally** (published, co-signed, or held by a relying party) before any tampering attempt.

- **Forks / equivocation.** A single OpenWright instance is not a gossiping CT log. If the signer can present different signed checkpoints to different parties (a split view), inclusion and consistency proofs are internally valid within each fork. Detecting equivocation requires comparing checkpoints across parties or external witness co-signing (see §6, FR-ATT-08). `verify_consistency_between()` (FR-ATT-03) supports comparing two checkpoints when both are available.

- **The signing key.** All of the above reduces to the secrecy and integrity of the Ed25519 signing key. An actor with the key can produce a fresh, internally consistent, fully valid history. Tamper-evidence is therefore exactly as strong as key custody (§2) and the independence of the verifier's trust in the public key (§3).

- **Truthfulness of leaf content.** Proofs say nothing about whether a committed event is true (§5).

### Corrections, not edits

The ledger is strictly append-only; there is no edit or delete operation (`LedgerBackend` ABC). Corrections are issued as **new events** (`correct()`, FR-LED-01). This preserves the original record and its proofs while recording the amendment, rather than mutating history.

## 2. Key Management

### KeySource abstraction

Signing is mediated by the `KeySource` ABC (`signing.py`), which exposes `sign()` and `public_key_raw()`. Three implementations ship:

- `InMemoryKeySource` — key held in process memory (tests, ephemeral use).
- `FileKeySource` — Ed25519 private key loaded from a PEM file.
- `EnvKeySource` — PEM key supplied through an environment variable.

A **KMS or HSM is supported by implementing the same ABC**: `sign()` delegates to the device and the private key never leaves it. OpenWright issues signing operations through the interface and never requires the raw key material to be present in its address space for KMS/HSM-backed sources.

The `key_id` is `"ed25519:" + sha256(pubkey)[:32]`, derived from the public key only.

### NFR-SEC-02: private keys are never logged or embedded

OpenWright **never logs or persists private keys**. Reports and checkpoints embed only public keys and key identifiers. No code path writes private key bytes to logs, reports, or other artifacts.

### The demo writes a key to disk

`run_demo()` (`demo.py`) and `openwright keygen` generate an operator-controlled key and write it to disk so the end-to-end flow can run locally. This is an **operator responsibility**: keys written to disk inherit the security of that disk and its filesystem permissions. For production, prefer a `FileKeySource` with appropriately restricted permissions, `EnvKeySource`, or a KMS/HSM-backed `KeySource`. The demo's on-disk key is a convenience for demonstration, not a recommended production posture.

## 3. The Verifier as Root of Trust

`verify.py` is a deliberately minimal **standalone verifier**. It imports only the Python standard library, `canonical.py`, `merkle.py`, and `cryptography`. It does **not** import pydantic, pyyaml, reportlab, or any networking stack. This keeps the trusted computing base small and auditable, and it lets verification run in an environment isolated from the producer.

`verify_report()` checks, with **zero network access** (FR-VER-02) and **without any raw payloads** (FR-VER-05):

1. The report's Ed25519 signature.
2. The checkpoint's Ed25519 signature.
3. Recomputation of each event's leaf from its hash-only content.
4. Each inclusion proof against the signed root.
5. Full-tree root recomputation against the signed checkpoint.
6. That every event cited as evidence by a control is present.

Because the entire report — including the computed control results — is Ed25519-signed (`report.py`), the control evaluation is itself tamper-evident: a verifier detects post-hoc edits to the reported satisfied/not-satisfied/insufficient outcomes.

### Why the public key must come through an independent channel

Every check above is performed **relative to a public key**. If the verifier obtains that public key from the same artifact (the report) that the producer controls, the producer can sign a fabricated report with a fabricated key and the report will verify against its own embedded key. **A self-consistent report proves nothing about authenticity** if the verifier trusts the key the report carries.

Therefore the signer's public key (or its `key_id`) **must be supplied to the verifier through an independent, trusted channel** — published out of band, pinned in CI configuration, distributed by the relying party, etc. The CLI surfaces this directly: `openwright verify <report.json> --pubkey <public_key.pem>` takes the key as a separate input. The report **may** embed the public key for convenience, but **the tool warns when verification relies on the embedded key**, because doing so reduces the check to internal consistency rather than authenticity.

## 4. Untrusted-Input Handling

All input crossing the trust boundary is treated as untrusted: OTLP telemetry, A2A AgentCards, SARIF findings, and SDK payloads. The governing requirements are NFR-SEC-01 (malformed input must not corrupt the ledger or crash the pipeline) and FR-ING-10.

- **Telemetry ingestion.** The OTLP path decodes protobuf into a proto-agnostic `SpanData` (`ingest/otlp_common.py`), then maps it through adapters (`adapters/`). Malformed spans are **counted, not fatal**; drops are **logged, not silent** (`ingest/pipeline.py`). The pipeline runs a single background worker against a bounded queue with non-blocking submit, so malformed or excessive input degrades throughput rather than corrupting state.

- **Additive evidence path (NFR-REL-01).** The evidence fork is strictly additive. The collector (`http_server.py`) forwards original telemetry bytes downstream **unchanged** (`fanout.py`) and forks evidence separately. A failure in the evidence path can never drop, delay, or alter primary telemetry. This also means a malformed-input failure in evidence processing does not affect the producer's observability pipeline.

- **AgentCards.** Identity claims (`identity.py`) verify an Ed25519 signature over the JCS-canonical AgentCard with the `signatures` field excluded. Verification is a pure cryptographic check over canonical bytes; a malformed or unsigned card fails verification rather than being trusted.

- **SARIF and adapters.** SARIF ingestion (`adapters/sarif_in.py`) uses defensive parsing to map findings into `conformance_finding` events. The GenAI adapter (`adapters/otel_genai.py`) tolerates attribute churn (current and legacy attribute names) and coerces fields (e.g. `finish_reasons` to a list) rather than failing on shape variation.

- **Canonical-form constraints.** The canonical encoder (`canonical.py`) enforces a strict JCS-compatible subset (sorted keys, UTF-8, `None` omitted, **floats forbidden**), so non-deterministic or ambiguous numeric encodings cannot enter the hashed content.

A malformed event therefore either fails validation before commit or is recorded as a well-formed `conformance_finding`/event; in neither case can it mutate or corrupt a previously committed leaf.

## 5. Privacy Model

The ledger is **hash-only with respect to payloads**. Raw inputs and outputs are referenced by hash (`IORef`, `hash_payload()` → `"sha256:<hex>"`); the SDK hashes raw payloads automatically so the developer never handles raw sensitive data in the evidence record (FR-SDK-04). Reports carry events in **hash-only** form.

Consequently, **verification needs no raw payloads** (NFR-PRIV, FR-VER-05). A verifier or auditor can confirm integrity, inclusion, consistency, and control evaluation against the signed checkpoint without ever receiving the underlying prompts, completions, or business data. Disclosure of a specific raw payload — to prove it matches a recorded hash — is a separate, deliberate, out-of-band act controlled by the data owner, not a prerequisite of verification.

Note that hashes are a commitment, not encryption: a party who already possesses a candidate plaintext can confirm it matches a recorded hash. Hashing protects against incidental disclosure through the evidence record; it is not a defense against an adversary who already holds the data.

## 6. What OpenWright Does NOT Defend Against

### A compromised producer signing false-but-well-formed events

This is the principal residual threat and follows directly from the boundary in §0. OpenWright proves the **integrity and non-repudiation** of what was recorded. It does **not** prove the **truthfulness** of the recorder.

An actor who controls a valid signing key and the ingestion path can commit events that are perfectly well-formed, fully signed, and that pass every inclusion and consistency check — but that misrepresent what the agent actually did. No cryptographic property of an append-only signed log can detect this, because the log faithfully records exactly what it was told. Tamper-evidence protects the record after commit; it does not validate reality at commit.

Mitigations OpenWright provides or enables, none of which fully eliminate this threat:

- **External witness co-signing (FR-ATT-08).** Having an independent witness co-sign checkpoints prevents the producer from silently rewriting or forking history after the fact and provides a second party whose attestation must also be compromised. This raises the bar from "compromise the producer's key" to "compromise the producer and the witness."

- **Identity binding (`identity.py`, FR-ATT-07).** Cryptographically binding events to a signed AgentCard identity closes the gap that A2A AgentCards are descriptive and not bound by default. It does not make a compromised identity honest, but it makes the asserting identity non-repudiable and attributable.

- **Segregation of duties (NFR-SEC-04).** Separating who may **write evidence** from who may **generate reports** (and ideally from who holds the checkpoint signing key and the witness key) reduces the blast radius of any single compromise. A party who can write events but not sign reports, or sign reports but not the checkpoint, cannot single-handedly produce an authentic, fabricated history.

### Other explicit non-goals

- **No blockchain/DLT (FR-ATT-09).** Trust does not derive from a distributed ledger; it derives from a signed Merkle log plus external witnessing. OpenWright makes no availability or decentralization claims beyond those of the chosen ledger backend.

- **Availability and ordering of un-checkpointed events.** See §1 limits. OpenWright does not guarantee that an event reached the log, only that committed-and-checkpointed events are tamper-evident.

- **Legal/compliance conclusions.** Per the boundary statement, OpenWright does not assert that any control was *adequately* exercised or that any regulation is *satisfied in law* — only that evidence exists and is integrity-protected.

### Regulatory caveat (informational, not a security control)

For deployments mapping to the EU AI Act crosswalk: high-risk Chapter III obligations apply **2 August 2026** under the enacted text of Regulation (EU) 2024/1689. A "Digital Omnibus" provisional agreement (6–7 May 2026) would defer Annex III standalone high-risk obligations to 2 December 2027, but is **not yet adopted or published**, so the 2 August 2026 date legally stands. This is a regulatory caveat, not a property of the tool.

## 7. Responsible Disclosure

If you discover a security vulnerability in OpenWright, please report it privately rather than opening a public issue.

- Do not file public GitHub issues for security-sensitive reports.
- Include a description, affected version (this document covers v0.1), and a minimal reproduction where possible.
- We will acknowledge receipt, investigate, and coordinate a fix and disclosure timeline with you.

Please direct reports to the project's designated security contact as listed in the repository's project metadata. This is a stub; maintainers should populate it with a monitored security contact (email or GitHub Security Advisory) before any public release.