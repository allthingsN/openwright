"""Generate the shared cross-language conformance vectors.

The Python core is the single source of truth (docs/OTEL_PROCESSOR_SCOPE.md,
Option C). This script emits `conformance/vectors.json`: canonical-encoding,
leaf-hash, Merkle-root, and inclusion-proof vectors that BOTH the Python core
and the Go core (core-go/) must reproduce byte-identically. If they ever
diverge, the Go conformance test and the Python conformance test both fail —
the gate that protects the trust model from a second implementation drifting.

Regenerate:  poetry run python conformance/generate_vectors.py
"""

from __future__ import annotations

import json
from pathlib import Path

from openwright.canonical import canonical_bytes, sha256_hex, to_rfc3339
from openwright.events import ComplianceEvent, EventKind
from openwright.merkle import consistency_proof, inclusion_proof, leaf_hash, tree_hash

# Canonical-encoding inputs. These deliberately stress the byte-identity edges:
# key sorting, null-dropping, unicode pass-through, and the control-character
# escaping where a naive Go encoding/json would diverge from Python (\b, \f,
# HTML escaping of <>&, etc.).
CANONICAL_INPUTS = [
    {"b": 1, "a": 2, "c": 3},
    {"z": {"y": 1, "x": 2}, "a": [3, 2, 1]},
    {"keep": 1, "drop": None, "nested": {"x": None, "y": 5}},
    {"unicode": "café — naïve ☕", "emoji": "🔐"},
    {"escapes": "quote\" back\\slash tab\there newline\nhere"},
    {"controls": "bell\x07 bs\x08 ff\x0c cr\x0d unit\x01"},
    {"html": "a<b>c&d", "slashes": "a/b"},
    {"ints": [0, -1, 42, 1234567890123456789], "bools": [True, False]},
    [],
    {},
    "a bare string with ünïcödé",
    1234567890,
]

# Merkle: leaf data sets of varying size; the Go core must reproduce the root
# and inclusion proofs exactly (RFC 6962 split = largest power of two < n).
MERKLE_SIZES = [0, 1, 2, 3, 4, 5, 7, 8, 11]

# Consistency proofs (RFC 9162) between an older tree size and the current size.
# A Go producer (Option C) must reproduce these before it can emit consistency
# proofs — core-go has no consistency implementation yet (F4), so today this
# section is enforced only by the Python conformance test.
CONSISTENCY_CASES = [(8, [1, 2, 3, 6, 8]), (11, [1, 4, 7, 11])]  # (size, [first_sizes])

# Timestamp normalization (to_rfc3339). The heuristic: a value > 1e14 is treated
# as unix nanoseconds, otherwise unix seconds. Computed with exact integer math
# (no float), so the fractional field is reproducible cross-language (F5). core-go
# has no to_rfc3339 yet (F4); enforced today only by the Python conformance test.
TIMESTAMP_VALUES = [
    0,
    1,
    1717200000,                 # seconds
    1717200000_000000000,       # same instant in nanoseconds
    1717200000_123456789,       # full nanosecond precision preserved
]

# Full event-model serialization. The byte-identity of an event depends on the
# pydantic ComplianceEvent -> dict serialization (exclude_none, enum-as-string,
# empty-dict defaults for provenance/attributes/labels). A Go producer (Option C)
# must reproduce the SAME leaf bytes. These cases stress the edges: a minimal
# event, a fully-populated one (io/model/tool/oversight/risk/provenance/labels),
# unicode + nested attributes, and a decimal-string cost (no floats).
_FIXED_TS = "2026-05-28T00:00:00.000000000Z"


def _event_cases() -> list:
    events = [
        # minimal: defaults make provenance/attributes/labels empty dicts that
        # must survive into the leaf (kept, not dropped).
        ComplianceEvent(
            timestamp=_FIXED_TS,
            kind=EventKind.GENERIC,
            actor={"agent_id": "a1"},
            source={"format": "sdk"},
        ),
        # fully populated across every optional sub-model.
        ComplianceEvent(
            timestamp=_FIXED_TS,
            kind=EventKind.LLM_CALL,
            actor={"agent_id": "loan-agent", "agent_card_ref": "sha256:abcd"},
            provenance={"task_id": "t1", "context_id": "c1", "root_task_id": "t1"},
            io={
                "input_ref": "sha256:" + "11" * 32,
                "output_ref": "sha256:" + "22" * 32,
                "input_tokens": 1200,
                "output_tokens": 345,
                "total_tokens": 1545,
                "cost": "0.002310",
                "cost_currency": "USD",
            },
            model={"provider": "openai", "request_model": "gpt-4o", "response_model": "gpt-4o-2026"},
            tool={"name": "lookup", "call_id": "call_7"},
            oversight={"status": "approved", "approval_ref": "evt_abc", "reviewer": "alice"},
            risk={"classification": "high", "rationale_ref": "evt_def", "framework": "eu-ai-act"},
            attributes={"operation": "chat", "finish_reasons": ["stop"], "nested": {"k": 1, "z": [2, 3]}},
            labels={"env": "prod", "team": "credit"},
            source={"format": "otel-genai", "span_id": "s1", "trace_id": "tr1"},
        ),
        # unicode + control-character edges inside attributes.
        ComplianceEvent(
            timestamp=_FIXED_TS,
            kind=EventKind.AGENT_DECISION,
            actor={"agent_id": "café-agent ☕"},
            attributes={"note": "naïve\ttab and <html> & slash/", "emoji": "🔐"},
            source={"format": "sdk"},
        ),
    ]
    cases = []
    for ev in events:
        ev.finalize_id()
        leaf = ev.leaf_content()  # everything except ledger, includes derived event_id
        cb = canonical_bytes(leaf)
        cases.append(
            {
                "event": leaf,
                "event_id": ev.event_id,
                "canonical": cb.decode("utf-8"),
                "leaf_hash": leaf_hash(cb).hex(),
            }
        )
    return cases


def build() -> dict:
    canonical = []
    for inp in CANONICAL_INPUTS:
        cb = canonical_bytes(inp)
        canonical.append(
            {
                "input": inp,
                "canonical": cb.decode("utf-8"),
                "leaf_hash": leaf_hash(cb).hex(),
            }
        )

    merkle = []
    for n in MERKLE_SIZES:
        data = [f"leaf-{i}".encode() for i in range(n)]
        leaves = [leaf_hash(d) for d in data]
        entry = {
            "leaves": [d.decode() for d in data],
            "root": tree_hash(leaves).hex(),
            "inclusion": [],
        }
        for m in range(n):
            entry["inclusion"].append(
                {"index": m, "proof": [h.hex() for h in inclusion_proof(leaves, m)]}
            )
        merkle.append(entry)

    consistency = []
    for size, first_sizes in CONSISTENCY_CASES:
        data = [f"leaf-{i}".encode() for i in range(size)]
        leaves = [leaf_hash(d) for d in data]
        consistency.append(
            {
                "leaves": [d.decode() for d in data],
                "root": tree_hash(leaves).hex(),
                "proofs": [
                    {"first": f, "second": size, "proof": [h.hex() for h in consistency_proof(leaves, f)]}
                    for f in first_sizes
                ],
            }
        )

    timestamps = [{"value": v, "rfc3339": to_rfc3339(v)} for v in TIMESTAMP_VALUES]

    return {
        "_comment": "Shared Python<->Go conformance vectors. Source of truth: the Python core. Regenerate with conformance/generate_vectors.py.",
        "canonical": canonical,
        "merkle": merkle,
        "consistency": consistency,
        "timestamps": timestamps,
        "events": _event_cases(),
        "empty_sha256": sha256_hex(b""),
    }


def main() -> None:
    out = Path(__file__).parent / "vectors.json"
    out.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
