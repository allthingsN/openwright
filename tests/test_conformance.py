"""The committed cross-language vectors must match what the Python core produces.

The Go core (core-go/) is verified byte-identical to Python via these vectors
(conformance/vectors.json). This test — which runs in CI without a Go toolchain
— keeps Python, the single source of truth, from silently drifting away from the
committed vectors the Go core depends on. If it fails, regenerate with
`poetry run python conformance/generate_vectors.py` and review the diff.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_build():
    spec = importlib.util.spec_from_file_location(
        "genvec", ROOT / "conformance" / "generate_vectors.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build


def _committed():
    return json.loads((ROOT / "conformance" / "vectors.json").read_text(encoding="utf-8"))


def test_committed_vectors_match_python_core():
    build = _load_build()
    committed = _committed()
    assert build() == committed, (
        "conformance/vectors.json is stale vs. the Python core; "
        "run: poetry run python conformance/generate_vectors.py"
    )


def test_committed_timestamp_vectors_verify():
    """F5: the committed timestamp vectors reproduce from the live core."""
    from openwright.canonical import to_rfc3339

    for tv in _committed()["timestamps"]:
        assert to_rfc3339(tv["value"]) == tv["rfc3339"]


def test_committed_consistency_vectors_verify():
    """F4/F5: the committed consistency proofs verify against the live core."""
    from openwright.merkle import leaf_hash, tree_hash, verify_consistency

    for case in _committed()["consistency"]:
        leaves = [leaf_hash(d.encode()) for d in case["leaves"]]
        second_root = tree_hash(leaves)
        assert second_root.hex() == case["root"]
        for p in case["proofs"]:
            first_root = tree_hash(leaves[: p["first"]])
            proof = [bytes.fromhex(h) for h in p["proof"]]
            assert verify_consistency(p["first"], p["second"], first_root, second_root, proof)


def test_committed_event_vectors_verify():
    """B12: the committed event-model serialization vectors reproduce from the
    live core — the leaf bytes a Go producer must match byte-for-byte."""
    from openwright.canonical import canonical_bytes, sha256_hex
    from openwright.merkle import leaf_hash

    for case in _committed()["events"]:
        cb = canonical_bytes(case["event"])
        assert cb.decode("utf-8") == case["canonical"]
        assert leaf_hash(cb).hex() == case["leaf_hash"]
        # the canonical form embeds the deterministic event id
        assert case["event"]["event_id"] == case["event_id"]
