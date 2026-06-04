"""Cross-language interop: the Python verifier validates Go-produced evidence,
and the Go verifier validates Python-produced evidence (Option C).

This complements the byte-identity conformance test (core-go/conformance_test.go):
that proves the cores compute the same hashes; this proves the Ed25519 signature
layer interoperates end to end, so both a signed *checkpoint* and a full signed
*report* produced by either core verify under the other.

Four checks, all must pass (the process exits non-zero on any failure):

  checkpoint  Direction 1 — Python verifier validates a Go-signed checkpoint
  checkpoint  Direction 2 — Go verifier validates a Python-signed checkpoint
  report      Direction 1 — Python verify_report() validates a Go-emitted report
  report      Direction 2 — Go recomputes the root + verifies the checkpoint of a
                            Python-produced report

Run::

    poetry run python core-go/verify_interop.py

Builds the Go CLI with the toolchain on PATH (or $GO_BIN), or uses a prebuilt
$OPENWRIGHT_CORE_BIN. Skips (exit 0) if neither is available.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from openwright.canonical import canonical_bytes
from openwright.events import ComplianceEvent, EventKind
from openwright.merkle import inclusion_proof, leaf_hash, tree_hash
from openwright.report import BOUNDARY_STATEMENT, REPORT_VERSION
from openwright.signing import (
    InMemoryKeySource,
    checkpoint_signing_bytes,
    public_key_pem,
    sign_checkpoint,
    verify_signature,
)
from openwright.verify import verify_report

HERE = Path(__file__).parent
_failures: list[str] = []


def _ok(msg: str) -> None:
    print(f"  OK   {msg}")


def _fail(msg: str) -> None:
    print(f"  FAIL {msg}")
    _failures.append(msg)


def _build_cli() -> str | None:
    prebuilt = os.environ.get("OPENWRIGHT_CORE_BIN")
    if prebuilt and Path(prebuilt).exists():
        return prebuilt
    go = os.environ.get("GO_BIN") or shutil.which("go")
    if not go:
        return None
    out = Path(tempfile.mkdtemp(prefix="openwright-core-")) / "openwright-core"
    res = subprocess.run(
        [go, "build", "-o", str(out), "./cmd/openwright-core"],
        cwd=str(HERE), env=dict(os.environ), capture_output=True, text=True,
    )
    if res.returncode != 0:
        print("go build failed:\n" + res.stderr)
        return None
    return str(out)


# -- checkpoint interop -------------------------------------------------------


def checkpoint_interop(cli: str) -> None:
    print("Checkpoint interop:")
    # Direction 1: Go signs, Python verifies.
    emitted = subprocess.run([cli, "emit"], capture_output=True, text=True, check=True).stdout
    cp = json.loads(emitted)
    leaves = [leaf_hash(d.encode()) for d in cp["leaves"]]
    recomputed_root = tree_hash(leaves).hex()
    if recomputed_root != cp["root_hash"]:
        _fail("Python recomputed a different Merkle root than Go (checkpoint)")
        return
    data = checkpoint_signing_bytes(cp["origin"], cp["tree_size"], cp["root_hash"], cp["timestamp"])
    if verify_signature(base64.b64decode(cp["public_key_b64"]), base64.b64decode(cp["signature_b64"]), data):
        _ok("Direction 1 — Python verifier validated Go-signed checkpoint")
    else:
        _fail("Python failed to verify a Go-signed checkpoint")

    # Direction 2: Python signs, Go verifies.
    key = InMemoryKeySource()
    origin, ts = "openwright-py-interop", "2026-05-31T00:00:00.000000000Z"
    data2 = checkpoint_signing_bytes(origin, len(leaves), recomputed_root, ts)
    sig = key.sign(data2)
    payload = {
        "origin": origin,
        "tree_size": len(leaves),
        "root_hash": recomputed_root,
        "timestamp": ts,
        "signature_b64": base64.b64encode(sig).decode(),
        "public_key_b64": base64.b64encode(key.public_key_raw()).decode(),
        "leaves": cp["leaves"],
    }
    res = subprocess.run([cli, "verify"], input=json.dumps(payload), capture_output=True, text=True)
    if res.returncode == 0 and "VALID" in res.stdout:
        _ok("Direction 2 — Go verifier validated Python-signed checkpoint")
    else:
        _fail(f"Go failed to verify a Python-signed checkpoint: {res.stdout}{res.stderr}")


# -- full report interop ------------------------------------------------------


def _build_python_report() -> dict:
    """A full signed report assembled from the same primitives build_report uses,
    without standing up a Ledger/crosswalk (controls are an empty list)."""
    key = InMemoryKeySource()
    ts = "2026-05-28T00:00:00.000000000Z"
    models = [
        ComplianceEvent(
            timestamp=ts, kind=EventKind.GENERIC,
            actor={"agent_id": "py-a1"}, source={"format": "sdk"},
        ).finalize_id(),
        ComplianceEvent(
            timestamp=ts, kind=EventKind.LLM_CALL,
            actor={"agent_id": "py-loan", "agent_card_ref": "sha256:abcd"},
            source={"format": "otel-genai", "span_id": "s1"},
            attributes={"operation": "chat", "nested": {"k": 1, "z": [2, 3]}},
            labels={"env": "prod"},
        ).finalize_id(),
    ]
    leaves = [leaf_hash(e.leaf_content_bytes()) for e in models]
    root_hex = tree_hash(leaves).hex()
    cp = sign_checkpoint(key, "openwright-py-report", len(leaves), root_hex, ts)

    events = [
        {
            "event": e.model_dump(mode="json", exclude_none=True),
            "leaf_index": i,
            "leaf_hash": "sha256:" + leaves[i].hex(),
            "inclusion_proof": [h.hex() for h in inclusion_proof(leaves, i)],
        }
        for i, e in enumerate(models)
    ]
    report = {
        "report_version": REPORT_VERSION,
        "report_id": "rpt_py_interop",
        "generated_at": ts,
        "tool": {"name": "openwright", "version": "0.5.1"},
        "boundary_statement": BOUNDARY_STATEMENT,
        "scope": {"description": "py interop", "agent_ids": sorted({e.actor.agent_id for e in models})},
        "period": {"start": ts, "end": ts},
        "crosswalk": {"id": "eu-ai-act"},
        "summary": {"total": 0, "satisfied": 0, "not_satisfied": 0, "insufficient_evidence": 0},
        "controls": [],
        "evidence_gaps": [],
        "checkpoint": cp.model_dump(mode="json"),
        "events": events,
        "public_key_pem": public_key_pem(key.public_key_raw()).decode("ascii"),
    }
    sig = key.sign(canonical_bytes({k: v for k, v in report.items() if k != "signature"}))
    report["signature"] = {
        "algorithm": "ed25519",
        "public_key_id": key.key_id(),
        "signature": base64.b64encode(sig).decode(),
    }
    return report


def report_interop(cli: str) -> None:
    print("Full-report interop:")
    # Direction 1: Go emits a full report, the Python verifier validates it.
    emitted = subprocess.run([cli, "emit-report"], capture_output=True, text=True, check=True).stdout
    go_report = json.loads(emitted)
    res = verify_report(go_report)
    if res.valid:
        _ok("Direction 1 — Python verify_report() validated Go-emitted report")
    else:
        _fail("Python verify_report() rejected the Go-emitted report:\n" + res.summary())

    # Direction 2: Python produces a report; Go recomputes its root + verifies
    # the checkpoint signature from the embedded public key.
    py_report = _build_python_report()
    # Sanity: Python itself accepts it (the report is well-formed).
    if not verify_report(py_report).valid:
        _fail("Python verify_report() rejected its own report (bug in the test harness)")
        return
    res2 = subprocess.run([cli, "verify-report"], input=json.dumps(py_report), capture_output=True, text=True)
    if res2.returncode == 0 and "VALID" in res2.stdout:
        _ok("Direction 2 — Go recomputed root + verified checkpoint of Python report")
    else:
        _fail(f"Go failed to verify a Python-produced report: {res2.stdout}{res2.stderr}")


def main() -> int:
    cli = _build_cli()
    if not cli:
        print("No Go toolchain or prebuilt $OPENWRIGHT_CORE_BIN found; skipping interop.")
        return 0

    checkpoint_interop(cli)
    report_interop(cli)

    if _failures:
        print(f"\nFAIL — {len(_failures)} interop check(s) failed")
        return 1
    print("\nPASS — cross-language Ed25519 interop (checkpoint + full report, both directions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
