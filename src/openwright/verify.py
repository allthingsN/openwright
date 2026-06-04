"""The standalone OpenWright verifier — the root of trust (FR-VER).

This module is deliberately minimal and dependency-light (FR-VER-03): it imports
only the standard library, the stdlib-only :mod:`openwright.canonical` and
:mod:`openwright.merkle` helpers, and ``cryptography`` for Ed25519. It does NOT
import pydantic, pyyaml, reportlab, or any networking library — so it has **zero
network dependencies** (FR-VER-02), needs no access to the producer's
infrastructure, and verifies using only the hash-only data in the report (no raw
payloads — FR-VER-05).

What it proves, given a signed report (and ideally a public key obtained through
a trusted channel):

1. the report's own signature is valid (computed control results are authentic);
2. the checkpoint (signed tree head) signature is valid;
3. every event's leaf hash recomputes from its hash-only content (tamper of any
   field is caught — FR-ATT-05);
4. every event's inclusion proof verifies against the signed root, and the full
   set of leaves recomputes to that exact root (deletion/reorder is caught);
5. every control's cited evidence event is actually present and included.

If any check fails, the report is invalid.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # cryptography is the normal path; absent in a pure WASM/Pyodide runtime
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - exercised only in dependency-free envs
    InvalidSignature = ValueError  # type: ignore[assignment,misc]
    serialization = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]

from .canonical import canonical_bytes
from .merkle import leaf_hash, tree_hash, verify_inclusion, verify_consistency


# -- tiny self-contained crypto helpers (no pydantic/signing import) ----------


def _ed25519_verify(public_key_raw: bytes, signature: bytes, data: bytes) -> bool:
    if Ed25519PublicKey is not None:
        try:
            Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False
    # Zero-third-party-dependency fallback (e.g. WASM/Pyodide) — pure-Python Ed25519.
    from ._ed25519_pure import verify as _pure_verify

    return _pure_verify(public_key_raw, signature, data)


def _key_id(public_key_raw: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public_key_raw).hexdigest()[:32]


def _public_key_raw_from_pem(pem: str) -> bytes:
    if serialization is not None:
        pk = serialization.load_pem_public_key(pem.encode("utf-8"))
        if not isinstance(pk, Ed25519PublicKey):
            raise TypeError("not an Ed25519 public key")
        return pk.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    # Pure fallback: an Ed25519 SubjectPublicKeyInfo DER ends with the 32-byte
    # raw key (fixed 12-byte prefix 30 2a 30 05 06 03 2b 65 70 03 21 00).
    import base64

    body = "".join(line for line in pem.splitlines() if "-----" not in line)
    der = base64.b64decode(body)
    if len(der) < 32:
        raise ValueError("invalid public key PEM")
    return der[-32:]


def _checkpoint_signing_bytes(cp: Dict[str, Any]) -> bytes:
    return canonical_bytes(
        {
            "origin": cp["origin"],
            "root_hash": cp["root_hash"],
            "timestamp": cp["timestamp"],
            "tree_size": cp["tree_size"],
        }
    )


def _report_signing_payload(report: Dict[str, Any]) -> bytes:
    return canonical_bytes({k: v for k, v in report.items() if k != "signature"})


def _leaf_from_event_dict(event: Dict[str, Any]) -> bytes:
    content = {k: v for k, v in event.items() if k != "ledger"}
    return leaf_hash(canonical_bytes(content))


# -- result -------------------------------------------------------------------


@dataclass
class VerificationResult:
    valid: bool
    checks: List[Tuple[str, bool, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    controls: List[Dict[str, str]] = field(default_factory=list)
    gaps: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"VALID: {self.valid}"]
        for name, ok, detail in self.checks:
            lines.append(f"  [{'OK' if ok else 'FAIL'}] {name}: {detail}")
        for w in self.warnings:
            lines.append(f"  [WARN] {w}")
        if self.controls:
            lines.append("Controls:")
            for c in self.controls:
                lines.append(f"  - {c['control_id']}: {c['status']}")
        return "\n".join(lines)


def verify_report(
    report: Dict[str, Any],
    *,
    trusted_public_key_raw: Optional[bytes] = None,
    deep: bool = False,
    crosswalk: Any = None,
) -> VerificationResult:
    """Verify a signed OpenWright report. Pass a trusted key when you have one.

    With ``deep=True`` the verifier also **re-evaluates the crosswalk** over the
    included events and asserts each reported control status actually follows from
    the evidence (F3) — closing the gap that signatures + Merkle integrity prove a
    verdict is authentic-to-the-producer but not that it's *correct*. Deep mode
    pulls in pydantic + the crosswalk engine, so it stays OFF by default to keep
    the minimal verifier dependency-light (FR-VER-03). ``crosswalk`` may be a
    loaded ``Crosswalk`` for non-built-in mappings; otherwise the built-in named
    by the report is loaded.
    """
    res = VerificationResult(valid=True)

    def check(name: str, ok: bool, detail: str = "") -> None:
        res.checks.append((name, ok, detail))
        if not ok:
            res.valid = False

    # 1. Establish the public key to trust.
    pub_raw = trusted_public_key_raw
    if pub_raw is None:
        embedded = report.get("public_key_pem")
        if not embedded:
            res.valid = False
            res.errors.append("no trusted public key supplied and none embedded in report")
            return res
        try:
            pub_raw = _public_key_raw_from_pem(embedded)
        except Exception as exc:  # noqa: BLE001 - report, don't crash (NFR-SEC-01)
            res.valid = False
            res.errors.append(f"could not parse embedded public key: {exc}")
            return res
        res.warnings.append(
            "verifying with the key embedded in the report; for real trust, supply "
            "the signer's public key through an independent channel"
        )
    else:
        embedded = report.get("public_key_pem")
        if embedded:
            try:
                if _public_key_raw_from_pem(embedded) != pub_raw:
                    check("embedded_key_matches_trusted", False, "embedded key != trusted key")
            except Exception:  # noqa: BLE001
                pass

    # 2. Report signature.
    sig_block = report.get("signature") or {}
    try:
        report_sig = base64.b64decode(sig_block.get("signature", ""))
        rep_ok = _ed25519_verify(pub_raw, report_sig, _report_signing_payload(report))
    except Exception:  # noqa: BLE001
        rep_ok = False
    check("report_signature", rep_ok, sig_block.get("public_key_id", ""))
    if sig_block.get("public_key_id") and sig_block["public_key_id"] != _key_id(pub_raw):
        check("report_key_id", False, "signature key id does not match the trusted key")

    # 3. Checkpoint signature.
    cp = report.get("checkpoint") or {}
    try:
        cp_sig = base64.b64decode(cp.get("signature", ""))
        cp_ok = _ed25519_verify(pub_raw, cp_sig, _checkpoint_signing_bytes(cp))
    except Exception:  # noqa: BLE001
        cp_ok = False
    if cp.get("public_key_id") and cp["public_key_id"] != _key_id(pub_raw):
        cp_ok = False
    check("checkpoint_signature", cp_ok, f"tree_size={cp.get('tree_size')} root={cp.get('root_hash','')[:16]}…")

    try:
        root = bytes.fromhex(cp["root_hash"])
        tree_size = int(cp["tree_size"])
    except Exception:  # noqa: BLE001
        check("checkpoint_well_formed", False, "missing/invalid root_hash or tree_size")
        return res

    # 4. Per-event leaf recomputation + inclusion proof.
    events = report.get("events") or []
    leaves_by_index: Dict[int, bytes] = {}
    leaf_ok_all = True
    incl_ok_all = True
    present_ids = set()
    for item in events:
        ev = item.get("event") or {}
        idx = item.get("leaf_index")
        present_ids.add(ev.get("event_id"))
        recomputed = _leaf_from_event_dict(ev)
        stored = item.get("leaf_hash", "")
        stored_bytes = bytes.fromhex(stored.split(":")[-1]) if stored else b""
        if recomputed != stored_bytes:
            leaf_ok_all = False
        proof = [bytes.fromhex(h) for h in item.get("inclusion_proof", [])]
        if not verify_inclusion(idx, tree_size, recomputed, proof, root):
            incl_ok_all = False
        if isinstance(idx, int):
            leaves_by_index[idx] = recomputed
    check("event_leaf_hashes", leaf_ok_all, f"{len(events)} event(s) recomputed from hash-only content")
    check("inclusion_proofs", incl_ok_all, f"{len(events)} inclusion proof(s) against signed root")

    # 5. Full-tree recomputation (catches deletion/reordering, not just per-leaf).
    if len(leaves_by_index) == tree_size and all(i in leaves_by_index for i in range(tree_size)):
        ordered = [leaves_by_index[i] for i in range(tree_size)]
        full_ok = tree_hash(ordered) == root
        check("full_tree_root", full_ok, "recomputed root equals signed checkpoint root")
    else:
        # Report carries a subset of leaves; per-leaf inclusion still binds them.
        res.warnings.append(
            f"report carries {len(leaves_by_index)}/{tree_size} leaves; relying on "
            "per-event inclusion proofs (selective disclosure)"
        )

    # 6. Control evidence cross-check + surface controls/gaps.
    evidence_ok = True
    for c in report.get("controls", []):
        entry = {"control_id": c.get("control_id"), "status": c.get("status"), "title": c.get("title", "")}
        res.controls.append(entry)
        if c.get("status") != "satisfied":
            res.gaps.append(entry)
        for eid in c.get("evidence_event_ids", []):
            if eid not in present_ids:
                evidence_ok = False
    check("evidence_events_present", evidence_ok, "all cited evidence events are included in the report")

    # 7. (opt-in) Deep verify: re-derive every verdict from the evidence.
    if deep:
        _deep_verify(report, res, check, crosswalk)

    return res


def _deep_verify(report: Dict[str, Any], res: "VerificationResult", check, crosswalk: Any) -> None:
    """Re-run the crosswalk over the included events and assert reported statuses.

    The crosswalk is **pinned** (B9): the report must carry
    ``crosswalk.content_hash``, and deep-verify recomputes that hash from the
    crosswalk it loads (or the one passed in) and *refuses* on absence or mismatch
    — so a verdict can never be silently re-derived under a different crosswalk
    than the one the report claims.
    """
    try:
        from .crosswalk import crosswalk_content_hash, evaluate
        from .events import ComplianceEvent
    except Exception as exc:  # noqa: BLE001 - deep mode needs the full package
        check("deep_verify_available", False, f"deep verify needs the full openwright package: {exc}")
        return

    cw_block = report.get("crosswalk") or {}
    pinned_hash = cw_block.get("content_hash")
    if not pinned_hash:
        check(
            "deep_verify_crosswalk_pin",
            False,
            "report carries no crosswalk content_hash; refusing to re-derive verdicts "
            "against an unpinned crosswalk (B9)",
        )
        return

    cw = crosswalk
    if cw is None:
        cw_id = cw_block.get("id")
        try:
            from .crosswalk_loader import available_builtins, load_builtin

            if cw_id in available_builtins():
                cw = load_builtin(cw_id)
            else:
                check("deep_verify_crosswalk", False, f"no built-in crosswalk {cw_id!r}; pass crosswalk=")
                return
        except Exception as exc:  # noqa: BLE001
            check("deep_verify_crosswalk", False, f"could not load crosswalk: {exc}")
            return

    # Refuse unless the loaded crosswalk is byte-identical to the pinned one.
    actual_hash = crosswalk_content_hash(cw)
    if actual_hash != pinned_hash:
        check(
            "deep_verify_crosswalk_pin",
            False,
            f"report pinned crosswalk {pinned_hash} but the crosswalk in hand hashes to "
            f"{actual_hash} (id={getattr(cw, 'id', '?')} v{getattr(cw, 'version', '?')}); refusing",
        )
        return
    check("deep_verify_crosswalk_pin", True, f"crosswalk pinned to {pinned_hash}")

    # Selective disclosure: the re-derivation is scoped to the disclosed events.
    n_events = len(report.get("events", []))
    tree_size = int((report.get("checkpoint") or {}).get("tree_size") or n_events)
    if n_events < tree_size:
        res.warnings.append(
            f"deep verify re-derives verdicts over the {n_events} disclosed event(s) of "
            f"{tree_size} in the log; verdicts are scoped to this selective disclosure"
        )

    try:
        events = [ComplianceEvent.model_validate(item.get("event") or {}) for item in report.get("events", [])]
    except Exception as exc:  # noqa: BLE001
        check("deep_verify_events", False, f"could not reconstruct events for re-evaluation: {exc}")
        return

    recomputed = {c.control_id: c.status.value for c in evaluate(cw, events).controls}
    mismatches: List[str] = []
    for c in report.get("controls", []):
        cid = c.get("control_id")
        want = c.get("status")
        got = recomputed.get(cid)
        if got is None:
            mismatches.append(f"{cid}: reported but absent from crosswalk {cw.id}")
        elif got != want:
            mismatches.append(f"{cid}: report claims '{want}' but evidence yields '{got}'")
    check(
        "deep_verify_verdicts",
        not mismatches,
        f"{len(report.get('controls', []))} control verdict(s) re-derived from evidence"
        if not mismatches
        else "; ".join(mismatches),
    )
    res.errors.extend(mismatches)


def verify_report_file(
    path: str,
    *,
    public_key_pem_path: Optional[str] = None,
    deep: bool = False,
    crosswalk: Any = None,
) -> VerificationResult:
    with open(path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    trusted = None
    if public_key_pem_path:
        with open(public_key_pem_path, "r", encoding="utf-8") as fh:
            trusted = _public_key_raw_from_pem(fh.read())
    return verify_report(report, trusted_public_key_raw=trusted, deep=deep, crosswalk=crosswalk)


def verify_consistency_between(
    old_checkpoint: Dict[str, Any],
    new_checkpoint: Dict[str, Any],
    proof_hex: List[str],
    *,
    trusted_public_key_raw: Optional[bytes],
) -> bool:
    """Verify both checkpoints are signed and the new log extends the old (FR-ATT-03)."""
    if trusted_public_key_raw is None:
        return False
    for cp in (old_checkpoint, new_checkpoint):
        sig = base64.b64decode(cp.get("signature", ""))
        if not _ed25519_verify(trusted_public_key_raw, sig, _checkpoint_signing_bytes(cp)):
            return False
        if cp.get("public_key_id") != _key_id(trusted_public_key_raw):
            return False
    return verify_consistency(
        int(old_checkpoint["tree_size"]),
        int(new_checkpoint["tree_size"]),
        bytes.fromhex(old_checkpoint["root_hash"]),
        bytes.fromhex(new_checkpoint["root_hash"]),
        [bytes.fromhex(h) for h in proof_hex],
    )
