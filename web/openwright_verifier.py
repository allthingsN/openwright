"""OpenWright standalone verifier — ONE file, ZERO third-party dependencies.

This is the auditable root of trust in its purest form (FR-VER-03): pure Python,
standard library only, no `cryptography`, no network. It runs in CPython and,
unchanged, inside a stock WASM Python (Pyodide) in the browser (FR-VER-04 [P2],
see verifier.html). It is intentionally self-contained so a reviewer can read the
entire trust-critical surface in a single file.

It verifies a OpenWright signed report against its signed checkpoint:
  * report + checkpoint Ed25519 signatures (pure-Python RFC 8032 verification),
  * every event's leaf hash recomputed from hash-only content (no raw payloads),
  * every inclusion proof against the signed root, and the full-tree root,
  * that cited evidence events are present.

Usage (CLI):  python openwright_verifier.py report.json public_key.pem
"""

import base64
import hashlib
import json
import sys

# --- canonical JSON (RFC 8785 / JCS-compatible subset; must match producer) ---

def _clean(obj):
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    if isinstance(obj, float):
        raise ValueError("floats are not allowed in canonical evidence")
    return obj

def canonical_bytes(obj):
    return json.dumps(_clean(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

# --- RFC 6962 Merkle verification ---

def _leaf_hash(data):       return hashlib.sha256(b"\x00" + data).digest()
def _node_hash(l, r):       return hashlib.sha256(b"\x01" + l + r).digest()

def _largest_pow2_lt(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k

def _tree_hash(leaves):
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _largest_pow2_lt(n)
    return _node_hash(_tree_hash(leaves[:k]), _tree_hash(leaves[k:]))

def _verify_inclusion(leaf_index, tree_size, leaf, proof, root):
    if leaf_index >= tree_size or leaf_index < 0:
        return False
    fn, sn, r = leaf_index, tree_size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            r = _node_hash(p, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root

# --- pure-Python Ed25519 verification (RFC 8032) ---

_P = 2**255 - 19
_LO = 2**252 + 27742317777372353535851937790883648493
def _inv(x): return pow(x, _P - 2, _P)
_D = (-121665 * _inv(121666)) % _P
_II = pow(2, (_P - 1) // 4, _P)
def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _II) % _P
    if x % 2 != 0:
        x = _P - x
    return x
_BY = (4 * _inv(5)) % _P
_B = (_xrecover(_BY) % _P, _BY)
def _add(p1, p2):
    x1, y1 = p1; x2, y2 = p2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _P
    return (x3, y3)
def _mul(point, e):
    result, addend = (0, 1), point
    while e > 0:
        if e & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        e >>= 1
    return result
def _on_curve(point):
    x, y = point
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0
def _decodepoint(s):
    val = int.from_bytes(s, "little")
    y = val & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((val >> 255) & 1):
        x = _P - x
    point = (x, y)
    if not _on_curve(point):
        raise ValueError("bad point")
    return point
def ed25519_verify(public_key, signature, message):
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        R = _decodepoint(signature[:32]); A = _decodepoint(public_key)
    except Exception:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _LO:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _LO
    return _mul(_B, S) == _add(R, _mul(A, h))

def pubkey_raw_from_pem(pem):
    body = "".join(line for line in pem.splitlines() if "-----" not in line)
    der = base64.b64decode(body)
    return der[-32:]  # Ed25519 SPKI ends with the 32-byte raw key

# --- report verification ---

def _key_id(pub):  return "ed25519:" + hashlib.sha256(pub).hexdigest()[:32]

def verify_report(report, trusted_public_key_raw):
    checks, valid = [], True
    def chk(name, ok):
        nonlocal valid
        checks.append((name, ok))
        valid = valid and ok

    sig = report.get("signature", {})
    chk("report_signature", ed25519_verify(
        trusted_public_key_raw, base64.b64decode(sig.get("signature", "")),
        canonical_bytes({k: v for k, v in report.items() if k != "signature"})))

    cp = report.get("checkpoint", {})
    cp_bytes = canonical_bytes({"origin": cp.get("origin"), "root_hash": cp.get("root_hash"),
                                "timestamp": cp.get("timestamp"), "tree_size": cp.get("tree_size")})
    chk("checkpoint_signature", ed25519_verify(trusted_public_key_raw,
        base64.b64decode(cp.get("signature", "")), cp_bytes)
        and cp.get("public_key_id") == _key_id(trusted_public_key_raw))

    root = bytes.fromhex(cp["root_hash"]); n = int(cp["tree_size"])
    leaves, leaf_ok, incl_ok, present = {}, True, True, set()
    for item in report.get("events", []):
        ev = item.get("event", {}); idx = item.get("leaf_index")
        present.add(ev.get("event_id"))
        recomputed = _leaf_hash(canonical_bytes({k: v for k, v in ev.items() if k != "ledger"}))
        stored = item.get("leaf_hash", "")
        if recomputed != bytes.fromhex(stored.split(":")[-1] if stored else ""):
            leaf_ok = False
        if not _verify_inclusion(idx, n, recomputed, [bytes.fromhex(h) for h in item.get("inclusion_proof", [])], root):
            incl_ok = False
        leaves[idx] = recomputed
    chk("event_leaf_hashes", leaf_ok)
    chk("inclusion_proofs", incl_ok)
    if len(leaves) == n and all(i in leaves for i in range(n)):
        chk("full_tree_root", _tree_hash([leaves[i] for i in range(n)]) == root)

    ev_ok = all(eid in present for c in report.get("controls", []) for eid in c.get("evidence_event_ids", []))
    chk("evidence_events_present", ev_ok)
    return valid, checks


def main(argv):
    if len(argv) != 3:
        print("usage: python openwright_verifier.py report.json public_key.pem")
        return 2
    report = json.load(open(argv[1]))
    pub = pubkey_raw_from_pem(open(argv[2]).read())
    valid, checks = verify_report(report, pub)
    print("VALID:", valid)
    for name, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
