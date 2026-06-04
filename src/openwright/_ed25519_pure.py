"""Pure-Python Ed25519 signature *verification* (RFC 8032).

Used as a fallback by the verifier when the ``cryptography`` package is not
available — e.g. when running the verifier inside a stock WASM Python (Pyodide)
in the browser (FR-VER-04 [P2]). With this fallback the verifier needs **zero
third-party dependencies**, only the standard library.

This implements verification only (never signing); it follows the cofactorless
group-equation check ``[S]B == R + [k]A`` from RFC 8032 §5.1.7, which accepts all
signatures produced by a compliant signer (e.g. ``cryptography``). It is not
constant-time, which is fine — verification uses only public data.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * _inv(5)) % _P
_BX = _xrecover(_BY) % _P
_B = (_BX, _BY)


def _edwards_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    denom = _inv(1 + _D * x1 * x2 * y1 * y2)
    x3 = (x1 * y2 + x2 * y1) * denom % _P
    denom2 = _inv(1 - _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * denom2 % _P
    return (x3, y3)


def _scalarmult(point, e: int):
    result = (0, 1)  # neutral element
    addend = point
    while e > 0:
        if e & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        e >>= 1
    return result


def _is_on_curve(point) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _decodepoint(s: bytes):
    val = int.from_bytes(s, "little")
    y = val & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((val >> 255) & 1):
        x = _P - x
    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("point not on curve")
    return point


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature of ``message``."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        r_point = _decodepoint(signature[:32])
        a_point = _decodepoint(public_key)
    except (ValueError, Exception):  # noqa: BLE001
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    sb = _scalarmult(_B, s)
    ha = _scalarmult(a_point, h)
    return sb == _edwards_add(r_point, ha)
