"""Deterministic canonical serialization and time normalization.

Reproducible hashing (FR-NRM-04) requires that identical inputs serialize to
byte-identical output. We use a JSON Canonicalization Scheme (RFC 8785, "JCS")
compatible subset:

* object keys sorted lexicographically by code point,
* no insignificant whitespace,
* UTF-8 output,
* ``null`` / unset values omitted entirely (so adding a new optional field that
  defaults to ``None`` never changes the hash of older events — DR-04),
* **no floating-point numbers** — floats have no canonical decimal form across
  languages, so monetary/derived quantities MUST be carried as decimal strings.

For our event model (ASCII field names, no floats) this subset is exactly
JCS-equivalent and stable across Python versions.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized deterministically."""


def _clean(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if v is None:
                continue
            if not isinstance(k, str):
                raise CanonicalizationError(f"object keys must be strings, got {type(k).__name__}")
            out[k] = _clean(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        raise CanonicalizationError(
            f"floats are not allowed in canonical evidence (carry as a decimal string instead): {obj!r}"
        )
    return obj


def canonical_bytes(obj: Any) -> bytes:
    """Return the canonical UTF-8 byte encoding of ``obj``."""
    cleaned = _clean(obj)
    return json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(obj: Any) -> str:
    """``sha256:<hex>`` digest over the canonical form of ``obj``.

    This is the format used for I/O reference hashes (DR-02): a payload is
    referenced by ``hash_payload(...)`` rather than stored inline.
    """
    return "sha256:" + sha256_hex(canonical_bytes(obj))


def hash_payload(payload: Any) -> str:
    """Hash a raw payload (str/bytes/JSON value) into a privacy-safe reference.

    Bytes and strings are hashed directly; other JSON values are canonicalized
    first. The result is a ``sha256:<hex>`` reference suitable for the ledger,
    so the raw payload need never be persisted (NFR-PRIV-02, DR-02).
    """
    if isinstance(payload, bytes):
        return "sha256:" + sha256_hex(payload)
    if isinstance(payload, str):
        return "sha256:" + sha256_hex(payload.encode("utf-8"))
    return content_hash(payload)


def to_rfc3339(value: Any) -> str:
    """Normalize a timestamp to a fixed-precision RFC 3339 UTC string.

    Accepts ``datetime``, unix seconds (int/str), or unix nanoseconds (int).
    Output always uses ``Z`` and a fixed 9-digit fractional field so that the
    same instant always serializes identically (FR-NRM-04).

    Precision note: a ``datetime`` carries at most microsecond resolution, so the
    fractional field is microsecond-real (its last three digits are always zero)
    and is computed with exact integer arithmetic — never via float seconds,
    whose mantissa cannot represent nanoseconds for current-epoch instants and
    would make the low digits rounding artifacts (a latent cross-language
    divergence). Integer-nanosecond inputs keep full nanosecond precision.
    """
    if isinstance(value, datetime):
        dt = value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        # Exact integer nanoseconds from the epoch — no float (see precision note).
        delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
        ns = (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000
    elif isinstance(value, int):
        # Heuristic: values above ~1e14 are nanoseconds; otherwise seconds.
        ns = value if value > 10**14 else value * 1_000_000_000
    elif isinstance(value, str):
        return value  # assume caller already supplied an RFC 3339 string
    else:
        raise CanonicalizationError(f"cannot normalize timestamp of type {type(value).__name__}")
    secs, rem = divmod(ns, 1_000_000_000)
    dt = datetime.fromtimestamp(secs, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{rem:09d}Z"
