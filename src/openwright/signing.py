"""Ed25519 signing, pluggable key sources, and signed checkpoints.

Signing keys are sourced from an external :class:`KeySource` (FR-ATT-06,
NFR-SEC-02): a file, an environment variable, or — by implementing the same
tiny interface — a KMS/HSM. The private key is never logged, never persisted by
OpenWright, and never embedded in code or images; for a KMS the key never leaves
the device at all because :meth:`KeySource.sign` delegates to it.

A *checkpoint* is a signed tree head (STH): it binds a Merkle root to a tree
size, an origin, and a timestamp, and is the artifact a third party verifies
offline (FR-ATT-02). The signed bytes are the canonical JSON of those fields,
so a verifier can reconstruct them from a report without trusting the producer.
"""

from __future__ import annotations

import abc
import base64
import hashlib
import os
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel, ConfigDict

from .canonical import canonical_bytes


def key_id_for(public_key_raw: bytes) -> str:
    """Stable identifier for a public key: ``ed25519:<first 32 hex of sha256>``."""
    return "ed25519:" + hashlib.sha256(public_key_raw).hexdigest()[:32]


def verify_signature(public_key_raw: bytes, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 ``signature`` over ``data`` with a raw 32-byte key."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


class KeySource(abc.ABC):
    """The signing interface. Implement :meth:`sign` + :meth:`public_key_raw`
    to back OpenWright with a file, env var, KMS, or HSM."""

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes: ...

    @abc.abstractmethod
    def public_key_raw(self) -> bytes:
        """The raw 32-byte Ed25519 public key."""

    def key_id(self) -> str:
        return key_id_for(self.public_key_raw())


class _PrivateKeyHolder(KeySource):
    """Base for sources that hold an in-process Ed25519 private key."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        # Held only in memory; never serialized back out or logged.
        self._sk = private_key
        self._pk_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)

    def public_key_raw(self) -> bytes:
        return self._pk_raw


class InMemoryKeySource(_PrivateKeyHolder):
    """A freshly generated keypair held in memory (tests, ephemeral demos)."""

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None) -> None:
        super().__init__(private_key or Ed25519PrivateKey.generate())


class FileKeySource(_PrivateKeyHolder):
    """Loads an Ed25519 private key from a PEM file the operator controls."""

    def __init__(self, path: str, password: Optional[bytes] = None) -> None:
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(f"{path} is not an Ed25519 private key")
        super().__init__(key)


class EnvKeySource(_PrivateKeyHolder):
    """Loads an Ed25519 private key (PEM) from an environment variable."""

    def __init__(self, env_var: str = "OPENWRIGHT_SIGNING_KEY", password: Optional[bytes] = None) -> None:
        pem = os.environ.get(env_var)
        if not pem:
            raise KeyError(f"environment variable {env_var} is not set")
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(f"{env_var} does not contain an Ed25519 private key")
        super().__init__(key)


def _ed25519_raw_from_ec_point(ec_point: bytes) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a PKCS#11 ``CKA_EC_POINT``.

    Tokens return the point as a DER OCTET STRING wrapping the 32 raw bytes
    (``04 20 ..``); some return the raw bytes directly. Handle both.
    """
    if len(ec_point) == 34 and ec_point[0] == 0x04 and ec_point[1] == 0x20:
        return ec_point[2:]
    if len(ec_point) == 32:
        return ec_point
    return ec_point[-32:]


# Ed25519 curve OID 1.3.101.112, DER-encoded — the CKA_EC_PARAMS a PKCS#11 token
# expects when generating an Edwards keypair.
_ED25519_EC_PARAMS = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])


class Pkcs11KeySource(KeySource):
    """Ed25519 signing backed by a PKCS#11 token / HSM (FR-ATT-06, NFR-SEC-02).

    The private key is generated and held **inside the token**; it never enters
    this process. :meth:`sign` delegates to the device (``CKM_EDDSA``); only the
    public key is read out. This is OpenWright's production *hardware* signing
    path (SoftHSM2, YubiHSM2, Thales Luna, AWS CloudHSM via its PKCS#11 provider,
    etc.).

    .. note::
       Cloud KMS services (AWS KMS, GCP Cloud KMS) do **not** offer Ed25519 — they
       sign with ECDSA P-256/384 or RSA only. A "KMS-backed Ed25519 signer" therefore
       cannot exist without introducing a second signature algorithm, which would
       break the single byte-exact crypto core (INV-1). So the Ed25519 key-never-in-
       process guarantee is delivered via PKCS#11/HSM, which every serious HSM (and
       CloudHSM) exposes. ``PyKCS11`` is imported lazily so the default install and
       the shallow verifier stay dependency-light (INV-2).
    """

    def __init__(
        self,
        lib_path: str,
        *,
        pin: str,
        key_label: str,
        token_label: Optional[str] = None,
        slot: Optional[int] = None,
    ) -> None:
        import PyKCS11  # lazy: optional `hsm` extra

        self._PyKCS11 = PyKCS11
        self._lib = PyKCS11.PyKCS11Lib()
        self._lib.load(lib_path)
        self._session = self._open_session(pin, token_label, slot)
        self._bind(key_label)

    def _open_session(self, pin: str, token_label: Optional[str], slot: Optional[int]):
        PyKCS11 = self._PyKCS11
        slots = self._lib.getSlotList(tokenPresent=True)
        if slot is None and token_label is not None:
            slot = next(
                (s for s in slots if self._lib.getTokenInfo(s).label.strip() == token_label), None
            )
            if slot is None:
                raise KeyError(f"no PKCS#11 token labelled {token_label!r}")
        if slot is None:
            if not slots:
                raise RuntimeError("no PKCS#11 token present")
            slot = slots[0]
        session = self._lib.openSession(slot, PyKCS11.CKF_RW_SESSION | PyKCS11.CKF_SERIAL_SESSION)
        session.login(pin)
        return session

    def _find(self, obj_class, label):
        PyKCS11 = self._PyKCS11
        found = self._session.findObjects(
            [(PyKCS11.CKA_CLASS, obj_class), (PyKCS11.CKA_LABEL, label)]
        )
        if not found:
            raise KeyError(f"no PKCS#11 object class={obj_class} label={label!r}")
        return found[0]

    def _bind(self, key_label: str) -> None:
        PyKCS11 = self._PyKCS11
        self._key_label = key_label
        self._priv = self._find(PyKCS11.CKO_PRIVATE_KEY, key_label)
        pub = self._find(PyKCS11.CKO_PUBLIC_KEY, key_label)
        ec_point = bytes(self._session.getAttributeValue(pub, [PyKCS11.CKA_EC_POINT])[0])
        self._pk_raw = _ed25519_raw_from_ec_point(ec_point)

    @classmethod
    def generate(
        cls,
        lib_path: str,
        *,
        pin: str,
        key_label: str,
        token_label: Optional[str] = None,
        slot: Optional[int] = None,
    ) -> "Pkcs11KeySource":
        """Generate a fresh Ed25519 keypair inside the token, then bind to it.

        Reuses one session (one ``C_Initialize``) for generation and signing, so a
        single process can both create and use the HSM key.
        """
        import PyKCS11

        self = cls.__new__(cls)
        self._PyKCS11 = PyKCS11
        self._lib = PyKCS11.PyKCS11Lib()
        self._lib.load(lib_path)
        self._session = self._open_session(pin, token_label, slot)
        pub_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_EC_EDWARDS),
            (PyKCS11.CKA_VERIFY, True),
            (PyKCS11.CKA_EC_PARAMS, _ED25519_EC_PARAMS),
            (PyKCS11.CKA_TOKEN, True),
            (PyKCS11.CKA_LABEL, key_label),
        ]
        priv_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_EC_EDWARDS),
            (PyKCS11.CKA_SIGN, True),
            (PyKCS11.CKA_TOKEN, True),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_LABEL, key_label),
        ]
        self._session.generateKeyPair(
            pub_template, priv_template,
            mecha=PyKCS11.Mechanism(PyKCS11.CKM_EC_EDWARDS_KEY_PAIR_GEN, None),
        )
        self._bind(key_label)
        return self

    def sign(self, data: bytes) -> bytes:
        return bytes(
            self._session.sign(self._priv, data, self._PyKCS11.Mechanism(self._PyKCS11.CKM_EDDSA, None))
        )

    def public_key_raw(self) -> bytes:
        return self._pk_raw

    def close(self) -> None:
        try:
            self._session.logout()
        except Exception:  # noqa: BLE001
            pass
        self._session.closeSession()


def generate_private_key_pem() -> bytes:
    """Generate a new Ed25519 private key as unencrypted PKCS#8 PEM bytes.

    Used by the demo/CLI to create a key the operator controls on disk; the
    key is written to a file, never embedded in an image (NFR-SEC-02).
    """
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_pem(public_key_raw: bytes) -> bytes:
    return Ed25519PublicKey.from_public_bytes(public_key_raw).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_raw_from_pem(pem: bytes) -> bytes:
    pk = serialization.load_pem_public_key(pem)
    if not isinstance(pk, Ed25519PublicKey):
        raise TypeError("not an Ed25519 public key")
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


# -- checkpoints (signed tree heads) ------------------------------------------


def checkpoint_signing_bytes(origin: str, tree_size: int, root_hash_hex: str, timestamp: str) -> bytes:
    """The exact bytes a checkpoint signs over. Deterministic and verifier-reproducible."""
    return canonical_bytes(
        {
            "origin": origin,
            "root_hash": root_hash_hex,
            "timestamp": timestamp,
            "tree_size": tree_size,
        }
    )


class Checkpoint(BaseModel):
    """A signed tree head over the evidence log (FR-ATT-02)."""

    model_config = ConfigDict(extra="allow")

    origin: str
    tree_size: int
    root_hash: str  # hex
    timestamp: str  # RFC 3339
    public_key_id: str
    signature: str  # base64 of the Ed25519 signature

    def signing_bytes(self) -> bytes:
        return checkpoint_signing_bytes(self.origin, self.tree_size, self.root_hash, self.timestamp)

    def verify(self, public_key_raw: bytes) -> bool:
        if key_id_for(public_key_raw) != self.public_key_id:
            return False
        try:
            sig = base64.b64decode(self.signature)
        except (ValueError, TypeError):
            return False
        return verify_signature(public_key_raw, sig, self.signing_bytes())


def sign_checkpoint(
    key: KeySource, origin: str, tree_size: int, root_hash_hex: str, timestamp: str
) -> Checkpoint:
    data = checkpoint_signing_bytes(origin, tree_size, root_hash_hex, timestamp)
    signature = key.sign(data)
    return Checkpoint(
        origin=origin,
        tree_size=tree_size,
        root_hash=root_hash_hex,
        timestamp=timestamp,
        public_key_id=key.key_id(),
        signature=base64.b64encode(signature).decode("ascii"),
    )
