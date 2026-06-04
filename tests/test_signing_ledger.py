"""Signing, key sources, and the append-only ledger (FR-ATT, FR-LED, NFR-REL)."""

from __future__ import annotations

import os
from datetime import timedelta

import pytest

from openwright.events import ComplianceEvent, EventKind
from openwright.ledger import FileLedgerBackend, InMemoryLedgerBackend, Ledger
from openwright.merkle import tree_hash
from openwright.signing import (
    Checkpoint,
    EnvKeySource,
    FileKeySource,
    InMemoryKeySource,
    generate_private_key_pem,
    sign_checkpoint,
)


def _ev(i):
    return ComplianceEvent(timestamp="2026-05-28T00:00:00.000000000Z", kind=EventKind.GENERIC,
                           actor={"agent_id": f"a{i}"}, source={"format": "sdk"},
                           attributes={"i": i})


def test_checkpoint_sign_and_verify():
    key = InMemoryKeySource()
    cp = sign_checkpoint(key, "openwright/x", 5, "ab" * 32, "2026-05-28T00:00:00.000000000Z")
    assert cp.verify(key.public_key_raw())
    assert not cp.verify(InMemoryKeySource().public_key_raw())


def test_checkpoint_rejects_modified_root():
    key = InMemoryKeySource()
    cp = sign_checkpoint(key, "o", 5, "ab" * 32, "2026-05-28T00:00:00.000000000Z")
    bad = Checkpoint(**{**cp.model_dump(), "root_hash": "cd" * 32})
    assert not bad.verify(key.public_key_raw())


def test_file_and_env_key_sources(tmp_path):
    pem = generate_private_key_pem()
    p = tmp_path / "k.pem"
    p.write_bytes(pem)
    fk = FileKeySource(str(p))
    os.environ["VT_TEST_KEY"] = pem.decode()
    ek = EnvKeySource("VT_TEST_KEY")
    # Same PEM via two sources => same key identity, both load correctly.
    assert fk.key_id() == ek.key_id()
    data = b"hello"
    from openwright.signing import verify_signature

    assert verify_signature(fk.public_key_raw(), fk.sign(data), data)
    assert verify_signature(ek.public_key_raw(), ek.sign(data), data)


def test_ledger_commit_assigns_leaf_and_index():
    led = Ledger(InMemoryLedgerBackend())
    e = led.commit(_ev(0))
    assert e.ledger.leaf_index == 0 and e.ledger.leaf_hash.startswith("sha256:")


def test_ledger_root_matches_merkle():
    led = Ledger(InMemoryLedgerBackend())
    for i in range(5):
        led.commit(_ev(i))
    assert led.root() == tree_hash(led.leaf_hashes())


def test_file_ledger_persists_and_reloads(tmp_path):
    from openwright.merkle import leaf_hash

    led = Ledger(FileLedgerBackend(tmp_path / "led"))
    for i in range(4):
        led.commit(_ev(i))
    root = led.root_hex()
    # reopen from disk
    led2 = Ledger(FileLedgerBackend(tmp_path / "led"))
    assert led2.size() == 4 and led2.root_hex() == root


def test_file_ledger_heals_torn_tail(tmp_path):
    led = Ledger(FileLedgerBackend(tmp_path / "led"))
    led.commit(_ev(0))
    led.commit(_ev(1))
    # simulate a crash mid-append: write a partial line
    path = tmp_path / "led" / "events.jsonl"
    with path.open("ab") as fh:
        fh.write(b'{"partial":')
    led2 = Ledger(FileLedgerBackend(tmp_path / "led"))
    assert led2.size() == 2  # torn line dropped


def test_retention_proof_is_attested(tmp_path):
    led = Ledger(FileLedgerBackend(tmp_path / "led"), retention=timedelta(days=180))
    led.commit(_ev(0))
    proof = led.prove_retention(0)
    assert proof["retention_until"] is not None
    assert proof["inclusion_proof"] == []  # single-leaf tree


def test_correction_is_new_event_not_mutation():
    led = Ledger(InMemoryLedgerBackend())
    orig = led.commit(_ev(0))
    corr = led.correct(orig.event_id, reason="typo", actor_id="ops")
    assert led.size() == 2 and corr.kind == "correction"
    assert led.get_event(0).event_id == orig.event_id  # history unchanged
