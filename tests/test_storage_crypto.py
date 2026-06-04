"""Storage + crypto adapters: S3 WORM (V3), HSM signing (V4), equivocation
detection (V14), and the standalone witness service (B8)."""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile
from datetime import timedelta

import pytest

from openwright.events import ComplianceEvent, EventKind
from openwright.ledger import InMemoryLedgerBackend, Ledger
from openwright.signing import (
    Checkpoint,
    InMemoryKeySource,
    public_key_pem,
    public_key_raw_from_pem,
    sign_checkpoint,
)

TS = "2026-05-28T00:00:00.000000000Z"


def _ev(i: int) -> ComplianceEvent:
    return ComplianceEvent(
        timestamp=TS, kind=EventKind.GENERIC, actor={"agent_id": f"a{i}"},
        source={"format": "sdk"}, attributes={"i": i},
    )


# -- B4 / V3: S3 checkpoint store with enforced WORM ---------------------------


def test_s3_checkpoint_store_enforces_object_lock_worm():
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    from openwright.checkpoint_store import S3CheckpointStore

    with moto.mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        S3CheckpointStore.create_locked_bucket(s3, "cp-bucket")
        store = S3CheckpointStore(
            "cp-bucket", client=s3, object_lock_mode="COMPLIANCE", retention=timedelta(days=180)
        )
        key = InMemoryKeySource()
        cp = sign_checkpoint(key, "o", 5, "ab" * 32, TS)
        store.put(cp)

        # Round-trips and the signed tree head still verifies.
        got = store.get(5)
        assert got is not None and got.verify(key.public_key_raw())
        assert store.tree_sizes() == [5]

        # Retention is enforced *in code*: the stored object carries Object Lock
        # metadata (mode + retain-until), not a comment.
        head = s3.head_object(Bucket="cp-bucket", Key=store._key(5))
        assert head["ObjectLockMode"] == "COMPLIANCE"
        assert head["ObjectLockRetainUntilDate"] is not None

        # WORM: the locked object version cannot be deleted before retention.
        versions = s3.list_object_versions(Bucket="cp-bucket", Prefix=store._key(5))["Versions"]
        vid = versions[0]["VersionId"]
        with pytest.raises(Exception):
            s3.delete_object(Bucket="cp-bucket", Key=store._key(5), VersionId=vid)


def test_s3_object_lock_mode_requires_retention():
    pytest.importorskip("boto3")
    from openwright.checkpoint_store import S3CheckpointStore

    class _FakeClient:  # never used; ctor must reject before any call
        pass

    with pytest.raises(ValueError):
        S3CheckpointStore("b", client=_FakeClient(), object_lock_mode="COMPLIANCE")


# -- B5 / V4: HSM signing with the private key never in process ----------------


def _find_softhsm_lib():
    for pat in (
        "/opt/homebrew/Cellar/softhsm/*/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/*/softhsm/libsofthsm2.so",
    ):
        hits = glob.glob(pat)
        if hits:
            return hits[0]
    return None


@pytest.fixture
def softhsm():
    pytest.importorskip("PyKCS11")
    lib = _find_softhsm_lib()
    if lib is None or shutil.which("softhsm2-util") is None:
        pytest.skip("SoftHSM2 (lib + softhsm2-util) not available")
    tmp = tempfile.mkdtemp(prefix="openwright-hsm-")
    tokens = os.path.join(tmp, "tokens")
    os.makedirs(tokens, exist_ok=True)
    conf = os.path.join(tmp, "softhsm2.conf")
    with open(conf, "w") as fh:
        fh.write(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
    old = os.environ.get("SOFTHSM2_CONF")
    os.environ["SOFTHSM2_CONF"] = conf
    subprocess.run(
        ["softhsm2-util", "--init-token", "--slot", "0", "--label", "openwright-test",
         "--so-pin", "1234", "--pin", "1234"],
        check=True, capture_output=True,
    )
    try:
        yield lib, "1234", "openwright-test"
    finally:
        if old is None:
            os.environ.pop("SOFTHSM2_CONF", None)
        else:
            os.environ["SOFTHSM2_CONF"] = old
        shutil.rmtree(tmp, ignore_errors=True)


def test_hsm_keysource_signs_with_no_in_process_private_key(softhsm):
    from openwright.report import build_report
    from openwright.signing import Pkcs11KeySource
    from openwright.verify import verify_report

    lib, pin, token = softhsm
    ks = Pkcs11KeySource.generate(lib, pin=pin, key_label="ossig-ed25519", token_label=token)
    try:
        # A checkpoint signed by the HSM verifies under the normal Ed25519 path.
        cp = sign_checkpoint(ks, "openwright/hsm", 3, "cd" * 32, TS)
        assert cp.verify(ks.public_key_raw())

        # The private key is NOT in this process: the source holds no private bytes.
        assert not hasattr(ks, "_sk")
        assert not hasattr(ks, "_private_key")

        # End-to-end: an HSM-signed report verifies offline.
        led = Ledger(InMemoryLedgerBackend())
        for i in range(3):
            led.commit(_ev(i))
        from openwright.crosswalk import evaluate
        from openwright.crosswalk_loader import load_builtin

        result = evaluate(load_builtin("eu-ai-act"), list(led.events()))
        rep = build_report(led, result, ks, scope_description="hsm-signed")
        vr = verify_report(rep)
        assert vr.valid
    finally:
        ks.close()


# -- B7 / V14: external anchor detects equivocation ----------------------------


def test_equivocation_split_view_detected_via_anchor():
    from openwright.anchor import TransparencyAnchor, detect_equivocation

    key = InMemoryKeySource()
    pub = key.public_key_raw()

    # Split view: two validly-signed checkpoints at the SAME tree_size, different roots.
    cp_a = sign_checkpoint(key, "o", 5, "aa" * 32, TS)
    cp_b = sign_checkpoint(key, "o", 5, "bb" * 32, TS)
    anchor = TransparencyAnchor()
    anchor.publish(cp_a)
    anchor.publish(cp_b)
    proof = detect_equivocation(anchor.checkpoints(), pub)
    assert proof is not None and proof.tree_size == 5

    # A consistent single history is NOT flagged.
    ok_anchor = TransparencyAnchor()
    ok_anchor.publish(cp_a)
    assert detect_equivocation(ok_anchor.checkpoints(), pub) is None

    # A checkpoint signed by a DIFFERENT key is not the producer equivocating.
    other = InMemoryKeySource()
    cp_other = sign_checkpoint(other, "o", 5, "cc" * 32, TS)
    mixed = TransparencyAnchor()
    mixed.publish(cp_a)
    mixed.publish(cp_other)
    assert detect_equivocation(mixed.checkpoints(), pub) is None


def test_equivocation_detected_by_failed_consistency_proof():
    from openwright.anchor import detect_equivocation
    from openwright.merkle import leaf_hash, tree_hash

    key = InMemoryKeySource()
    pub = key.public_key_raw()
    honest = [leaf_hash(f"leaf-{i}".encode()) for i in range(5)]
    r3 = tree_hash(honest[:3]).hex()
    r5 = tree_hash(honest).hex()
    from openwright.merkle import consistency_proof

    real_proof = [h.hex() for h in consistency_proof(honest, 3)]

    cp3 = sign_checkpoint(key, "o", 3, r3, TS)
    # A forked size-5 head (different leaves) the producer also signed.
    forked = [leaf_hash(f"forked-{i}".encode()) for i in range(5)]
    cp5_fork = sign_checkpoint(key, "o", 5, tree_hash(forked).hex(), TS)

    # Claiming the forked size-5 head extends the honest size-3 head, with the
    # honest proof, must fail to verify -> equivocation.
    proof = detect_equivocation(
        [cp3.model_dump(), cp5_fork.model_dump()], pub, consistency_proofs={(3, 5): real_proof}
    )
    assert proof is not None and "consistency" in proof.reason.lower()

    # The honest pair (real r5) does verify -> no equivocation.
    cp5 = sign_checkpoint(key, "o", 5, r5, TS)
    assert (
        detect_equivocation(
            [cp3.model_dump(), cp5.model_dump()], pub, consistency_proofs={(3, 5): real_proof}
        )
        is None
    )


# -- B8: standalone witness service (separate infra, independent key) ----------


def test_witness_service_cosigns_over_http_and_rejects_forks():
    from openwright.witness import verify_cosignature, WitnessError
    from openwright.witness_service import WitnessClient, WitnessService

    producer = InMemoryKeySource()
    witness_key = InMemoryKeySource()
    assert witness_key.key_id() != producer.key_id()  # independent key

    svc = WitnessService(witness_key).start()
    try:
        client = WitnessClient(svc.url)
        witness_pub = public_key_raw_from_pem(client.public_key_pem().encode("utf-8"))
        producer_pem = public_key_pem(producer.public_key_raw()).decode("ascii")

        led = Ledger(InMemoryLedgerBackend())
        for i in range(2):
            led.commit(_ev(i))
        cp1 = led.checkpoint(producer)
        cosig1 = client.cosign(cp1, producer_pem)
        assert verify_cosignature(cp1, cosig1, witness_pub)

        # Extend the log; a valid consistency proof lets the witness co-sign.
        for i in range(3):
            led.commit(_ev(10 + i))
        cp2 = led.checkpoint(producer)
        proof = led.consistency_proof_hex(2, tree_size=cp2.tree_size)
        cosig2 = client.cosign(cp2, producer_pem, consistency_proof_hex=proof)
        assert verify_cosignature(cp2, cosig2, witness_pub)

        # A forked head with a bogus/empty consistency proof is refused — so the
        # witness will not endorse a rewritten history.
        forged = sign_checkpoint(producer, cp2.origin, cp2.tree_size + 1, "ab" * 32, TS)
        with pytest.raises(WitnessError):
            client.cosign(forged, producer_pem, consistency_proof_hex=[])
    finally:
        svc.stop()
