"""RFC 6962 Merkle correctness against Google CT reference vectors (FR-ATT)."""

from __future__ import annotations

import pytest

from openwright import merkle
from openwright.merkle import (
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    tree_hash,
    verify_consistency,
    verify_inclusion,
)
from tests.conftest import CT_CONSISTENCY, CT_INCLUSION, CT_LEAVES_HEX, CT_ROOTS


@pytest.fixture
def leaves():
    return [leaf_hash(bytes.fromhex(h)) for h in CT_LEAVES_HEX]


@pytest.mark.parametrize("n,expected", CT_ROOTS.items())
def test_tree_hash_vectors(leaves, n, expected):
    assert tree_hash(leaves[:n]).hex() == expected


def test_empty_root():
    import hashlib

    assert tree_hash([]).hex() == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("m,n,expected", CT_INCLUSION)
def test_inclusion_proof_vectors(leaves, m, n, expected):
    proof = inclusion_proof(leaves[:n], m)
    assert [h.hex() for h in proof] == expected
    assert verify_inclusion(m, n, leaves[m], proof, tree_hash(leaves[:n]))


@pytest.mark.parametrize("f,s,expected", CT_CONSISTENCY)
def test_consistency_proof_vectors(leaves, f, s, expected):
    proof = consistency_proof(leaves[:s], f)
    assert [h.hex() for h in proof] == expected
    assert verify_consistency(f, s, tree_hash(leaves[:f]), tree_hash(leaves[:s]), proof)


def test_inclusion_rejects_tampered_leaf(leaves):
    proof = inclusion_proof(leaves[:8], 3)
    root = tree_hash(leaves[:8])
    assert not verify_inclusion(3, 8, leaf_hash(b"tampered"), proof, root)


def test_inclusion_rejects_wrong_index(leaves):
    proof = inclusion_proof(leaves[:8], 3)
    root = tree_hash(leaves[:8])
    assert not verify_inclusion(4, 8, leaves[3], proof, root)


def test_consistency_rejects_divergent_history(leaves):
    proof = consistency_proof(leaves[:8], 6)
    # claim a different "old" root than the true prefix root
    assert not verify_consistency(6, 8, leaf_hash(b"fake"), tree_hash(leaves[:8]), proof)


def test_domain_separation_prefixes():
    # leaf and node hashing must use distinct prefixes (second-preimage resistance)
    assert merkle.leaf_hash(b"x") != merkle.node_hash(b"x"[:0], b"x"[:0])


def test_largest_pow2_lt():
    assert [merkle._largest_pow2_lt(n) for n in (2, 3, 4, 5, 8, 9)] == [1, 2, 2, 4, 4, 8]
