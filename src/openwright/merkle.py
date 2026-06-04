"""RFC 6962 / RFC 9162 Merkle tree: tree head, inclusion and consistency proofs.

This is the cryptographic heart of the tamper-evidence guarantee (FR-ATT-01/03/05).
It depends only on :mod:`hashlib` from the standard library so the verifier can
reuse it as a small, independently auditable root of trust (FR-VER-03).

Domain separation follows RFC 6962 §2.1: leaf hash = ``SHA-256(0x00 || data)``,
interior node = ``SHA-256(0x01 || left || right)``, empty tree = ``SHA-256("")``.
The split point ``k`` is the largest power of two strictly less than ``n``.

The proof *generators* use the recursive PATH / SUBPROOF definitions from
RFC 6962 §2.1.1–2.1.2. The proof *verifiers* use the iterative algorithms from
RFC 9162 §2.1.3.2 (inclusion) and §2.1.4.2 (consistency). Both are validated
against the Google Certificate Transparency reference test vectors in the test
suite, so this file is correct-by-fixture, not by assertion.
"""

from __future__ import annotations

import hashlib
from typing import List

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 leaf hash of raw leaf ``data``."""
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior-node hash of two child hashes."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def empty_root() -> bytes:
    return hashlib.sha256(b"").digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly less than ``n`` (k < n <= 2k)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def tree_hash(leaves: List[bytes]) -> bytes:
    """Merkle Tree Hash (root) over a list of *leaf hashes*.

    ``leaves`` are already-computed leaf hashes (each via :func:`leaf_hash`),
    matching how the ledger stores them.
    """
    n = len(leaves)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaves[0]
    k = _largest_pow2_lt(n)
    return node_hash(tree_hash(leaves[:k]), tree_hash(leaves[k:]))


def inclusion_proof(leaves: List[bytes], m: int) -> List[bytes]:
    """Audit path proving the leaf at 0-based index ``m`` is in the tree."""
    n = len(leaves)
    if not 0 <= m < n:
        raise IndexError(f"leaf index {m} out of range for tree size {n}")
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if m < k:
        return inclusion_proof(leaves[:k], m) + [tree_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], m - k) + [tree_hash(leaves[:k])]


def _subproof(m: int, leaves: List[bytes], b: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [tree_hash(leaves)]
    k = _largest_pow2_lt(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [tree_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [tree_hash(leaves[:k])]


def consistency_proof(leaves: List[bytes], m: int) -> List[bytes]:
    """Proof that the tree of size ``m`` is a prefix of the current tree."""
    n = len(leaves)
    if not 0 < m <= n:
        raise ValueError(f"old tree size {m} out of range for tree size {n}")
    if m == n:
        return []
    return _subproof(m, leaves, True)


# -- verification (RFC 9162 §2.1.3.2 / §2.1.4.2) -------------------------------


def verify_inclusion(
    leaf_index: int,
    tree_size: int,
    leaf: bytes,
    proof: List[bytes],
    root: bytes,
) -> bool:
    """Verify an inclusion proof for ``leaf`` at ``leaf_index`` (RFC 9162 §2.1.3.2)."""
    if leaf_index >= tree_size or leaf_index < 0:
        return False
    fn, sn = leaf_index, tree_size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


class IncrementalMerkleTree:
    """O(log n) append + O(log n) root — byte-identical to :func:`tree_hash`.

    This is the scalability optimization described for NFR-SCAL-01, now
    implemented (not merely designed). It keeps only the tree's right-edge
    "frontier" — at most ``⌈log2 n⌉`` perfect-subtree roots, one per set bit of
    the size — instead of all leaves. Appending updates the frontier in
    ``O(log n)``; the root folds the frontier in ``O(log n)``. The output is
    verified byte-identical to the recursive ``tree_hash`` in the test suite
    (against the CT vectors and random fuzzing), so it is a drop-in replacement
    that never changes a single proof.
    """

    def __init__(self) -> None:
        self._frontier: List[bytes | None] = []  # index i = pending subtree of size 2^i
        self._size = 0

    @classmethod
    def from_leaves(cls, leaves: List[bytes]) -> "IncrementalMerkleTree":
        t = cls()
        for h in leaves:
            t.append(h)
        return t

    def append(self, leaf: bytes) -> None:
        carry = leaf
        level = 0
        while level < len(self._frontier) and self._frontier[level] is not None:
            carry = node_hash(self._frontier[level], carry)  # type: ignore[arg-type]
            self._frontier[level] = None
            level += 1
        if level == len(self._frontier):
            self._frontier.append(carry)
        else:
            self._frontier[level] = carry
        self._size += 1

    @property
    def size(self) -> int:
        return self._size

    def root(self) -> bytes:
        present = [(lvl, h) for lvl, h in enumerate(self._frontier) if h is not None]
        if not present:
            return empty_root()
        present.sort(key=lambda x: x[0], reverse=True)  # largest perfect subtree first
        acc = present[-1][1]
        for _, h in present[-2::-1]:
            acc = node_hash(h, acc)
        return acc

    def root_hex(self) -> str:
        return self.root().hex()


# -- shard aggregation: global verifiability across sharded logs (NFR-SCAL-01) --


def shard_super_root(shard_roots: List[bytes]) -> bytes:
    """Root of a super-tree whose leaves are per-shard Merkle roots."""
    return tree_hash([leaf_hash(r) for r in shard_roots])


def shard_super_proof(shard_roots: List[bytes], shard_index: int) -> List[bytes]:
    """Inclusion proof of shard ``shard_index``'s root within the super-tree."""
    return inclusion_proof([leaf_hash(r) for r in shard_roots], shard_index)


def verify_sharded_inclusion(
    leaf: bytes,
    leaf_index: int,
    shard_size: int,
    shard_proof: List[bytes],
    shard_root: bytes,
    shard_index: int,
    num_shards: int,
    super_proof: List[bytes],
    super_root: bytes,
) -> bool:
    """Verify an event is in its shard AND that shard is in the signed super-tree.

    Tampering with the event breaks the shard proof; tampering with a whole
    shard breaks the super proof — so global verifiability holds across shards.
    """
    if not verify_inclusion(leaf_index, shard_size, leaf, shard_proof, shard_root):
        return False
    return verify_inclusion(shard_index, num_shards, leaf_hash(shard_root), super_proof, super_root)


def verify_consistency(
    first_size: int,
    second_size: int,
    first_root: bytes,
    second_root: bytes,
    proof: List[bytes],
) -> bool:
    """Verify a consistency proof between two tree heads (RFC 9162 §2.1.4.2)."""
    if first_size > second_size:
        return False
    if first_size == second_size:
        return not proof and first_root == second_root
    if first_size == 0:
        # Any tree is consistent with the empty tree; proof is empty.
        return not proof

    path = list(proof)
    # If the first tree is a complete subtree, its root is not transmitted in
    # the proof — splice it in as the first node.
    if first_size & (first_size - 1) == 0:  # exact power of two
        path = [first_root] + path
    if not path:
        return False

    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == first_root and sr == second_root
