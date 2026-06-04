package openwrightcore

import "bytes"

// Consistency proofs (RFC 9162 §2.1.2 generators / §2.1.4.2 verifier), ported
// byte-identically from src/openwright/merkle.py. The generators use the
// recursive SUBPROOF definition; the verifier uses the iterative RFC 9162
// algorithm. Both must reproduce the committed proof bytes in
// conformance/vectors.json.

// subproof mirrors merkle.py:_subproof.
func subproof(m int, leaves [][]byte, b bool) [][]byte {
	n := len(leaves)
	if m == n {
		if b {
			return [][]byte{}
		}
		return [][]byte{TreeHash(leaves)}
	}
	k := largestPow2Lt(n)
	if m <= k {
		return append(subproof(m, leaves[:k], b), TreeHash(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), TreeHash(leaves[:k]))
}

// ConsistencyProof returns a proof that the tree of size m is a prefix of the
// current tree built from leaves (already-computed leaf hashes). It mirrors
// merkle.py:consistency_proof. Returns nil for out-of-range m (Python raises);
// the conformance gate only exercises valid 0 < m <= n.
func ConsistencyProof(leaves [][]byte, m int) [][]byte {
	n := len(leaves)
	if m <= 0 || m > n {
		return nil
	}
	if m == n {
		return [][]byte{}
	}
	return subproof(m, leaves, true)
}

// VerifyConsistency verifies a consistency proof between two tree heads
// (RFC 9162 §2.1.4.2), mirroring merkle.py:verify_consistency exactly.
func VerifyConsistency(firstSize, secondSize int, firstRoot, secondRoot []byte, proof [][]byte) bool {
	if firstSize > secondSize {
		return false
	}
	if firstSize == secondSize {
		return len(proof) == 0 && bytes.Equal(firstRoot, secondRoot)
	}
	if firstSize == 0 {
		// Any tree is consistent with the empty tree; proof is empty.
		return len(proof) == 0
	}

	path := make([][]byte, 0, len(proof)+1)
	// If the first tree is a complete subtree, its root is not transmitted in
	// the proof — splice it in as the first node.
	if firstSize&(firstSize-1) == 0 { // exact power of two
		path = append(path, firstRoot)
	}
	path = append(path, proof...)
	if len(path) == 0 {
		return false
	}

	fn, sn := firstSize-1, secondSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	fr := path[0]
	sr := path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return false
		}
		if (fn&1) == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if (fn & 1) == 0 {
				for (fn&1) == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}

	return sn == 0 && bytes.Equal(fr, firstRoot) && bytes.Equal(sr, secondRoot)
}
