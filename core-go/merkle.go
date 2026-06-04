package openwrightcore

import "crypto/sha256"

// RFC 6962 §2.1 domain separation, mirroring src/openwright/merkle.py:
//   leaf  = SHA-256(0x00 || data)
//   node  = SHA-256(0x01 || left || right)
//   empty = SHA-256("")
// The split point k is the largest power of two strictly less than n.

func LeafHash(data []byte) []byte {
	buf := make([]byte, 0, len(data)+1)
	buf = append(buf, 0x00)
	buf = append(buf, data...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

func NodeHash(left, right []byte) []byte {
	buf := make([]byte, 0, len(left)+len(right)+1)
	buf = append(buf, 0x01)
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

func EmptyRoot() []byte {
	sum := sha256.Sum256(nil)
	return sum[:]
}

func largestPow2Lt(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// TreeHash returns the Merkle Tree Hash over a list of already-computed leaf
// hashes (matching how the ledger stores them).
func TreeHash(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		return EmptyRoot()
	}
	if n == 1 {
		return leaves[0]
	}
	k := largestPow2Lt(n)
	return NodeHash(TreeHash(leaves[:k]), TreeHash(leaves[k:]))
}

// InclusionProof returns the audit path for the leaf at 0-based index m.
func InclusionProof(leaves [][]byte, m int) [][]byte {
	n := len(leaves)
	if m < 0 || m >= n {
		return nil
	}
	if n == 1 {
		return [][]byte{}
	}
	k := largestPow2Lt(n)
	if m < k {
		return append(InclusionProof(leaves[:k], m), TreeHash(leaves[k:]))
	}
	return append(InclusionProof(leaves[k:], m-k), TreeHash(leaves[:k]))
}
