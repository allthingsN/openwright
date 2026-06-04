package openwrightcore

import "crypto/ed25519"

// CheckpointSigningBytes reproduces src/openwright/signing.py:checkpoint_signing_bytes
// exactly: canonical encoding of {origin, root_hash, timestamp, tree_size}
// (keys sorted). A checkpoint signed here verifies under the Python verifier and
// vice-versa.
func CheckpointSigningBytes(origin string, treeSize int, rootHex, timestamp string) ([]byte, error) {
	return CanonicalBytes(map[string]interface{}{
		"origin":    origin,
		"root_hash": rootHex,
		"timestamp": timestamp,
		"tree_size": treeSize,
	})
}

// SignCheckpoint signs the canonical checkpoint bytes with an Ed25519 key.
func SignCheckpoint(priv ed25519.PrivateKey, origin string, treeSize int, rootHex, timestamp string) ([]byte, error) {
	data, err := CheckpointSigningBytes(origin, treeSize, rootHex, timestamp)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data), nil
}

// VerifyCheckpoint verifies an Ed25519 checkpoint signature.
func VerifyCheckpoint(pub ed25519.PublicKey, origin string, treeSize int, rootHex, timestamp string, sig []byte) bool {
	data, err := CheckpointSigningBytes(origin, treeSize, rootHex, timestamp)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, data, sig)
}
