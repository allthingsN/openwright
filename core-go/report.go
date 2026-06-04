package openwrightcore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// Report assembly + signing, mirroring src/openwright/report.py:build_report and
// src/openwright/signing.py so a Go-produced report verifies under the Python
// verifier (openwright.verify.verify_report) byte-for-byte.

const reportVersion = "1.0.0"

// BoundaryStatement is copied verbatim from src/openwright/report.py — it is part
// of the signed payload, so a single character drift breaks the signature.
const BoundaryStatement = "This report constitutes EVIDENCE that the listed controls were exercised at " +
	"runtime, attested with a tamper-evident Merkle log and an Ed25519 signature. " +
	"It DOES NOT constitute legal compliance, certification, conformity assessment, " +
	"or an audit opinion. Determinations of compliance are reserved for qualified " +
	"auditors, notified bodies, and counsel. Crosswalks are maintainer-authored, " +
	"rigorously cited, and pending qualified legal/standards review."

// KeyID mirrors signing.py:key_id_for — "ed25519:" + first 32 hex of sha256(rawpub).
func KeyID(publicKeyRaw []byte) string {
	sum := sha256.Sum256(publicKeyRaw)
	return "ed25519:" + hex.EncodeToString(sum[:])[:32]
}

// PublicKeyPEM returns the SubjectPublicKeyInfo PEM for a raw Ed25519 public key,
// matching signing.py:public_key_pem (which Python's verifier parses back).
func PublicKeyPEM(publicKeyRaw []byte) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(publicKeyRaw))
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// PublicKeyRawFromPEM extracts the raw 32-byte Ed25519 key from a
// SubjectPublicKeyInfo PEM, mirroring signing.py:public_key_raw_from_pem.
func PublicKeyRawFromPEM(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edpub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 public key")
	}
	return []byte(edpub), nil
}

// ReportEventInput is one event to place in the report, alongside its committed
// leaf hash (as stored by the ledger; "sha256:" prefix optional — Python stores
// hex without a prefix in the vectors but the verifier strips a prefix anyway).
type ReportEventInput struct {
	Event    *Event
	LeafHash string // hex (no prefix), as the ledger stores it
}

// ReportInputs are the values build_report needs that are not derivable here.
type ReportInputs struct {
	Origin      string
	Timestamp   string // checkpoint + report timestamp (RFC 3339)
	ReportID    string
	GeneratedAt string
	ScopeDesc   string
	ToolVersion string
	CrosswalkID string
	Events      []ReportEventInput
}

// BuildReport assembles and signs a full report dict, byte-compatible with the
// Python verifier. controls/evidence_gaps are empty (a Go producer emits raw
// evidence; crosswalk evaluation stays in Python). It returns the report as an
// ordered-insensitive map (canonicalization sorts keys).
func BuildReport(priv ed25519.PrivateKey, in ReportInputs) (map[string]interface{}, error) {
	pub := priv.Public().(ed25519.PublicKey)
	pubRaw := []byte(pub)
	keyID := KeyID(pubRaw)

	// Leaves + checkpoint root over the committed leaf hashes.
	leaves := make([][]byte, len(in.Events))
	for i, e := range in.Events {
		lh, err := e.Event.LeafHash()
		if err != nil {
			return nil, fmt.Errorf("event %d leaf hash: %w", i, err)
		}
		// Sanity: the committed leaf hash (if provided) must match recomputation.
		if e.LeafHash != "" {
			want := stripSha256Prefix(e.LeafHash)
			if hex.EncodeToString(lh) != want {
				return nil, fmt.Errorf("event %d committed leaf_hash mismatch", i)
			}
		}
		leaves[i] = lh
	}
	treeSize := len(leaves)
	root := TreeHash(leaves)
	rootHex := hex.EncodeToString(root)

	// Sign the checkpoint.
	cpSig, err := SignCheckpoint(priv, in.Origin, treeSize, rootHex, in.Timestamp)
	if err != nil {
		return nil, err
	}
	checkpoint := map[string]interface{}{
		"origin":        in.Origin,
		"tree_size":     treeSize,
		"root_hash":     rootHex,
		"timestamp":     in.Timestamp,
		"public_key_id": keyID,
		"signature":     base64.StdEncoding.EncodeToString(cpSig),
	}

	// Per-event entries with inclusion proofs pinned to the checkpoint tree_size.
	events := make([]interface{}, 0, len(in.Events))
	var timestamps []string
	seenAgents := map[string]bool{}
	for i, e := range in.Events {
		content, err := e.Event.leafContent()
		if err != nil {
			return nil, err
		}
		proof := InclusionProof(leaves, i)
		entry := map[string]interface{}{
			"event":           content,
			"leaf_index":      i,
			"leaf_hash":       e.LeafHash,
			"inclusion_proof": hexProofList(proof),
		}
		events = append(events, entry)
		timestamps = append(timestamps, e.Event.Timestamp)
		seenAgents[e.Event.Actor.AgentID] = true
	}

	period := map[string]interface{}{}
	if len(timestamps) > 0 {
		min, max := timestamps[0], timestamps[0]
		for _, t := range timestamps[1:] {
			if t < min {
				min = t
			}
			if t > max {
				max = t
			}
		}
		period = map[string]interface{}{"start": min, "end": max}
	}

	agentIDs := make([]interface{}, 0, len(seenAgents))
	for a := range seenAgents {
		agentIDs = append(agentIDs, a)
	}
	// build_report uses sorted(agent_ids or seen_agents); canonical encoding does
	// not sort list elements, so sort here to match Python.
	sortStrings(agentIDs)

	pemStr, err := PublicKeyPEM(pubRaw)
	if err != nil {
		return nil, err
	}

	report := map[string]interface{}{
		"report_version":     reportVersion,
		"report_id":          in.ReportID,
		"generated_at":       in.GeneratedAt,
		"tool":               map[string]interface{}{"name": "openwright", "version": in.ToolVersion},
		"boundary_statement": BoundaryStatement,
		"scope": map[string]interface{}{
			"description": in.ScopeDesc,
			"agent_ids":   agentIDs,
		},
		"period": period,
		"crosswalk": map[string]interface{}{
			"id": in.CrosswalkID,
		},
		"summary": map[string]interface{}{
			"total":                 0,
			"satisfied":             0,
			"not_satisfied":         0,
			"insufficient_evidence": 0,
		},
		"controls":       []interface{}{},
		"evidence_gaps":  []interface{}{},
		"checkpoint":     checkpoint,
		"events":         events,
		"public_key_pem": pemStr,
	}

	// Sign the report over canonical(report without "signature").
	payload, err := CanonicalBytes(report)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, payload)
	report["signature"] = map[string]interface{}{
		"algorithm":     "ed25519",
		"public_key_id": keyID,
		"signature":     base64.StdEncoding.EncodeToString(sig),
	}
	return report, nil
}

// VerifyReportRoot recomputes the Merkle root from a report's events (via the
// event-model serializer) and checks it matches the checkpoint, then verifies
// the checkpoint Ed25519 signature with the report's embedded public key. This
// is the Go side of the bidirectional interop: Go verifying Python evidence.
func VerifyReportRoot(report map[string]interface{}) (bool, string) {
	cp, ok := report["checkpoint"].(map[string]interface{})
	if !ok {
		return false, "no checkpoint"
	}
	rootHex, _ := cp["root_hash"].(string)
	origin, _ := cp["origin"].(string)
	timestamp, _ := cp["timestamp"].(string)
	treeSize := toInt(cp["tree_size"])
	cpSigB64, _ := cp["signature"].(string)

	pemStr, _ := report["public_key_pem"].(string)
	pubRaw, err := PublicKeyRawFromPEM(pemStr)
	if err != nil {
		return false, "bad public_key_pem: " + err.Error()
	}

	// Recompute the root from the events using the event-model serializer.
	rawEvents, ok := report["events"].([]interface{})
	if !ok {
		return false, "no events"
	}
	leavesByIndex := map[int][]byte{}
	for _, re := range rawEvents {
		item, ok := re.(map[string]interface{})
		if !ok {
			return false, "bad event entry"
		}
		idx := toInt(item["leaf_index"])
		evMap, _ := item["event"].(map[string]interface{})
		ev, err := eventFromMap(evMap)
		if err != nil {
			return false, "event decode: " + err.Error()
		}
		lh, err := ev.LeafHash()
		if err != nil {
			return false, "leaf hash: " + err.Error()
		}
		leavesByIndex[idx] = lh
	}
	leaves := make([][]byte, treeSize)
	for i := 0; i < treeSize; i++ {
		lh, ok := leavesByIndex[i]
		if !ok {
			return false, fmt.Sprintf("missing leaf at index %d", i)
		}
		leaves[i] = lh
	}
	recomputed := hex.EncodeToString(TreeHash(leaves))
	if recomputed != rootHex {
		return false, fmt.Sprintf("root mismatch: recomputed=%s checkpoint=%s", recomputed, rootHex)
	}

	// Verify the checkpoint signature.
	cpSig, err := base64.StdEncoding.DecodeString(cpSigB64)
	if err != nil {
		return false, "bad checkpoint signature b64"
	}
	if !VerifyCheckpoint(ed25519.PublicKey(pubRaw), origin, treeSize, rootHex, timestamp, cpSig) {
		return false, "checkpoint signature failed"
	}
	return true, "root recomputed and checkpoint signature verified"
}

// -- small helpers ------------------------------------------------------------

func stripSha256Prefix(s string) string {
	const p = "sha256:"
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

func hexProofList(p [][]byte) []interface{} {
	out := make([]interface{}, len(p))
	for i, h := range p {
		out[i] = hex.EncodeToString(h)
	}
	return out
}

func toInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	}
	return 0
}

func sortStrings(s []interface{}) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0; j-- {
			a, _ := s[j-1].(string)
			b, _ := s[j].(string)
			if a <= b {
				break
			}
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// eventFromMap re-encodes a generic map into JSON and decodes it through the
// typed Event unmarshaler, so it benefits from the same exclude_none / extra
// handling used during conformance. The map values may carry json.Number from a
// UseNumber-decoded report; json.Marshal emits those as raw numbers.
func eventFromMap(m map[string]interface{}) (*Event, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var e Event
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
