// Command openwright-core is a small CLI exercising the Go evidence core for
// cross-language interop with the Python verifier (Option C). It signs and
// verifies checkpoints AND emits/verifies full signed reports, all with bytes
// byte-identical to the Python core's, proving the two implementations
// interoperate end to end.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	core "github.com/allthingsN/openwright/core-go"
)

type checkpoint struct {
	Origin       string   `json:"origin"`
	TreeSize     int      `json:"tree_size"`
	RootHash     string   `json:"root_hash"`
	Timestamp    string   `json:"timestamp"`
	SignatureB64 string   `json:"signature_b64"`
	PublicKeyB64 string   `json:"public_key_b64"`
	Leaves       []string `json:"leaves"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: openwright-core emit|verify|emit-report|verify-report")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "emit":
		emit()
	case "verify":
		verify()
	case "emit-report":
		emitReport()
	case "verify-report":
		verifyReport()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}

func emit() {
	leavesData := []string{"leaf-0", "leaf-1", "leaf-2", "leaf-3", "leaf-4"}
	origin := "openwright-go-interop"
	timestamp := "2026-05-31T00:00:00.000000000Z"

	leaves := make([][]byte, len(leavesData))
	for i, d := range leavesData {
		leaves[i] = core.LeafHash([]byte(d))
	}
	rootHex := hex.EncodeToString(core.TreeHash(leaves))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sig, err := core.SignCheckpoint(priv, origin, len(leaves), rootHex, timestamp)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(checkpoint{
		Origin:       origin,
		TreeSize:     len(leaves),
		RootHash:     rootHex,
		Timestamp:    timestamp,
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
		Leaves:       leavesData,
	})
}

func verify() {
	var cp checkpoint
	if err := json.NewDecoder(os.Stdin).Decode(&cp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pub, err := base64.StdEncoding.DecodeString(cp.PublicKeyB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sig, err := base64.StdEncoding.DecodeString(cp.SignatureB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if core.VerifyCheckpoint(ed25519.PublicKey(pub), cp.Origin, cp.TreeSize, cp.RootHash, cp.Timestamp, sig) {
		fmt.Println("VALID")
		os.Exit(0)
	}
	fmt.Println("INVALID")
	os.Exit(1)
}

// emitReport produces a full signed report (events + signed checkpoint +
// per-event leaf_hash + inclusion proofs + report signature + embedded public
// key PEM) in the shape src/openwright/report.py:build_report produces, so the
// Python verifier validates it end to end.
func emitReport() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = pub
	timestamp := "2026-05-31T00:00:00.000000000Z"

	// Three sample events covering scalar, rich, and unicode shapes.
	events := []core.ReportEventInput{
		{Event: newEvent("evt_go_0", "a1", "generic", "sdk", nil)},
		{Event: newEvent("evt_go_1", "loan-agent", "llm_call", "otel-genai", map[string]interface{}{
			"operation": "chat",
			"nested":    map[string]interface{}{"k": 1, "z": []interface{}{2, 3}},
		})},
		{Event: newEvent("evt_go_2", "café-agent ☕", "agent_decision", "sdk", map[string]interface{}{
			"emoji": "🔐",
			"note":  "naïve\ttab and <html> & slash/",
		})},
	}
	// Fill committed leaf hashes (as the ledger would store them: "sha256:"+hex).
	for i := range events {
		lh, err := events[i].Event.LeafHash()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		events[i].LeafHash = "sha256:" + hex.EncodeToString(lh)
	}

	report, err := core.BuildReport(priv, core.ReportInputs{
		Origin:      "openwright-go-report",
		Timestamp:   timestamp,
		ReportID:    "rpt_go_interop",
		GeneratedAt: timestamp,
		ScopeDesc:   "Go evidence core interop report",
		ToolVersion: "0.5.1",
		CrosswalkID: "eu-ai-act",
		Events:      events,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// verifyReport reads a report (Python- or Go-produced) on stdin, recomputes the
// Merkle root from its events, and verifies the checkpoint signature with the
// embedded public key. Prints VALID/INVALID and exits accordingly.
func verifyReport() {
	dec := json.NewDecoder(os.Stdin)
	dec.UseNumber()
	var report map[string]interface{}
	if err := dec.Decode(&report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ok, detail := core.VerifyReportRoot(report)
	if ok {
		fmt.Println("VALID:", detail)
		os.Exit(0)
	}
	fmt.Println("INVALID:", detail)
	os.Exit(1)
}

func newEvent(id, agentID, kind, format string, attrs map[string]interface{}) *core.Event {
	return &core.Event{
		SchemaVersion: "1.0.0",
		EventID:       id,
		Timestamp:     "2026-05-28T00:00:00.000000000Z",
		Kind:          kind,
		Actor:         core.Actor{AgentID: agentID},
		Attributes:    attrs,
		Source:        core.SourceMeta{Format: format},
	}
}
