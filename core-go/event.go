package openwrightcore

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Event is the Go mirror of the Python ComplianceEvent (src/openwright/events.py).
// Its CanonicalBytes() reproduces, byte-for-byte, the Python leaf_content() ->
// canonical_bytes pipeline: model_dump(mode="json", exclude_none=True) with the
// "ledger" key removed.
//
// Faithfulness rules mirrored here:
//   - exclude_none: absent optional scalars/objects are dropped entirely.
//   - provenance, attributes, labels default to EMPTY dicts that are KEPT in the
//     leaf (they serialize as {} even when empty), because pydantic gives them a
//     default_factory rather than None.
//   - enums (kind, oversight.status) carry their string value.
//   - attributes is arbitrary nested JSON; ints stay ints (json.Number, never
//     float64) and unicode is preserved.
//   - extra="allow": unknown top-level keys are preserved (DR-04).
//
// A missing struct field would silently drop that key and make the conformance
// test fail (the re-serialized canonical would not match the committed vector),
// which is the intended guard.

type IdentityClaim struct {
	ClaimType     *string `json:"claim_type,omitempty"`
	PublicKeyID   *string `json:"public_key_id,omitempty"`
	AgentCardHash *string `json:"agent_card_hash,omitempty"`
	SignatureB64  *string `json:"signature_b64,omitempty"`
}

type Actor struct {
	AgentID       string         `json:"agent_id"`
	AgentCardRef  *string        `json:"agent_card_ref,omitempty"`
	IdentityClaim *IdentityClaim `json:"identity_claim,omitempty"`
}

type Provenance struct {
	TaskID       *string `json:"task_id,omitempty"`
	ContextID    *string `json:"context_id,omitempty"`
	ParentTaskID *string `json:"parent_task_id,omitempty"`
	RootTaskID   *string `json:"root_task_id,omitempty"`
}

type IORef struct {
	InputRef     *string `json:"input_ref,omitempty"`
	OutputRef    *string `json:"output_ref,omitempty"`
	ArgumentsRef *string `json:"arguments_ref,omitempty"`
	InputTokens  *int64  `json:"input_tokens,omitempty"`
	OutputTokens *int64  `json:"output_tokens,omitempty"`
	TotalTokens  *int64  `json:"total_tokens,omitempty"`
	Cost         *string `json:"cost,omitempty"`
	CostCurrency *string `json:"cost_currency,omitempty"`
}

type ModelInfo struct {
	Provider      *string `json:"provider,omitempty"`
	RequestModel  *string `json:"request_model,omitempty"`
	ResponseModel *string `json:"response_model,omitempty"`
}

type ToolInfo struct {
	Name   *string `json:"name,omitempty"`
	CallID *string `json:"call_id,omitempty"`
}

type Oversight struct {
	Status      *string `json:"status,omitempty"`
	ApprovalRef *string `json:"approval_ref,omitempty"`
	Reviewer    *string `json:"reviewer,omitempty"`
}

type Risk struct {
	Classification *string `json:"classification,omitempty"`
	RationaleRef   *string `json:"rationale_ref,omitempty"`
	Framework      *string `json:"framework,omitempty"`
}

type SourceMeta struct {
	Format           string  `json:"format"`
	SpanID           *string `json:"span_id,omitempty"`
	TraceID          *string `json:"trace_id,omitempty"`
	CollectorVersion *string `json:"collector_version,omitempty"`
	IngestedAt       *string `json:"ingested_at,omitempty"`
}

// Event mirrors ComplianceEvent. The three always-kept dicts (provenance,
// attributes, labels) are pointers so we can tell "absent in input" (still
// emitted as {} by pydantic's default_factory) from a populated value; absent
// becomes an empty map at serialization time.
type Event struct {
	SchemaVersion string `json:"schema_version"`
	EventID       string `json:"event_id"`
	Timestamp     string `json:"timestamp"`
	Kind          string `json:"kind"`
	Actor         Actor  `json:"actor"`

	Provenance *Provenance            `json:"provenance,omitempty"`
	IO         *IORef                 `json:"io,omitempty"`
	Model      *ModelInfo             `json:"model,omitempty"`
	Tool       *ToolInfo              `json:"tool,omitempty"`
	Oversight  *Oversight             `json:"oversight,omitempty"`
	Risk       *Risk                  `json:"risk,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Labels     map[string]string      `json:"labels,omitempty"`
	Source     SourceMeta             `json:"source"`

	// extra="allow": any top-level key not modeled above is round-tripped.
	Extra map[string]json.RawMessage `json:"-"`

	// ledger is parsed but never serialized into the leaf (excluded).
	Ledger json.RawMessage `json:"ledger,omitempty"`
}

// known top-level keys that are handled by typed fields; everything else lands
// in Extra during UnmarshalJSON.
var eventKnownKeys = map[string]bool{
	"schema_version": true, "event_id": true, "timestamp": true, "kind": true,
	"actor": true, "provenance": true, "io": true, "model": true, "tool": true,
	"oversight": true, "risk": true, "attributes": true, "labels": true,
	"source": true, "ledger": true,
}

func (e *Event) UnmarshalJSON(data []byte) error {
	type alias Event // avoid recursion
	var a alias
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep ints as ints inside attributes
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*e = Event(a)

	// Capture any extra (DR-04) top-level keys.
	var raw map[string]json.RawMessage
	dec2 := json.NewDecoder(bytes.NewReader(data))
	dec2.UseNumber()
	if err := dec2.Decode(&raw); err != nil {
		return err
	}
	for k, v := range raw {
		if !eventKnownKeys[k] {
			if e.Extra == nil {
				e.Extra = map[string]json.RawMessage{}
			}
			e.Extra[k] = v
		}
	}
	return nil
}

// leafContent builds the map that Python's leaf_content() produces:
// model_dump(mode="json", exclude_none=True) minus "ledger". Returns an error if
// attributes carry a float (matching the canonical encoder's refusal).
func (e *Event) leafContent() (map[string]interface{}, error) {
	out := map[string]interface{}{
		"schema_version": e.SchemaVersion,
		"event_id":       e.EventID,
		"timestamp":      e.Timestamp,
		"kind":           e.Kind,
		"actor":          actorMap(e.Actor),
		"source":         sourceMap(e.Source),
	}

	// Always-kept dicts (default_factory in pydantic): emitted even when empty.
	out["provenance"] = provenanceMap(e.Provenance)
	out["attributes"] = attributesValue(e.Attributes)
	out["labels"] = labelsValue(e.Labels)

	// exclude_none optional sub-objects: present only when supplied.
	if e.IO != nil {
		out["io"] = ioMap(e.IO)
	}
	if e.Model != nil {
		out["model"] = modelMap(e.Model)
	}
	if e.Tool != nil {
		out["tool"] = toolMap(e.Tool)
	}
	if e.Oversight != nil {
		out["oversight"] = oversightMap(e.Oversight)
	}
	if e.Risk != nil {
		out["risk"] = riskMap(e.Risk)
	}

	// Preserve extra top-level keys (DR-04). exclude_none drops nulls in the
	// canonical encoder already, so we just decode them as generic values.
	for k, v := range e.Extra {
		val, err := decodeRawNumber(v)
		if err != nil {
			return nil, fmt.Errorf("extra field %q: %w", k, err)
		}
		out[k] = val
	}
	return out, nil
}

// CanonicalBytes returns the canonical UTF-8 bytes of the event leaf content,
// byte-identical to Python's ComplianceEvent.leaf_content_bytes().
func (e *Event) CanonicalBytes() ([]byte, error) {
	content, err := e.leafContent()
	if err != nil {
		return nil, err
	}
	return CanonicalBytes(content)
}

// LeafHash returns the RFC 6962 leaf hash over the event's canonical bytes.
func (e *Event) LeafHash() ([]byte, error) {
	cb, err := e.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	return LeafHash(cb), nil
}

// -- helpers: build maps that drop nil fields (exclude_none) ------------------

func putStr(m map[string]interface{}, k string, v *string) {
	if v != nil {
		m[k] = *v
	}
}
func putInt(m map[string]interface{}, k string, v *int64) {
	if v != nil {
		m[k] = *v
	}
}

func actorMap(a Actor) map[string]interface{} {
	m := map[string]interface{}{"agent_id": a.AgentID}
	putStr(m, "agent_card_ref", a.AgentCardRef)
	if a.IdentityClaim != nil {
		ic := a.IdentityClaim
		cm := map[string]interface{}{}
		putStr(cm, "claim_type", ic.ClaimType)
		putStr(cm, "public_key_id", ic.PublicKeyID)
		putStr(cm, "agent_card_hash", ic.AgentCardHash)
		putStr(cm, "signature_b64", ic.SignatureB64)
		m["identity_claim"] = cm
	}
	return m
}

func provenanceMap(p *Provenance) map[string]interface{} {
	m := map[string]interface{}{}
	if p != nil {
		putStr(m, "task_id", p.TaskID)
		putStr(m, "context_id", p.ContextID)
		putStr(m, "parent_task_id", p.ParentTaskID)
		putStr(m, "root_task_id", p.RootTaskID)
	}
	return m
}

func ioMap(io *IORef) map[string]interface{} {
	m := map[string]interface{}{}
	putStr(m, "input_ref", io.InputRef)
	putStr(m, "output_ref", io.OutputRef)
	putStr(m, "arguments_ref", io.ArgumentsRef)
	putInt(m, "input_tokens", io.InputTokens)
	putInt(m, "output_tokens", io.OutputTokens)
	putInt(m, "total_tokens", io.TotalTokens)
	putStr(m, "cost", io.Cost)
	putStr(m, "cost_currency", io.CostCurrency)
	return m
}

func modelMap(mi *ModelInfo) map[string]interface{} {
	m := map[string]interface{}{}
	putStr(m, "provider", mi.Provider)
	putStr(m, "request_model", mi.RequestModel)
	putStr(m, "response_model", mi.ResponseModel)
	return m
}

func toolMap(t *ToolInfo) map[string]interface{} {
	m := map[string]interface{}{}
	putStr(m, "name", t.Name)
	putStr(m, "call_id", t.CallID)
	return m
}

func oversightMap(o *Oversight) map[string]interface{} {
	m := map[string]interface{}{}
	putStr(m, "status", o.Status)
	putStr(m, "approval_ref", o.ApprovalRef)
	putStr(m, "reviewer", o.Reviewer)
	return m
}

func riskMap(r *Risk) map[string]interface{} {
	m := map[string]interface{}{}
	putStr(m, "classification", r.Classification)
	putStr(m, "rationale_ref", r.RationaleRef)
	putStr(m, "framework", r.Framework)
	return m
}

func sourceMap(s SourceMeta) map[string]interface{} {
	m := map[string]interface{}{"format": s.Format}
	putStr(m, "span_id", s.SpanID)
	putStr(m, "trace_id", s.TraceID)
	putStr(m, "collector_version", s.CollectorVersion)
	putStr(m, "ingested_at", s.IngestedAt)
	return m
}

// attributesValue returns an empty map when absent (kept as {}); otherwise the
// parsed value with ints preserved (json.Number).
func attributesValue(a map[string]interface{}) interface{} {
	if a == nil {
		return map[string]interface{}{}
	}
	return a
}

func labelsValue(l map[string]string) interface{} {
	if l == nil {
		return map[string]interface{}{}
	}
	m := make(map[string]interface{}, len(l))
	for k, v := range l {
		m[k] = v
	}
	return m
}

// decodeRawNumber decodes a raw JSON value keeping integers as json.Number.
func decodeRawNumber(raw json.RawMessage) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
