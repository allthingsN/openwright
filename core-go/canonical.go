// Package openwrightcore is a Go reimplementation of the OpenWright evidence core
// (Option C in docs/OTEL_PROCESSOR_SCOPE.md): canonical JSON, RFC 6962 Merkle
// hashing, and Ed25519 checkpoint signing.
//
// It exists ONLY to enable a Python-free single-binary deployment, and it is
// gated by a shared conformance-vector suite (conformance/vectors.json,
// reproduced byte-identically by conformance_test.go). A single byte of
// divergence from the Python core breaks cross-language verification, so the
// canonical encoder below mirrors Python's json.dumps(sort_keys=True,
// separators=(",",":"), ensure_ascii=False) exactly — including the \b and \f
// short escapes and the absence of HTML escaping.
package openwrightcore

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CanonicalBytes returns the canonical UTF-8 encoding of v, byte-identical to
// the Python core's canonical_bytes. Maps drop nil values and sort keys by code
// point; floats are rejected (carry decimals as strings).
func CanonicalBytes(v interface{}) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encode(b *strings.Builder, v interface{}) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		encodeString(b, x)
	case json.Number:
		s := x.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("floats are not allowed in canonical evidence: %s", s)
		}
		b.WriteString(s)
	case float64:
		return fmt.Errorf("floats are not allowed in canonical evidence: %v", x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case []interface{}:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k, val := range x {
			if val == nil { // null values are dropped, matching the Python core
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys) // UTF-8 byte order == Unicode code-point order
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, k)
			b.WriteByte(':')
			if err := encode(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T in canonical encoding", v)
	}
	return nil
}

// encodeString mirrors Python's py_encode_basestring (ensure_ascii=False):
// escape " and \; use the short forms \b \f \n \r \t; emit other control
// characters (<0x20) as \u00xx (lowercase); pass everything else through as
// UTF-8 (no HTML escaping of <, >, &, /).
func encodeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
