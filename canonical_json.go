package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// canonicalJSON emits an RFC-8785-style canonical JSON representation
// of v. Used by the envelope sealer to produce the exact bytes the
// creator signs over — must match the NpvTunnel client's canonical JSON
// emitter byte-for-byte, since cross-language verification depends on the
// receiver re-computing the same hash input.
//
// Rules implemented (matching the client side):
//   - Object keys sorted lexicographically (UTF-16 / byte order — equivalent
//     for ASCII keys, which is all we use in the header schema).
//   - No whitespace.
//   - String escapes per RFC 8259: `"`, `\`, `\b`, `\f`, `\n`, `\r`,
//     `\t`, plus any control char < 0x20 as `\uXXXX`.
//   - Booleans render as `true` / `false`.
//   - Numbers are emitted as their decoded text form (no floats are
//     used in our schema; integer field reuse the JSON number text
//     `encoding/json` produces).
//   - `null` for nil.
//
// Caller passes a Go value that's already a generic JSON shape
// (map[string]any, []any, string, bool, json.Number, nil). The
// envelope sealer marshals its typed struct with encoding/json then
// re-decodes with json.Number to preserve integer-ness, then passes
// the result here.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// canonicalJSONOfStruct is the typed-struct convenience: marshal v
// via encoding/json, re-decode with UseNumber, canonicalize. This is
// the entry point the sealer uses on its EnvelopeHeader struct.
func canonicalJSONOfStruct(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal struct: %w", err)
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("re-decode for canonicalization: %w", err)
	}
	return canonicalJSON(generic)
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, x)
	case json.Number:
		// json.Number is a string holding the original JSON number
		// text — for our schema this is always integer text, which
		// is already canonical (no leading zeros, no trailing
		// fractional part for the integer fields we use).
		buf.WriteString(string(x))
	case int:
		fmt.Fprintf(buf, "%d", x)
	case int64:
		fmt.Fprintf(buf, "%d", x)
	case float64:
		// Our schema doesn't use floats. If one shows up it's a bug
		// the operator wants to know about loudly.
		return fmt.Errorf("canonical JSON: float64 not supported (value %v)", x)
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		buf.WriteByte('{')
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON: unsupported type %T", v)
	}
	return nil
}

func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	var esc strings.Builder
	_ = esc
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				// Pass non-control codepoints through as their UTF-8
				// encoding. Matches the client emitter, which writes
				// the source char directly into the StringBuilder.
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
