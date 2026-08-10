package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Canonical JSON: a single, byte-exact serialization of a value so that
// independent implementations produce identical bytes. The envelope header is
// canonicalized this way before it is signed and used as AEAD associated data,
// so the rules here (sorted object keys, fixed string escaping, integers only)
// are part of the wire contract and are guarded by a cross-language fixture
// test.

// canonicalJSON serializes an already-generic value (the types produced by
// decoding into any) to canonical bytes.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// canonicalJSONOfStruct canonicalizes a Go struct by marshaling it, then
// re-decoding into generic values (with UseNumber so integers stay exact)
// before serializing. This routes struct output through the same key-sorting
// and escaping rules as any other value.
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

// writeCanonical emits the canonical form of v. Object keys are sorted; numbers
// must be integers (json.Number or Go ints) — floats are rejected so no
// implementation-specific float formatting can leak into signed bytes.
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

		buf.WriteString(string(x))
	case int:
		fmt.Fprintf(buf, "%d", x)
	case int64:
		fmt.Fprintf(buf, "%d", x)
	case float64:

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

// writeCanonicalString writes a JSON string with a fixed escaping table: the
// seven short escapes, \u00xx for the remaining control characters, and raw
// UTF-8 for everything else (no \uXXXX escaping of non-ASCII).
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

				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
