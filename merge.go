package main

import (
	"encoding/json"
	"fmt"
)

// deepMergeConfigBody produces the per-recipient ConfigBody JSON by deep-
// merging variant over base. Either or both may be nil/empty.
//
//   - base or variant nil/empty: returns whichever side has content,
//     or nil if both are empty.
//   - both present: recursively merges. Object-valued fields recurse;
//     scalar/array/null values in variant replace the corresponding
//     base value wholesale.
//
// Why deep merge: ConfigBody nests V2rayProfile / SshConfig sub-objects,
// and per-recipient watermarking targets specific leaves inside those
// sub-objects (e.g. v2rayProfile.shortId). A shallow merge would force
// each variant to re-state the entire v2rayProfile to override one leaf
// — bad ergonomics for the typical watermarking case.
//
// Why arrays replace (no concatenation): JSON arrays in a config tend
// to be ordered settings lists (alpn, etc.); element-by-element merge
// would be ambiguous and almost never what the operator wants.
//
// Inputs are validated at configs.json load time to be JSON objects.
// The "not a JSON object" branches here are defense in depth against
// concurrent edits or future code paths that don't go through
// loadConfigsFile.
func deepMergeConfigBody(base, variant json.RawMessage) (json.RawMessage, error) {
	if len(variant) == 0 {
		return base, nil
	}
	if len(base) == 0 {
		return variant, nil
	}

	var baseTree, variantTree any
	if err := json.Unmarshal(base, &baseTree); err != nil {
		return nil, fmt.Errorf("base config: %w", err)
	}
	if err := json.Unmarshal(variant, &variantTree); err != nil {
		return nil, fmt.Errorf("variant: %w", err)
	}

	merged := deepMerge(baseTree, variantTree)
	out, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshal merged config: %w", err)
	}
	return out, nil
}

// deepMerge recursively merges override into base. When both sides at a
// given path are objects, fields recurse; otherwise the override side
// replaces. Mutates baseObj in place but the returned value is what
// callers should use (handles the non-object root case).
func deepMerge(base, override any) any {
	baseObj, baseIsObj := base.(map[string]any)
	overObj, overIsObj := override.(map[string]any)
	if !baseIsObj || !overIsObj {
		return override
	}
	for k, v := range overObj {
		if existing, ok := baseObj[k]; ok {
			baseObj[k] = deepMerge(existing, v)
		} else {
			baseObj[k] = v
		}
	}
	return baseObj
}
