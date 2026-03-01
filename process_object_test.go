package sdjwt

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestProcessObject(t *testing.T) {
	// Helper: build a discMap with a single object disclosure keyed by its sha-256 digest.
	makeObjDisc := func(salt, name string, value any) (map[string]*disclosure, string) {
		raw := encodeDisclosure(`["` + salt + `", "` + name + `", "` + value.(string) + `"]`)
		discMap, err := indexDisclosures([]string{raw}, "sha-256")
		if err != nil {
			t.Fatalf("indexDisclosures: %v", err)
		}
		digests := slices.Collect(maps.Keys(discMap))
		return discMap, digests[0]
	}

	// Helper: build a discMap with a single array disclosure.
	makeArrDisc := func(salt, value string) (map[string]*disclosure, string) {
		raw := encodeDisclosure(`["` + salt + `", "` + value + `"]`)
		discMap, err := indexDisclosures([]string{raw}, "sha-256")
		if err != nil {
			t.Fatalf("indexDisclosures: %v", err)
		}
		digests := slices.Collect(maps.Keys(discMap))
		return discMap, digests[0]
	}

	t.Run("no _sd key is a no-op", func(t *testing.T) {
		obj := map[string]any{"name": "Alice"}
		used := map[string]bool{}

		if err := processObject(obj, nil, used); err != nil {
			t.Fatalf("processObject() error: %v", err)
		}
		if obj["name"] != "Alice" {
			t.Errorf("name = %v, want Alice", obj["name"])
		}
	})

	t.Run("disclose object property via _sd", func(t *testing.T) {
		discMap, digest := makeObjDisc("s1", "given_name", "John")
		obj := map[string]any{
			"_sd": []any{digest},
			"iss": "https://example.com",
		}
		used := map[string]bool{}

		if err := processObject(obj, discMap, used); err != nil {
			t.Fatalf("processObject() error: %v", err)
		}
		if obj["given_name"] != "John" {
			t.Errorf("given_name = %v, want John", obj["given_name"])
		}
		if _, ok := obj["_sd"]; ok {
			t.Error("_sd key should be removed after processing")
		}
		if !used[digest] {
			t.Error("digest should be marked as used")
		}
	})

	t.Run("unmatched digest in _sd is ignored", func(t *testing.T) {
		obj := map[string]any{
			"_sd": []any{"no-such-digest"},
		}
		used := map[string]bool{}

		if err := processObject(obj, map[string]*disclosure{}, used); err != nil {
			t.Fatalf("processObject() error: %v", err)
		}
		if _, ok := obj["_sd"]; ok {
			t.Error("_sd key should be removed even with unmatched digests")
		}
	})

	t.Run("_sd is not an array", func(t *testing.T) {
		obj := map[string]any{"_sd": "not-an-array"}
		used := map[string]bool{}

		err := processObject(obj, nil, used)
		if err == nil || !strings.Contains(err.Error(), "_sd is not an array") {
			t.Fatalf("expected '_sd is not an array' error, got: %v", err)
		}
	})

	t.Run("_sd element is not a string", func(t *testing.T) {
		obj := map[string]any{"_sd": []any{42}}
		used := map[string]bool{}

		err := processObject(obj, map[string]*disclosure{}, used)
		if err == nil || !strings.Contains(err.Error(), "_sd element is not a string") {
			t.Fatalf("expected '_sd element is not a string' error, got: %v", err)
		}
	})

	t.Run("array disclosure referenced in _sd", func(t *testing.T) {
		discMap, digest := makeArrDisc("s1", "US")
		obj := map[string]any{"_sd": []any{digest}}
		used := map[string]bool{}

		err := processObject(obj, discMap, used)
		if err == nil || !strings.Contains(err.Error(), "array disclosure referenced in _sd") {
			t.Fatalf("expected 'array disclosure referenced in _sd' error, got: %v", err)
		}
	})

	t.Run("recursive processing of nested object", func(t *testing.T) {
		discMap, digest := makeObjDisc("s1", "street", "123 Main St")
		obj := map[string]any{
			"address": map[string]any{
				"_sd": []any{digest},
			},
		}
		used := map[string]bool{}

		if err := processObject(obj, discMap, used); err != nil {
			t.Fatalf("processObject() error: %v", err)
		}
		addr, ok := obj["address"].(map[string]any)
		if !ok {
			t.Fatal("address should be a map")
		}
		if addr["street"] != "123 Main St" {
			t.Errorf("address.street = %v, want 123 Main St", addr["street"])
		}
	})

	t.Run("error propagated from nested object", func(t *testing.T) {
		obj := map[string]any{
			"nested": map[string]any{
				"_sd": "not-an-array",
			},
		}
		used := map[string]bool{}

		err := processObject(obj, nil, used)
		if err == nil || !strings.Contains(err.Error(), "_sd is not an array") {
			t.Fatalf("expected error from nested object, got: %v", err)
		}
	})

	t.Run("error propagated from nested array", func(t *testing.T) {
		// Create an array element with an invalid "..." value (not a string)
		obj := map[string]any{
			"items": []any{
				map[string]any{"...": 42},
			},
		}
		used := map[string]bool{}

		err := processObject(obj, map[string]*disclosure{}, used)
		if err == nil || !strings.Contains(err.Error(), "not a string") {
			t.Fatalf("expected error from nested array, got: %v", err)
		}
	})

	t.Run("disclosed claim name already exists as plaintext", func(t *testing.T) {
		// RFC 9901 §7.1 step 3c(ii)(3): "If the claim name already exists at
		// the level of the _sd key, the SD-JWT MUST be rejected."
		discMap, digest := makeObjDisc("s1", "given_name", "John")
		obj := map[string]any{
			"_sd":        []any{digest},
			"given_name": "Eve", // plaintext claim with same name
		}
		used := map[string]bool{}

		err := processObject(obj, discMap, used)
		if err == nil {
			t.Fatal("processObject() should reject when disclosed claim name conflicts with existing key")
		}
	})

	t.Run("two disclosures with the same claim name", func(t *testing.T) {
		// RFC 9901 §7.1 step 3c(ii)(3): the second disclosure's claim name
		// "already exists" because the first was already inserted.
		discMap1, digest1 := makeObjDisc("s1", "given_name", "John")
		discMap2, digest2 := makeObjDisc("s2", "given_name", "Jane")
		// Merge into one discMap
		for k, v := range discMap2 {
			discMap1[k] = v
		}
		obj := map[string]any{
			"_sd": []any{digest1, digest2},
		}
		used := map[string]bool{}

		err := processObject(obj, discMap1, used)
		if err == nil {
			t.Fatal("processObject() should reject when two disclosures use the same claim name")
		}
	})
}
