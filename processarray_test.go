package sdjwt

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestProcessArray(t *testing.T) {
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

	// Helper: build a discMap with a single object disclosure.
	makeObjDisc := func(salt, name, value string) (map[string]*disclosure, string) {
		raw := encodeDisclosure(`["` + salt + `", "` + name + `", "` + value + `"]`)
		discMap, err := indexDisclosures([]string{raw}, "sha-256")
		if err != nil {
			t.Fatalf("indexDisclosures: %v", err)
		}
		digests := slices.Collect(maps.Keys(discMap))
		return discMap, digests[0]
	}

	t.Run("empty array", func(t *testing.T) {
		result, err := processArray([]any{}, map[string]*disclosure{}, map[string]bool{})
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected empty result, got %d elements", len(result))
		}
	})

	t.Run("plain values pass through", func(t *testing.T) {
		arr := []any{"hello", 42.0, true, nil}
		result, err := processArray(arr, map[string]*disclosure{}, map[string]bool{})
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 4 {
			t.Fatalf("expected 4 elements, got %d", len(result))
		}
		if result[0] != "hello" {
			t.Errorf("result[0] = %v, want hello", result[0])
		}
	})

	t.Run("disclosed array element replaces placeholder", func(t *testing.T) {
		discMap, digest := makeArrDisc("s1", "US")
		arr := []any{map[string]any{"...": digest}}
		used := map[string]bool{}

		result, err := processArray(arr, discMap, used)
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 element, got %d", len(result))
		}
		if result[0] != "US" {
			t.Errorf("result[0] = %v, want US", result[0])
		}
		if !used[digest] {
			t.Error("digest should be marked as used")
		}
	})

	t.Run("undisclosed placeholder removed", func(t *testing.T) {
		arr := []any{map[string]any{"...": "no-such-digest"}, "keep"}
		result, err := processArray(arr, map[string]*disclosure{}, map[string]bool{})
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 element, got %d", len(result))
		}
		if result[0] != "keep" {
			t.Errorf("result[0] = %v, want keep", result[0])
		}
	})

	t.Run("digest value is not a string", func(t *testing.T) {
		arr := []any{map[string]any{"...": 42}}
		_, err := processArray(arr, map[string]*disclosure{}, map[string]bool{})
		if err == nil || !strings.Contains(err.Error(), "not a string") {
			t.Fatalf("expected 'not a string' error, got: %v", err)
		}
	})

	t.Run("object disclosure in array position", func(t *testing.T) {
		discMap, digest := makeObjDisc("s1", "name", "John")
		arr := []any{map[string]any{"...": digest}}
		used := map[string]bool{}

		_, err := processArray(arr, discMap, used)
		if err == nil || !strings.Contains(err.Error(), "object disclosure in array position") {
			t.Fatalf("expected 'object disclosure in array position' error, got: %v", err)
		}
	})

	t.Run("non-placeholder single-key object passes through", func(t *testing.T) {
		// An object with one key that isn't "..." should not be treated as a placeholder
		arr := []any{map[string]any{"name": "Alice"}}
		result, err := processArray(arr, map[string]*disclosure{}, map[string]bool{})
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 element, got %d", len(result))
		}
	})

	t.Run("multi-key object passes through without placeholder check", func(t *testing.T) {
		// An object with multiple keys including "..." should not be treated as a placeholder
		arr := []any{map[string]any{"...": "some-digest", "extra": "value"}}
		result, err := processArray(arr, map[string]*disclosure{}, map[string]bool{})
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 element, got %d", len(result))
		}
	})

	t.Run("recursive processing of disclosed object value", func(t *testing.T) {
		// Create an array disclosure whose value is a JSON object (decoded by indexDisclosures)
		// We need to construct this manually since our helper only handles string values.
		disc := &disclosure{
			salt:    "s1",
			value:   map[string]any{"city": "Berlin"},
			isArray: true,
		}
		digest := "fake-digest-obj"
		discMap := map[string]*disclosure{digest: disc}
		arr := []any{map[string]any{"...": digest}}
		used := map[string]bool{}

		result, err := processArray(arr, discMap, used)
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 element, got %d", len(result))
		}
		obj, ok := result[0].(map[string]any)
		if !ok {
			t.Fatalf("result[0] is %T, want map[string]any", result[0])
		}
		if obj["city"] != "Berlin" {
			t.Errorf("city = %v, want Berlin", obj["city"])
		}
	})

	t.Run("recursive processing of disclosed array value", func(t *testing.T) {
		disc := &disclosure{
			salt:    "s1",
			value:   []any{"a", "b"},
			isArray: true,
		}
		digest := "fake-digest-arr"
		discMap := map[string]*disclosure{digest: disc}
		arr := []any{map[string]any{"...": digest}}
		used := map[string]bool{}

		result, err := processArray(arr, discMap, used)
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 element, got %d", len(result))
		}
		inner, ok := result[0].([]any)
		if !ok {
			t.Fatalf("result[0] is %T, want []any", result[0])
		}
		if len(inner) != 2 || inner[0] != "a" || inner[1] != "b" {
			t.Errorf("inner = %v, want [a b]", inner)
		}
	})

	t.Run("error propagated from recursive processObject on disclosed value", func(t *testing.T) {
		disc := &disclosure{
			salt:    "s1",
			value:   map[string]any{"_sd": "not-an-array"},
			isArray: true,
		}
		digest := "fake-digest-err"
		discMap := map[string]*disclosure{digest: disc}
		arr := []any{map[string]any{"...": digest}}
		used := map[string]bool{}

		_, err := processArray(arr, discMap, used)
		if err == nil || !strings.Contains(err.Error(), "_sd is not an array") {
			t.Fatalf("expected '_sd is not an array' error, got: %v", err)
		}
	})

	t.Run("error propagated from recursive processArray on disclosed value", func(t *testing.T) {
		disc := &disclosure{
			salt:    "s1",
			value:   []any{map[string]any{"...": 42}},
			isArray: true,
		}
		digest := "fake-digest-err2"
		discMap := map[string]*disclosure{digest: disc}
		arr := []any{map[string]any{"...": digest}}
		used := map[string]bool{}

		_, err := processArray(arr, discMap, used)
		if err == nil || !strings.Contains(err.Error(), "not a string") {
			t.Fatalf("expected 'not a string' error, got: %v", err)
		}
	})

	t.Run("nested object in array is recursively processed", func(t *testing.T) {
		// A regular (non-placeholder) object in the array should still be recursively processed
		discMap, digest := makeArrDisc("s1", "US")
		_ = digest // not used in the array directly
		arr := []any{
			map[string]any{"nested": map[string]any{"_sd": "not-an-array"}},
		}
		_, err := processArray(arr, discMap, map[string]bool{})
		if err == nil || !strings.Contains(err.Error(), "_sd is not an array") {
			t.Fatalf("expected error from nested object processing, got: %v", err)
		}
	})

	t.Run("nested array in array is recursively processed", func(t *testing.T) {
		inner := []any{map[string]any{"...": 42}}
		arr := []any{inner}
		_, err := processArray(arr, map[string]*disclosure{}, map[string]bool{})
		if err == nil || !strings.Contains(err.Error(), "not a string") {
			t.Fatalf("expected error from nested array processing, got: %v", err)
		}
	})

	t.Run("nested plain array in array passes through", func(t *testing.T) {
		arr := []any{[]any{"a", "b"}}
		result, err := processArray(arr, map[string]*disclosure{}, map[string]bool{})
		if err != nil {
			t.Fatalf("processArray() error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 element, got %d", len(result))
		}
		inner, ok := result[0].([]any)
		if !ok {
			t.Fatalf("result[0] is %T, want []any", result[0])
		}
		if len(inner) != 2 || inner[0] != "a" || inner[1] != "b" {
			t.Errorf("inner = %v, want [a b]", inner)
		}
	})
}
