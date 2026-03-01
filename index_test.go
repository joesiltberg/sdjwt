package sdjwt

import (
	"encoding/base64"
	"strings"
	"testing"
)

// encodeDisclosure base64url-encodes a JSON string for use as a disclosure.
func encodeDisclosure(json string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

func TestIndexDisclosures(t *testing.T) {
	tests := []struct {
		name            string
		disclosures     []string
		wantCount       int
		wantErrContains string
	}{
		{
			name:        "empty list",
			disclosures: nil,
			wantCount:   0,
		},
		{
			name: "valid 3-element disclosure (object property)",
			disclosures: []string{
				encodeDisclosure(`["salt123", "given_name", "John"]`),
			},
			wantCount: 1,
		},
		{
			name: "valid 2-element disclosure (array element)",
			disclosures: []string{
				encodeDisclosure(`["salt123", "US"]`),
			},
			wantCount: 1,
		},
		{
			name: "multiple valid disclosures",
			disclosures: []string{
				encodeDisclosure(`["salt1", "given_name", "John"]`),
				encodeDisclosure(`["salt2", "family_name", "Doe"]`),
				encodeDisclosure(`["salt3", "US"]`),
			},
			wantCount: 3,
		},
		{
			name:            "invalid base64",
			disclosures:     []string{"not valid base64!!!"},
			wantErrContains: "invalid disclosure encoding",
		},
		{
			name: "invalid JSON",
			disclosures: []string{
				encodeDisclosure(`not json`),
			},
			wantErrContains: "invalid disclosure JSON",
		},
		{
			name: "1-element array",
			disclosures: []string{
				encodeDisclosure(`["salt_only"]`),
			},
			wantErrContains: "want 2 or 3",
		},
		{
			name: "4-element array",
			disclosures: []string{
				encodeDisclosure(`["salt", "name", "value", "extra"]`),
			},
			wantErrContains: "want 2 or 3",
		},
		{
			name: "3-element: salt is not a string",
			disclosures: []string{
				encodeDisclosure(`[42, "name", "value"]`),
			},
			wantErrContains: "salt is not a string",
		},
		{
			name: "2-element: salt is not a string",
			disclosures: []string{
				encodeDisclosure(`[42, "value"]`),
			},
			wantErrContains: "salt is not a string",
		},
		{
			name: "claim name is not a string",
			disclosures: []string{
				encodeDisclosure(`["salt", 42, "value"]`),
			},
			wantErrContains: "claim name is not a string",
		},
		{
			name: "illegal claim name _sd",
			disclosures: []string{
				encodeDisclosure(`["salt", "_sd", "value"]`),
			},
			wantErrContains: "illegal disclosure claim name",
		},
		{
			name: "illegal claim name ...",
			disclosures: []string{
				encodeDisclosure(`["salt", "...", "value"]`),
			},
			wantErrContains: "illegal disclosure claim name",
		},
		{
			name: "duplicate disclosure digest",
			disclosures: []string{
				encodeDisclosure(`["salt", "name", "value"]`),
				encodeDisclosure(`["salt", "name", "value"]`),
			},
			wantErrContains: "duplicate disclosure digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := indexDisclosures(tt.disclosures, "sha-256")
			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("indexDisclosures() expected error containing %q, got nil", tt.wantErrContains)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("indexDisclosures() error = %q, want substring %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("indexDisclosures() unexpected error: %v", err)
			}
			if len(result) != tt.wantCount {
				t.Errorf("indexDisclosures() returned %d disclosures, want %d", len(result), tt.wantCount)
			}
		})
	}
}

func TestIndexDisclosures_ParsedContent(t *testing.T) {
	disclosures := []string{
		encodeDisclosure(`["salt1", "given_name", "John"]`),
		encodeDisclosure(`["salt2", "DE"]`),
	}

	result, err := indexDisclosures(disclosures, "sha-256")
	if err != nil {
		t.Fatalf("indexDisclosures() error: %v", err)
	}

	// Find the object disclosure and verify its parsed content
	var objDisc, arrDisc *disclosure
	for _, d := range result {
		if d.isArray {
			arrDisc = d
		} else {
			objDisc = d
		}
	}

	if objDisc == nil {
		t.Fatal("expected an object disclosure")
	}
	if objDisc.salt != "salt1" {
		t.Errorf("object disclosure salt = %q, want %q", objDisc.salt, "salt1")
	}
	if objDisc.name != "given_name" {
		t.Errorf("object disclosure name = %q, want %q", objDisc.name, "given_name")
	}
	if objDisc.value != "John" {
		t.Errorf("object disclosure value = %v, want %q", objDisc.value, "John")
	}

	if arrDisc == nil {
		t.Fatal("expected an array disclosure")
	}
	if arrDisc.salt != "salt2" {
		t.Errorf("array disclosure salt = %q, want %q", arrDisc.salt, "salt2")
	}
	if arrDisc.value != "DE" {
		t.Errorf("array disclosure value = %v, want %q", arrDisc.value, "DE")
	}
}
