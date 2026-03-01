package sdjwt

import (
	"strings"
	"testing"
)

func TestGetSDAlg(t *testing.T) {
	tests := []struct {
		name            string
		payload         map[string]any
		want            string
		wantErrContains string
	}{
		{
			name:    "missing _sd_alg defaults to sha-256",
			payload: map[string]any{"iss": "https://example.com"},
			want:    "sha-256",
		},
		{
			name:    "explicit sha-256",
			payload: map[string]any{"_sd_alg": "sha-256"},
			want:    "sha-256",
		},
		{
			name:            "unsupported algorithm",
			payload:         map[string]any{"_sd_alg": "sha-384"},
			wantErrContains: "unsupported _sd_alg",
		},
		{
			name:            "_sd_alg is not a string",
			payload:         map[string]any{"_sd_alg": 42},
			wantErrContains: "not a string",
		},
		{
			name:    "empty payload defaults to sha-256",
			payload: map[string]any{},
			want:    "sha-256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getSDAlg(tt.payload)
			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("getSDAlg() expected error containing %q, got nil", tt.wantErrContains)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("getSDAlg() error = %q, want substring %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("getSDAlg() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("getSDAlg() = %q, want %q", got, tt.want)
			}
		})
	}
}
