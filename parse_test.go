package sdjwt

import (
	"strings"
	"testing"
)

func TestParseSDJWT(t *testing.T) {
	tests := []struct {
		name            string
		token           string
		wantJWT         string
		wantDisclosures []string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:    "empty string",
			token:   "",
			wantErr: true,
		},
		{
			name:            "no trailing tilde (Key Binding not supported)",
			token:           "header.payload.signature~disc1~kb-jwt",
			wantErr:         true,
			wantErrContains: "Key Binding",
		},
		{
			name:            "JWT without any tilde (Key Binding not supported)",
			token:           "header.payload.signature",
			wantErr:         true,
			wantErrContains: "Key Binding",
		},
		{
			name:    "empty JWT part",
			token:   "~disc1~",
			wantErr: true,
		},
		{
			name:    "empty disclosure segment",
			token:   "header.payload.signature~disc1~~disc2~",
			wantErr: true,
		},
		{
			name:            "JWT only with trailing tilde (no disclosures)",
			token:           "header.payload.signature~",
			wantJWT:         "header.payload.signature",
			wantDisclosures: nil,
		},
		{
			name:            "JWT with one disclosure",
			token:           "header.payload.signature~disc1~",
			wantJWT:         "header.payload.signature",
			wantDisclosures: []string{"disc1"},
		},
		{
			name:            "JWT with multiple disclosures",
			token:           "header.payload.signature~disc1~disc2~disc3~",
			wantJWT:         "header.payload.signature",
			wantDisclosures: []string{"disc1", "disc2", "disc3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt, disclosures, err := parseSDJWT(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseSDJWT() expected error, got nil")
				}
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSDJWT() unexpected error: %v", err)
			}
			if jwt != tt.wantJWT {
				t.Errorf("jwt = %q, want %q", jwt, tt.wantJWT)
			}
			if len(disclosures) != len(tt.wantDisclosures) {
				t.Fatalf("len(disclosures) = %d, want %d", len(disclosures), len(tt.wantDisclosures))
			}
			for i, d := range disclosures {
				if d != tt.wantDisclosures[i] {
					t.Errorf("disclosures[%d] = %q, want %q", i, d, tt.wantDisclosures[i])
				}
			}
		})
	}
}
