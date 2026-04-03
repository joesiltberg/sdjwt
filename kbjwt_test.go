package sdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signKBJWT signs a KB-JWT with the given key, typ header, and claims.
func signKBJWT(t *testing.T, key *ecdsa.PrivateKey, typ string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = typ
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign KB-JWT: %v", err)
	}
	return s
}

func TestVerifyKeyBindingJWT(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sdHash := "test-sd-hash-value"
	nonce := "test-nonce-123"
	aud := "https://verifier.example.org"
	iat := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	verifyTime := iat.Add(time.Second)

	validClaims := jwt.MapClaims{
		"iat":     jwt.NewNumericDate(iat),
		"nonce":   nonce,
		"aud":     aud,
		"sd_hash": sdHash,
	}

	validCfg := &verifyConfig{
		kbRequired: true,
		kbNonce:    nonce,
		kbAud:      aud,
		now:        func() time.Time { return verifyTime },
	}

	tests := []struct {
		name            string
		kbJWT           string
		holderKey       *ecdsa.PublicKey
		sdHash          string
		cfg             *verifyConfig
		wantErr         bool
		wantErrContains string
	}{
		{
			name:      "valid KB-JWT",
			kbJWT:     signKBJWT(t, holderKey, "kb+jwt", validClaims),
			holderKey: &holderKey.PublicKey,
			sdHash:    sdHash,
			cfg:       validCfg,
		},
		{
			name:            "wrong signature (wrong key)",
			kbJWT:           signKBJWT(t, wrongKey, "kb+jwt", validClaims),
			holderKey:       &holderKey.PublicKey,
			sdHash:          sdHash,
			cfg:             validCfg,
			wantErr:         true,
			wantErrContains: "KB-JWT verification failed",
		},
		{
			name:            "wrong typ header",
			kbJWT:           signKBJWT(t, holderKey, "JWT", validClaims),
			holderKey:       &holderKey.PublicKey,
			sdHash:          sdHash,
			cfg:             validCfg,
			wantErr:         true,
			wantErrContains: `KB-JWT typ is "JWT"`,
		},
		{
			name:            "missing typ header",
			kbJWT:           signKBJWT(t, holderKey, "", validClaims),
			holderKey:       &holderKey.PublicKey,
			sdHash:          sdHash,
			cfg:             validCfg,
			wantErr:         true,
			wantErrContains: `KB-JWT typ is ""`,
		},
		{
			name: "missing iat claim",
			kbJWT: signKBJWT(t, holderKey, "kb+jwt", jwt.MapClaims{
				"nonce":   nonce,
				"aud":     aud,
				"sd_hash": sdHash,
			}),
			holderKey:       &holderKey.PublicKey,
			sdHash:          sdHash,
			cfg:             validCfg,
			wantErr:         true,
			wantErrContains: "missing required iat",
		},
		{
			name: "nonce mismatch",
			kbJWT: signKBJWT(t, holderKey, "kb+jwt", jwt.MapClaims{
				"iat":     jwt.NewNumericDate(iat),
				"nonce":   "wrong-nonce",
				"aud":     aud,
				"sd_hash": sdHash,
			}),
			holderKey:       &holderKey.PublicKey,
			sdHash:          sdHash,
			cfg:             validCfg,
			wantErr:         true,
			wantErrContains: "nonce mismatch",
		},
		{
			name: "audience mismatch",
			kbJWT: signKBJWT(t, holderKey, "kb+jwt", jwt.MapClaims{
				"iat":     jwt.NewNumericDate(iat),
				"nonce":   nonce,
				"aud":     "https://wrong.example.org",
				"sd_hash": sdHash,
			}),
			holderKey:       &holderKey.PublicKey,
			sdHash:          sdHash,
			cfg:             validCfg,
			wantErr:         true,
			wantErrContains: "audience mismatch",
		},
		{
			name:            "sd_hash mismatch",
			kbJWT:           signKBJWT(t, holderKey, "kb+jwt", validClaims),
			holderKey:       &holderKey.PublicKey,
			sdHash:          "wrong-sd-hash",
			cfg:             validCfg,
			wantErr:         true,
			wantErrContains: "sd_hash mismatch",
		},
		{
			name: "expired KB-JWT rejected with WithTime",
			kbJWT: signKBJWT(t, holderKey, "kb+jwt", jwt.MapClaims{
				"iat":     jwt.NewNumericDate(iat),
				"exp":     jwt.NewNumericDate(iat.Add(10 * time.Second)),
				"nonce":   nonce,
				"aud":     aud,
				"sd_hash": sdHash,
			}),
			holderKey: &holderKey.PublicKey,
			sdHash:    sdHash,
			cfg: &verifyConfig{
				kbRequired: true,
				kbNonce:    nonce,
				kbAud:      aud,
				// 1 hour after expiry
				now: func() time.Time { return iat.Add(time.Hour) },
			},
			wantErr:         true,
			wantErrContains: "KB-JWT verification failed",
		},
		{
			name:            "malformed KB-JWT",
			kbJWT:           "not-a-jwt",
			holderKey:       &holderKey.PublicKey,
			sdHash:          sdHash,
			cfg:             validCfg,
			wantErr:         true,
			wantErrContains: "KB-JWT verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := verifyKeyBindingJWT(tt.kbJWT, tt.holderKey, tt.sdHash, tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if payload == nil {
				t.Fatal("expected non-nil payload")
			}
			if payload["nonce"] != nonce {
				t.Errorf("nonce = %v, want %q", payload["nonce"], nonce)
			}
			if payload["aud"] != aud {
				t.Errorf("aud = %v, want %q", payload["aud"], aud)
			}
		})
	}
}
