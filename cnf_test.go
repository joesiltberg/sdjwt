package sdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func ecJWK(crv string, curve elliptic.Curve) map[string]any {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	byteLen := (curve.Params().BitSize + 7) / 8
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()
	// Left-pad to required length per RFC 7518 §6.2.1.2.
	if len(xBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(yBytes):], yBytes)
		yBytes = padded
	}
	return map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

func rsaJWK() map[string]any {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func TestHolderKeyFromCnf(t *testing.T) {
	tests := []struct {
		name            string
		payload         map[string]any
		wantErr         bool
		wantErrContains string
		wantKeyType     string // "EC", "RSA", or ""
	}{
		{
			name:            "missing cnf claim",
			payload:         map[string]any{},
			wantErr:         true,
			wantErrContains: "cnf claim not found",
		},
		{
			name:            "cnf is not an object",
			payload:         map[string]any{"cnf": "not-an-object"},
			wantErr:         true,
			wantErrContains: "cnf claim is not an object",
		},
		{
			name:            "cnf.jwk missing",
			payload:         map[string]any{"cnf": map[string]any{}},
			wantErr:         true,
			wantErrContains: "cnf.jwk not found",
		},
		{
			name: "cnf.jwk is not an object",
			payload: map[string]any{
				"cnf": map[string]any{"jwk": "not-an-object"},
			},
			wantErr:         true,
			wantErrContains: "cnf.jwk is not an object",
		},
		{
			name: "unsupported key type",
			payload: map[string]any{
				"cnf": map[string]any{
					"jwk": map[string]any{"kty": "OKP"},
				},
			},
			wantErr:         true,
			wantErrContains: "unsupported key type",
		},
		{
			name: "kty missing (not a string)",
			payload: map[string]any{
				"cnf": map[string]any{
					"jwk": map[string]any{"kty": 42},
				},
			},
			wantErr:         true,
			wantErrContains: "unsupported key type",
		},
		{
			name: "valid EC key",
			payload: map[string]any{
				"cnf": map[string]any{"jwk": ecJWK("P-256", elliptic.P256())},
			},
			wantKeyType: "EC",
		},
		{
			name: "valid RSA key",
			payload: map[string]any{
				"cnf": map[string]any{"jwk": rsaJWK()},
			},
			wantKeyType: "RSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := holderKeyFromCnf(tt.payload)
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
			switch tt.wantKeyType {
			case "EC":
				if _, ok := key.(*ecdsa.PublicKey); !ok {
					t.Errorf("expected *ecdsa.PublicKey, got %T", key)
				}
			case "RSA":
				if _, ok := key.(*rsa.PublicKey); !ok {
					t.Errorf("expected *rsa.PublicKey, got %T", key)
				}
			}
		})
	}
}

func TestParseECPublicKey(t *testing.T) {
	tests := []struct {
		name            string
		jwk             map[string]any
		wantErr         bool
		wantErrContains string
		wantCurve       elliptic.Curve
	}{
		{
			name:      "P-256",
			jwk:       ecJWK("P-256", elliptic.P256()),
			wantCurve: elliptic.P256(),
		},
		{
			name:      "P-384",
			jwk:       ecJWK("P-384", elliptic.P384()),
			wantCurve: elliptic.P384(),
		},
		{
			name:      "P-521",
			jwk:       ecJWK("P-521", elliptic.P521()),
			wantCurve: elliptic.P521(),
		},
		{
			name:            "unsupported curve",
			jwk:             map[string]any{"kty": "EC", "crv": "secp256k1", "x": "AA", "y": "AA"},
			wantErr:         true,
			wantErrContains: "unsupported EC curve",
		},
		{
			name:            "crv missing (not a string)",
			jwk:             map[string]any{"kty": "EC", "crv": 42, "x": "AA", "y": "AA"},
			wantErr:         true,
			wantErrContains: "unsupported EC curve",
		},
		{
			name:            "missing x coordinate",
			jwk:             map[string]any{"kty": "EC", "crv": "P-256", "y": "AA"},
			wantErr:         true,
			wantErrContains: `JWK field "x"`,
		},
		{
			name: "missing y coordinate",
			jwk: map[string]any{
				"kty": "EC", "crv": "P-256",
				"x": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			},
			wantErr:         true,
			wantErrContains: `JWK field "y"`,
		},
		{
			name:            "invalid base64 in x",
			jwk:             map[string]any{"kty": "EC", "crv": "P-256", "x": "!!!invalid", "y": "AA"},
			wantErr:         true,
			wantErrContains: `invalid JWK field "x"`,
		},
		{
			name: "wrong coordinate length",
			jwk: map[string]any{
				"kty": "EC", "crv": "P-256",
				"x": base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}), // 3 bytes, want 32
				"y": base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
			},
			wantErr:         true,
			wantErrContains: "3 bytes, want 32",
		},
		{
			name: "point not on curve",
			jwk: map[string]any{
				"kty": "EC", "crv": "P-256",
				// Valid-length (32 bytes) but (0, 0) is not on P-256
				"x": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				"y": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			},
			wantErr:         true,
			wantErrContains: "invalid EC public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseECPublicKey(tt.jwk)
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
			ecKey, ok := key.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
			}
			if ecKey.Curve != tt.wantCurve {
				t.Errorf("curve = %v, want %v", ecKey.Curve.Params().Name, tt.wantCurve.Params().Name)
			}
		})
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	validJWK := rsaJWK()

	tests := []struct {
		name            string
		jwk             map[string]any
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "valid RSA key",
			jwk:  validJWK,
		},
		{
			name:            "missing n",
			jwk:             map[string]any{"kty": "RSA", "e": "AQAB"},
			wantErr:         true,
			wantErrContains: `JWK field "n"`,
		},
		{
			name:            "missing e",
			jwk:             map[string]any{"kty": "RSA", "n": "AA"},
			wantErr:         true,
			wantErrContains: `JWK field "e"`,
		},
		{
			name:            "invalid base64 in n",
			jwk:             map[string]any{"kty": "RSA", "n": "!!!invalid", "e": "AQAB"},
			wantErr:         true,
			wantErrContains: `invalid JWK field "n"`,
		},
		{
			name: "exponent too large",
			jwk: map[string]any{
				"kty": "RSA",
				"n":   base64.RawURLEncoding.EncodeToString(big.NewInt(12345).Bytes()),
				// 9 bytes → 72-bit integer, exceeds int64 range
				"e": base64.RawURLEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
			},
			wantErr:         true,
			wantErrContains: "exponent too large",
		},
		{
			name: "exponent too small (e=0)",
			jwk: map[string]any{
				"kty": "RSA",
				"n":   validJWK["n"],
				"e":   base64.RawURLEncoding.EncodeToString([]byte{0}),
			},
			wantErr:         true,
			wantErrContains: "exponent too small",
		},
		{
			name: "exponent too small (e=1)",
			jwk: map[string]any{
				"kty": "RSA",
				"n":   validJWK["n"],
				"e":   base64.RawURLEncoding.EncodeToString([]byte{1}),
			},
			wantErr:         true,
			wantErrContains: "exponent too small",
		},
		{
			name: "modulus too small",
			jwk: map[string]any{
				"kty": "RSA",
				"n":   base64.RawURLEncoding.EncodeToString(big.NewInt(12345).Bytes()),
				"e":   "AQAB",
			},
			wantErr:         true,
			wantErrContains: "modulus too small",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseRSAPublicKey(tt.jwk)
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
			rsaKey, ok := key.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("expected *rsa.PublicKey, got %T", key)
			}
			if rsaKey.N == nil || rsaKey.N.Sign() <= 0 {
				t.Error("RSA N should be positive")
			}
			if rsaKey.E <= 0 {
				t.Error("RSA E should be positive")
			}
		})
	}
}
