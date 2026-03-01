package sdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signTestJWT creates a compact JWT signed with the given key using ES256.
func signTestJWT(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign test JWT: %v", err)
	}
	return s
}

// testECKey generates a fresh P-256 key pair for use in tests.
func testECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func TestVerifyJWS(t *testing.T) {
	key := testECKey(t)

	baseClaims := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://example.com",
			"sub": "user_1",
			"iat": jwt.NewNumericDate(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
			"exp": jwt.NewNumericDate(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
		}
	}

	t.Run("valid JWT with WithTime", func(t *testing.T) {
		jwtStr := signTestJWT(t, key, baseClaims())
		cfg := &verifyConfig{now: func() time.Time {
			return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		}}

		payload, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err != nil {
			t.Fatalf("verifyJWS() error = %v", err)
		}
		if payload["iss"] != "https://example.com" {
			t.Errorf("iss = %v, want https://example.com", payload["iss"])
		}
		if payload["sub"] != "user_1" {
			t.Errorf("sub = %v, want user_1", payload["sub"])
		}
	})

	t.Run("valid JWT with default time (no options)", func(t *testing.T) {
		jwtStr := signTestJWT(t, key, baseClaims())

		// Empty config: uses system clock (exp is 2030, so it should pass)
		cfg := &verifyConfig{}

		payload, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err != nil {
			t.Fatalf("verifyJWS() error = %v", err)
		}
		if payload["sub"] != "user_1" {
			t.Errorf("sub = %v, want user_1", payload["sub"])
		}
	})

	t.Run("expired JWT rejected with default time", func(t *testing.T) {
		claims := baseClaims()
		claims["exp"] = jwt.NewNumericDate(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
		jwtStr := signTestJWT(t, key, claims)

		cfg := &verifyConfig{}

		_, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject expired JWT")
		}
	})

	t.Run("expired JWT rejected with WithTime after exp", func(t *testing.T) {
		jwtStr := signTestJWT(t, key, baseClaims())

		cfg := &verifyConfig{now: func() time.Time {
			return time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
		}}

		_, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject JWT when WithTime is after exp")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		jwtStr := signTestJWT(t, key, baseClaims())
		otherKey := testECKey(t)

		cfg := &verifyConfig{now: func() time.Time {
			return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		}}

		_, err := verifyJWS(jwtStr, &otherKey.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject JWT signed with different key")
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		jwtStr := signTestJWT(t, key, baseClaims())
		// Flip a character in the payload (second segment)
		bytes := []byte(jwtStr)
		for i, b := range bytes {
			if b == '.' {
				// Modify first char after the dot
				if bytes[i+1] == 'a' {
					bytes[i+1] = 'b'
				} else {
					bytes[i+1] = 'a'
				}
				break
			}
		}
		cfg := &verifyConfig{now: func() time.Time {
			return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		}}

		_, err := verifyJWS(string(bytes), &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject JWT with tampered payload")
		}
	})

	t.Run("malformed JWT string", func(t *testing.T) {
		cfg := &verifyConfig{now: func() time.Time {
			return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		}}

		_, err := verifyJWS("not.a.valid-jwt", &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject malformed JWT")
		}
	})

	t.Run("JWT with none algorithm rejected", func(t *testing.T) {
		// Create an unsigned JWT using "none" algorithm
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
		jwtStr, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign none JWT: %v", err)
		}

		cfg := &verifyConfig{now: func() time.Time {
			return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		}}

		_, err = verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject JWT with 'none' algorithm")
		}
	})

	t.Run("issuer match", func(t *testing.T) {
		jwtStr := signTestJWT(t, key, baseClaims())
		cfg := &verifyConfig{
			now:    func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
			issuer: "https://example.com",
		}

		payload, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err != nil {
			t.Fatalf("verifyJWS() error = %v", err)
		}
		if payload["iss"] != "https://example.com" {
			t.Errorf("iss = %v, want https://example.com", payload["iss"])
		}
	})

	t.Run("issuer mismatch", func(t *testing.T) {
		jwtStr := signTestJWT(t, key, baseClaims())
		cfg := &verifyConfig{
			now:    func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
			issuer: "https://other-issuer.com",
		}

		_, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject JWT with wrong issuer")
		}
	})

	t.Run("issuer required but missing from JWT", func(t *testing.T) {
		claims := baseClaims()
		delete(claims, "iss")
		jwtStr := signTestJWT(t, key, claims)
		cfg := &verifyConfig{
			now:    func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
			issuer: "https://example.com",
		}

		_, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject JWT when required issuer is missing")
		}
	})

	t.Run("audience match", func(t *testing.T) {
		claims := baseClaims()
		claims["aud"] = "https://verifier.example.org"
		jwtStr := signTestJWT(t, key, claims)
		cfg := &verifyConfig{
			now:      func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
			audience: "https://verifier.example.org",
		}

		payload, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err != nil {
			t.Fatalf("verifyJWS() error = %v", err)
		}
		if payload["aud"] != "https://verifier.example.org" {
			t.Errorf("aud = %v, want https://verifier.example.org", payload["aud"])
		}
	})

	t.Run("audience mismatch", func(t *testing.T) {
		claims := baseClaims()
		claims["aud"] = "https://verifier.example.org"
		jwtStr := signTestJWT(t, key, claims)
		cfg := &verifyConfig{
			now:      func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
			audience: "https://other-verifier.com",
		}

		_, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject JWT with wrong audience")
		}
	})

	t.Run("audience required but missing from JWT", func(t *testing.T) {
		// baseClaims has no aud claim
		jwtStr := signTestJWT(t, key, baseClaims())
		cfg := &verifyConfig{
			now:      func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
			audience: "https://verifier.example.org",
		}

		_, err := verifyJWS(jwtStr, &key.PublicKey, cfg)
		if err == nil {
			t.Fatal("verifyJWS() should reject JWT when required audience is missing")
		}
	})
}
