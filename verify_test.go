package sdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// rfc9901VerifyTime is a fixed time used for exp/nbf validation in tests.
// It falls between the RFC 9901 example's iat (2023-05-02) and exp (~2029-09).
var rfc9901VerifyTime = time.Date(2023, time.May, 2, 0, 0, 1, 0, time.UTC)

// rfc9901IssuerKey returns the EC public key from RFC 9901 Appendix A.5,
// used to validate issuer signatures in the RFC examples.
func rfc9901IssuerKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	decodeCoord := func(s string) *big.Int {
		t.Helper()
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decode JWK coordinate: %v", err)
		}
		return new(big.Int).SetBytes(b)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     decodeCoord("b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ"),
		Y:     decodeCoord("Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"),
	}
}

// Issuer-signed JWT from RFC 9901 Section 5.1.
// Header: {"alg": "ES256", "typ": "example+sd-jwt"}
// Payload structure (decoded):
//   - _sd: 8 digests (given_name, family_name, email, phone_number,
//     phone_number_verified, address, birthdate, updated_at)
//   - iss: "https://issuer.example.com", sub: "user_42"
//   - iat: 1683000000, exp: 1883000000
//   - nationalities: [{"...": <digest>}, {"...": <digest>}] (US, DE)
//   - _sd_alg: "sha-256", cnf: holder key (permanently visible)
const rfc9901JWT = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0." +
	"eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tq" +
	"UEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIs" +
	"ICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRH" +
	"ZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQ" +
	"S3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002" +
	"R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3" +
	"LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8z" +
	"Smx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVy" +
	"LmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAw" +
	"LCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5k" +
	"amtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjog" +
	"IjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJf" +
	"c2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJj" +
	"cnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxp" +
	"bERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVj" +
	"Q0U2dDRqVDlGMkhaUSJ9fX0." +
	"MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz" +
	"-CXo6R04b7jYrpj9mNRAvVssXou1iw"

// Disclosures from RFC 9901 Section 5.1.
// Each is a base64url-encoded JSON array: [salt, claim_name, value] for
// object properties, or [salt, value] for array elements.
const (
	discGivenName           = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"                                                                                                     // ["...", "given_name", "John"]
	discFamilyName          = "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd"                                                                                                     // ["...", "family_name", "Doe"]
	discEmail               = "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ"                                                                                       // ["...", "email", "johndoe@example.com"]
	discPhoneNumber         = "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ"                                                                                     // ["...", "phone_number", "+1-202-555-0101"]
	discPhoneNumberVerified = "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd"                                                                                           // ["...", "phone_number_verified", true]
	discAddress             = "WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0" // ["...", "address", {"street_address": "123 Main St", ...}]
	discBirthdate           = "WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0"                                                                                               // ["...", "birthdate", "1940-01-01"]
	discUpdatedAt           = "WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ"                                                                                                 // ["...", "updated_at", 1570000000]
	discNationalityUS       = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0"                                                                                                                             // ["...", "US"]
	discNationalityDE       = "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0"                                                                                                                             // ["...", "DE"]
)

// buildSDJWT constructs an SD-JWT (compact serialization) from the issuer-signed
// JWT and selected disclosures, ending with a trailing tilde.
func buildSDJWT(jwt string, disclosures ...string) string {
	parts := []string{jwt}
	parts = append(parts, disclosures...)
	return strings.Join(parts, "~") + "~"
}

func assertStringClaim(t *testing.T, claims *Claims, key, want string) {
	t.Helper()
	got, ok := claims.Payload[key]
	if !ok {
		t.Errorf("claim %q not found in payload", key)
		return
	}
	s, ok := got.(string)
	if !ok {
		t.Errorf("claim %q is %T, want string", key, got)
		return
	}
	if s != want {
		t.Errorf("claim %q = %q, want %q", key, s, want)
	}
}

func assertFloat64Claim(t *testing.T, claims *Claims, key string, want float64) {
	t.Helper()
	got, ok := claims.Payload[key]
	if !ok {
		t.Errorf("claim %q not found in payload", key)
		return
	}
	f, ok := got.(float64)
	if !ok {
		t.Errorf("claim %q is %T, want float64", key, got)
		return
	}
	if f != want {
		t.Errorf("claim %q = %v, want %v", key, f, want)
	}
}

func assertClaimAbsent(t *testing.T, claims *Claims, key string) {
	t.Helper()
	if _, ok := claims.Payload[key]; ok {
		t.Errorf("claim %q should not be present in processed payload", key)
	}
}

func assertBoolClaim(t *testing.T, claims *Claims, key string, want bool) {
	t.Helper()
	got, ok := claims.Payload[key]
	if !ok {
		t.Errorf("claim %q not found in payload", key)
		return
	}
	b, ok := got.(bool)
	if !ok {
		t.Errorf("claim %q is %T, want bool", key, got)
		return
	}
	if b != want {
		t.Errorf("claim %q = %v, want %v", key, b, want)
	}
}

// TestVerify_RFC9901_Section5_AllDisclosures verifies an SD-JWT from RFC 9901
// Section 5.1 with all 10 disclosures included, producing the full set of claims.
func TestVerify_RFC9901_Section5_AllDisclosures(t *testing.T) {
	key := rfc9901IssuerKey(t)
	token := buildSDJWT(rfc9901JWT,
		discGivenName, discFamilyName, discEmail,
		discPhoneNumber, discPhoneNumberVerified,
		discAddress, discBirthdate, discUpdatedAt,
		discNationalityUS, discNationalityDE,
	)

	// Use a fixed time between iat and exp from the RFC example.
	at := WithTime(rfc9901VerifyTime)

	claims, err := Verify(token, key, at)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims == nil {
		t.Fatal("Verify() returned nil claims")
	}

	// Always-visible claims
	assertStringClaim(t, claims, "iss", "https://issuer.example.com")
	assertStringClaim(t, claims, "sub", "user_42")
	assertFloat64Claim(t, claims, "iat", 1683000000)
	assertFloat64Claim(t, claims, "exp", 1883000000)

	// Selectively disclosed claims
	assertStringClaim(t, claims, "given_name", "John")
	assertStringClaim(t, claims, "family_name", "Doe")
	assertStringClaim(t, claims, "email", "johndoe@example.com")
	assertStringClaim(t, claims, "phone_number", "+1-202-555-0101")
	assertStringClaim(t, claims, "birthdate", "1940-01-01")
	assertFloat64Claim(t, claims, "updated_at", 1570000000)

	assertBoolClaim(t, claims, "phone_number_verified", true)

	// Address (flat disclosure as an object)
	addrRaw, ok := claims.Payload["address"]
	if !ok {
		t.Fatal("address claim not found in payload")
	}
	addr, ok := addrRaw.(map[string]any)
	if !ok {
		t.Fatalf("address claim is %T, want map[string]any", addrRaw)
	}
	for _, tc := range []struct{ key, want string }{
		{"street_address", "123 Main St"},
		{"locality", "Anytown"},
		{"region", "Anystate"},
		{"country", "US"},
	} {
		if got, _ := addr[tc.key].(string); got != tc.want {
			t.Errorf("address.%s = %q, want %q", tc.key, got, tc.want)
		}
	}

	// Nationalities array (both elements disclosed)
	nats, ok := claims.Payload["nationalities"].([]any)
	if !ok {
		t.Fatal("nationalities claim is not a []any")
	}
	if len(nats) != 2 {
		t.Fatalf("len(nationalities) = %d, want 2", len(nats))
	}

	// cnf should be present (permanently disclosed)
	if _, ok := claims.Payload["cnf"]; !ok {
		t.Error("cnf claim not found in processed payload")
	}

	// _sd and _sd_alg must be removed per RFC 9901 Section 7.1
	assertClaimAbsent(t, claims, "_sd")
	assertClaimAbsent(t, claims, "_sd_alg")
}

// TestVerify_RFC9901_Section5_SelectiveDisclosure verifies an SD-JWT matching
// the presentation in RFC 9901 Section 5.2 (without Key Binding).
// Only family_name, given_name, address, and one nationality (US) are disclosed.
func TestVerify_RFC9901_Section5_SelectiveDisclosure(t *testing.T) {
	key := rfc9901IssuerKey(t)
	token := buildSDJWT(rfc9901JWT,
		discFamilyName, discAddress,
		discGivenName, discNationalityUS,
	)

	at := WithTime(rfc9901VerifyTime)
	claims, err := Verify(token, key, at)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims == nil {
		t.Fatal("Verify() returned nil claims")
	}

	// Always-visible claims
	assertStringClaim(t, claims, "iss", "https://issuer.example.com")
	assertStringClaim(t, claims, "sub", "user_42")
	assertFloat64Claim(t, claims, "iat", 1683000000)
	assertFloat64Claim(t, claims, "exp", 1883000000)

	// Disclosed claims
	assertStringClaim(t, claims, "given_name", "John")
	assertStringClaim(t, claims, "family_name", "Doe")

	addr, ok := claims.Payload["address"].(map[string]any)
	if !ok {
		t.Fatal("address claim is not a map[string]any")
	}
	if addr["street_address"] != "123 Main St" {
		t.Errorf("address.street_address = %v, want '123 Main St'", addr["street_address"])
	}

	// Only US nationality disclosed
	nats, ok := claims.Payload["nationalities"].([]any)
	if !ok {
		t.Fatal("nationalities claim is not a []any")
	}
	if len(nats) != 1 {
		t.Fatalf("len(nationalities) = %d, want 1", len(nats))
	}
	if nats[0] != "US" {
		t.Errorf("nationalities[0] = %v, want 'US'", nats[0])
	}

	// Claims not disclosed must be absent from processed payload
	assertClaimAbsent(t, claims, "email")
	assertClaimAbsent(t, claims, "phone_number")
	assertClaimAbsent(t, claims, "phone_number_verified")
	assertClaimAbsent(t, claims, "birthdate")
	assertClaimAbsent(t, claims, "updated_at")

	assertClaimAbsent(t, claims, "_sd")
	assertClaimAbsent(t, claims, "_sd_alg")
}

// TestVerify_RFC9901_Section5_NoDisclosures verifies an SD-JWT with no
// disclosures, so only permanently visible claims appear in the output.
func TestVerify_RFC9901_Section5_NoDisclosures(t *testing.T) {
	key := rfc9901IssuerKey(t)
	token := buildSDJWT(rfc9901JWT)

	at := WithTime(rfc9901VerifyTime)
	claims, err := Verify(token, key, at)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims == nil {
		t.Fatal("Verify() returned nil claims")
	}

	// Always-visible claims
	assertStringClaim(t, claims, "iss", "https://issuer.example.com")
	assertStringClaim(t, claims, "sub", "user_42")
	assertFloat64Claim(t, claims, "iat", 1683000000)
	assertFloat64Claim(t, claims, "exp", 1883000000)

	// cnf is permanently disclosed
	if _, ok := claims.Payload["cnf"]; !ok {
		t.Error("cnf claim not found")
	}

	// nationalities array should be empty (all elements undisclosed, removed per Section 7.1)
	nats, ok := claims.Payload["nationalities"].([]any)
	if !ok {
		t.Fatal("nationalities claim is not a []any")
	}
	if len(nats) != 0 {
		t.Errorf("len(nationalities) = %d, want 0 (no elements disclosed)", len(nats))
	}

	// No selectively disclosable claims should be present
	assertClaimAbsent(t, claims, "given_name")
	assertClaimAbsent(t, claims, "family_name")
	assertClaimAbsent(t, claims, "email")
	assertClaimAbsent(t, claims, "phone_number")
	assertClaimAbsent(t, claims, "phone_number_verified")
	assertClaimAbsent(t, claims, "address")
	assertClaimAbsent(t, claims, "birthdate")
	assertClaimAbsent(t, claims, "updated_at")

	assertClaimAbsent(t, claims, "_sd")
	assertClaimAbsent(t, claims, "_sd_alg")
}

// TestVerify_InvalidSignature verifies that a tampered JWT signature is rejected.
func TestVerify_InvalidSignature(t *testing.T) {
	key := rfc9901IssuerKey(t)

	// Flip a character in the signature portion of the JWT
	tampered := strings.Replace(rfc9901JWT, "MczwjBFGtzf", "XczwjBFGtzf", 1)
	token := buildSDJWT(tampered)

	_, err := Verify(token, key, WithTime(rfc9901VerifyTime))
	if err == nil {
		t.Fatal("Verify() should return error for tampered signature")
	}
}

// TestVerify_EmptyToken verifies that an empty string is rejected.
func TestVerify_EmptyToken(t *testing.T) {
	key := rfc9901IssuerKey(t)

	// WithTime omitted: error occurs during parsing, before time validation.
	_, err := Verify("", key)
	if err == nil {
		t.Fatal("Verify() should return error for empty token")
	}
}

// TestVerify_MalformedJWT verifies that a token with an invalid JWT part is rejected.
func TestVerify_MalformedJWT(t *testing.T) {
	key := rfc9901IssuerKey(t)

	// WithTime omitted: error occurs during JWT parsing, before time validation.
	_, err := Verify("not-a-jwt~", key)
	if err == nil {
		t.Fatal("Verify() should return error for malformed JWT")
	}
}

// TestVerify_UnreferencedDisclosure verifies that an SD-JWT containing a
// disclosure not referenced by any digest in the JWT is rejected,
// per RFC 9901 Section 7.1 step 5.
func TestVerify_UnreferencedDisclosure(t *testing.T) {
	key := rfc9901IssuerKey(t)

	// WyJkdW1teXNhbHQiLCAiZm9vIiwgImJhciJd = ["dummysalt", "foo", "bar"]
	unreferenced := "WyJkdW1teXNhbHQiLCAiZm9vIiwgImJhciJd"
	token := buildSDJWT(rfc9901JWT, discGivenName, unreferenced)

	_, err := Verify(token, key, WithTime(rfc9901VerifyTime))
	if err == nil {
		t.Fatal("Verify() should return error for unreferenced disclosure")
	}
}

// TestVerify_DuplicateDisclosure verifies that including the same disclosure
// twice is rejected (the digest would appear more than once in the processing).
func TestVerify_DuplicateDisclosure(t *testing.T) {
	key := rfc9901IssuerKey(t)

	token := buildSDJWT(rfc9901JWT, discGivenName, discGivenName)

	_, err := Verify(token, key, WithTime(rfc9901VerifyTime))
	if err == nil {
		t.Fatal("Verify() should return error for duplicate disclosure")
	}
}

// TestVerify_WrongKey verifies that verification fails when using a key
// that does not match the issuer's signing key.
func TestVerify_WrongKey(t *testing.T) {
	// Use a different point on P-256 (not the issuer's key)
	wrongKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(1),
		Y:     big.NewInt(1),
	}

	token := buildSDJWT(rfc9901JWT, discGivenName)

	_, err := Verify(token, wrongKey, WithTime(rfc9901VerifyTime))
	if err == nil {
		t.Fatal("Verify() should return error when using wrong key")
	}
}

// TestVerify_NilKey verifies that a nil public key is rejected.
func TestVerify_NilKey(t *testing.T) {
	token := buildSDJWT(rfc9901JWT)

	_, err := Verify(token, nil)
	if err == nil {
		t.Fatal("Verify() should return error for nil key")
	}
}
