package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims holds the verified and processed payload of an SD-JWT.
// When Key Binding is used, KeyBindingPayload contains the KB-JWT claims.
type Claims struct {
	Payload           map[string]any
	KeyBindingPayload map[string]any
}

// Option configures the behavior of Verify.
type Option func(*verifyConfig)

type verifyConfig struct {
	now      func() time.Time
	issuer   string
	audience string
	kbNonce  string
	kbAud    string
	kbRequired bool
}

// WithTime sets a fixed time for exp/nbf validation instead of the system clock.
func WithTime(t time.Time) Option {
	return func(c *verifyConfig) {
		c.now = func() time.Time { return t }
	}
}

// WithIssuer requires the iss claim to match the expected issuer.
func WithIssuer(issuer string) Option {
	return func(c *verifyConfig) {
		c.issuer = issuer
	}
}

// WithAudience requires the aud claim to contain the expected audience.
func WithAudience(audience string) Option {
	return func(c *verifyConfig) {
		c.audience = audience
	}
}

// WithKeyBinding requires the Holder to provide a Key Binding JWT (SD-JWT+KB).
// The nonce and audience are verified against the KB-JWT claims.
func WithKeyBinding(nonce, audience string) Option {
	return func(c *verifyConfig) {
		c.kbRequired = true
		c.kbNonce = nonce
		c.kbAud = audience
	}
}

// Verify verifies an SD-JWT compact serialization, validates the issuer's
// signature, processes disclosures, and returns the reconstructed claims.
func Verify(token string, key crypto.PublicKey, opts ...Option) (*Claims, error) {
	if key == nil {
		return nil, errors.New("sdjwt: public key must not be nil")
	}

	cfg := &verifyConfig{}
	for _, o := range opts {
		o(cfg)
	}

	jwtPart, disclosures, kbJWT, err := parseSDJWT(token)
	if err != nil {
		return nil, err
	}

	payload, err := verifyJWS(jwtPart, key, cfg)
	if err != nil {
		return nil, err
	}

	sdAlg, err := getSDAlg(payload)
	if err != nil {
		return nil, err
	}

	discMap, err := indexDisclosures(disclosures, sdAlg)
	if err != nil {
		return nil, err
	}

	used := make(map[string]bool)
	if err := processObject(payload, discMap, used); err != nil {
		return nil, err
	}

	if len(used) != len(discMap) {
		return nil, errors.New("sdjwt: unreferenced disclosure(s)")
	}

	delete(payload, "_sd_alg")

	result := &Claims{Payload: payload}

	// Key Binding verification per RFC 9901 §7.3.
	if cfg.kbRequired {
		if kbJWT == "" {
			return nil, errors.New("sdjwt: key binding required but no KB-JWT provided")
		}

		holderKey, err := holderKeyFromCnf(payload)
		if err != nil {
			return nil, err
		}

		// Compute sd_hash over the SD-JWT portion (everything before the KB-JWT).
		sdJWTPortion := token[:len(token)-len(kbJWT)]
		sdHash := computeSDHash(sdJWTPortion)

		kbPayload, err := verifyKeyBindingJWT(kbJWT, holderKey, sdHash, cfg)
		if err != nil {
			return nil, err
		}

		delete(kbPayload, "sd_hash")
		result.KeyBindingPayload = kbPayload
	}

	return result, nil
}

// parseSDJWT splits an SD-JWT or SD-JWT+KB compact serialization into the
// issuer-signed JWT, disclosure strings, and an optional Key Binding JWT.
// For SD-JWT (no Key Binding), kbJWT is empty. For SD-JWT+KB, kbJWT contains
// the Key Binding JWT.
func parseSDJWT(token string) (string, []string, string, error) {
	if token == "" {
		return "", nil, "", errors.New("sdjwt: empty token")
	}

	parts := strings.Split(token, "~")
	// parts has at least 1 element (the JWT).
	// SD-JWT:    JWT~D1~D2~...~DN~   → last element is ""
	// SD-JWT+KB: JWT~D1~D2~...~DN~KB → last element is the KB-JWT

	jwtPart := parts[0]
	if jwtPart == "" {
		return "", nil, "", errors.New("sdjwt: empty JWT part")
	}

	if len(parts) < 2 {
		return "", nil, "", errors.New("sdjwt: missing trailing '~'")
	}

	var kbJWT string
	var disclosures []string

	last := parts[len(parts)-1]
	if last == "" {
		// SD-JWT without Key Binding: trailing ~ produces empty last element.
		disclosures = parts[1 : len(parts)-1]
	} else {
		// SD-JWT+KB: last element is the KB-JWT.
		kbJWT = last
		disclosures = parts[1 : len(parts)-1]
	}

	if slices.Contains(disclosures, "") {
		return "", nil, "", errors.New("sdjwt: empty disclosure segment")
	}

	return jwtPart, disclosures, kbJWT, nil
}

// verifyJWS parses and verifies the issuer-signed JWT, returning the payload.
func verifyJWS(jwtPart string, key crypto.PublicKey, cfg *verifyConfig) (map[string]any, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{
			"ES256", "ES384", "ES512",
			"RS256", "RS384", "RS512",
			"PS256", "PS384", "PS512",
			"EdDSA",
		}),
	}

	if cfg.now != nil {
		parserOpts = append(parserOpts, jwt.WithTimeFunc(cfg.now))
	}
	if cfg.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(cfg.issuer))
	}
	if cfg.audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(cfg.audience))
	}

	tok, err := jwt.Parse(jwtPart, func(t *jwt.Token) (any, error) {
		return key, nil
	}, parserOpts...)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: JWT verification failed: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("sdjwt: unexpected claims type")
	}

	return map[string]any(claims), nil
}

func getSDAlg(payload map[string]any) (string, error) {
	raw, ok := payload["_sd_alg"]
	if !ok {
		return "sha-256", nil
	}
	alg, ok := raw.(string)
	if !ok {
		return "", errors.New("sdjwt: _sd_alg is not a string")
	}
	if alg != "sha-256" {
		return "", fmt.Errorf("sdjwt: unsupported _sd_alg: %s", alg)
	}
	return alg, nil
}

type disclosure struct {
	salt    string
	name    string // empty for array disclosures
	value   any
	isArray bool
}

// indexDisclosures hashes and decodes each disclosure string, returning a map
// from digest to parsed disclosure.
func indexDisclosures(discStrings []string, sdAlg string) (map[string]*disclosure, error) {
	result := make(map[string]*disclosure)

	for _, d := range discStrings {
		hash := sha256.Sum256([]byte(d))
		digest := base64.RawURLEncoding.EncodeToString(hash[:])

		if _, exists := result[digest]; exists {
			return nil, errors.New("sdjwt: duplicate disclosure digest")
		}

		decoded, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			return nil, fmt.Errorf("sdjwt: invalid disclosure encoding: %w", err)
		}

		var arr []any
		if err := json.Unmarshal(decoded, &arr); err != nil {
			return nil, fmt.Errorf("sdjwt: invalid disclosure JSON: %w", err)
		}

		disc := &disclosure{}
		switch len(arr) {
		case 2:
			salt, ok := arr[0].(string)
			if !ok {
				return nil, errors.New("sdjwt: disclosure salt is not a string")
			}
			disc.salt = salt
			disc.value = arr[1]
			disc.isArray = true
		case 3:
			salt, ok := arr[0].(string)
			if !ok {
				return nil, errors.New("sdjwt: disclosure salt is not a string")
			}
			name, ok := arr[1].(string)
			if !ok {
				return nil, errors.New("sdjwt: disclosure claim name is not a string")
			}
			if name == "_sd" || name == "..." {
				return nil, fmt.Errorf("sdjwt: illegal disclosure claim name: %q", name)
			}
			disc.salt = salt
			disc.name = name
			disc.value = arr[2]
		default:
			return nil, fmt.Errorf("sdjwt: disclosure has %d elements, want 2 or 3", len(arr))
		}

		result[digest] = disc
	}

	return result, nil
}

// processObject recursively processes an object, replacing _sd digests with
// disclosed claims and handling nested structures.
func processObject(obj map[string]any, discMap map[string]*disclosure, used map[string]bool) error {
	if sdRaw, ok := obj["_sd"]; ok {
		sdArr, ok := sdRaw.([]any)
		if !ok {
			return errors.New("sdjwt: _sd is not an array")
		}

		for _, digestRaw := range sdArr {
			digest, ok := digestRaw.(string)
			if !ok {
				return errors.New("sdjwt: _sd element is not a string")
			}

			if disc, found := discMap[digest]; found {
				if disc.isArray {
					return errors.New("sdjwt: array disclosure referenced in _sd")
				}
				if _, exists := obj[disc.name]; exists {
					return fmt.Errorf("sdjwt: disclosed claim name %q already exists", disc.name)
				}
				obj[disc.name] = disc.value
				used[digest] = true
			}
		}

		delete(obj, "_sd")
	}

	for key, val := range obj {
		switch v := val.(type) {
		case map[string]any:
			if err := processObject(v, discMap, used); err != nil {
				return err
			}
		case []any:
			processed, err := processArray(v, discMap, used)
			if err != nil {
				return err
			}
			obj[key] = processed
		}
	}

	return nil
}

// processArray recursively processes an array, replacing {"...": digest}
// placeholders with disclosed values and removing undisclosed elements.
func processArray(arr []any, discMap map[string]*disclosure, used map[string]bool) ([]any, error) {
	result := make([]any, 0, len(arr))

	for _, elem := range arr {
		obj, isObj := elem.(map[string]any)
		if isObj && len(obj) == 1 {
			if digestRaw, ok := obj["..."]; ok {
				digest, ok := digestRaw.(string)
				if !ok {
					return nil, errors.New("sdjwt: array element digest is not a string")
				}
				if disc, found := discMap[digest]; found {
					if !disc.isArray {
						return nil, errors.New("sdjwt: object disclosure in array position")
					}
					used[digest] = true
					val := disc.value
					switch v := val.(type) {
					case map[string]any:
						if err := processObject(v, discMap, used); err != nil {
							return nil, err
						}
						val = v
					case []any:
						processed, err := processArray(v, discMap, used)
						if err != nil {
							return nil, err
						}
						val = processed
					}
					result = append(result, val)
				}
				continue
			}
		}

		switch v := elem.(type) {
		case map[string]any:
			if err := processObject(v, discMap, used); err != nil {
				return nil, err
			}
			result = append(result, v)
		case []any:
			processed, err := processArray(v, discMap, used)
			if err != nil {
				return nil, err
			}
			result = append(result, processed)
		default:
			result = append(result, elem)
		}
	}

	return result, nil
}

// holderKeyFromCnf extracts the Holder's public key from the cnf claim
// in the issuer-signed JWT payload per RFC 9901 §4.1.2 and RFC 7800.
func holderKeyFromCnf(payload map[string]any) (crypto.PublicKey, error) {
	cnfRaw, ok := payload["cnf"]
	if !ok {
		return nil, errors.New("sdjwt: cnf claim not found")
	}
	cnf, ok := cnfRaw.(map[string]any)
	if !ok {
		return nil, errors.New("sdjwt: cnf claim is not an object")
	}
	jwkRaw, ok := cnf["jwk"]
	if !ok {
		return nil, errors.New("sdjwt: cnf.jwk not found")
	}
	jwk, ok := jwkRaw.(map[string]any)
	if !ok {
		return nil, errors.New("sdjwt: cnf.jwk is not an object")
	}

	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		return parseECPublicKey(jwk)
	case "RSA":
		return parseRSAPublicKey(jwk)
	default:
		return nil, fmt.Errorf("sdjwt: unsupported key type: %q", kty)
	}
}

// parseECPublicKey parses an EC public key from a JWK object.
func parseECPublicKey(jwk map[string]any) (crypto.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("sdjwt: unsupported EC curve: %q", crv)
	}

	x, err := decodeJWKCoord(jwk, "x")
	if err != nil {
		return nil, err
	}
	y, err := decodeJWKCoord(jwk, "y")
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// parseRSAPublicKey parses an RSA public key from a JWK object.
func parseRSAPublicKey(jwk map[string]any) (crypto.PublicKey, error) {
	nBytes, err := decodeJWKField(jwk, "n")
	if err != nil {
		return nil, err
	}
	eBytes, err := decodeJWKField(jwk, "e")
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("sdjwt: RSA exponent too large")
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// decodeJWKCoord decodes a base64url-encoded big integer coordinate from a JWK.
func decodeJWKCoord(jwk map[string]any, field string) (*big.Int, error) {
	b, err := decodeJWKField(jwk, field)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// decodeJWKField decodes a base64url-encoded field from a JWK.
func decodeJWKField(jwk map[string]any, field string) ([]byte, error) {
	s, ok := jwk[field].(string)
	if !ok {
		return nil, fmt.Errorf("sdjwt: JWK field %q missing or not a string", field)
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: invalid JWK field %q: %w", field, err)
	}
	return b, nil
}

// computeSDHash computes the sd_hash over the SD-JWT portion (everything before
// the KB-JWT), per RFC 9901 §4.3.1. Uses SHA-256 (same as _sd_alg).
func computeSDHash(sdJWTPortion string) string {
	hash := sha256.Sum256([]byte(sdJWTPortion))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// verifyKeyBindingJWT verifies the Key Binding JWT per RFC 9901 §7.3 step 5.
func verifyKeyBindingJWT(kbJWT string, holderKey crypto.PublicKey, sdHash string, cfg *verifyConfig) (map[string]any, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{
			"ES256", "ES384", "ES512",
			"RS256", "RS384", "RS512",
			"PS256", "PS384", "PS512",
			"EdDSA",
		}),
	}

	if cfg.now != nil {
		parserOpts = append(parserOpts, jwt.WithTimeFunc(cfg.now))
	}

	tok, err := jwt.Parse(kbJWT, func(t *jwt.Token) (any, error) {
		return holderKey, nil
	}, parserOpts...)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: KB-JWT verification failed: %w", err)
	}

	// Check typ header is "kb+jwt" per §7.3 step 5d.
	typ, _ := tok.Header["typ"].(string)
	if typ != "kb+jwt" {
		return nil, fmt.Errorf("sdjwt: KB-JWT typ is %q, want \"kb+jwt\"", typ)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("sdjwt: unexpected KB-JWT claims type")
	}
	kbPayload := map[string]any(claims)

	// Check iat is present per §4.3.
	if _, ok := kbPayload["iat"]; !ok {
		return nil, errors.New("sdjwt: KB-JWT missing required iat claim")
	}

	// Validate nonce per §7.3 step 5f.
	nonce, _ := kbPayload["nonce"].(string)
	if nonce != cfg.kbNonce {
		return nil, errors.New("sdjwt: KB-JWT nonce mismatch")
	}

	// Validate aud per §7.3 step 5f.
	aud, _ := kbPayload["aud"].(string)
	if aud != cfg.kbAud {
		return nil, errors.New("sdjwt: KB-JWT audience mismatch")
	}

	// Validate sd_hash per §7.3 step 5g.
	claimedHash, _ := kbPayload["sd_hash"].(string)
	if claimedHash != sdHash {
		return nil, errors.New("sdjwt: KB-JWT sd_hash mismatch")
	}

	return kbPayload, nil
}
