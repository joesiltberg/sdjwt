package sdjwt

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims holds the verified and processed payload of an SD-JWT.
type Claims struct {
	Payload map[string]any
}

// Option configures the behavior of Verify.
type Option func(*verifyConfig)

type verifyConfig struct {
	now      func() time.Time
	issuer   string
	audience string
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

	jwtPart, disclosures, err := parseSDJWT(token)
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

	return &Claims{Payload: payload}, nil
}

// parseSDJWT splits an SD-JWT compact serialization into the issuer-signed JWT
// and disclosure strings. The token must end with a trailing '~' (SD-JWT without
// Key Binding). SD-JWT+KB (Key Binding) is not yet supported.
func parseSDJWT(token string) (string, []string, error) {
	if token == "" {
		return "", nil, errors.New("sdjwt: empty token")
	}

	if !strings.HasSuffix(token, "~") {
		return "", nil, errors.New("sdjwt: SD-JWT+KB (Key Binding) is not supported")
	}

	parts := strings.Split(token, "~")
	// With trailing ~, Split always produces at least ["", ""].
	// parts[len(parts)-1] is always "" (the trailing empty string).

	jwtPart := parts[0]
	if jwtPart == "" {
		return "", nil, errors.New("sdjwt: empty JWT part")
	}

	disclosures := parts[1 : len(parts)-1]
	if slices.Contains(disclosures, "") {
		return "", nil, errors.New("sdjwt: empty disclosure segment")
	}

	return jwtPart, disclosures, nil
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
