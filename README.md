# sdjwt

Go implementation of [SD-JWT (RFC 9901)](https://datatracker.ietf.org/doc/rfc9901/) verification.

## Scope

This module implements **verifier** functionality only. It does not support issuing or holding SD-JWTs.

### Supported

- Verification of SD-JWT and SD-JWT+KB compact serialization
- Key Binding verification (SD-JWT+KB)
- Selective disclosure processing (object properties and array elements)
- Recursive disclosures
- `sha-256` digest algorithm
- Signature algorithms: ES256/384/512, RS256/384/512, PS256/384/512, EdDSA
- Validation of `exp`, `nbf`, `iss`, and `aud` claims

### Not supported

- Issuance (creating SD-JWTs)
- Holder operations (selecting disclosures, creating presentations)
- Digest algorithms other than `sha-256`
- JWS JSON serialization

## Usage

```go
import "github.com/joesiltberg/sdjwt"
```

### Basic verification (SD-JWT)

```go
claims, err := sdjwt.Verify(token, issuerPublicKey,
    sdjwt.WithTime(time.Now()),
    sdjwt.WithIssuer("https://issuer.example.com"),
)
// claims.Payload contains the reconstructed JSON payload
```

### Verification with Key Binding (SD-JWT+KB)

```go
claims, err := sdjwt.Verify(token, issuerPublicKey,
    sdjwt.WithTime(time.Now()),
    sdjwt.WithKeyBinding("expected-nonce", "https://verifier.example.org"),
)
// claims.Payload contains the reconstructed JSON payload
// claims.KeyBindingPayload contains the KB-JWT claims (iat, nonce, aud)
```
