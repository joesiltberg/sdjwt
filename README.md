# sdjwt

Go implementation of [SD-JWT (RFC 9901)](https://datatracker.ietf.org/doc/rfc9901/) verification.

## Scope

This module implements **verifier** functionality only. It does not support issuing or holding SD-JWTs.

### Supported

- Verification of SD-JWT compact serialization
- Selective disclosure processing (object properties and array elements)
- Recursive disclosures
- `sha-256` digest algorithm
- Signature algorithms: ES256/384/512, RS256/384/512, PS256/384/512, EdDSA
- Validation of `exp`, `nbf`, `iss`, and `aud` claims

### Not supported

- Issuance (creating SD-JWTs)
- Holder operations (selecting disclosures, creating presentations)
- Key Binding (SD-JWT+KB)
- Digest algorithms other than `sha-256`
- JWS JSON serialization
