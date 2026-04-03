package sdjwt

import "fmt"

// ExampleVerify demonstrates verifying an SD-JWT with selective disclosure.
// The token and key are from RFC 9901 Section 5. Only four of the ten
// disclosures are included: given_name, family_name, address, and one
// nationality (US).
func ExampleVerify() {
	key := rfc9901IssuerKey(nil)
	token := buildSDJWT(rfc9901JWT,
		discFamilyName, discAddress,
		discGivenName, discNationalityUS,
	)

	claims, err := Verify(token, key, WithTime(rfc9901VerifyTime))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("iss:", claims.Payload["iss"])
	fmt.Println("given_name:", claims.Payload["given_name"])
	fmt.Println("family_name:", claims.Payload["family_name"])

	nats := claims.Payload["nationalities"].([]any)
	fmt.Println("nationalities:", nats)

	// Output:
	// iss: https://issuer.example.com
	// given_name: John
	// family_name: Doe
	// nationalities: [US]
}

// ExampleVerify_keyBinding demonstrates verifying an SD-JWT+KB with Key Binding.
// The verifier requires a specific nonce and audience, which are checked against
// the KB-JWT claims.
func ExampleVerify_keyBinding() {
	key := rfc9901IssuerKey(nil)
	token := buildSDJWTKB(rfc9901JWT, rfc9901KBJWT,
		discFamilyName, discAddress,
		discGivenName, discNationalityUS,
	)

	claims, err := Verify(token, key,
		WithTime(rfc9901KBVerifyTime),
		WithKeyBinding("1234567890", "https://verifier.example.org"),
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("given_name:", claims.Payload["given_name"])
	fmt.Println("family_name:", claims.Payload["family_name"])
	fmt.Println("kb nonce:", claims.KeyBindingPayload["nonce"])
	fmt.Println("kb aud:", claims.KeyBindingPayload["aud"])

	// Output:
	// given_name: John
	// family_name: Doe
	// kb nonce: 1234567890
	// kb aud: https://verifier.example.org
}
