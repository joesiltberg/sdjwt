#!/usr/bin/env python3
"""
Extract SD-JWT test vectors from the OpenWallet Foundation (OWF) Labs SD-JWT
reference implementation (https://github.com/openwallet-foundation-labs/sd-jwt-python).

For each test case and example in the reference repository, this script runs
the full Issuer -> Holder -> Verifier flow and outputs a JSON file containing
presentation tokens, issuer keys, and expected verified claims — suitable for
testing the Go sdjwt verifier.

Usage (via Docker — see Dockerfile):
    docker build -t sdjwt-extract testdata/
    docker run --rm -v "$PWD/testdata:/output" sdjwt-extract
"""

import argparse
import json
import sys
import traceback
from pathlib import Path

from sd_jwt.holder import SDJWTHolder
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.verifier import SDJWTVerifier
from sd_jwt.utils.demo_utils import get_jwk, load_yaml_settings
from sd_jwt.utils.yaml_specification import load_yaml_specification


def process_testcase(name, source, spec, settings):
    """Run the full SD-JWT flow for one test case and return the extracted data."""
    local_settings = dict(settings)
    local_settings.update(spec.get("settings_override", {}))

    seed = local_settings["random_seed"]
    demo_keys = get_jwk(local_settings["key_settings"], True, seed)
    use_decoys = spec.get("add_decoy_claims", False)
    serialization_format = spec.get("serialization_format", "compact")
    sign_alg = spec.get("sign_alg", "ES256")
    has_key_binding = spec.get("key_binding", False)

    extra_header_parameters = {"typ": "testcase+sd-jwt"}
    extra_header_parameters.update(spec.get("extra_header_parameters", {}))

    # --- Issuer ---
    user_claims = {"iss": local_settings["identifiers"]["issuer"]}
    user_claims.update(spec["user_claims"])

    SDJWTIssuer.unsafe_randomness = True
    sdjwt_at_issuer = SDJWTIssuer(
        user_claims,
        demo_keys["issuer_keys"],
        demo_keys["holder_key"] if has_key_binding else None,
        sign_alg=sign_alg,
        add_decoy_claims=use_decoys,
        serialization_format=serialization_format,
        extra_header_parameters=extra_header_parameters,
    )

    output_issuance = sdjwt_at_issuer.sd_jwt_issuance

    # --- Holder ---
    sdjwt_at_holder = SDJWTHolder(
        output_issuance,
        serialization_format=serialization_format,
    )

    kb_nonce = local_settings.get("key_binding_nonce", "1234567890")
    kb_aud = local_settings["identifiers"]["verifier"]

    sdjwt_at_holder.create_presentation(
        spec["holder_disclosed_claims"],
        kb_nonce if has_key_binding else None,
        kb_aud if has_key_binding else None,
        demo_keys["holder_key"] if has_key_binding else None,
    )

    output_holder = sdjwt_at_holder.sd_jwt_presentation

    # --- Verifier (Python-side validation) ---
    def cb_get_issuer_key(issuer, header_parameters):
        return demo_keys["issuer_public_keys"]

    sdjwt_at_verifier = SDJWTVerifier(
        output_holder,
        cb_get_issuer_key,
        kb_aud if has_key_binding else None,
        kb_nonce if has_key_binding else None,
        serialization_format=serialization_format,
    )
    verified = sdjwt_at_verifier.get_verified_payload()

    # Build expected claims.
    # Test cases have expect_verified_user_claims; examples may not.
    if "expect_verified_user_claims" in spec:
        expected_claims = dict(spec["expect_verified_user_claims"])
        expected_claims["iss"] = local_settings["identifiers"]["issuer"]

        if has_key_binding:
            expected_claims["cnf"] = {
                "jwk": demo_keys["holder_key"].export_public(as_dict=True)
            }

        assert verified == expected_claims, (
            f"Python verification mismatch for {name}:\n"
            f"  got:    {json.dumps(verified, indent=2)}\n"
            f"  expect: {json.dumps(expected_claims, indent=2)}"
        )
    else:
        # For examples without explicit expected output, use the verifier result.
        expected_claims = verified

    # --- Extract data for Go tests ---
    # Get the first issuer key's public JWK
    issuer_pub_jwk = json.loads(demo_keys["issuer_keys"][0].export_public())

    result = {
        "name": name,
        "source": source,
        "serialization_format": serialization_format,
        "sign_alg": sign_alg,
        "key_binding": has_key_binding,
        "issuer_public_key_jwk": issuer_pub_jwk,
        "sd_jwt_presentation": output_holder,
        "expected_verified_claims": expected_claims,
        "iat": local_settings.get("iat", 1683000000),
        "exp": local_settings.get("exp", 1883000000),
    }

    if has_key_binding:
        result["kb_nonce"] = kb_nonce
        result["kb_aud"] = kb_aud
        result["holder_public_key_jwk"] = json.loads(
            demo_keys["holder_key"].export_public()
        )

    return result


def discover_cases(repo_dir):
    """Find all specification.yml files in testcases/ and examples/."""
    cases = []

    for source_dir, source_label in [
        (repo_dir / "tests" / "testcases", "testcases"),
        (repo_dir / "examples", "examples"),
    ]:
        if not source_dir.exists():
            print(f"Warning: {source_dir} not found, skipping", file=sys.stderr)
            continue

        settings_file = source_dir / "settings.yml"
        if not settings_file.exists():
            print(
                f"Warning: {settings_file} not found, skipping {source_label}",
                file=sys.stderr,
            )
            continue

        settings = load_yaml_settings(settings_file)

        for spec_file in sorted(source_dir.glob("*/specification.yml")):
            case_name = spec_file.parent.name
            spec = load_yaml_specification(spec_file)
            cases.append((case_name, source_label, spec, settings))

    return cases


def main():
    parser = argparse.ArgumentParser(
        description="Extract SD-JWT test vectors for Go testing"
    )
    parser.add_argument(
        "--repo-dir",
        type=Path,
        required=True,
        help="Path to the sd-jwt-python repository clone",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("owf_reference_testcases.json"),
        help="Output JSON file path",
    )
    args = parser.parse_args()

    cases = discover_cases(args.repo_dir)
    print(f"Found {len(cases)} test cases", file=sys.stderr)

    results = []
    errors = []

    for case_name, source_label, spec, settings in cases:
        try:
            result = process_testcase(case_name, source_label, spec, settings)
            results.append(result)
            print(f"  OK: {source_label}/{case_name}", file=sys.stderr)
        except Exception as e:
            errors.append((case_name, source_label, str(e)))
            print(
                f"  FAIL: {source_label}/{case_name}: {e}",
                file=sys.stderr,
            )
            traceback.print_exc(file=sys.stderr)

    # Ensure output directory exists
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)

    print(
        f"\nWrote {len(results)} test cases to {args.output}",
        file=sys.stderr,
    )
    if errors:
        print(f"{len(errors)} test cases failed:", file=sys.stderr)
        for name, source, err in errors:
            print(f"  {source}/{name}: {err}", file=sys.stderr)

    # Exit with error if any cases failed
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
