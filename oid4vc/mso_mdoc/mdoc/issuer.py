"""Operations supporting mso_mdoc issuance using isomdl-uniffi.

This module implements ISO/IEC 18013-5:2021 compliant mobile document issuance
using the isomdl-uniffi Rust library via UniFFI bindings. It provides
cryptographic operations for creating signed mobile documents (mDocs) including
mobile driver's licenses (mDLs).

Protocol Compliance:
- OpenID4VCI 1.0 § E.1.1: mso_mdoc Credential Format
  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
- ISO/IEC 18013-5:2021 § 8: Mobile document format and structure
- ISO/IEC 18013-5:2021 § 9: Cryptographic mechanisms
- RFC 8152: CBOR Object Signing and Encryption (COSE)
- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 7517: JSON Web Key (JWK) format for key material

The mso_mdoc format is defined in OpenID4VCI 1.0 Appendix E.1.1 as a specific
credential format that follows the ISO 18013-5 mobile document structure.
"""

import json
import logging
from typing import Any, Mapping

import cbor2

# ISO 18013-5 § 8.4: Presentation session
# ISO 18013-5 § 9.1.3.5: ECDSA P-256 key pairs
# ISO 18013-5 § 8.4.1: Session establishment
# ISO 18013-5 § 8.4.2: Response handling
# Test mDL generation for ISO 18013-5 compliance
# Import ISO 18013-5 compliant mDoc operations from isomdl-uniffi
# These provide cryptographically secure implementations of:
# - mDoc creation and signing (ISO 18013-5 § 8.3)
# - Presentation protocols (ISO 18013-5 § 8.4)
# - P-256 elliptic curve cryptography (ISO 18013-5 § 9.1.3.5)
from isomdl_uniffi import Mdoc  # ISO 18013-5 § 8.3: Mobile document structure

LOGGER = logging.getLogger(__name__)


def isomdl_mdoc_sign(
    jwk: dict,
    headers: Mapping[str, Any],
    payload: Mapping[str, Any],
    iaca_cert_pem: str,
    iaca_key_pem: str,
) -> str:
    """Create a signed mso_mdoc using isomdl-uniffi.

    Creates and signs a mobile security object (MSO) compliant with
    ISO 18013-5 § 9.1.3. The signing uses ECDSA with P-256 curve (ES256)
    as mandated by ISO 18013-5 § 9.1.3.5 for mDoc cryptographic protection.

    Protocol Compliance:
    - ISO 18013-5 § 9.1.3: Mobile security object (MSO) structure
    - ISO 18013-5 § 9.1.3.5: ECDSA P-256 signature algorithm
    - RFC 8152: COSE signing for MSO authentication
    - RFC 7517: JWK format for key material input

    Args:
        jwk: The signing key in JWK format
        headers: Header parameters including doctype
        payload: The credential data to sign
        iaca_cert_pem: Issuer certificate in PEM format
        iaca_key_pem: Issuer private key in PEM format

    Returns:
        CBOR-encoded mDoc as string
    """
    if not isinstance(headers, dict):
        raise ValueError("missing headers.")

    if not isinstance(payload, dict):
        raise ValueError("missing payload.")

    try:
        doctype = headers.get("doctype")
        holder_jwk = json.dumps(jwk)

        LOGGER.info(f"holder_jwk: {holder_jwk}")
        LOGGER.info(f"iaca_cert_pem length: {len(iaca_cert_pem)}")
        LOGGER.info(f"iaca_key_pem length: {len(iaca_key_pem)}")

        if doctype == "org.iso.18013.5.1.mDL":
            namespaces = {}

            # Handle mDL namespace
            # Extract mDL items from payload if wrapped in namespace
            mdl_payload = payload.get("org.iso.18013.5.1", payload)
            mdl_ns = {}
            for k, v in mdl_payload.items():
                # Skip nested namespaces if we are processing the wrapper
                if k == "org.iso.18013.5.1.aamva":
                    continue
                mdl_ns[k] = cbor2.dumps(v)
            namespaces["org.iso.18013.5.1"] = mdl_ns

            # Handle AAMVA namespace
            aamva_payload = payload.get("org.iso.18013.5.1.aamva")
            if aamva_payload:
                aamva_ns = {}
                for k, v in aamva_payload.items():
                    aamva_ns[k] = cbor2.dumps(v)
                namespaces["org.iso.18013.5.1.aamva"] = aamva_ns

            LOGGER.info(f"Creating mdoc with namespaces: {list(namespaces.keys())}")

            mdoc = Mdoc.create_and_sign(
                doctype,
                namespaces,
                holder_jwk,
                iaca_cert_pem,
                iaca_key_pem,
            )
        else:
            # For generic doctypes, we assume the payload belongs to the namespace
            # equal to the doctype. This supports the generic use case where claims
            # are in the main namespace

            # Encode payload values to CBOR bytes as expected by create_and_sign
            encoded_payload = {}
            for k, v in payload.items():
                encoded_payload[k] = cbor2.dumps(v)

            namespaces = {doctype: encoded_payload}

            mdoc = Mdoc.create_and_sign(
                doctype,
                namespaces,
                holder_jwk,
                iaca_cert_pem,
                iaca_key_pem,
            )

        LOGGER.info("Generated mdoc with doctype: %s", mdoc.doctype())

        # Return the stringified CBOR
        mdoc_b64 = mdoc.stringify()
        
        # Patch: isomdl returns 'issuer_auth' but spec requires 'issuerAuth'
        # We decode, fix the key, and re-encode.
        try:
            import base64
            # Add padding if needed
            pad = len(mdoc_b64) % 4
            if pad > 0:
                mdoc_b64_padded = mdoc_b64 + "=" * (4 - pad)
            else:
                mdoc_b64_padded = mdoc_b64
                
            mdoc_bytes = base64.urlsafe_b64decode(mdoc_b64_padded)
            mdoc_map = cbor2.loads(mdoc_bytes)
            
            patched = False
            if "issuer_auth" in mdoc_map:
                LOGGER.info("Patching issuer_auth to issuerAuth in mdoc")
                mdoc_map["issuerAuth"] = mdoc_map.pop("issuer_auth")
                patched = True
            
            if "namespaces" in mdoc_map:
                LOGGER.info("Patching namespaces to nameSpaces in mdoc")
                namespaces = mdoc_map.pop("namespaces")
                # Convert dict of items to list of items as per ISO 18013-5
                fixed_namespaces = {}
                for ns, items in namespaces.items():
                    if isinstance(items, dict):
                        fixed_namespaces[ns] = list(items.values())
                    else:
                        fixed_namespaces[ns] = items
                mdoc_map["nameSpaces"] = fixed_namespaces
                patched = True

            if patched:
                # Construct IssuerSigned object (filter out internal fields like 'id', 'mso')
                issuer_signed = {}
                if "issuerAuth" in mdoc_map:
                    issuer_signed["issuerAuth"] = mdoc_map["issuerAuth"]
                if "nameSpaces" in mdoc_map:
                    issuer_signed["nameSpaces"] = mdoc_map["nameSpaces"]
                
                # Re-encode
                patched_bytes = cbor2.dumps(issuer_signed)
                patched_b64 = base64.urlsafe_b64encode(patched_bytes).decode("ascii").rstrip("=")
                return patched_b64
                
        except Exception as e:
            LOGGER.warning(f"Failed to patch mdoc keys: {e}")
            # Fallback to original if patching fails
            
        return mdoc_b64

    except Exception as ex:
        LOGGER.error("Failed to create mdoc with isomdl: %s", ex)
        raise ValueError(f"Failed to create mdoc: {ex}") from ex


def parse_mdoc(cbor_data: str) -> Mdoc:
    """Parse a CBOR-encoded mDoc string into an Mdoc object."""
    try:
        return Mdoc.from_string(cbor_data)
    except Exception as ex:
        LOGGER.error("Failed to parse mdoc: %s", ex)
        raise ValueError(f"Failed to parse mdoc: {ex}") from ex
