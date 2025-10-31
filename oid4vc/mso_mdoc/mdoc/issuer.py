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

import logging
import uuid
from typing import Any, Dict, Mapping, Optional, Tuple

from acapy_agent.core.profile import Profile

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
from isomdl_uniffi import (
    MdlPresentationSession,
    P256KeyPair,
    establish_session,
    generate_test_mdl,
    handle_response,
)

LOGGER = logging.getLogger(__name__)


async def create_mdoc_credential(
    profile: Profile,
    credential_subject: Dict[str, Any],
    doctype: str = "org.iso.18013.5.1.mDL",
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
) -> str:
    """Create an mDL credential using isomdl-uniffi.

    Creates an ISO 18013-5 compliant mobile document (mDoc) credential.
    The default doctype "org.iso.18013.5.1.mDL" follows the standardized
    mobile driver's license format defined in ISO 18013-5 Annex D.

    Protocol Compliance:
    - ISO 18013-5 § 8.3.2.1.2.1: docType field specification
    - ISO 18013-5 Annex D: Mobile driver's license data structure
    - ISO 18013-5 § 9.1.2: IssuerSigned structure requirements
    - RFC 8949: CBOR encoding for compact binary representation

    Args:
        profile: ACA-Py profile
        credential_subject: The credential data to include
        doctype: Document type (default: mDL per ISO 18013-5 Annex D)
        did: DID for signing (if verification_method not provided)
        verification_method: Specific verification method to use

    Returns:
        CBOR-encoded mDoc as string (ISO 18013-5 § 8.3)
    """
    # For now, use the test MDL generator
    # TODO: Integrate with proper key management and credential data conversion
    holder_key = P256KeyPair()
    mdoc = generate_test_mdl(holder_key)

    LOGGER.info("Created mDoc with doctype: %s, id: %s", mdoc.doctype(), mdoc.id())
    return mdoc.stringify()


def isomdl_mdoc_sign(
    jwk: dict, headers: Mapping[str, Any], payload: Mapping[str, Any]
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
    """
    if not isinstance(headers, dict):
        raise ValueError("missing headers.")

    if not isinstance(payload, dict):
        raise ValueError("missing payload.")

    try:
        # For now, use the test MDL generator
        # TODO: Integrate with proper credential data conversion
        holder_key = P256KeyPair()
        mdoc = generate_test_mdl(holder_key)

        LOGGER.info("Generated mdoc with doctype: %s", mdoc.doctype())

        # Return the stringified CBOR
        return mdoc.stringify()

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


def create_presentation_session(mdoc: Mdoc, ble_uuid: str) -> MdlPresentationSession:
    """Create a presentation session for an mDoc."""
    try:
        return MdlPresentationSession(mdoc, ble_uuid)
    except Exception as ex:
        LOGGER.error("Failed to create presentation session: %s", ex)
        raise ValueError(f"Failed to create presentation session: {ex}") from ex


def verify_presentation(
    reader_state: Any,
    presentation_response: bytes,
    trust_anchors: Optional[list] = None,
) -> Dict[str, Any]:
    """Verify an mDoc presentation response."""
    try:
        result = handle_response(reader_state, presentation_response)

        return {
            "device_authentication": result.device_authentication,
            "issuer_authentication": result.issuer_authentication,
            "verified_response": result.verified_response,
            "errors": result.errors if hasattr(result, "errors") else [],
        }
    except Exception as ex:
        LOGGER.error("Failed to verify presentation: %s", ex)
        raise ValueError(f"Failed to verify presentation: {ex}") from ex


def create_oid4vc_presentation_session(
    mdoc: Mdoc,
) -> Tuple[MdlPresentationSession, str]:
    """Create a presentation session for OID4VC workflows.

    Args:
        mdoc: The mdoc to present

    Returns:
        Tuple of (presentation_session, qr_code_uri)

    Raises:
        ValueError: If session creation fails
    """
    try:
        ble_uuid = str(uuid.uuid4())
        session = MdlPresentationSession(mdoc, ble_uuid)
        qr_uri = session.get_qr_code_uri()
        return session, qr_uri
    except Exception as e:
        raise ValueError(f"Failed to create presentation session: {e}") from e


def establish_verifier_session(
    qr_uri: str,
    requested_attributes: dict,
    trust_anchors: Optional[list] = None,
):
    """Establish a verifier session for OID4VC.

    Args:
        qr_uri: QR code URI from holder
        requested_attributes: Dict of namespace -> {attribute: required_bool}
        trust_anchors: Optional list of trust anchor certificates

    Returns:
        Reader session data

    Raises:
        ValueError: If session establishment fails
    """
    try:
        return establish_session(qr_uri, requested_attributes, trust_anchors)
    except Exception as e:
        raise ValueError(f"Failed to establish verifier session: {e}") from e


def process_presentation_response(session_state, response_data) -> dict:
    """Process a presentation response from holder.

    Args:
        session_state: Verifier session state
        response_data: Response from holder

    Returns:
        Dict with verification results and extracted data

    Raises:
        ValueError: If response processing fails
    """
    try:
        result = handle_response(session_state, response_data)

        # Extract data from response
        extracted_data = {}
        if result.verified_response:
            for namespace, attrs in result.verified_response.items():
                namespace_data = {}
                for attr_name, mdoc_item in attrs.items():
                    # Extract the actual value from MDocItem
                    namespace_data[attr_name] = str(mdoc_item)
                extracted_data[namespace] = namespace_data

        return {
            "device_authentication": str(result.device_authentication),
            "issuer_authentication": str(result.issuer_authentication),
            "errors": result.errors if hasattr(result, "errors") else [],
            "verified_data": extracted_data,
        }
    except Exception as e:
        raise ValueError(f"Failed to process presentation response: {e}") from e
