"""Issue a mso_mdoc credential.

This module implements ISO/IEC 18013-5:2021 compliant mobile document (mDoc)
credential issuance using the isomdl-uniffi library. The implementation follows
the mDoc format specification for mobile driver's licenses and other mobile
identity documents as defined in ISO 18013-5.

Key Protocol Compliance:
- ISO/IEC 18013-5:2021 - Mobile driving licence (mDL) application
- RFC 8152 - CBOR Object Signing and Encryption (COSE)
- RFC 9052 - CBOR Object Signing and Encryption (COSE): Structures and Process
- RFC 8949 - Concise Binary Object Representation (CBOR)
"""

import json
import logging
import re
import ast
from typing import Any, Dict, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.storage.error import StorageError

from oid4vc.cred_processor import CredProcessorError, Issuer
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult

from .key_generation import generate_ec_key_pair
from .mdoc.issuer import isomdl_mdoc_sign
from .storage import MdocStorageManager

LOGGER = logging.getLogger(__name__)


async def resolve_signing_key_for_credential(
    profile: Profile,
    session: ProfileSession,
    verification_method: Optional[str] = None,
) -> dict:
    """Resolve a signing key for credential issuance.

    This function implements ISO 18013-5 § 7.2.4 requirements for issuer
    authentication by resolving cryptographic keys for mDoc signing.
    The keys must support ECDSA with P-256 curve (ES256) as per
    ISO 18013-5 § 9.1.3.5 and RFC 7518 § 3.4.

    Protocol Compliance:
    - ISO 18013-5 § 7.2.4: Issuer authentication mechanisms
    - ISO 18013-5 § 9.1.3.5: Cryptographic algorithms for mDoc
    - RFC 7517: JSON Web Key (JWK) format
    - RFC 7518 § 3.4: ES256 signature algorithm

    Args:
        profile: The profile for storage access
        verification_method: Optional verification method URI

    Returns:
        JWK dictionary with private key component
    """
    storage_manager = MdocStorageManager(profile)

    if verification_method:
        # Parse verification method to get key identifier
        if "#" in verification_method:
            _, key_id = verification_method.split("#", 1)
        else:
            key_id = verification_method

        # Look up in storage using the new get_signing_key method
        stored_key = await storage_manager.get_signing_key(
            session,
            identifier=key_id,
            verification_method=verification_method,
        )

        if stored_key and stored_key.get("jwk"):
            return stored_key["jwk"]

        # If not found or storage unavailable, generate a transient keypair
        private_key_pem, public_key_pem, jwk = generate_ec_key_pair()

        # Persist the generated key
        key_metadata = {
            "jwk": jwk,
            "public_key_pem": public_key_pem,
            "private_key_pem": private_key_pem,
            "verification_method": verification_method,
            "key_id": key_id,
            "key_type": "EC",
            "curve": "P-256",
            "purpose": "signing",
        }
        await storage_manager.store_signing_key(
            session,
            key_id=verification_method or key_id,
            key_metadata=key_metadata,
        )
        LOGGER.info("Persisted generated signing key: %s", key_id)

        return jwk

    # Fall back to default key
    stored_key = await storage_manager.get_default_signing_key(session)
    if stored_key and stored_key.get("jwk"):
        return stored_key["jwk"]

    # Generate a default key if none exists
    private_key_pem, public_key_pem, jwk = generate_ec_key_pair()

    key_metadata = {
        "jwk": jwk,
        "public_key_pem": public_key_pem,
        "private_key_pem": private_key_pem,
        "key_id": "default",
        "key_type": "EC",
        "curve": "P-256",
        "purpose": "signing",
        "is_default": True,
    }

    try:
        await storage_manager.store_signing_key(
            session, key_id="default", key_metadata=key_metadata
        )
    except StorageError as e:
        LOGGER.warning("Unable to persist default signing key: %s", e)

    return jwk


class MsoMdocCredProcessor(Issuer):
    """Credential processor class for mso_mdoc credential format."""

    def _validate_and_get_doctype(
        self, body: Dict[str, Any], supported: SupportedCredential
    ) -> str:
        """Validate and extract doctype from request and configuration.

        Validates the document type identifier according to ISO 18013-5 § 8.3.2.1.2.1
        requirements and OpenID4VCI 1.0 § E.1.1 specification.

        Args:
            body: Request body containing credential issuance parameters
            supported: Supported credential configuration with format data

        Returns:
            Validated doctype string (e.g., "org.iso.18013.5.1.mDL")

        Raises:
            CredProcessorError: If doctype validation fails with detailed context
        """
        doctype_from_request = body.get("doctype")
        doctype_from_config = (
            supported.format_data.get("doctype") if supported.format_data else None
        )

        if not doctype_from_request and not doctype_from_config:
            raise CredProcessorError(
                "Document type (doctype) is required for mso_mdoc format. "
                "Provide doctype in request body or credential configuration. "
                "See OpenID4VCI 1.0 § E.1.1 and ISO 18013-5 § 8.3.2.1.2.1"
            )

        # Use doctype from request if provided, otherwise from configuration
        doctype = doctype_from_request or doctype_from_config

        if doctype_from_request and doctype_from_config:
            if doctype_from_request != doctype_from_config:
                raise CredProcessorError(
                    f"Document type mismatch: request contains '{doctype_from_request}' "
                    f"but credential configuration specifies '{doctype_from_config}'. "
                    "Ensure consistency between request and credential configuration."
                )

        # Validate doctype format (basic ISO format check)
        if not doctype or not isinstance(doctype, str):
            raise CredProcessorError(
                f"Invalid doctype format: expected non-empty string, got {type(doctype).__name__}"
            )

        if not doctype.startswith("org.iso."):
            LOGGER.warning(
                "Document type '%s' does not follow ISO format convention (org.iso.*)",
                doctype,
            )

        return doctype

    def _extract_device_key(
        self, pop: PopResult, ex_record: OID4VCIExchangeRecord
    ) -> Optional[str]:
        """Extract device authentication key from proof of possession or exchange record.

        Extracts and validates the device key for holder binding according to
        ISO 18013-5 § 9.1.3.4 device authentication requirements and
        OpenID4VCI proof of possession mechanisms.

        Args:
            pop: Proof of possession result containing holder key information
            ex_record: Exchange record with credential issuance context

        Returns:
            Serialized device key string (JWK JSON or key identifier), or None if unavailable

        Raises:
            CredProcessorError: If device key format is invalid or unsupported
        """
        # Priority order: holder JWK > holder key ID > verification method from record
        device_candidate = (
            pop.holder_jwk or pop.holder_kid or ex_record.verification_method
        )

        if isinstance(device_candidate, dict):
            # JWK provided by holder
            return json.dumps(device_candidate)
        elif isinstance(device_candidate, str):
            # If a DID with fragment, prefer fragment (key id); otherwise raw string
            m = re.match(r"did:(.+?):(.+?)(?:#(.*))?$", device_candidate)
            if m:
                return m.group(3) if m.group(3) else device_candidate
            else:
                return device_candidate

        return None

    def _build_headers(
        self, doctype: str, device_key_str: Optional[str]
    ) -> Dict[str, Any]:
        """Build mso_mdoc headers according to OID4VCI specification."""
        headers = {"doctype": doctype}
        if device_key_str:
            headers["deviceKey"] = device_key_str
        return headers

    async def _resolve_signing_key(
        self,
        context: AdminRequestContext,
        session: Any,
        verification_method: Optional[str],
    ) -> Dict[str, Any]:
        """Resolve the signing key for credential issuance."""
        storage_manager = MdocStorageManager(context.profile)

        if verification_method:
            # Use verification method to resolve signing key
            if "#" in verification_method:
                _, key_id = verification_method.split("#", 1)
            else:
                key_id = verification_method

            key_data = await storage_manager.get_signing_key(
                session,
                identifier=key_id,
                verification_method=verification_method,
            )

            if key_data:
                LOGGER.info(
                    "Using signing key from verification method: %s",
                    verification_method,
                )
                return key_data

        # Fall back to default signing key from storage
        key_data = await storage_manager.get_default_signing_key(session)
        if key_data:
            LOGGER.info("Using default signing key")
            return key_data

        # Generate new default key if none exists
        await resolve_signing_key_for_credential(
            context.profile, session
        )
        LOGGER.info("Generated new default signing key")

        key_data = await storage_manager.get_default_signing_key(session)
        if key_data:
            return key_data

        raise CredProcessorError("Failed to resolve signing key")

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Return signed credential in CBOR format.

        Issues an ISO 18013-5 compliant mDoc credential using the mobile
        security object (MSO) format. The credential is CBOR-encoded and
        follows the issuerSigned structure defined in ISO 18013-5.

        Protocol Compliance:
        - OpenID4VCI 1.0 § 7.3.1: Credential Response for mso_mdoc format
        - OpenID4VCI 1.0 Appendix E.1.1: mso_mdoc Credential format identifier
        - ISO 18013-5 § 8.3: Mobile document structure
        - ISO 18013-5 § 9.1.2: IssuerSigned data structure
        - ISO 18013-5 § 9.1.3: Mobile security object (MSO)
        - RFC 8949: CBOR encoding for binary efficiency
        - RFC 8152: COSE signing for cryptographic protection

        OpenID4VCI 1.0 § E.1.1: mso_mdoc Format
        https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
        """
        if not supported.format_data:
            raise CredProcessorError("Supported credential must have format_data")

        try:
            # Validate and extract doctype
            doctype = self._validate_and_get_doctype(body, supported)

            # Extract device key for holder binding
            device_key_str = self._extract_device_key(pop, ex_record)

            # Build mso_mdoc headers
            headers = self._build_headers(doctype, device_key_str)

            # Get payload and verification method
            verification_method = ex_record.verification_method
            payload = ex_record.credential_subject

            # Resolve signing key
            async with context.profile.session() as session:
                key_data = await self._resolve_signing_key(
                    context, session, verification_method
                )
                jwk = key_data.get("jwk")
                key_id = key_data.get("key_id")
                private_key_pem = key_data.get("metadata", {}).get("private_key_pem")

                # Fetch certificate
                storage_manager = MdocStorageManager(context.profile)
                certificate_pem = await storage_manager.get_certificate_for_key(
                    session, key_id
                )

            if not private_key_pem:
                raise CredProcessorError("Private key PEM not found for signing key")

            if not certificate_pem:
                raise CredProcessorError("Certificate PEM not found for signing key")

            # Issue mDoc using isomdl-uniffi library with ISO 18013-5 compliance
            LOGGER.debug(
                "Issuing mso_mdoc with jwk=%s headers=%s payload_keys=%s",
                "<redacted>" if jwk else None,
                headers,
                (list(payload.keys()) if isinstance(payload, dict) else type(payload)),
            )
            mso_mdoc = isomdl_mdoc_sign(
                jwk, headers, payload, certificate_pem, private_key_pem
            )

            # Normalize mDoc result handling for robust string/bytes processing
            mso_mdoc = self._normalize_mdoc_result(mso_mdoc)

            LOGGER.info(
                "Issued mso_mdoc credential with doctype: %s, format: %s",
                doctype,
                supported.format,
            )

        except Exception as ex:
            # Log full exception for debugging before raising a generic error
            LOGGER.exception("mso_mdoc issuance error: %s", ex)
            # Surface the underlying exception text in the CredProcessorError
            raise CredProcessorError(
                f"Failed to issue mso_mdoc credential: {ex}"
            ) from ex

        return mso_mdoc

    def _normalize_mdoc_result(self, result: Any) -> str:
        """Normalize mDoc result handling for robust string/bytes processing.

        Handles various return formats from isomdl-uniffi library including
        string representations of bytes, actual bytes objects, and plain strings.
        Ensures consistent string output for credential storage and transmission.

        Args:
            result: Raw result from isomdl_mdoc_sign operation

        Returns:
            Normalized string representation of the mDoc credential

        Raises:
            CredProcessorError: If result format cannot be normalized
        """
        if result is None:
            raise CredProcessorError(
                "mDoc signing returned None result. "
                "Check key material and payload format."
            )

        # Handle bytes objects
        if isinstance(result, bytes):
            try:
                return result.decode("utf-8")
            except UnicodeDecodeError as e:
                raise CredProcessorError(
                    f"Failed to decode mDoc bytes result: {e}. "
                    "Result may contain binary data requiring base64 encoding."
                ) from e

        # Handle string representations of bytes (e.g., "b'data'")
        if isinstance(result, str):
            # Remove b' prefix and ' suffix if present
            if result.startswith("b'") and result.endswith("'"):
                cleaned = result[2:-1]
                # Handle escaped quotes and other characters
                try:
                    # Use literal_eval to safely parse escape sequences
                    return ast.literal_eval(f"'{cleaned}'")
                except (ValueError, SyntaxError):
                    # Fallback to simple string cleanup
                    return cleaned
            # Remove b" prefix and " suffix if present
            elif result.startswith('b"') and result.endswith('"'):
                cleaned = result[2:-1]
                try:
                    return ast.literal_eval(f'"{cleaned}"')
                except (ValueError, SyntaxError):
                    return cleaned
            else:
                return result

        # Handle other types by converting to string
        try:
            return str(result)
        except Exception as e:
            raise CredProcessorError(
                f"Failed to normalize mDoc result of type {type(result).__name__}: {e}"
            ) from e

    def validate_credential_subject(
        self, supported: SupportedCredential, subject: dict
    ):
        """Validate the credential subject."""
        return True

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported MSO MDOC Credential."""
        return True
