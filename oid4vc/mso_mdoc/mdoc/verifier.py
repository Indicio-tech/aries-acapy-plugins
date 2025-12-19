"""Mdoc Verifier implementation using isomdl-uniffi."""

import asyncio
import base64
import json
import logging
import os
from abc import abstractmethod
from typing import Any, List, Optional, Protocol

# Import isomdl_uniffi library directly
import isomdl_uniffi
from acapy_agent.core.profile import Profile

from oid4vc.config import Config
from oid4vc.cred_processor import (
    CredVerifier,
    PresVerifier,
    PresVerifierError,
    VerifyResult,
)
from oid4vc.models.presentation import OID4VPPresentation

LOGGER = logging.getLogger(__name__)


def extract_mdoc_item_value(item: Any) -> Any:
    """Extract the actual value from an MDocItem enum variant.

    MDocItem is a Rust enum exposed via UniFFI with variants:
    - TEXT(str)
    - BOOL(bool)
    - INTEGER(int)
    - ARRAY(List[MDocItem])
    - ITEM_MAP(Dict[str, MDocItem])

    Each variant stores its value in _values[0].
    """
    if item is None:
        return None

    # Check if it's an MDocItem variant by checking for _values attribute
    if hasattr(item, "_values") and item._values:
        inner_value = item._values[0]

        # Handle nested structures recursively
        if isinstance(inner_value, dict):
            return {k: extract_mdoc_item_value(v) for k, v in inner_value.items()}
        elif isinstance(inner_value, list):
            return [extract_mdoc_item_value(v) for v in inner_value]
        else:
            return inner_value

    # Already a plain value
    return item


def extract_verified_claims(verified_response: dict) -> dict:
    """Extract claims from MdlReaderVerifiedData.verified_response.

    The verified_response is structured as:
    dict[str, dict[str, MDocItem]]
    e.g. {"org.iso.18013.5.1": {"given_name": MDocItem.TEXT("Alice"), ...}}

    This function converts it to:
    {"org.iso.18013.5.1": {"given_name": "Alice", ...}}
    """
    claims = {}
    for namespace, elements in verified_response.items():
        ns_claims = {}
        for element_name, mdoc_item in elements.items():
            ns_claims[element_name] = extract_mdoc_item_value(mdoc_item)
        claims[namespace] = ns_claims
    return claims


class TrustStore(Protocol):
    """Protocol for retrieving trust anchors."""

    @abstractmethod
    def get_trust_anchors(self) -> List[str]:
        """Retrieve trust anchors as PEM strings."""
        ...


class FileTrustStore:
    """Trust store implementation backed by a directory of PEM files."""

    def __init__(self, path: str):
        """Initialize the file trust store."""
        self.path = path

    def get_trust_anchors(self) -> List[str]:
        """Retrieve trust anchors from the directory."""
        anchors = []
        if not os.path.isdir(self.path):
            LOGGER.warning(f"Trust store path {self.path} is not a directory.")
            return anchors

        for filename in os.listdir(self.path):
            if filename.endswith(".pem") or filename.endswith(".crt"):
                try:
                    with open(os.path.join(self.path, filename), "r") as f:
                        anchors.append(f.read())
                except Exception as e:
                    LOGGER.warning(f"Failed to read trust anchor {filename}: {e}")
        return anchors


class WalletTrustStore:
    """Trust store implementation backed by Askar wallet storage.

    This implementation stores trust anchor certificates in the ACA-Py
    wallet using the MdocStorageManager, providing secure storage that
    doesn't require filesystem access or static certificate files.
    """

    def __init__(self, profile: Profile):
        """Initialize the wallet trust store.

        Args:
            profile: ACA-Py profile for accessing wallet storage
        """
        self.profile = profile
        self._cached_anchors: Optional[List[str]] = None

    def get_trust_anchors(self) -> List[str]:
        """Retrieve trust anchors from wallet storage.

        Note: This method is synchronous to match the TrustStore protocol,
        but internally runs an async operation. The cache helps minimize
        repeated async calls during verification.

        Returns:
            List of PEM-encoded trust anchor certificates

        Raises:
            RuntimeError: If called from async context without cache.
                Call refresh_cache() before verification operations.
        """
        # Use cached value if available
        if self._cached_anchors is not None:
            return self._cached_anchors

        # Run async retrieval synchronously
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're in an async context - cache must be populated first
                raise RuntimeError(
                    "WalletTrustStore.get_trust_anchors called from async context "
                    "without cache. Call await refresh_cache() before verification."
                )
            else:
                self._cached_anchors = loop.run_until_complete(
                    self._fetch_trust_anchors()
                )
        except RuntimeError as e:
            if "async context" in str(e):
                raise  # Re-raise our custom error
            # No event loop, create one
            self._cached_anchors = asyncio.run(self._fetch_trust_anchors())

        return self._cached_anchors or []

    async def refresh_cache(self) -> List[str]:
        """Refresh the cached trust anchors from wallet storage.

        This method should be called before verification operations
        when running in an async context.

        Returns:
            List of PEM-encoded trust anchor certificates
        """
        self._cached_anchors = await self._fetch_trust_anchors()
        return self._cached_anchors

    async def _fetch_trust_anchors(self) -> List[str]:
        """Fetch trust anchors from wallet storage.

        Returns:
            List of PEM-encoded trust anchor certificates
        """
        # Import here to avoid circular imports
        from mso_mdoc.storage import MdocStorageManager

        storage_manager = MdocStorageManager(self.profile)
        async with self.profile.session() as session:
            anchors = await storage_manager.get_all_trust_anchor_pems(session)
            LOGGER.debug("Loaded %d trust anchors from wallet", len(anchors))
            return anchors

    def clear_cache(self) -> None:
        """Clear the cached trust anchors."""
        self._cached_anchors = None


def _is_preverified_claims_dict(credential: Any) -> bool:
    """Check if credential is a pre-verified claims dict from presentation.

    Args:
        credential: The credential to check

    Returns:
        True if credential is a pre-verified claims dict
    """
    if not isinstance(credential, dict):
        return False
    return any(
        key.startswith("org.iso.") or key == "status"
        for key in credential.keys()
    )


def _parse_string_credential(credential: str) -> Optional[Any]:
    """Parse a string credential into an Mdoc object.

    Tries multiple formats: hex, base64url IssuerSigned, base64url DeviceResponse.

    Args:
        credential: String credential to parse

    Returns:
        Parsed Mdoc object or None if parsing fails
    """
    # Try hex first (full DeviceResponse)
    try:
        if all(c in "0123456789abcdefABCDEF" for c in credential):
            LOGGER.debug("Trying to parse credential as hex DeviceResponse")
            return isomdl_uniffi.Mdoc.from_string(credential)
    except Exception as hex_err:
        LOGGER.debug(f"Hex parsing failed: {hex_err}")

    # Try base64url-encoded IssuerSigned
    try:
        LOGGER.debug("Trying to parse credential as base64url IssuerSigned")
        return isomdl_uniffi.Mdoc.new_from_base64url_encoded_issuer_signed(
            credential, "verified-inner"
        )
    except Exception as issuer_signed_err:
        LOGGER.debug(f"IssuerSigned parsing failed: {issuer_signed_err}")

    # Try base64url decoding to hex, then DeviceResponse parsing
    try:
        LOGGER.debug("Trying to parse credential as base64url DeviceResponse")
        padded = (
            credential + "=" * (4 - len(credential) % 4)
            if len(credential) % 4
            else credential
        )
        standard_b64 = padded.replace("-", "+").replace("_", "/")
        decoded_bytes = base64.b64decode(standard_b64)
        return isomdl_uniffi.Mdoc.from_string(decoded_bytes.hex())
    except Exception as b64_err:
        LOGGER.debug(f"Base64 parsing failed: {b64_err}")

    # Last resort: try direct string parsing
    try:
        return isomdl_uniffi.Mdoc.from_string(credential)
    except Exception:
        return None


def _extract_mdoc_claims(mdoc: Any) -> dict:
    """Extract claims from an Mdoc object.

    Args:
        mdoc: The Mdoc object

    Returns:
        Dictionary of namespaced claims
    """
    claims = {}
    try:
        details = mdoc.details()
        LOGGER.debug(f"mdoc details keys: {list(details.keys())}")
        for namespace, elements in details.items():
            ns_claims = {}
            for element in elements:
                if element.value:
                    try:
                        ns_claims[element.identifier] = json.loads(element.value)
                    except json.JSONDecodeError:
                        ns_claims[element.identifier] = element.value
                else:
                    ns_claims[element.identifier] = None
            claims[namespace] = ns_claims
    except Exception as e:
        LOGGER.warning(f"Failed to extract claims from mdoc: {e}")
    return claims


class MsoMdocCredVerifier(CredVerifier):
    """Verifier for mso_mdoc credentials."""

    def __init__(self, trust_store: Optional[TrustStore] = None):
        """Initialize the credential verifier."""
        self.trust_store = trust_store

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ) -> VerifyResult:
        """Verify an mso_mdoc credential.

        For mso_mdoc format, credentials can arrive in two forms:
        1. Raw credential (bytes/hex string) - parsed and verified via Rust library
        2. Pre-verified claims dict - already verified by verify_presentation,
           contains namespaced claims extracted from DeviceResponse

        Args:
            profile: The profile for context
            credential: The credential to verify (bytes, hex string, or claims dict)

        Returns:
            VerifyResult: The verification result
        """
        try:
            # Check if credential is pre-verified claims dict
            if _is_preverified_claims_dict(credential):
                LOGGER.debug("Credential is pre-verified claims dict from presentation")
                return VerifyResult(verified=True, payload=credential)

            # Parse credential to Mdoc object
            mdoc = None
            if isinstance(credential, str):
                mdoc = _parse_string_credential(credential)
            elif isinstance(credential, bytes):
                mdoc = isomdl_uniffi.Mdoc.from_string(credential.hex())

            if not mdoc:
                return VerifyResult(
                    verified=False, payload={"error": "Invalid credential format"}
                )

            # Refresh trust store cache if needed
            if self.trust_store and isinstance(self.trust_store, WalletTrustStore):
                await self.trust_store.refresh_cache()

            trust_anchors = (
                self.trust_store.get_trust_anchors() if self.trust_store else None
            )

            # Verify issuer signature
            try:
                verification_result = mdoc.verify_issuer_signature(trust_anchors, True)

                if verification_result.verified:
                    claims = _extract_mdoc_claims(mdoc)
                    payload = {
                        "status": "verified",
                        "doctype": mdoc.doctype(),
                        "id": str(mdoc.id()),
                        "issuer_common_name": verification_result.common_name,
                    }
                    payload.update(claims)
                    LOGGER.debug(f"Mdoc Payload: {json.dumps(payload)}")
                    return VerifyResult(verified=True, payload=payload)
                else:
                    return VerifyResult(
                        verified=False,
                        payload={
                            "error": verification_result.error
                            or "Signature verification failed",
                            "doctype": mdoc.doctype(),
                            "id": str(mdoc.id()),
                        },
                    )
            except isomdl_uniffi.MdocVerificationError as e:
                LOGGER.error(f"Issuer signature verification failed: {e}")
                return VerifyResult(
                    verified=False,
                    payload={
                        "error": str(e),
                        "doctype": mdoc.doctype(),
                        "id": str(mdoc.id()),
                    },
                )

        except Exception as e:
            LOGGER.error(f"Failed to parse mdoc credential: {e}")
            return VerifyResult(verified=False, payload={"error": str(e)})


def _normalize_presentation_input(presentation: Any) -> tuple[list, bool]:
    """Normalize presentation input to a list.

    Args:
        presentation: The presentation data

    Returns:
        Tuple of (list of presentations, is_list_input flag)
    """
    if isinstance(presentation, str):
        try:
            parsed = json.loads(presentation)
            if isinstance(parsed, list):
                return parsed, True
        except json.JSONDecodeError:
            pass
        return [presentation], False
    elif isinstance(presentation, list):
        return presentation, True
    return [presentation], False


def _decode_presentation_bytes(pres_item: Any) -> bytes:
    """Decode presentation item to bytes.

    Args:
        pres_item: The presentation item (string or bytes)

    Returns:
        Decoded bytes

    Raises:
        PresVerifierError: If unable to decode to bytes
    """
    if isinstance(pres_item, bytes):
        return pres_item

    if isinstance(pres_item, str):
        # Try base64url decode
        try:
            return base64.urlsafe_b64decode(pres_item + "=" * (-len(pres_item) % 4))
        except (ValueError, TypeError):
            pass
        # Try hex decode
        try:
            return bytes.fromhex(pres_item)
        except (ValueError, TypeError):
            pass

    raise PresVerifierError("Presentation must be bytes or base64/hex string")


async def _get_oid4vp_verification_params(
    profile: Profile,
    presentation_record: "OID4VPPresentation",
) -> tuple[str, str, str]:
    """Get OID4VP verification parameters.

    Args:
        profile: The profile
        presentation_record: The presentation record

    Returns:
        Tuple of (nonce, client_id, response_uri)
    """
    nonce = presentation_record.nonce
    config = Config.from_settings(profile.settings)

    from oid4vc.did_utils import retrieve_or_create_did_jwk

    async with profile.session() as session:
        jwk = await retrieve_or_create_did_jwk(session)

    client_id = jwk.did

    wallet_id = (
        profile.settings.get("wallet.id")
        if profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    response_uri = (
        f"{config.endpoint}{subpath}/oid4vp/response/"
        f"{presentation_record.presentation_id}"
    )

    return nonce, client_id, response_uri


def _verify_single_presentation(
    response_bytes: bytes,
    nonce: str,
    client_id: str,
    response_uri: str,
    trust_anchors_json: List[str],
) -> Optional[dict]:
    """Verify a single OID4VP presentation.

    Args:
        response_bytes: The presentation bytes
        nonce: The nonce
        client_id: The client ID
        response_uri: The response URI
        trust_anchors_json: JSON-encoded trust anchors

    Returns:
        Verified payload dict if successful, None if failed
    """
    LOGGER.info(
        f"DEBUG: Calling verify_oid4vp_response with:\n"
        f"  nonce={nonce}\n"
        f"  client_id={client_id}\n"
        f"  response_uri={response_uri}\n"
        f"  response_bytes_len={len(response_bytes)}\n"
        f"  response_bytes_hex={response_bytes[:50].hex()}..."
    )

    # Try spec-compliant format (2024) first
    verified_data = isomdl_uniffi.verify_oid4vp_response(
        response_bytes,
        nonce,
        client_id,
        response_uri,
        trust_anchors_json,
        True,
    )

    # If device auth failed but issuer is valid, try legacy format
    if (
        verified_data.device_authentication != isomdl_uniffi.AuthenticationStatus.VALID
        and verified_data.issuer_authentication
        == isomdl_uniffi.AuthenticationStatus.VALID
    ):
        if hasattr(isomdl_uniffi, "verify_oid4vp_response_legacy"):
            LOGGER.info(
                "Device auth failed with spec-compliant format, "
                "trying legacy 2023 format"
            )
            verified_data = isomdl_uniffi.verify_oid4vp_response_legacy(
                response_bytes,
                nonce,
                client_id,
                response_uri,
                trust_anchors_json,
                True,
            )
        else:
            LOGGER.warning(
                "Device auth failed and legacy format not available in isomdl_uniffi"
            )

    return verified_data


class MsoMdocPresVerifier(PresVerifier):
    """Verifier for mso_mdoc presentations (OID4VP)."""

    def __init__(self, trust_store: Optional[TrustStore] = None):
        """Initialize the presentation verifier."""
        self.trust_store = trust_store

    def _parse_jsonpath(self, path: str) -> List[str]:
        """Parse JSONPath to extract segments."""
        # Handle $['namespace']['element'] format
        if "['" in path:
            return [
                p.strip("]['\"")
                for p in path.split("['")
                if p.strip("]['\"") and p != "$"
            ]

        # Handle $.namespace.element format
        clean = path.replace("$", "")
        if clean.startswith("."):
            clean = clean[1:]
        return clean.split(".")

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: OID4VPPresentation,
    ) -> VerifyResult:
        """Verify an mso_mdoc presentation.

        Args:
            profile: The profile for context
            presentation: The presentation data (bytes)
            presentation_record: The presentation record containing request info

        Returns:
            VerifyResult: The verification result
        """
        try:
            # 1. Prepare Trust Anchors
            if self.trust_store and isinstance(self.trust_store, WalletTrustStore):
                await self.trust_store.refresh_cache()

            trust_anchors = (
                self.trust_store.get_trust_anchors() if self.trust_store else []
            )
            trust_anchors_json = [
                json.dumps({"certificate_pem": a, "purpose": "Iaca"})
                for a in trust_anchors
            ]

            # 2. Get verification parameters
            nonce, client_id, response_uri = await _get_oid4vp_verification_params(
                profile, presentation_record
            )

            # 3. Normalize presentation input
            presentations_to_verify, is_list_input = _normalize_presentation_input(
                presentation
            )

            verified_payloads = []

            for pres_item in presentations_to_verify:
                pres_preview = str(pres_item)[:100] if pres_item else "None"
                LOGGER.info(
                    f"DEBUG: vp_token type={type(pres_item).__name__}, "
                    f"len={len(pres_item) if hasattr(pres_item, '__len__') else 'N/A'}, "
                    f"preview={pres_preview}..."
                )

                response_bytes = _decode_presentation_bytes(pres_item)

                verified_data = _verify_single_presentation(
                    response_bytes,
                    nonce,
                    client_id,
                    response_uri,
                    trust_anchors_json,
                )

                if (
                    verified_data.issuer_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                    and verified_data.device_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                ):
                    try:
                        claims = extract_verified_claims(
                            verified_data.verified_response
                        )
                    except Exception as e:
                        LOGGER.warning(f"Failed to extract claims: {e}")
                        claims = {}

                    payload = {
                        "status": "verified",
                        "docType": verified_data.doc_type,
                        "issuer_auth": str(verified_data.issuer_authentication),
                        "device_auth": str(verified_data.device_authentication),
                    }
                    payload.update(claims)
                    verified_payloads.append(payload)
                else:
                    LOGGER.error(
                        "Verification failed: Issuer=%s, Device=%s, Errors=%s",
                        verified_data.issuer_authentication,
                        verified_data.device_authentication,
                        verified_data.errors,
                    )
                    try:
                        claims = extract_verified_claims(
                            verified_data.verified_response
                        )
                    except Exception:
                        claims = {}

                    return VerifyResult(
                        verified=False,
                        payload={
                            "error": verified_data.errors,
                            "issuer_auth": str(verified_data.issuer_authentication),
                            "device_auth": str(verified_data.device_authentication),
                            "claims": claims,
                        },
                    )

            # Return list if input was list, otherwise single item
            payload = verified_payloads
            if not is_list_input and len(verified_payloads) == 1:
                payload = verified_payloads[0]

            return VerifyResult(verified=True, payload=payload)

        except Exception as e:
            LOGGER.exception("Error verifying mdoc presentation")
            return VerifyResult(verified=False, payload={"error": str(e)})


class MdocVerifyResult:
    """Result of mdoc verification."""

    def __init__(
        self,
        verified: bool,
        payload: Optional[dict] = None,
        error: Optional[str] = None,
    ):
        """Initialize the verification result."""
        self.verified = verified
        self.payload = payload
        self.error = error

    def serialize(self):
        """Serialize the result to a dictionary."""
        return {
            "verified": self.verified,
            "payload": self.payload,
            "error": self.error,
        }


def mdoc_verify(
    mso_mdoc: str, trust_anchors: Optional[List[str]] = None
) -> MdocVerifyResult:
    """Verify an mso_mdoc credential.

    Args:
        mso_mdoc: The hex-encoded or base64 encoded mdoc string.
        trust_anchors: Optional list of PEM-encoded trust anchor certificates.

    Returns:
        MdocVerifyResult: The verification result.
    """
    try:
        # Parse the mdoc
        mdoc = isomdl_uniffi.Mdoc.from_string(mso_mdoc)

        # Verify issuer signature
        try:
            # Enable intermediate certificate chaining by default
            verification_result = mdoc.verify_issuer_signature(trust_anchors, True)

            if verification_result.verified:
                return MdocVerifyResult(
                    verified=True,
                    payload={
                        "status": "verified",
                        "doctype": mdoc.doctype(),
                        "issuer_common_name": verification_result.common_name,
                    },
                )
            else:
                return MdocVerifyResult(
                    verified=False,
                    payload={"doctype": mdoc.doctype()},
                    error=verification_result.error or "Signature verification failed",
                )
        except isomdl_uniffi.MdocVerificationError as e:
            return MdocVerifyResult(
                verified=False,
                payload={"doctype": mdoc.doctype()},
                error=str(e),
            )

    except Exception as e:
        return MdocVerifyResult(verified=False, error=str(e))
