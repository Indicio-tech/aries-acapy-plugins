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

        The second case occurs because mso_mdoc presentations (DeviceResponse)
        contain embedded credentials that are verified together with the
        presentation, unlike JWT-VC where presentation and credential are
        verified separately.

        Args:
            profile: The profile for context
            credential: The credential to verify (bytes, hex string, or claims dict)

        Returns:
            VerifyResult: The verification result
        """
        try:
            # If credential is already a dict with namespaced claims structure,
            # it was extracted and verified by verify_presentation.
            # We validate it has the expected structure and return it.
            if isinstance(credential, dict):
                # Check for mso_mdoc namespace structure (e.g., "org.iso.18013.5.1")
                # or verification status markers
                has_namespace = any(
                    key.startswith("org.iso.") or key == "status"
                    for key in credential.keys()
                )
                if has_namespace:
                    LOGGER.debug(
                        "Credential is pre-verified claims dict from presentation"
                    )
                    return VerifyResult(verified=True, payload=credential)

            # Basic parsing check for raw credential data
            mdoc = None
            if isinstance(credential, str):
                # Credential could be:
                # 1. hex-encoded DeviceResponse CBOR
                # 2. base64url-encoded DeviceResponse CBOR
                # 3. base64url-encoded IssuerSigned CBOR (from VP inner credential)

                # Try hex first (full DeviceResponse)
                try:
                    if all(c in "0123456789abcdefABCDEF" for c in credential):
                        LOGGER.debug("Trying to parse credential as hex DeviceResponse")
                        mdoc = isomdl_uniffi.Mdoc.from_string(credential)
                    else:
                        raise ValueError("Not hex, try base64url methods")
                except Exception as hex_err:
                    LOGGER.debug(f"Hex parsing failed: {hex_err}")

                    # Try base64url-encoded IssuerSigned (common for VP inner credentials)
                    try:
                        LOGGER.debug(
                            "Trying to parse credential as base64url IssuerSigned"
                        )
                        # new_from_base64url_encoded_issuer_signed requires (credential, key_alias)
                        # key_alias is a simple string identifier, not critical for verification
                        mdoc = (
                            isomdl_uniffi.Mdoc.new_from_base64url_encoded_issuer_signed(
                                credential, "verified-inner"
                            )
                        )
                    except Exception as issuer_signed_err:
                        LOGGER.debug(
                            f"IssuerSigned parsing failed: {issuer_signed_err}"
                        )

                        # Try base64url decoding to hex, then DeviceResponse parsing
                        try:
                            LOGGER.debug(
                                "Trying to parse credential as base64url DeviceResponse"
                            )
                            padded = (
                                credential + "=" * (4 - len(credential) % 4)
                                if len(credential) % 4
                                else credential
                            )
                            standard_b64 = padded.replace("-", "+").replace("_", "/")
                            decoded_bytes = base64.b64decode(standard_b64)
                            mdoc = isomdl_uniffi.Mdoc.from_string(decoded_bytes.hex())
                        except Exception as b64_err:
                            LOGGER.warning(
                                f"All parsing methods failed. Hex: {hex_err}, IssuerSigned: {issuer_signed_err}, Base64: {b64_err}"
                            )
                            # Last resort: try direct string parsing
                            mdoc = isomdl_uniffi.Mdoc.from_string(credential)

            elif isinstance(credential, bytes):
                # Convert bytes to hex string for parsing
                mdoc = isomdl_uniffi.Mdoc.from_string(credential.hex())

            if not mdoc:
                return VerifyResult(
                    verified=False, payload={"error": "Invalid credential format"}
                )

            # Get trust anchors if available
            # Note: verify_issuer_signature expects plain PEM strings, NOT JSON
            # For WalletTrustStore, refresh cache before getting anchors since we're in async context
            if self.trust_store and isinstance(self.trust_store, WalletTrustStore):
                await self.trust_store.refresh_cache()

            trust_anchors = (
                self.trust_store.get_trust_anchors() if self.trust_store else None
            )

            # Verify issuer signature
            try:
                # Enable intermediate certificate chaining by default
                verification_result = mdoc.verify_issuer_signature(trust_anchors, True)

                if verification_result.verified:
                    # Extract claims from mdoc details
                    claims = {}
                    try:
                        details = mdoc.details()
                        LOGGER.debug(f"mdoc details keys: {list(details.keys())}")
                        for namespace, elements in details.items():
                            # Namespace is a string alias
                            ns_claims = {}
                            for element in elements:
                                # element.value is a JSON string
                                if element.value:
                                    try:
                                        ns_claims[element.identifier] = json.loads(
                                            element.value
                                        )
                                    except json.JSONDecodeError:
                                        ns_claims[element.identifier] = element.value
                                else:
                                    ns_claims[element.identifier] = None
                            claims[namespace] = ns_claims
                    except Exception as e:
                        LOGGER.warning(f"Failed to extract claims from mdoc: {e}")

                    payload = {
                        "status": "verified",
                        "doctype": mdoc.doctype(),
                        "id": str(mdoc.id()),
                        "issuer_common_name": verification_result.common_name,
                    }
                    # Merge claims into payload so they are at the top level for PEX matching
                    payload.update(claims)

                    LOGGER.debug(f"Mdoc Payload: {json.dumps(payload)}")

                    return VerifyResult(
                        verified=True,
                        payload=payload,
                    )
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
            # For WalletTrustStore, refresh cache before getting anchors since we're in async context
            if self.trust_store and isinstance(self.trust_store, WalletTrustStore):
                await self.trust_store.refresh_cache()

            trust_anchors = (
                self.trust_store.get_trust_anchors() if self.trust_store else []
            )
            # isomdl-uniffi expects a list of JSON-encoded strings for trust anchors
            # Each string must be a JSON object representing PemTrustAnchor struct
            trust_anchors_json = [
                json.dumps({"certificate_pem": a, "purpose": "Iaca"})
                for a in trust_anchors
            ]
            LOGGER.info(
                f"DEBUG: trust_anchors_json (count: {len(trust_anchors_json)}): {[a[:100] + '...' for a in trust_anchors_json] if trust_anchors_json else '[]'}"
            )

            # 2. Verify OID4VP Response
            # We need nonce, client_id, response_uri
            nonce = presentation_record.nonce

            config = Config.from_settings(profile.settings)

            # Get the DID:JWK that was used as client_id when the request was created
            # Use retrieve_or_create_did_jwk to ensure consistency with request creation
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

            # 3. Handle Response
            presentations_to_verify = []
            is_list_input = False

            if isinstance(presentation, str):
                try:
                    parsed = json.loads(presentation)
                    if isinstance(parsed, list):
                        presentations_to_verify = parsed
                        is_list_input = True
                    else:
                        presentations_to_verify = [presentation]
                except json.JSONDecodeError:
                    presentations_to_verify = [presentation]
            elif isinstance(presentation, list):
                presentations_to_verify = presentation
                is_list_input = True
            else:
                presentations_to_verify = [presentation]

            verified_payloads = []

            for pres_item in presentations_to_verify:
                # Debug: Log the vp_token format for troubleshooting
                pres_preview = str(pres_item)[:100] if pres_item else "None"
                LOGGER.info(
                    f"DEBUG: vp_token type={type(pres_item).__name__}, "
                    f"len={len(pres_item) if hasattr(pres_item, '__len__') else 'N/A'}, "
                    f"preview={pres_preview}..."
                )

                response_bytes = pres_item
                if isinstance(pres_item, str):
                    # Try to decode if it's base64
                    try:
                        response_bytes = base64.urlsafe_b64decode(
                            pres_item + "=" * (-len(pres_item) % 4)
                        )
                    except (ValueError, TypeError):
                        # Maybe it's hex?
                        try:
                            response_bytes = bytes.fromhex(pres_item)
                        except (ValueError, TypeError):
                            pass

                if not isinstance(response_bytes, bytes):
                    raise PresVerifierError(
                        "Presentation must be bytes or base64/hex string"
                    )

                # 4. Verify using isomdl-uniffi
                # Try spec-compliant 2024 format first, fall back to legacy 2023 format
                # for compatibility with older wallets (e.g., Credo)
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

                # If device authentication failed but issuer is valid, try legacy format
                # This handles wallets using the 2023 draft SessionTranscript format
                if (
                    verified_data.device_authentication
                    != isomdl_uniffi.AuthenticationStatus.VALID
                    and verified_data.issuer_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                ):
                    # Check if legacy function is available (not all isomdl_uniffi versions have it)
                    if hasattr(isomdl_uniffi, "verify_oid4vp_response_legacy"):
                        LOGGER.info(
                            "Device authentication failed with spec-compliant format, "
                            "trying legacy 2023 format for backwards compatibility"
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
                            "Device authentication failed and legacy format not available in isomdl_uniffi. "
                            "Consider upgrading isomdl_uniffi to a version with verify_oid4vp_response_legacy."
                        )

                if (
                    verified_data.issuer_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                    and verified_data.device_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                ):
                    # Extract verified claims from the Rust library response
                    # verified_data.verified_response is dict[str, dict[str, MDocItem]]
                    # We need to convert MDocItem enum variants to their actual values
                    try:
                        claims = extract_verified_claims(
                            verified_data.verified_response
                        )
                        LOGGER.info(
                            f"DEBUG: Extracted claims namespaces: {list(claims.keys())}"
                        )
                    except Exception as e:
                        LOGGER.warning(
                            f"Failed to extract claims from verified response: {e}"
                        )
                        claims = {}

                    # Build payload with verified claims
                    # This payload will be passed to verify_credential which will
                    # recognize it as pre-verified by the namespace structure
                    payload = {
                        "status": "verified",
                        "docType": verified_data.doc_type,  # Include docType for DCQL validation
                        "issuer_auth": str(verified_data.issuer_authentication),
                        "device_auth": str(verified_data.device_authentication),
                    }
                    # Merge claims into payload (namespaced structure like org.iso.18013.5.1)
                    payload.update(claims)

                    LOGGER.info(
                        f"DEBUG: Verified presentation payload keys: {list(payload.keys())}"
                    )
                    verified_payloads.append(payload)
                else:
                    LOGGER.error(
                        "Verification failed: Issuer=%s, Device=%s, Errors=%s",
                        verified_data.issuer_authentication,
                        verified_data.device_authentication,
                        verified_data.errors,
                    )
                    # Convert verified response to JSON/dict for error details
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
