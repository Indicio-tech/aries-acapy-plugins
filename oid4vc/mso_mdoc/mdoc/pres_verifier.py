"""mso_mdoc presentation verifier, OID4VP helpers, and standalone mdoc_verify."""

import base64
import json
import logging
from typing import Any, List, Optional

import isomdl_uniffi
from acapy_agent.core.profile import Profile
from cryptography import x509 as _x509

from oid4vc.config import Config
from oid4vc.cred_processor import PresVerifier, PresVerifierError, VerifyResult
from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.models.presentation import OID4VPPresentation

from ..storage import MdocStorageManager
from .trust_store import TrustStore, WalletTrustStore
from .utils import flatten_trust_anchors
from .cred_verifier import PreverifiedMdocClaims

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
    trust_anchor_registry: List[str],
) -> Any:
    """Verify a single OID4VP presentation.

    Args:
        response_bytes: The presentation bytes
        nonce: The nonce
        client_id: The client ID
        response_uri: The response URI
        trust_anchor_registry: JSON-serialized PemTrustAnchor strings, each of the form
            '{"certificate_pem": "...", "purpose": "Iaca"}'

    Returns:
        Verified payload dict if successful, None if failed
    """
    LOGGER.debug(
        "Calling verify_oid4vp_response with: "
        "nonce=%s client_id=%s response_uri=%s "
        "response_bytes_len=%d",
        nonce,
        client_id,
        response_uri,
        len(response_bytes),
    )

    # Try spec-compliant format (2024) first
    verified_data = isomdl_uniffi.verify_oid4vp_response(
        response_bytes,
        nonce,
        client_id,
        response_uri,
        trust_anchor_registry,
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
                "Device auth failed with spec-compliant format, trying legacy 2023 format"
            )
            verified_data = isomdl_uniffi.verify_oid4vp_response_legacy(
                response_bytes,
                nonce,
                client_id,
                response_uri,
                trust_anchor_registry,
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
            LOGGER.debug(
                "Trust anchors loaded: %d cert(s)",
                len(trust_anchors) if trust_anchors else 0,
            )
            for i, pem in enumerate(trust_anchors or []):
                pem_stripped = pem.strip() if pem else ""
                LOGGER.debug(
                    "Trust anchor %d: len=%d",
                    i,
                    len(pem_stripped),
                )
                # Validate that the PEM is parseable by Python before
                # passing to Rust
                try:
                    _x509.load_pem_x509_certificate(pem_stripped.encode())
                except Exception as pem_err:
                    LOGGER.error(
                        "Trust anchor %d: PEM validation FAILED: %s",
                        i,
                        pem_err,
                    )

            # Flatten concatenated PEM chains into individual certs BEFORE
            # building the registry.  Rust (x509_cert) only reads the first
            # PEM block from a string; any additional certs in a chain string
            # are silently dropped, breaking trust-anchor validation.
            if trust_anchors:
                trust_anchors = flatten_trust_anchors(trust_anchors)
                LOGGER.debug(
                    "Trust anchors after chain-splitting: %d individual cert(s)",
                    len(trust_anchors),
                )

            # Fail-closed guard: refuse to verify without at least one trust
            # anchor.  An empty list causes Rust to accept any self-signed
            # issuer certificate, bypassing chain validation entirely.
            if not trust_anchors:
                return VerifyResult(
                    verified=False,
                    payload={
                        "error": "No trust anchors configured; presentation "
                        "verification requires at least one trust anchor."
                    },
                )

            # verify_oid4vp_response expects JSON-serialized PemTrustAnchor per anchor:
            # {"certificate_pem": "...", "purpose": "Iaca"}
            # Rust parses each string via serde_json::from_str::<PemTrustAnchor>().
            trust_anchor_registry = (
                [
                    json.dumps({"certificate_pem": pem, "purpose": "Iaca"})
                    for pem in trust_anchors
                ]
                if trust_anchors
                else []
            )
            if trust_anchor_registry:
                LOGGER.debug(
                    "trust_anchor_registry[0] first100: %r",
                    trust_anchor_registry[0][:100],
                )

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
                LOGGER.debug(
                    "vp_token type=%s len=%s",
                    type(pres_item).__name__,
                    len(pres_item) if hasattr(pres_item, "__len__") else "N/A",
                )

                response_bytes = _decode_presentation_bytes(pres_item)

                verified_data = _verify_single_presentation(
                    response_bytes,
                    nonce,
                    client_id,
                    response_uri,
                    trust_anchor_registry,
                )

                # Per ISO 18013-5, deviceSigned is optional (marked with '?' in
                # the CDDL).  For OID4VP web-wallet flows a device key binding
                # round-trip is not performed, so device_authentication will not
                # be VALID.  Issuer authentication is sufficient to trust that
                # the credential was issued by a known authority.
                issuer_ok = (
                    verified_data.issuer_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                )
                device_ok = (
                    verified_data.device_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                )

                if issuer_ok:
                    if not device_ok:
                        LOGGER.info(
                            "Device authentication not present/valid (issuer-only "
                            "OID4VP presentation — deviceSigned is optional per "
                            "ISO 18013-5): Device=%s",
                            verified_data.device_authentication,
                        )
                    try:
                        claims = extract_verified_claims(verified_data.verified_response)
                    except Exception as e:
                        LOGGER.warning("Failed to extract claims: %s", e)
                        claims = {}

                    payload = {
                        "status": "verified",
                        "docType": verified_data.doc_type,
                        "issuer_auth": str(verified_data.issuer_authentication),
                        "device_auth": str(verified_data.device_authentication),
                    }
                    payload.update(claims)
                    verified_payloads.append(PreverifiedMdocClaims(claims=payload))
                else:
                    LOGGER.error(
                        "Verification failed: Issuer=%s, Device=%s, Errors=%s",
                        verified_data.issuer_authentication,
                        verified_data.device_authentication,
                        verified_data.errors,
                    )
                    try:
                        claims = extract_verified_claims(verified_data.verified_response)
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

    Accepts mDOC strings in any format understood by ``_parse_string_credential``:
    hex-encoded DeviceResponse, base64url IssuerSigned, or raw base64.

    Args:
        mso_mdoc: The mDOC string (hex, base64url, or base64).
        trust_anchors: Optional list of PEM-encoded trust anchor certificates.
            Each element may contain a single cert or a concatenated PEM chain;
            chains are automatically split before being passed to Rust.

    Returns:
        MdocVerifyResult: The verification result.
    """
    from .cred_verifier import _parse_string_credential

    try:
        # Parse the mdoc — try all supported formats
        mdoc, parse_error = _parse_string_credential(mso_mdoc)
        if not mdoc:
            return MdocVerifyResult(
                verified=False,
                error=f"Failed to parse mDOC: {parse_error or 'unknown format'}",
            )

        # Flatten concatenated PEM chains so Rust receives one cert per list
        # entry (isomdl_uniffi only reads the first PEM block in a string).
        if trust_anchors:
            trust_anchors = flatten_trust_anchors(trust_anchors)

        # Fail-closed guard: refuse to verify without at least one trust anchor.
        if not trust_anchors:
            return MdocVerifyResult(
                verified=False,
                error="No trust anchors configured; mDOC verification requires "
                "at least one trust anchor.",
            )

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
