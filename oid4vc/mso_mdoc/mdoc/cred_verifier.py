"""mso_mdoc credential verifier and related helpers."""

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

import isomdl_uniffi
from acapy_agent.core.profile import Profile

from oid4vc.cred_processor import CredVerifier, VerifyResult

from .trust_store import TrustStore, WalletTrustStore

LOGGER = logging.getLogger(__name__)


@dataclass
class PreverifiedMdocClaims:
    """Typed sentinel wrapping namespaced claims already verified by verify_presentation.

    Only ``MsoMdocPresVerifier.verify_presentation`` (trusted code) should
    construct instances of this class; external callers cannot spoof it.
    """

    claims: dict


def _is_preverified_claims_dict(credential: Any) -> bool:
    """Return True only when *credential* is a typed :class:`PreverifiedMdocClaims`."""
    return isinstance(credential, PreverifiedMdocClaims)


def _parse_string_credential(credential: str) -> tuple[Optional[Any], Optional[str]]:
    """Parse a string credential into an Mdoc object.

    Tries three formats: hex CBOR DeviceResponse, base64url IssuerSigned,
    then base64url-encoded DeviceResponse (wallet-compatible format).

    Args:
        credential: String credential to parse

    Returns:
        Tuple of (Parsed Mdoc object or None if parsing fails, error message if any)
    """
    # Try hex first (full DeviceResponse)
    try:
        if all(c in "0123456789abcdefABCDEF" for c in credential):
            LOGGER.debug("Trying to parse credential as hex DeviceResponse")
            return isomdl_uniffi.Mdoc.from_string(credential), None
    except Exception as hex_err:
        LOGGER.debug("Hex parsing failed: %s", hex_err)

    # Try base64url-encoded IssuerSigned
    try:
        LOGGER.debug("Trying to parse credential as base64url IssuerSigned")
        mdoc = isomdl_uniffi.Mdoc.new_from_base64url_encoded_issuer_signed(
            credential, "verified-inner"
        )
        return mdoc, None
    except Exception as issuer_signed_err:
        LOGGER.debug("IssuerSigned parsing failed: %s", issuer_signed_err)

    # Try base64url-encoded DeviceResponse (wallet-compatible format)
    try:
        LOGGER.debug("Trying to parse credential as base64url DeviceResponse")
        padded = (
            credential + "=" * (4 - len(credential) % 4)
            if len(credential) % 4
            else credential
        )
        standard_b64 = padded.replace("-", "+").replace("_", "/")
        decoded_bytes = base64.b64decode(standard_b64)
        return isomdl_uniffi.Mdoc.from_string(decoded_bytes.hex()), None
    except Exception as b64_err:
        LOGGER.debug("Base64 DeviceResponse parsing failed: %s", b64_err)
        return None, str(b64_err)


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
        LOGGER.debug("mdoc details keys: %s", list(details.keys()))
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
        LOGGER.warning("Failed to extract claims from mdoc: %s", e)
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
            # Check if credential is pre-verified claims sentinel
            if _is_preverified_claims_dict(credential):
                LOGGER.debug("Credential is pre-verified claims dict from presentation")
                return VerifyResult(verified=True, payload=credential.claims)

            # Parse credential to Mdoc object
            mdoc = None
            parse_error = None
            if isinstance(credential, str):
                mdoc, parse_error = _parse_string_credential(credential)
            elif isinstance(credential, bytes):
                try:
                    mdoc = isomdl_uniffi.Mdoc.from_string(credential.hex())
                except Exception as e:
                    parse_error = str(e)

            if not mdoc:
                if parse_error:
                    error_msg = f"Invalid credential format: {parse_error}"
                else:
                    error_msg = "Invalid credential format"
                return VerifyResult(verified=False, payload={"error": error_msg})

            # Refresh trust store cache if needed
            if self.trust_store and isinstance(self.trust_store, WalletTrustStore):
                await self.trust_store.refresh_cache()

            trust_anchors = (
                self.trust_store.get_trust_anchors() if self.trust_store else []
            )

            # Flatten any concatenated PEM chains into individual cert PEMs.
            # isomdl_uniffi (x509_cert) reads only the first certificate in a
            # PEM string; passing a chain as one element silently drops all
            # certs after the first, breaking trust-anchor validation.
            if trust_anchors:
                from .utils import flatten_trust_anchors

                trust_anchors = flatten_trust_anchors(trust_anchors)

            # Fail-closed guard: refuse to verify without at least one trust
            # anchor.  An empty list causes the Rust library to accept any
            # self-signed issuer certificate, effectively disabling chain
            # validation and allowing an attacker to present forgeries.
            if not trust_anchors:
                return VerifyResult(
                    verified=False,
                    payload={
                        "error": "No trust anchors configured; credential "
                        "verification requires at least one trust anchor."
                    },
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
                    LOGGER.debug("Mdoc Payload: %s", json.dumps(payload))
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
                LOGGER.error("Issuer signature verification failed: %s", e)
                return VerifyResult(
                    verified=False,
                    payload={
                        "error": str(e),
                        "doctype": mdoc.doctype(),
                        "id": str(mdoc.id()),
                    },
                )

        except Exception as e:
            LOGGER.error("Failed to parse mdoc credential: %s", e)
            return VerifyResult(verified=False, payload={"error": str(e)})
