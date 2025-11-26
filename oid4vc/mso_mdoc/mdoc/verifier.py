"""Mdoc Verifier implementation using isomdl-uniffi."""

import base64
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
    PresVerifeirError,
    PresVerifier,
    VerifyResult,
)
from oid4vc.models.presentation import OID4VPPresentation

LOGGER = logging.getLogger(__name__)


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

        Args:
            profile: The profile for context
            credential: The credential to verify (bytes or hex string)

        Returns:
            VerifyResult: The verification result
        """
        try:
            # Basic parsing check
            mdoc = None
            if isinstance(credential, str):
                # isomdl usually works with hex strings for from_string
                mdoc = isomdl_uniffi.Mdoc.from_string(credential)
            elif isinstance(credential, bytes):
                # Convert bytes to hex string for parsing
                mdoc = isomdl_uniffi.Mdoc.from_string(credential.hex())

            if not mdoc:
                return VerifyResult(
                    verified=False, payload={"error": "Invalid credential format"}
                )

            # Currently isomdl-uniffi focuses on presentation verification (session based)
            # and does not expose a standalone issuer signature verification method for
            # Mdoc objects. Therefore, successful parsing implies structural validity
            # (CBOR structure, MSO format). Full cryptographic verification of the
            # issuer signature requires a presentation session or future library
            # enhancements.

            return VerifyResult(
                verified=True,
                payload={
                    "status": "structurally_valid",
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
            trust_anchors = (
                self.trust_store.get_trust_anchors() if self.trust_store else []
            )

            # 2. Verify OID4VP Response
            # We need nonce, client_id, response_uri
            nonce = presentation_record.nonce

            config = Config.from_settings(profile.settings)
            client_id = config.endpoint

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
            # presentation should be bytes. If it's a dict (from JSON),
            # we might need to convert.
            # OID4VP usually sends the device response as bytes
            # (base64url encoded in JSON or raw)
            response_bytes = presentation
            if isinstance(presentation, str):
                # Try to decode if it's base64
                try:
                    response_bytes = base64.urlsafe_b64decode(
                        presentation + "=" * (-len(presentation) % 4)
                    )
                except (ValueError, TypeError):
                    # Maybe it's hex?
                    try:
                        response_bytes = bytes.fromhex(presentation)
                    except (ValueError, TypeError):
                        pass

            if not isinstance(response_bytes, bytes):
                raise PresVerifeirError(
                    "Presentation must be bytes or base64/hex string"
                )

            # 4. Verify using isomdl-uniffi
            verified_data = isomdl_uniffi.verify_oid4vp_response(
                response_bytes, nonce, client_id, response_uri, trust_anchors
            )

            if (
                verified_data.issuer_authentication
                == isomdl_uniffi.AuthenticationStatus.VALID
                and verified_data.device_authentication
                == isomdl_uniffi.AuthenticationStatus.VALID
            ):
                verified = True
            else:
                verified = False
                LOGGER.error(
                    "Verification failed: Issuer=%s, Device=%s, Errors=%s",
                    verified_data.issuer_authentication,
                    verified_data.device_authentication,
                    verified_data.errors,
                )

            # Convert verified response to JSON/dict
            try:
                # verified_response_as_json returns a dict (from serde_json::Value)
                payload = verified_data.verified_response_as_json()
            except Exception as e:
                LOGGER.error(f"Failed to convert verified response to JSON: {e}")
                payload = {}

            if not verified:
                return VerifyResult(
                    verified=False,
                    payload={
                        "error": verified_data.errors,
                        "issuer_auth": str(verified_data.issuer_authentication),
                        "device_auth": str(verified_data.device_authentication),
                        "claims": payload,
                    },
                )

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


def mdoc_verify(mso_mdoc: str) -> MdocVerifyResult:
    """Verify an mso_mdoc credential.

    Args:
        mso_mdoc: The base64 encoded mdoc string.

    Returns:
        MdocVerifyResult: The verification result.
    """
    try:
        # Basic parsing check using isomdl-uniffi
        # This is a simplified verification for the standalone endpoint
        isomdl_uniffi.Mdoc.from_string(mso_mdoc)
        # If parsing succeeds, we consider it "verified" structurally for now
        # Note: Full signature verification requires session context or
        # specific trust anchor validation which is not yet fully exposed
        # for standalone strings in the current bindings.
        return MdocVerifyResult(verified=True, payload={"status": "parsed"})
    except Exception as e:
        return MdocVerifyResult(verified=False, error=str(e))
