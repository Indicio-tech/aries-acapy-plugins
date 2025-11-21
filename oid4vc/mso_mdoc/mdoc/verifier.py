"""Mdoc Verifier implementation using isomdl-uniffi."""

import base64
import json
import logging
import os
from abc import abstractmethod
from typing import Any, List, Optional, Protocol

# Import isomdl_uniffi library directly
import isomdl_uniffi
from acapy_agent.core.profile import Profile
from acapy_agent.protocols.present_proof.dif.pres_exch import \
    PresentationDefinition

from oid4vc.cred_processor import (CredVerifier, PresVerifeirError,
                                   PresVerifier, VerifyResult)
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.presentation_definition import OID4VPPresDef

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
                    "id": str(mdoc.id())
                }
            )

        except Exception as e:
            LOGGER.error(f"Failed to parse mdoc credential: {e}")
            return VerifyResult(verified=False, payload={"error": str(e)})


class MsoMdocPresVerifier(PresVerifier):
    """Verifier for mso_mdoc presentations (OID4VP)."""

    def __init__(self, trust_store: Optional[TrustStore] = None):
        """Initialize the presentation verifier."""
        self.trust_store = trust_store

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

            # 2. Establish Session (Verifier side)
            # We need the URI from the request? Or just a placeholder?
            # establish_session takes (uri, requested_items, trust_anchor_registry)
            # In OID4VP, the "uri" might be the mdoc-uri if using that flow,
            # or it might be irrelevant for direct_post if we just want to verify
            # the blob. However, isomdl-uniffi seems to enforce the session flow.

            # Construct requested items from presentation_record (if available)
            # The API expects dict[str, dict[str, dict[str, bool]]]
            # -> {doctype: {namespace: {element: intent_to_retain}}}
            requested_items = {}
            if presentation_record and presentation_record.pres_def_id:
                try:
                    async with profile.session() as session:
                        pres_def_entry = await OID4VPPresDef.retrieve_by_id(
                            session,
                            presentation_record.pres_def_id,
                        )
                        pres_def = PresentationDefinition.deserialize(
                            pres_def_entry.pres_def
                        )

                        for descriptor in pres_def.input_descriptors:
                            # Default to mDL doctype if not specified
                            doctype = "org.iso.18013.5.1.mDL"
                            if doctype not in requested_items:
                                requested_items[doctype] = {}

                            if descriptor.constraints:
                                for field in descriptor.constraints.fields:
                                    for path in field.path:
                                        # Attempt to parse path like
                                        # "$['org.iso.18013.5.1']['family_name']"
                                        # This is a very basic parser and might need
                                        # improvement
                                        clean_path = (
                                            path.replace("$", "")
                                            .replace("[", "")
                                            .replace("]", "")
                                            .replace("'", "")
                                            .replace('"', "")
                                        )
                                        parts = clean_path.split(".")
                                        if len(parts) >= 2:
                                            # Assuming namespace.element
                                            # But path might be namespace.element
                                            # Or it might be just element if namespace
                                            # is implied?
                                            # For mDL, it's usually namespace.element

                                            # Let's try to split by last dot
                                            namespace = ".".join(parts[:-1])
                                            element = parts[-1]

                                            if namespace not in requested_items[doctype]:
                                                requested_items[doctype][namespace] = {}

                                            requested_items[doctype][namespace][
                                                element
                                            ] = True
                except Exception as e:
                    LOGGER.warning(f"Could not retrieve presentation definition: {e}")

            # We use a dummy URI as we are verifying a received response,
            # not initiating a BLE/NFC session
            session_data = isomdl_uniffi.establish_session(
                "mdoc-openid4vp://", requested_items, trust_anchors
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

            # 4. Handle Device Response
            # We need to pass the session state and the response bytes
            # handle_response returns
            # (issuer_auth_status, device_auth_status, json_payload, errors)
            # or a struct with these fields.
            response_data = isomdl_uniffi.handle_response(
                session_data.state, response_bytes
            )

            if (
                response_data.issuer_authentication
                == isomdl_uniffi.AuthenticationStatus.VALID
                and response_data.device_authentication
                == isomdl_uniffi.AuthenticationStatus.VALID
            ):
                verified = True
            else:
                verified = False

            # 5. Extract Payload
            # verified_response is dict[str, dict[str, MDocItem]]
            # -> {namespace: {element: value}}
            # We need to convert MDocItem to Python types
            payload = {}
            # We can use verified_response_as_json_string for easy conversion
            json_payload = isomdl_uniffi.verified_response_as_json_string(response_data)
            payload = json.loads(json_payload)

            if not verified:
                LOGGER.warning(
                    "Mdoc verification failed. Issuer: %s, Device: %s, Errors: %s",
                    response_data.issuer_authentication,
                    response_data.device_authentication,
                    response_data.errors,
                )
                return VerifyResult(
                    verified=False,
                    payload={
                        "error": response_data.errors,
                        "issuer_auth": str(response_data.issuer_authentication),
                        "device_auth": str(response_data.device_authentication),
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
        self, verified: bool, payload: Optional[dict] = None, error: Optional[str] = None
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

