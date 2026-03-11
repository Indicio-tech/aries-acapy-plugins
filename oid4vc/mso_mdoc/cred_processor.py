"""mso_mdoc credential processor.

Glues together the signing-key resolution, payload preparation, and isomdl
binding layers to implement ISO/IEC 18013-5:2021 compliant mDoc issuance and
verification inside the OID4VCI plugin framework.

Public API re-exported from sub-modules for backward compatibility:

- ``check_certificate_not_expired`` — from :mod:`.signing_key`
- ``resolve_signing_key_for_credential`` — from :mod:`.signing_key`
"""

import base64
import json
import logging
import os
import re
from typing import Any, Dict, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile, ProfileSession

from oid4vc.cred_processor import CredProcessorError, CredVerifier, Issuer, PresVerifier
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult

from .key_generation import pem_from_jwk, pem_to_jwk
from .mdoc.issuer import isomdl_mdoc_sign
from .mdoc.cred_verifier import MsoMdocCredVerifier
from .mdoc.pres_verifier import MsoMdocPresVerifier
from .mdoc.trust_store import WalletTrustStore
from .payload import normalize_mdoc_result, prepare_mdoc_payload
from .signing_key import (
    check_certificate_not_expired,
    resolve_signing_key_for_credential,
)
from .storage import MdocStorageManager

# Re-export so existing ``from .cred_processor import X`` and
# ``patch("mso_mdoc.cred_processor.X")`` usages continue to work.
__all__ = [
    "MsoMdocCredProcessor",
    "check_certificate_not_expired",
    "resolve_signing_key_for_credential",
]

LOGGER = logging.getLogger(__name__)


class MsoMdocCredProcessor(Issuer, CredVerifier, PresVerifier):
    """Credential processor class for mso_mdoc credential format."""

    def format_data_is_top_level(self) -> bool:
        """mso_mdoc format_data (doctype, claims, etc.) belongs at top level.

        Per OID4VCI spec Appendix E, mso_mdoc credential configurations must
        have ``doctype`` and other format fields at the top level of the
        credential configuration object, NOT inside ``credential_definition``.
        """
        return True

    # COSE algorithm name → integer identifier mapping (RFC 8152 / IANA COSE registry)
    _COSE_ALG: dict = {"ES256": -7, "ES384": -35, "ES512": -36, "ES256K": -47}

    def transform_issuer_metadata(self, metadata: dict) -> None:
        """Convert mso_mdoc metadata to OID4VCI 1.0 spec-compliant form.

        Performs two transformations required by OID4VCI 1.0:

        1. ``credential_signing_alg_values_supported`` — converts string
           algorithm names to COSE integer identifiers (e.g. "ES256" → -7)
           per OID4VCI 1.0 Appendix A.2.2 and ISO 18013-5.

        2. ``claims`` — converts the stored namespace-keyed dict
           ``{namespace: {claim_name: descriptor}}`` to the spec-compliant
           flat array ``[{path: [namespace, claim_name], ...}]`` and nests
           it inside ``credential_metadata`` per OID4VCI 1.0 Appendix A.2.2,
           Section 12.2.4, and Appendix B.2.

        3. ``display`` — moves the credential display array into
           ``credential_metadata`` per OID4VCI 1.0 Section 12.2.4.
        """
        algs = metadata.get("credential_signing_alg_values_supported")
        if algs:
            metadata["credential_signing_alg_values_supported"] = [
                self._COSE_ALG.get(a, a) if isinstance(a, str) else a for a in algs
            ]

        claims = metadata.pop("claims", None)
        if isinstance(claims, dict):
            claims_list = []
            for namespace, claim_map in claims.items():
                if isinstance(claim_map, dict):
                    for claim_name, descriptor in claim_map.items():
                        entry: dict = {"path": [namespace, claim_name]}
                        if isinstance(descriptor, dict):
                            if "mandatory" in descriptor:
                                entry["mandatory"] = descriptor["mandatory"]
                            if "display" in descriptor:
                                entry["display"] = descriptor["display"]
                        claims_list.append(entry)
            credential_metadata = metadata.setdefault("credential_metadata", {})
            credential_metadata["claims"] = claims_list
        elif isinstance(claims, list):
            # Already converted — just ensure it's nested in credential_metadata
            credential_metadata = metadata.setdefault("credential_metadata", {})
            credential_metadata["claims"] = claims

        # Move display into credential_metadata per OID4VCI 1.0 Section 12.2.4
        display = metadata.pop("display", None)
        if display is not None:
            credential_metadata = metadata.setdefault("credential_metadata", {})
            credential_metadata["display"] = display

    def __init__(self, trust_store: Optional[Any] = None):
        """Initialize the processor."""
        self.trust_store = trust_store

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
                "Invalid doctype format: expected non-empty string, "
                f"got {type(doctype).__name__}"
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
            Serialized device key string (JWK JSON or key identifier),
            or None if unavailable

        Raises:
            CredProcessorError: If device key format is invalid or unsupported
        """
        # Priority order: holder JWK > holder key ID > verification method from record
        device_candidate = (
            pop.holder_jwk or pop.holder_kid or ex_record.verification_method
        )

        if isinstance(device_candidate, dict):
            # The device key embedded in the mDoc MSO must contain ONLY public
            # parameters; passing 'd' to the Rust isomdl library would leak
            # the holder's private key into the issued credential.
            _PUBLIC_JWK_FIELDS = frozenset(("kty", "crv", "x", "y", "n", "e"))
            public_only = {
                k: v for k, v in device_candidate.items() if k in _PUBLIC_JWK_FIELDS
            }
            return json.dumps(public_only)
        elif isinstance(device_candidate, str):
            # If a DID with fragment, prefer fragment (key id); otherwise raw string
            m = re.match(r"did:(.+?):(.+?)(?:#(.*))?$", device_candidate)
            if m:
                method = m.group(1)
                identifier = m.group(2)
                fragment = m.group(3)

                if method == "jwk":
                    # did:jwk encodes the holder's public JWK as a base64url
                    # value in the DID identifier itself (i.e. between
                    # "did:jwk:" and "#0").  ACA-Py uses this method natively
                    # when a wallet generates ephemeral keys.
                    #
                    # Without special handling the generic DID regex returns
                    # only the fragment "0", and json.loads("0") silently
                    # produces the integer 0 — which the Rust isomdl library
                    # then receives as the holder key, causing an opaque
                    # failure with no hint that the root cause is a
                    # mis-parsed DID method.
                    try:
                        # Base64url may be missing padding — add it back.
                        padding = "=" * (-len(identifier) % 4)
                        jwk_bytes = base64.urlsafe_b64decode(identifier + padding)
                        return jwk_bytes.decode("utf-8")
                    except Exception as exc:
                        raise CredProcessorError(
                            f"Invalid did:jwk identifier — could not decode "
                            f"embedded JWK from '{device_candidate}': {exc}"
                        ) from exc

                return fragment if fragment else device_candidate
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

        # Check for environment variables for static key
        key_path = os.getenv("OID4VC_MDOC_SIGNING_KEY_PATH")
        cert_path = os.getenv("OID4VC_MDOC_SIGNING_CERT_PATH")

        if (
            key_path
            and cert_path
            and os.path.exists(key_path)
            and os.path.exists(cert_path)
        ):
            static_key_id = "static-signing-key"
            # Use the same API as the rest of the signing-key path.
            existing_key = await storage_manager.get_signing_key(
                session, identifier=static_key_id
            )
            if not existing_key:
                LOGGER.info("Loading static signing key from %s", key_path)
                try:
                    with open(key_path, "r") as f:
                        private_key_pem = f.read()
                    with open(cert_path, "r") as f:
                        certificate_pem = f.read()

                    # Derive JWK from PEM
                    jwk = pem_to_jwk(private_key_pem)

                    await storage_manager.store_key(
                        session,
                        key_id=static_key_id,
                        jwk=jwk,
                        purpose="signing",
                        metadata={"static": True},
                    )

                    cert_id = f"mdoc-cert-{static_key_id}"
                    await storage_manager.store_certificate(
                        session,
                        cert_id=cert_id,
                        certificate_pem=certificate_pem,
                        key_id=static_key_id,
                        metadata={"static": True, "purpose": "mdoc_issuing"},
                    )

                    # Only set as default when no key has been configured yet.
                    # Without this guard the env-var key would silently overwrite
                    # whatever key the operator registered via the key management API.
                    existing_default = await storage_manager.get_config(
                        session, "default_signing_key"
                    )
                    if not existing_default:
                        await storage_manager.store_config(
                            session, "default_signing_key", {"key_id": static_key_id}
                        )

                except CredProcessorError:
                    raise
                except Exception as e:
                    raise CredProcessorError(
                        f"Failed to load static signing key from {key_path!r}: {e}"
                    ) from e

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

        raise CredProcessorError(
            "No default signing key is configured. "
            "Register a signing key via the mso_mdoc key management API before issuing."
        )

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
            payload = prepare_mdoc_payload(ex_record.credential_subject, doctype)

            # Resolve signing key
            async with context.profile.session() as session:
                key_data = await self._resolve_signing_key(
                    context, session, verification_method
                )
                key_id = key_data.get("key_id")
                # Reconstruct private_key_pem on-demand from the JWK 'd' parameter.
                private_key_pem = key_data.get("metadata", {}).get("private_key_pem")
                if not private_key_pem:
                    signing_jwk = key_data.get("jwk", {})
                    if signing_jwk.get("d"):
                        private_key_pem = pem_from_jwk(signing_jwk)

                # Fetch certificate
                storage_manager = MdocStorageManager(context.profile)
                certificate_pem = await storage_manager.get_certificate_for_key(
                    session, key_id
                )

                if not certificate_pem:
                    raise CredProcessorError(
                        f"Certificate not found for key {key_id!r}. "
                        "Keys must be registered with a certificate before use."
                    )

            if not private_key_pem:
                raise CredProcessorError("Private key PEM not found for signing key")

            if not certificate_pem:
                raise CredProcessorError("Certificate PEM not found for signing key")

            # Validity-period guard: reject expired or not-yet-valid certificates
            # before passing them to the Rust signing library.
            check_certificate_not_expired(certificate_pem)

            if not device_key_str and not pop.holder_jwk:
                raise CredProcessorError(
                    "No device key available: provide holder_jwk, "
                    "holder_kid, or verification_method"
                )

            # Clean up JWK for isomdl (remove extra fields like kid, alg, use)
            # isomdl rejects alg and use fields in the holder JWK
            if pop.holder_jwk and isinstance(pop.holder_jwk, dict):
                if pop.holder_jwk.get("kty") != "EC":
                    raise CredProcessorError(
                        "mso_mdoc requires an EC holder key, "
                        f"got kty={pop.holder_jwk.get('kty')}"
                    )
                holder_jwk_clean = {
                    k: v
                    for k, v in pop.holder_jwk.items()
                    if k in ["kty", "crv", "x", "y"]
                }
            else:
                # Fallback: build a minimal JWK placeholder from device_key_str
                # The Rust library needs a JWK dict for the holder key binding
                holder_jwk_clean = None

            # Issue mDoc using isomdl-uniffi library with ISO 18013-5 compliance
            LOGGER.debug(
                "Issuing mso_mdoc with holder_jwk=%s headers=%s payload_keys=%s",
                holder_jwk_clean,
                headers,
                (list(payload.keys()) if isinstance(payload, dict) else type(payload)),
            )
            # Use cleaned JWK if available, otherwise fall back to
            # the device key extracted from holder_kid / verification_method.
            # isomdl_mdoc_sign expects a dict-like JWK.
            signing_holder_key = holder_jwk_clean
            if signing_holder_key is None and device_key_str:
                try:
                    signing_holder_key = json.loads(device_key_str)
                except (json.JSONDecodeError, TypeError):
                    # device_key_str is a key-id, not a JWK —
                    # cannot bind holder key without a JWK.
                    raise CredProcessorError(
                        "Holder key identifier provided but a full "
                        "EC JWK is required for mso_mdoc device "
                        "key binding. Provide holder_jwk in the "
                        "proof of possession."
                    )

            if signing_holder_key is None:
                raise CredProcessorError(
                    "Unable to resolve a holder JWK for device key binding."
                )

            mso_mdoc = isomdl_mdoc_sign(
                signing_holder_key, headers, payload, certificate_pem, private_key_pem
            )

            # Normalize mDoc result handling for robust string/bytes processing
            mso_mdoc = normalize_mdoc_result(mso_mdoc)

            LOGGER.info(
                "Issued mso_mdoc credential with doctype: %s, format: %s",
                doctype,
                supported.format,
            )

        except Exception as ex:
            # Log full exception for debugging before raising a generic error
            LOGGER.exception("mso_mdoc issuance error: %s", ex)
            # Surface the underlying exception text in the CredProcessorError
            raise CredProcessorError(f"Failed to issue mso_mdoc credential: {ex}") from ex

        return mso_mdoc

    def _prepare_payload(
        self, payload: Dict[str, Any], doctype: str = None
    ) -> Dict[str, Any]:
        return prepare_mdoc_payload(payload, doctype)

    def _normalize_mdoc_result(self, result: Any) -> str:
        return normalize_mdoc_result(result)

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject."""
        if not subject:
            raise CredProcessorError("Credential subject cannot be empty")

        if not isinstance(subject, dict):
            raise CredProcessorError("Credential subject must be a dictionary")

        return True

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported MSO MDOC Credential."""
        if not supported.format_data:
            raise CredProcessorError("format_data is required for mso_mdoc format")

        # Validate doctype presence and format
        self._validate_and_get_doctype({}, supported)

        return True

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ):
        """Verify an mso_mdoc credential."""
        # Always build a per-request WalletTrustStore from the calling profile
        # so each tenant's Askar partition is queried (wallet-scoped registry).
        trust_store = WalletTrustStore(profile)
        verifier = MsoMdocCredVerifier(trust_store=trust_store)
        return await verifier.verify_credential(profile, credential)

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: "OID4VPPresentation",
    ):
        """Verify an mso_mdoc presentation."""
        # Always build a per-request WalletTrustStore from the calling profile
        # so each tenant's Askar partition is queried (wallet-scoped registry).
        trust_store = WalletTrustStore(profile)
        verifier = MsoMdocPresVerifier(trust_store=trust_store)
        return await verifier.verify_presentation(
            profile, presentation, presentation_record
        )
