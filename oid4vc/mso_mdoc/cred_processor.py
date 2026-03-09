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

import base64
import json
import logging
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.storage.error import StorageError

from oid4vc.cred_processor import CredProcessorError, CredVerifier, Issuer, PresVerifier
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult

from .key_generation import (
    generate_ec_key_pair,
    generate_self_signed_certificate,
    pem_from_jwk,
    pem_to_jwk,
)
from .mdoc.issuer import isomdl_mdoc_sign
from .mdoc.verifier import MsoMdocCredVerifier, MsoMdocPresVerifier, WalletTrustStore
from .storage import MdocStorageManager

LOGGER = logging.getLogger(__name__)


def check_certificate_not_expired(cert_pem: str) -> None:
    """Validate that a PEM-encoded X.509 certificate is currently valid.

    Raises ``CredProcessorError`` when the certificate is expired, not yet
    valid, or cannot be parsed.  Returns ``None`` silently on success.

    Args:
        cert_pem: PEM-encoded X.509 certificate string.

    Raises:
        CredProcessorError: If the certificate is expired, not yet valid, or
            cannot be parsed from PEM.
    """
    from cryptography import x509 as _x509  # noqa: PLC0415

    if not cert_pem or not cert_pem.strip():
        raise CredProcessorError("Empty certificate PEM string")

    try:
        cert = _x509.load_pem_x509_certificate(cert_pem.strip().encode())
    except Exception as exc:
        raise CredProcessorError(
            f"Invalid certificate PEM — could not parse: {exc}"
        ) from exc

    now = datetime.now(UTC)
    if cert.not_valid_before_utc > now:
        nb = cert.not_valid_before_utc.isoformat()
        raise CredProcessorError(f"Certificate is not yet valid (NotBefore={nb})")
    if cert.not_valid_after_utc < now:
        na = cert.not_valid_after_utc.isoformat()
        raise CredProcessorError(f"Certificate has expired (NotAfter={na})")


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
        profile: The active profile
        session: The active profile session
        verification_method: Optional verification method identifier

    Returns:
        Dictionary containing key information
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

        # Persist the generated key.
        # C-1: do NOT store private_key_pem; the JWK 'd' parameter is the
        # single source of truth for the private scalar.
        key_metadata = {
            "jwk": jwk,
            "public_key_pem": public_key_pem,
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

    # C-1: do NOT store private_key_pem; the JWK 'd' parameter is the
    # single source of truth for the private scalar.
    key_metadata = {
        "jwk": jwk,
        "public_key_pem": public_key_pem,
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

        Two transformations are applied in-place:

        1. ``credential_signing_alg_values_supported``: string names → COSE
           integer identifiers (e.g. "ES256" → -7) per OID4VCI 1.0 Appendix
           E.2.1 and ISO 18013-5.

        2. ``claims``: stored as ``{namespace: {claim_name: descriptor}}``
           dict; converted to the array of claim descriptor objects required
           by OID4VCI 1.0 Appendix B.2 / E.2.1:
           ``[{"path": [namespace, claim_name], "mandatory": ..., "display": ...}]``
        """
        algs = metadata.get("credential_signing_alg_values_supported")
        if algs:
            metadata["credential_signing_alg_values_supported"] = [
                self._COSE_ALG.get(a, a) if isinstance(a, str) else a for a in algs
            ]

        claims = metadata.get("claims")
        if isinstance(claims, dict):
            claims_arr = []
            for namespace, namespace_claims in claims.items():
                if isinstance(namespace_claims, dict):
                    for claim_name, claim_meta in namespace_claims.items():
                        entry: dict = {"path": [namespace, claim_name]}
                        if isinstance(claim_meta, dict):
                            if "display" in claim_meta:
                                entry["display"] = claim_meta["display"]
                            if "mandatory" in claim_meta:
                                entry["mandatory"] = claim_meta["mandatory"]
                        claims_arr.append(entry)
            metadata["claims"] = claims_arr

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
            # M-4: strip private key material before serialising.
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
            # Check if already stored
            existing_key = await storage_manager.get_key(session, static_key_id)
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
                        # C-1: store only public metadata; private key is in jwk['d']
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

                    # Set as default
                    await storage_manager.store_config(
                        session, "default_signing_key", {"key_id": static_key_id}
                    )

                except Exception as e:
                    LOGGER.error("Failed to load static signing key: %s", e)

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
        await resolve_signing_key_for_credential(context.profile, session)
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
            payload = self._prepare_payload(ex_record.credential_subject, doctype)

            # Resolve signing key
            async with context.profile.session() as session:
                key_data = await self._resolve_signing_key(
                    context, session, verification_method
                )
                key_id = key_data.get("key_id")
                # C-1: private_key_pem is no longer persisted in metadata.
                # Reconstruct it on-demand from the JWK 'd' parameter.
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

                if not certificate_pem and private_key_pem:
                    LOGGER.info(
                        "Certificate not found for key %s, generating one", key_id
                    )
                    certificate_pem = generate_self_signed_certificate(private_key_pem)

                    # Store the generated certificate
                    cert_id = f"mdoc-cert-{uuid.uuid4().hex[:8]}"
                    await storage_manager.store_certificate(
                        session,
                        cert_id=cert_id,
                        certificate_pem=certificate_pem,
                        key_id=key_id,
                        metadata={
                            "self_signed": True,
                            "purpose": "mdoc_issuing",
                            "generated_on_demand": True,
                            "valid_from": datetime.now(UTC).isoformat(),
                            "valid_to": (
                                datetime.now(UTC) + timedelta(days=365)
                            ).isoformat(),
                        },
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
            raise CredProcessorError(f"Failed to issue mso_mdoc credential: {ex}") from ex

        return mso_mdoc

    def _prepare_payload(
        self, payload: Dict[str, Any], doctype: str = None
    ) -> Dict[str, Any]:
        """Prepare payload for mDoc issuance.

        Ensures required fields are present and binary data is correctly encoded.
        """
        prepared = payload.copy()

        # Flatten doctype dictionary if present
        # The Rust struct expects a flat dictionary with all fields
        if doctype and doctype in prepared:
            doctype_claims = prepared.pop(doctype)
            if isinstance(doctype_claims, dict):
                # Warn if flattening would silently overwrite existing top-level
                # keys — callers should not mix namespaced and flat claims for
                # the same fields.
                conflicts = set(doctype_claims.keys()) & set(prepared.keys())
                if conflicts:
                    LOGGER.warning(
                        "Payload namespace flattening for doctype '%s': "
                        "top-level keys %s will be overwritten by doctype claims",
                        doctype,
                        sorted(conflicts),
                    )
                LOGGER.debug(
                    "Flattening doctype wrapper '%s' (%d claims) into top-level payload",
                    doctype,
                    len(doctype_claims),
                )
                prepared.update(doctype_claims)

        # Encode portrait if present
        if "portrait" in prepared:
            portrait = prepared["portrait"]
            if isinstance(portrait, bytes):
                prepared["portrait"] = base64.b64encode(portrait).decode("utf-8")
            elif isinstance(portrait, list):
                # Handle list of integers (byte array representation)
                try:
                    prepared["portrait"] = base64.b64encode(bytes(portrait)).decode(
                        "utf-8"
                    )
                except Exception:
                    # If conversion fails, leave as is
                    pass

        return prepared

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
                # C-2: do NOT call codecs.decode(cleaned, "unicode_escape") —
                # that interprets arbitrary byte sequences in attacker-controlled
                # input and can be exploited for code-path attacks.  The hex/base64
                # string produced by isomdl-uniffi contains only printable ASCII,
                # so returning it directly is both safe and correct.
                return cleaned
            # Remove b" prefix and " suffix if present
            elif result.startswith('b"') and result.endswith('"'):
                cleaned = result[2:-1]
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
