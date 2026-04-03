"""Pluggable signing backend for mDoc credential issuance.

Defines an abstract ``MdocSigningBackend`` interface that decouples signing-key
resolution and mDoc signing from the storage representation.  The default
``SoftwareSigningBackend`` wraps the prepare/complete signing flow from
isomdl-uniffi — private keys never cross the FFI boundary.  A future
``PKCS11SigningBackend`` can implement the same interface using HSM-backed
key material.

Backends are registered on the injection context via ``CredProcessors`` or
directly on the ``InjectionContext`` so they can be swapped per deployment.
"""

import abc
import json
import logging
from typing import Any, Dict, Mapping, Optional

from acapy_agent.core.profile import Profile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from isomdl_uniffi import Mdoc, PreparedMdoc

from .signing_key import MdocSigningKeyRecord

LOGGER = logging.getLogger(__name__)


class MdocSigningBackend(abc.ABC):
    """Abstract base class for mDoc signing backends.

    Implementations must provide:
    - ``resolve_signing_material`` — locate key + cert for a given doctype
    - ``sign_mdoc`` — produce a signed CBOR mDoc

    The split allows backends that hold key material externally (HSM, KMS)
    to avoid ever exposing raw private keys.
    """

    @abc.abstractmethod
    async def resolve_signing_material(
        self,
        profile: Profile,
        *,
        signing_key_id: Optional[str] = None,
        doctype: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resolve signing material for credential issuance.

        Returns a dict that ``sign_mdoc`` can consume.  The dict contents
        are backend-specific — the software backend returns PEM strings
        while an HSM backend might return a key handle / URI.

        Raises:
            ValueError: If no suitable signing material is found.
        """

    @abc.abstractmethod
    async def sign_mdoc(
        self,
        signing_material: Dict[str, Any],
        holder_jwk: dict,
        headers: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> str:
        """Produce a signed CBOR mDoc.

        Args:
            signing_material: Output of ``resolve_signing_material``.
            holder_jwk: The holder's public key (EC JWK dict).
            headers: mDoc headers (must include ``doctype``).
            payload: Namespace-keyed claim data.

        Returns:
            The signed mDoc as a string (base64url or hex, depending on
            the underlying library).
        """


class SoftwareSigningBackend(MdocSigningBackend):
    """Default software-based signing using isomdl-uniffi with PEM keys.

    This mirrors the original ``_resolve_signing_key`` + ``isomdl_mdoc_sign``
    path that existed before the pluggable backend refactor.
    """

    async def resolve_signing_material(
        self,
        profile: Profile,
        *,
        signing_key_id: Optional[str] = None,
        doctype: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resolve PEM key material from MdocSigningKeyRecord storage."""

        # 1. Explicit signing key record ID
        if signing_key_id:
            try:
                async with profile.session() as session:
                    key_record = await MdocSigningKeyRecord.retrieve_by_id(
                        session, signing_key_id
                    )
                if key_record.private_key_pem and key_record.certificate_pem:
                    return {
                        "private_key_pem": key_record.private_key_pem,
                        "certificate_pem": key_record.certificate_pem,
                    }
            except Exception as exc:
                LOGGER.warning(
                    "Could not load MdocSigningKeyRecord %s: %s",
                    signing_key_id,
                    exc,
                )

        # 2. Query by doctype (or any key if no doctype)
        try:
            async with profile.session() as session:
                tag_filter = {"doctype": doctype} if doctype else None
                key_records = await MdocSigningKeyRecord.query(
                    session, tag_filter=tag_filter
                )
                if not key_records and doctype:
                    # fall back to wildcard keys (no doctype set)
                    key_records = await MdocSigningKeyRecord.query(session)
                for key_record in key_records:
                    if key_record.private_key_pem and key_record.certificate_pem:
                        return {
                            "private_key_pem": key_record.private_key_pem,
                            "certificate_pem": key_record.certificate_pem,
                        }
        except Exception as exc:
            LOGGER.debug("MdocSigningKeyRecord query failed: %s", exc)

        raise ValueError(
            "No mDoc signing key configured. "
            "Import a signing key via POST /mso-mdoc/signing-keys."
        )

    async def sign_mdoc(
        self,
        signing_material: Dict[str, Any],
        holder_jwk: dict,
        headers: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> str:
        """Sign an mDoc using isomdl-uniffi with PEM key material.

        For the ISO 18013-5 mDL doctype, ``Mdoc.create_and_sign_mdl()`` is
        used directly so that mDL namespace elements are encoded with the
        correct CBOR field types (e.g. ``birth_date`` as a CBOR full-date
        rather than a plain text string).

        For all other doctypes, the prepare/complete flow is used — the mDoc
        structure is prepared in the Rust FFI layer, the signature payload is
        signed in Python, and the mDoc is completed with the raw signature and
        certificate chain.  Private keys never cross the FFI boundary in that
        path.
        """
        doctype = headers.get("doctype", "")
        holder_jwk_str = (
            json.dumps(holder_jwk) if isinstance(holder_jwk, dict) else str(holder_jwk)
        )
        cert_pem = signing_material["certificate_pem"]
        key_pem = signing_material["private_key_pem"]

        if doctype == "org.iso.18013.5.1.mDL":
            # Use the typed mDL builder (OrgIso1801351::from_json) which
            # encodes ISO 18013-5 fields with proper CBOR types.
            # The credential subject may be namespaced ({"org.iso.18013.5.1":
            # {...}}) or flat; normalise here as the old code did.
            mdl_ns = "org.iso.18013.5.1"
            aamva_key = "org.iso.18013.5.1.aamva"
            mdl_payload = payload.get(mdl_ns, payload)
            mdl_items: Dict[str, Any] = {
                k: v for k, v in mdl_payload.items() if k != aamva_key
            }
            mdl_items.setdefault("driving_privileges", [])
            aamva_payload: Optional[Dict[str, Any]] = payload.get(aamva_key)
            mdoc = Mdoc.create_and_sign_mdl(
                mdl_items=json.dumps(mdl_items),
                aamva_items=(
                    json.dumps(aamva_payload) if aamva_payload is not None else None
                ),
                holder_jwk=holder_jwk_str,
                iaca_cert_pem=cert_pem,
                iaca_key_pem=key_pem,
            )
            return mdoc.issuer_signed_b64()

        # Generic doctype: prepare/complete flow (private key stays in Python)
        namespaces: Dict[str, Dict[str, str]] = {
            doctype: {k: json.dumps(v) for k, v in payload.items()}
        }
        prepared = PreparedMdoc(
            doc_type=doctype,
            namespaces=namespaces,
            holder_jwk=holder_jwk_str,
            signature_algorithm="ES256",
        )

        sig_payload = prepared.signature_payload()

        # Sign with the DS private key via Python's cryptography library
        private_key = serialization.load_pem_private_key(
            key_pem.encode("utf-8"),
            password=None,
        )
        der_sig = private_key.sign(sig_payload, ec.ECDSA(hashes.SHA256()))

        # Convert DER-encoded ECDSA signature to raw r||s for COSE
        r_int, s_int = decode_dss_signature(der_sig)
        key_size = (private_key.key_size + 7) // 8
        raw_sig = r_int.to_bytes(key_size, byteorder="big") + s_int.to_bytes(
            key_size, byteorder="big"
        )

        # Complete the mDoc with signature and certificate chain
        mdoc = prepared.complete(
            certificate_chain_pem=cert_pem,
            signature=raw_sig,
        )

        return mdoc.issuer_signed_b64()
