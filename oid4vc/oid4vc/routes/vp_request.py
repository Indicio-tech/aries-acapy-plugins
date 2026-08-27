"""OID4VP request routes for admin API."""

import json
import re
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone
from typing import List
from urllib.parse import quote

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.askar.profile_anon import AskarAnonCredsProfileSession
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import P256
from acapy_agent.wallet.util import bytes_to_b64
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
)
from aries_askar import Key
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from marshmallow import fields

from ..config import Config
from ..did_utils import retrieve_or_create_did_jwk
from ..jwk import DID_JWK
from ..models.presentation import (
    OID4VPPresentation,
    OID4VPPresentationSchema,
)
from ..models.request import (
    OID4VPRequest,
    OID4VPRequestSchema,
)


class CreateOID4VPReqResponseSchema(OpenAPISchema):
    """Response schema for creating an OID4VP Request."""

    request_uri = fields.Str(
        required=True,
        metadata={
            "description": "URI for the holder to resolve the request",
        },
    )

    request = fields.Nested(
        OID4VPRequestSchema,
        required=True,
        metadata={"descripton": "The created request"},
    )

    presentation = fields.Nested(
        OID4VPPresentationSchema,
        required=True,
        metadata={"descripton": "The created presentation"},
    )


class CreateOID4VPReqRequestSchema(OpenAPISchema):
    """Request schema for creating an OID4VP Request."""

    pres_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify presentation definition",
        },
    )

    dcql_query_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify DCQL query",
        },
    )

    vp_formats = fields.Dict(
        required=True,
        metadata={
            "description": "Expected presentation formats from the holder",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Create an OID4VP Request.",
)
@request_schema(CreateOID4VPReqRequestSchema)
@response_schema(CreateOID4VPReqResponseSchema)
async def create_oid4vp_request(request: web.Request):
    """Create an OID4VP Request."""

    context: AdminRequestContext = request["context"]
    body = await request.json()

    async with context.session() as session:
        # Get the DID:JWK that will be used as fallback client_id
        jwk = await retrieve_or_create_did_jwk(session)

        # Use x509 identity (x509_san_dns) when registered; otherwise did:jwk.
        storage = session.inject(BaseStorage)
        try:
            x509_record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            x509_id = json.loads(x509_record.value)
        except StorageNotFoundError:
            x509_id = None

        # OID4VP Final (ID3+): client_id for x509_san_dns scheme uses
        # URI prefix format: "x509_san_dns:{dns_name}".
        # This must match the client_id in the JAR payload.
        if x509_id:
            effective_client_id = f"x509_san_dns:{x509_id['client_id']}"
        else:
            effective_client_id = jwk.did

        if pres_def_id := body.get("pres_def_id"):
            req_record = OID4VPRequest(
                pres_def_id=pres_def_id, vp_formats=body["vp_formats"]
            )
            await req_record.save(session=session)

            pres_record = OID4VPPresentation(
                pres_def_id=pres_def_id,
                state=OID4VPPresentation.REQUEST_CREATED,
                request_id=req_record.request_id,
                client_id=effective_client_id,
            )
            await pres_record.save(session=session)

        elif dcql_query_id := body.get("dcql_query_id"):
            req_record = OID4VPRequest(
                dcql_query_id=dcql_query_id, vp_formats=body["vp_formats"]
            )
            await req_record.save(session=session)

            pres_record = OID4VPPresentation(
                dcql_query_id=dcql_query_id,
                state=OID4VPPresentation.REQUEST_CREATED,
                request_id=req_record.request_id,
                client_id=effective_client_id,
            )
            await pres_record.save(session=session)
        else:
            raise web.HTTPBadRequest(
                reason="One of pres_def_id or dcql_query_id must be provided"
            )

    config = Config.from_settings(context.settings)
    # wallet.id is present on sub-wallet profiles in all multitenant modes;
    # do not gate on multitenant.enabled (absent from sub-wallet settings in
    # single-wallet-askar mode), just read it directly.
    wallet_id = context.profile.settings.get("wallet.id")
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    # Use OID4VP_ENDPOINT when available (may differ from OID4VCI endpoint,
    # e.g.served via a separate TLS-terminating proxy for conformance tests).
    oid4vp_base = config.oid4vp_endpoint or config.endpoint
    request_uri = quote(f"{oid4vp_base}{subpath}/oid4vp/request/{req_record._id}")
    # In OID4VP Final spec, client_id_scheme was removed from authorization
    # request query parameters (it was removed in ID3 / draft-28).  The scheme
    # is communicated inside the signed JAR instead.  Do NOT include
    # client_id_scheme as a query parameter.
    full_uri = (
        f"openid://?client_id={quote(effective_client_id)}&request_uri={request_uri}"
    )

    return web.json_response(
        {
            "request_uri": full_uri,
            "request": req_record.serialize(),
            "presentation": pres_record.serialize(),
        }
    )


class OID4VPRequestQuerySchema(OpenAPISchema):
    """Parameters and validators for presentations list query."""

    request_id = fields.UUID(
        required=False,
        metadata={"description": "Filter by request identifier."},
    )
    pres_def_id = fields.Str(
        required=False,
        metadata={"description": "Filter by presentation definition identifier."},
    )
    dcql_query_id = fields.Str(
        required=False,
        metadata={"description": "Filter by DCQL query identifier."},
    )


class OID4VPRequestListSchema(OpenAPISchema):
    """Result schema for an presentations query."""

    results = fields.Nested(
        OID4VPPresentationSchema(),
        many=True,
        metadata={"description": "Presentation Requests"},
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch all OID4VP Requests.",
)
@querystring_schema(OID4VPRequestQuerySchema())
@response_schema(OID4VPRequestListSchema())
async def list_oid4vp_requests(request: web.Request):
    """Request handler for searching requests."""

    context: AdminRequestContext = request["context"]

    try:
        async with context.profile.session() as session:
            if request_id := request.query.get("request_id"):
                record = await OID4VPRequest.retrieve_by_id(session, request_id)
                results = [record.serialize()]
            else:
                filter_ = {
                    attr: value
                    for attr in ("pres_def_id", "dcql_query_id")
                    if (value := request.query.get(attr))
                }
                records = await OID4VPRequest.query(session=session, tag_filter=filter_)
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


# ---------------------------------------------------------------------------
# X.509 identity admin endpoints
#
# These endpoints manage a single "X.509 identity" record that lets ACA-Py act
# as an OID4VP verifier with client_id_scheme=x509_san_dns.  The record stores
# the DER certificate chain (base64, leaf-first) together with the
# verification method referencing the matching signing key and the DNS name
# used as client_id.
# ---------------------------------------------------------------------------

X509_IDENTITY_RECORD_TYPE = "OID4VP.x509_identity"
X509_IDENTITY_RECORD_ID = "OID4VP.x509_identity"


class RegisterX509IdentitySchema(OpenAPISchema):
    """Request body for registering an X.509 identity."""

    cert_chain_pem = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM-encoded certificate chain (leaf first, concatenated).  "
                "Each certificate will be stored as a base64-encoded DER value "
                "in the x5c array."
            )
        },
    )
    verification_method = fields.Str(
        required=True,
        metadata={
            "description": (
                'Verification method identifier (e.g. "did:jwk:...#0") that '
                "references the key matching the leaf certificate."
            )
        },
    )
    client_id = fields.Str(
        required=True,
        metadata={
            "description": (
                "DNS name used as client_id in OID4VP requests "
                "(must match the dNSName SAN in the leaf certificate)."
            )
        },
    )


class BootstrapX509IdentitySchema(OpenAPISchema):
    """Temporary X.509 reader bootstrap request."""

    client_id = fields.Str(
        required=True,
        metadata={"description": "DNS name used as the x509_san_dns client_id."},
    )


def _b64url(value: int) -> str:
    """Encode an EC integer as an unpadded base64url value."""
    return urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()


async def _store_x509_identity(session, pem, verification_method, client_id):
    """Store the active X.509 verifier identity and return its public record."""
    b64_certs: List[str] = [
        re.sub(r"\s+", "", cert)
        for cert in re.findall(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            pem,
            re.DOTALL,
        )
    ]
    if not b64_certs:
        raise web.HTTPBadRequest(reason="No certificates found in cert_chain_pem")

    identity = {
        "cert_chain": b64_certs,
        "verification_method": verification_method,
        "client_id": client_id,
    }
    storage = session.inject(BaseStorage)
    try:
        existing = await storage.get_record(
            X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
        )
        await storage.update_record(existing, json.dumps(identity), {})
    except StorageNotFoundError:
        await storage.add_record(
            StorageRecord(
                type=X509_IDENTITY_RECORD_TYPE,
                value=json.dumps(identity),
                id=X509_IDENTITY_RECORD_ID,
            )
        )
    return identity


@docs(tags=["oid4vp"], summary="Bootstrap a temporary X.509 verifier identity")
@request_schema(BootstrapX509IdentitySchema())
async def bootstrap_x509_identity(request: web.Request):
    """Create a wallet-backed P-256 key and a temporary matching certificate chain."""
    context: AdminRequestContext = request["context"]
    client_id = (await request.json())["client_id"]

    try:
        x509.DNSName(client_id)
    except ValueError as err:
        raise web.HTTPBadRequest(reason="client_id must be a valid DNS name") from err

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Proven Temporary Reader CA")]
    )
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_id)])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, SHA256())
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(client_id)]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, SHA256())
    )

    private_numbers = leaf_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    private_jwk = json.dumps(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(public_numbers.x),
            "y": _b64url(public_numbers.y),
            "d": _b64url(private_numbers.private_value),
        }
    )
    wallet_key = Key.from_jwk(private_jwk)
    thumbprint = wallet_key.get_jwk_thumbprint()
    public_jwk = json.loads(wallet_key.get_jwk_public())
    public_jwk["use"] = "sig"
    did = "did:jwk:" + bytes_to_b64(
        json.dumps(public_jwk).encode(), urlsafe=True, pad=False
    )
    verification_method = f"{did}#0"
    leaf_pem = leaf_cert.public_bytes(Encoding.PEM).decode()
    ca_pem = ca_cert.public_bytes(Encoding.PEM).decode()
    cert_chain_pem = leaf_pem + ca_pem

    async with context.session() as session:
        assert isinstance(
            session,
            (AskarProfileSession, AskarAnonCredsProfileSession),
        )
        await session.handle.insert_key(thumbprint, wallet_key)
        wallet = session.inject(BaseWallet)
        await wallet.store_did(
            DIDInfo(
                did=did,
                verkey=thumbprint,
                metadata={"temporary_x509_identity": True},
                method=DID_JWK,
                key_type=P256,
            )
        )
        await _store_x509_identity(
            session, cert_chain_pem, verification_method, client_id
        )

    return web.json_response(
        {
            "client_id": client_id,
            "did": did,
            "verification_method": verification_method,
            "leaf_certificate_pem": leaf_pem,
            "ca_certificate_pem": ca_pem,
            "cert_chain_pem": cert_chain_pem,
            "expires_at": leaf_cert.not_valid_after_utc.isoformat(),
        }
    )


@docs(tags=["oid4vp"], summary="Register X.509 identity for OID4VP requests")
@request_schema(RegisterX509IdentitySchema())
async def register_x509_identity(request: web.Request):
    """Store an X.509 certificate chain for x509_san_dns OID4VP requests."""
    context: AdminRequestContext = request["context"]
    body = await request.json()

    pem: str = body["cert_chain_pem"]
    verification_method: str = body["verification_method"]
    client_id: str = body["client_id"]

    async with context.session() as session:
        identity = await _store_x509_identity(
            session, pem, verification_method, client_id
        )

    return web.json_response(identity)


@docs(tags=["oid4vp"], summary="Retrieve registered X.509 identity")
async def get_x509_identity(request: web.Request):
    """Return the stored X.509 identity record."""
    context: AdminRequestContext = request["context"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            return web.json_response(json.loads(record.value))
        except StorageNotFoundError:
            raise web.HTTPNotFound(reason="No X.509 identity registered")


@docs(tags=["oid4vp"], summary="Delete registered X.509 identity")
async def delete_x509_identity(request: web.Request):
    """Remove the stored X.509 identity record."""
    context: AdminRequestContext = request["context"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            await storage.delete_record(record)
        except StorageNotFoundError:
            raise web.HTTPNotFound(reason="No X.509 identity registered")

    return web.json_response({"deleted": True})
