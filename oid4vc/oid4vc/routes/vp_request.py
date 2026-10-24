"""OID4VP request routes for admin API."""

from datetime import datetime, timezone
from urllib.parse import quote

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.error import WalletNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields
from marshmallow.validate import OneOf

from ..config import Config
from ..did_utils import retrieve_or_create_did_jwk
from ..models.presentation import (
    OID4VPPresentation,
    OID4VPPresentationSchema,
)
from ..models.request import (
    OID4VPRequest,
    OID4VPRequestSchema,
)
from ..x509_identity import (
    ACTIVE_ID,
    PENDING_ID,
    PREVIOUS_ID,
    SCHEME_X509_HASH,
    SCHEME_X509_SAN_DNS,
    SCHEMES,
    X509IdentityError,
    X509IdentityUnusable,
    active_record,
    build_csr,
    check_chain,
    conflict_response,
    create_p256_did_jwk,
    delete_did_jwk_key,
    delete_record,
    expiry_status,
    get_record,
    load_trust_roots,
    parse_chain,
    public_jwk_of,
    put_record,
    recheck_record,
    resolve_client_identity,
    validate_csr_input,
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

        # Use the registered X.509 identity when there is one; otherwise did:jwk.
        # An identity that cannot sign (expired, or failing its checks) stops
        # the request: there is no fallback to did:jwk.
        try:
            identity = await resolve_client_identity(session, context.profile.settings)
        except X509IdentityUnusable as err:
            return conflict_response(str(err))
        # This must match the client_id in the JAR payload.
        effective_client_id = identity.client_id if identity else jwk.did

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
# A tenant holds one X.509 identity for signing OID4VP request objects
# (client_id x509_hash, or x509_san_dns). The key is made in the wallet and a
# CSR is returned; the certificate chain issued for it is registered only
# after every check passes. See oid4vc/x509_identity.py.
# ---------------------------------------------------------------------------


class CreateX509IdentityCsrSchema(OpenAPISchema):
    """Request body for creating a verifier key and CSR."""

    subject = fields.Dict(
        required=True,
        metadata={
            "description": (
                "Certificate subject: common_name (required), organization, "
                "organizational_unit, country, locality, state"
            ),
            "example": {"common_name": "Example Clinic", "country": "US"},
        },
    )
    san = fields.Dict(
        required=False,
        metadata={
            "description": "Optional subject alternative names: dns and uri lists",
            "example": {"dns": ["verifier.example.org"]},
        },
    )


class RegisterX509IdentitySchema(OpenAPISchema):
    """Request body for registering an X.509 identity."""

    cert_chain_pem = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM certificate chain, leaf first. It is registered only if "
                "every check passes: the leaf holds the wallet key, is not "
                "self-signed, each certificate is issued by the next, all are "
                "in date, the leaf allows digitalSignature, and (when roots are "
                "configured) the chain ends at a configured root."
            )
        },
    )
    client_id_scheme = fields.Str(
        required=False,
        validate=OneOf(SCHEMES),
        metadata={
            "description": "x509_hash (default) or x509_san_dns",
        },
    )
    client_id = fields.Str(
        required=False,
        metadata={
            "description": (
                "x509_san_dns only: the DNS name used as client_id; it must be "
                "a dNSName SAN of the leaf certificate"
            )
        },
    )
    verification_method = fields.Str(
        required=False,
        metadata={
            "description": (
                "did:jwk verification method of the P-256 key the leaf "
                "certifies; defaults to the key of the open CSR"
            )
        },
    )


class DeleteX509IdentityQuerySchema(OpenAPISchema):
    """Query parameters for deleting an X.509 identity."""

    pending = fields.Bool(
        required=False,
        metadata={"description": "Delete the open CSR instead of the active identity"},
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _identity_view(active, pending, previous) -> dict:
    """Return what the read routes show: no key material."""
    result = dict(active or {})
    if active and "leaf_not_after" in active:
        result.update(expiry_status(active))
    if pending:
        result["pending"] = {
            "state": pending["state"],
            "created_at": pending["created_at"],
            "verification_method": pending["verification_method"],
            "csr_pem": pending["csr_pem"],
        }
    if previous:
        result["previous"] = {
            "client_id": previous.get("client_id"),
            "leaf_not_after": previous.get("leaf_not_after"),
        }
    return result


async def _delete_key_if_unused(session, record: dict) -> None:
    """Delete a record's key if this flow made it and nothing else uses it."""
    if not record.get("managed_key"):
        return
    in_use = set()
    for record_id in (ACTIVE_ID, PENDING_ID, PREVIOUS_ID):
        other = await get_record(session, record_id)
        if other:
            in_use.add(other.get("verification_method"))
    if record["verification_method"] not in in_use:
        await delete_did_jwk_key(session, record["verification_method"])


@docs(tags=["oid4vp"], summary="Create a verifier key and CSR for an X.509 identity")
@request_schema(CreateX509IdentityCsrSchema())
async def create_x509_identity_csr(request: web.Request):
    """Make a P-256 key in the wallet and return a CSR signed with it."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    subject = body.get("subject")
    san = body.get("san")
    # Refuse bad input before a key exists, so nothing is left behind.
    try:
        validate_csr_input(subject, san)
    except X509IdentityError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    async with context.session() as session:
        did_info = await create_p256_did_jwk(session)
        verification_method = f"{did_info.did}#0"
        try:
            csr_pem = await build_csr(session, did_info, subject, san)
            old_pending = await get_record(session, PENDING_ID)
            await put_record(
                session,
                PENDING_ID,
                {
                    "state": "csr_created",
                    "verification_method": verification_method,
                    "csr_pem": csr_pem,
                    "subject": subject,
                    "managed_key": True,
                    "created_at": _now(),
                },
            )
        except Exception as err:
            # Any failure after the key was made removes it again.
            await delete_did_jwk_key(session, did_info.did)
            if isinstance(err, X509IdentityError):
                raise web.HTTPBadRequest(reason=str(err)) from err
            raise
        if old_pending:
            # A new CSR replaces an open one.
            await _delete_key_if_unused(session, old_pending)

    return web.json_response(
        {
            "csr_pem": csr_pem,
            "verification_method": verification_method,
            "public_jwk": public_jwk_of(verification_method),
        }
    )


@docs(tags=["oid4vp"], summary="Register X.509 identity for OID4VP requests")
@request_schema(RegisterX509IdentitySchema())
async def register_x509_identity(request: web.Request):
    """Check a certificate chain and store it as the tenant's X.509 identity."""
    context: AdminRequestContext = request["context"]
    body = await request.json()

    if body.get("client_id") and body.get("client_id_scheme") != SCHEME_X509_SAN_DNS:
        # Before x509_hash, the route took a DNS client_id with no scheme.
        # Refuse rather than silently registering a different client_id.
        raise web.HTTPBadRequest(
            reason='client_id is only used with client_id_scheme "x509_san_dns"'
        )
    scheme = body.get("client_id_scheme") or SCHEME_X509_HASH
    if scheme not in SCHEMES:
        raise web.HTTPBadRequest(
            reason="client_id_scheme must be x509_hash or x509_san_dns"
        )
    dns_name = body.get("client_id") if scheme == SCHEME_X509_SAN_DNS else None
    if scheme == SCHEME_X509_SAN_DNS and not dns_name:
        raise web.HTTPBadRequest(reason="client_id is required for x509_san_dns")
    cert_chain_pem = body.get("cert_chain_pem")
    if not isinstance(cert_chain_pem, str):
        raise web.HTTPBadRequest(reason="cert_chain_pem is required")

    async with context.session() as session:
        pending = await get_record(session, PENDING_ID)
        verification_method = body.get("verification_method") or (pending or {}).get(
            "verification_method"
        )
        if not verification_method:
            raise web.HTTPBadRequest(
                reason="No verification_method given and no open CSR"
            )
        try:
            jwk = public_jwk_of(verification_method)
            try:
                await session.inject(BaseWallet).get_local_did(
                    verification_method.split("#", 1)[0]
                )
            except WalletNotFoundError as err:
                raise X509IdentityError("The key is not in this wallet") from err
            checked = check_chain(
                parse_chain(cert_chain_pem),
                jwk,
                scheme=scheme,
                dns_name=dns_name,
                roots=load_trust_roots(context.profile.settings),
            )
        except X509IdentityError as err:
            raise web.HTTPBadRequest(reason=str(err)) from err

        record = active_record(checked, scheme, verification_method)
        record["managed_key"] = bool(
            pending and pending["verification_method"] == verification_method
        )

        current = await get_record(session, ACTIVE_ID)
        if current and current.get("verification_method") != verification_method:
            # Keep the replaced identity for rollback; delete anything older.
            older = await get_record(session, PREVIOUS_ID)
            await put_record(session, PREVIOUS_ID, current)
            if older:
                await _delete_key_if_unused(session, older)
        await put_record(session, ACTIVE_ID, record)
        if record["managed_key"]:
            await delete_record(session, PENDING_ID)

        view = _identity_view(
            record,
            await get_record(session, PENDING_ID),
            await get_record(session, PREVIOUS_ID),
        )

    return web.json_response(view)


@docs(tags=["oid4vp"], summary="Retrieve registered X.509 identity")
async def get_x509_identity(request: web.Request):
    """Return the X.509 identity, its expiry status and any open CSR."""
    context: AdminRequestContext = request["context"]

    async with context.session() as session:
        active = await get_record(session, ACTIVE_ID)
        pending = await get_record(session, PENDING_ID)
        previous = await get_record(session, PREVIOUS_ID)

    if not active and not pending:
        raise web.HTTPNotFound(reason="No X.509 identity registered")
    return web.json_response(_identity_view(active, pending, previous))


@docs(tags=["oid4vp"], summary="Delete registered X.509 identity")
@querystring_schema(DeleteX509IdentityQuerySchema())
async def delete_x509_identity(request: web.Request):
    """Remove the active identity (or the open CSR) and its key."""
    context: AdminRequestContext = request["context"]
    pending_only = request.query.get("pending", "").lower() in ("true", "1")
    record_id = PENDING_ID if pending_only else ACTIVE_ID

    async with context.session() as session:
        record = await get_record(session, record_id)
        if not record:
            raise web.HTTPNotFound(
                reason="No open CSR" if pending_only else "No X.509 identity registered"
            )
        await delete_record(session, record_id)
        await _delete_key_if_unused(session, record)

    return web.json_response({"deleted": True})


@docs(tags=["oid4vp"], summary="Roll back to the previous X.509 identity")
async def rollback_x509_identity(request: web.Request):
    """Make the previous identity active again, if it still passes its checks."""
    context: AdminRequestContext = request["context"]

    async with context.session() as session:
        previous = await get_record(session, PREVIOUS_ID)
        if not previous:
            return conflict_response("No previous X.509 identity to roll back to")
        try:
            restored = await recheck_record(session, previous, context.profile.settings)
        except X509IdentityError as err:
            return conflict_response(f"The previous X.509 identity cannot be used: {err}")
        restored["managed_key"] = previous.get("managed_key", False)

        current = await get_record(session, ACTIVE_ID)
        await put_record(session, ACTIVE_ID, restored)
        if current:
            await put_record(session, PREVIOUS_ID, current)
        else:
            await delete_record(session, PREVIOUS_ID)

        view = _identity_view(
            restored,
            await get_record(session, PENDING_ID),
            await get_record(session, PREVIOUS_ID),
        )

    return web.json_response(view)
