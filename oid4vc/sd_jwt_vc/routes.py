"""Admin routes for the SD-JWT extra."""

import logging
from typing import Any, Dict
from aiohttp_apispec import docs, request_schema, response_schema
from aiohttp import web

from oid4vc.cred_processor import CredProcessors
from sd_jwt_vc.supported_credential import (
    SdJwtSupportedCredential,
    SdJwtSupportedCredentialSchema,
)
from aries_cloudagent.admin.decorators.auth import tenant_authentication
from aries_cloudagent.admin.request_context import AdminRequestContext

LOGGER = logging.getLogger(__name__)


@docs(tags=["oid4vci"], summary="Register an SD-JWT credential")
@request_schema(SdJwtSupportedCredentialSchema())
@response_schema(SdJwtSupportedCredentialSchema())
@tenant_authentication
async def sd_jwt_supported_credential_create(request: web.Request):
    """Request handler for creating a credential supported record."""
    context = request["context"]
    assert isinstance(context, AdminRequestContext)
    profile = context.profile

    body: Dict[str, Any] = await request.json()
    LOGGER.info(f"body: {body}")

    record = SdJwtSupportedCredential.deserialize(body)

    registered_processors = context.inject(CredProcessors)
    if record.format not in registered_processors.issuers:
        raise web.HTTPBadRequest(
            reason=f"Format {record.format} is not supported by"
            " currently registered processors"
        )

    processor = registered_processors.issuer_for_format(record.format)
    try:
        processor.validate_supported_credential(record)
    except ValueError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    async with profile.session() as session:
        await record.save(session, reason="Save credential supported record.")

    return web.json_response(record.serialize())


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post(
                "/oid4vci/credential-supported/sd-jwt/create",
                sd_jwt_supported_credential_create,
            ),
        ]
    )
