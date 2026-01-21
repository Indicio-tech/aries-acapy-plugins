"""Credential issuer metadata endpoint for OID4VCI."""

import logging
from typing import Any

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, response_schema
from marshmallow import fields

from ..config import Config
from ..models.supported_cred import SupportedCredential
from ..utils import get_tenant_subpath

LOGGER = logging.getLogger(__name__)


class BatchCredentialIssuanceSchema(OpenAPISchema):
    """Batch credential issuance schema."""

    batch_size = fields.Int(
        required=True, metadata={"description": "The maximum array size for the proofs"}
    )


class CredentialIssuerMetadataSchema(OpenAPISchema):
    """Credential issuer metadata schema."""

    credential_issuer = fields.Str(
        required=True,
        metadata={"description": "The credential issuer endpoint."},
    )
    authorization_servers = fields.List(
        fields.Str(),
        required=False,
        metadata={"description": "The authorization server endpoint."},
    )
    credential_endpoint = fields.Str(
        required=True,
        metadata={"description": "The credential endpoint."},
    )
    nonce_endpoint = fields.Str(
        required=False,
        metadata={"description": "The nonce endpoint."},
    )
    credential_configurations_supported = fields.List(
        fields.Dict(),
        metadata={"description": "The supported credentials."},
    )
    batch_credential_issuance = fields.Nested(
        BatchCredentialIssuanceSchema,
        required=False,
        metadata={"description": "The batch credential issuance. Currently ignored."},
    )


@docs(tags=["oid4vc"], summary="Get credential issuer metadata")
@response_schema(CredentialIssuerMetadataSchema())
async def credential_issuer_metadata(request: web.Request):
    """Credential issuer metadata endpoint."""
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""
        metadata: dict[str, Any] = {"credential_issuer": f"{public_url}{subpath}"}
        if config.auth_server_url:
            auth_tenant_subpath = get_tenant_subpath(context.profile)
            metadata["authorization_servers"] = [
                f"{config.auth_server_url}{auth_tenant_subpath}"
            ]
        metadata["credential_endpoint"] = f"{public_url}{subpath}/credential"
        metadata["notification_endpoint"] = f"{public_url}{subpath}/notification"
        metadata["credential_configurations_supported"] = {
            supported.identifier: supported.to_issuer_metadata()
            for supported in credentials_supported
        }

    LOGGER.debug("METADATA: %s", metadata)

    return web.json_response(metadata)
