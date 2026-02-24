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
        # NOTE: token_endpoint is NOT part of credential issuer metadata per
        # OID4VCI spec (§11.2.1). It belongs in the authorization server metadata
        # (/.well-known/oauth-authorization-server or /.well-known/openid-configuration).
        metadata["credential_endpoint"] = f"{public_url}{subpath}/credential"
        metadata["notification_endpoint"] = f"{public_url}{subpath}/notification"
        metadata["nonce_endpoint"] = f"{public_url}{subpath}/nonce"
        metadata["credential_configurations_supported"] = {
            supported.identifier: supported.to_issuer_metadata()
            for supported in credentials_supported
        }

    LOGGER.debug("METADATA: %s", metadata)

    return web.json_response(metadata)


@docs(tags=["oid4vc"], summary="OpenID Connect Discovery with OID4VCI")
async def openid_configuration(request: web.Request):
    """OpenID Connect Discovery endpoint with OID4VCI compatibility.

    Returns combined OpenID Connect Discovery 1.0 metadata and OID4VCI
    credential issuer metadata for maximum interoperability.
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""
        base_url = f"{public_url}{subpath}"

        # Combined OIDC Discovery + OID4VCI metadata
        metadata: dict[str, Any] = {
            # OIDC Discovery fields (RFC 8414 / OIDC Discovery required fields)
            "issuer": base_url,
            # authorization_endpoint is required by CheckServerConfiguration in the
            # OIDF conformance suite (condition.common.CheckServerConfiguration checks
            # for "authorization_endpoint", "token_endpoint", and "issuer").
            # For pre-authorized_code flow the authorization endpoint is not invoked,
            # but it must be advertised in the AS metadata.
            "authorization_endpoint": f"{base_url}/authorize",
            "token_endpoint": f"{base_url}/token",
            "response_types_supported": ["code"],
            # DPoP support - required by HAIP profile (DPOP-5.1).
            # Advertise the algorithms supported for DPoP proof JWTs.
            "dpop_signing_alg_values_supported": ["ES256", "ES384", "ES512"],
            # OAuth 2.0 AS Metadata fields
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            # RFC 9396 Rich Authorization Requests — advertise the authorization_details
            # type(s) supported (required by OID4VCI HAIP AS metadata validation).
            "authorization_details_types_supported": ["openid_credential"],
            # OID4VCI fields
            "credential_issuer": base_url,
            "credential_endpoint": f"{base_url}/credential",
            "notification_endpoint": f"{base_url}/notification",
            # OID4VCI nonce endpoint for server-generated nonces (HAIP required).
            # Wallets call this before building a credential proof to get a fresh
            # nonce that ACA-Py validates in the JWT proof `nonce` claim.
            "nonce_endpoint": f"{base_url}/nonce",
            "credential_configurations_supported": {
                supported.identifier: supported.to_issuer_metadata()
                for supported in credentials_supported
            },
        }

        if config.auth_server_url:
            auth_tenant_subpath = get_tenant_subpath(context.profile)
            metadata["authorization_servers"] = [
                f"{config.auth_server_url}{auth_tenant_subpath}"
            ]

    LOGGER.debug("OPENID CONFIG: %s", metadata)

    return web.json_response(metadata)
