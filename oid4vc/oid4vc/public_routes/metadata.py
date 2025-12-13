"""Credential issuer metadata endpoints for OID4VCI and OpenID Connect Discovery."""

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, response_schema
from marshmallow import fields

from ..config import Config
from ..models.supported_cred import SupportedCredential
from ..utils import get_tenant_subpath
from .constants import LOGGER


class OpenIDConfigurationSchema(OpenAPISchema):
    """OpenID Provider Configuration schema.

    OpenID Connect Discovery 1.0 § 3: OpenID Provider Metadata
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

    Also incorporates OAuth 2.0 Authorization Server Metadata (RFC 8414).
    """

    issuer = fields.Str(
        required=True,
        metadata={
            "description": "URL using the https scheme with no query or fragment "
            "component that the OP asserts as its Issuer Identifier. REQUIRED."
        },
    )
    authorization_endpoint = fields.Str(
        required=False,
        metadata={
            "description": "URL of the OP's OAuth 2.0 Authorization Endpoint. "
            "REQUIRED for Authorization Code Flow, OPTIONAL for pre-authorized code."
        },
    )
    token_endpoint = fields.Str(
        required=True,
        metadata={
            "description": "URL of the OP's OAuth 2.0 Token Endpoint. REQUIRED."
        },
    )
    jwks_uri = fields.Str(
        required=False,
        metadata={
            "description": "URL of the OP's JWK Set document. OPTIONAL."
        },
    )
    registration_endpoint = fields.Str(
        required=False,
        metadata={
            "description": "URL of the OP's Dynamic Client Registration Endpoint. OPTIONAL."
        },
    )
    scopes_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "JSON array containing a list of the OAuth 2.0 scope values "
            "that this server supports. RECOMMENDED."
        },
    )
    response_types_supported = fields.List(
        fields.Str(),
        required=True,
        metadata={
            "description": "JSON array containing a list of the OAuth 2.0 response_type "
            "values that this OP supports. REQUIRED."
        },
    )
    response_modes_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "JSON array containing a list of the OAuth 2.0 response_mode "
            "values that this OP supports. OPTIONAL."
        },
    )
    grant_types_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "JSON array containing a list of the OAuth 2.0 Grant Type "
            "values that this OP supports. OPTIONAL."
        },
    )
    subject_types_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "JSON array containing a list of the Subject Identifier types "
            "that this OP supports. Valid types include 'pairwise' and 'public'. OPTIONAL."
        },
    )
    id_token_signing_alg_values_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "JSON array containing a list of the JWS signing algorithms "
            "supported by the OP for the ID Token. OPTIONAL."
        },
    )
    token_endpoint_auth_methods_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "JSON array containing a list of Client Authentication methods "
            "supported by this Token Endpoint. OPTIONAL."
        },
    )
    credential_issuer = fields.Str(
        required=False,
        metadata={
            "description": "URL of the Credential Issuer. Included for OID4VCI compatibility."
        },
    )
    credential_endpoint = fields.Str(
        required=False,
        metadata={
            "description": "URL of the Credential Endpoint. Included for OID4VCI compatibility."
        },
    )
    credential_configurations_supported = fields.Dict(
        required=False,
        metadata={
            "description": "Credential configurations supported by this issuer. "
            "Included for OID4VCI compatibility."
        },
    )
    request_parameter_supported = fields.Bool(
        required=False,
        metadata={
            "description": "Boolean value specifying whether the OP supports use of the "
            "request parameter. OPTIONAL. Defaults to false."
        },
    )
    request_uri_parameter_supported = fields.Bool(
        required=False,
        metadata={
            "description": "Boolean value specifying whether the OP supports use of the "
            "request_uri parameter. OPTIONAL. Defaults to true."
        },
    )
    code_challenge_methods_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "JSON array containing a list of PKCE code challenge methods "
            "supported by this authorization server. OPTIONAL."
        },
    )


class BatchCredentialIssuanceSchema(OpenAPISchema):
    """Batch credential issuance schema."""

    batch_size = fields.Int(
        required=True, metadata={"description": "The maximum array size for the proofs"}
    )


class CredentialIssuerMetadataSchema(OpenAPISchema):
    """Credential issuer metadata schema.

    OpenID4VCI 1.0 § 11.2.1: Credential Issuer Metadata
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2.1
    """

    credential_issuer = fields.Str(
        required=True,
        metadata={
            "description": "The credential issuer identifier. REQUIRED. "
            "URL using the https scheme with no query or fragment component."
        },
    )
    authorization_servers = fields.List(
        fields.Str(),
        required=False,
        metadata={"description": "The authorization server endpoint."},
    )
    credential_endpoint = fields.Str(
        required=True,
        metadata={
            "description": "URL of the Credential Endpoint. REQUIRED. "
            "This URL MUST use the https scheme."
        },
    )
    credential_configurations_supported = fields.Dict(
        required=True,
        metadata={
            "description": "A JSON object containing a list of key-value pairs, "
            "where the key is a string serving as an identifier "
            "of the Credential Configuration, and the value is a JSON object. REQUIRED."
        },
    )
    authorization_servers = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "Array of strings that identify the OAuth 2.0 "
            "Authorization Servers (as defined in [RFC8414]) the Credential "
            "Issuer relies on for authorization. OPTIONAL."
        },
    )
    batch_credential_endpoint = fields.Str(
        required=False,
        metadata={
            "description": "URL of the Batch Credential Endpoint. OPTIONAL. "
            "This URL MUST use the https scheme."
        },
    )
    deferred_credential_endpoint = fields.Str(
        required=False,
        metadata={
            "description": "URL of the Deferred Credential Endpoint. OPTIONAL. "
            "This URL MUST use the https scheme."
        },
    )
    nonce_endpoint = fields.Str(
        required=False,
        metadata={"description": "The nonce endpoint."},
    )
    batch_credential_issuance = fields.Nested(
        BatchCredentialIssuanceSchema,
        required=False,
        metadata={"description": "The batch credential issuance. Currently ignored."},
    )


@docs(tags=["oid4vc"], summary="Get credential issuer metadata")
@response_schema(CredentialIssuerMetadataSchema())
async def credential_issuer_metadata(request: web.Request):
    """Credential issuer metadata endpoint.

    OpenID4VCI 1.0 § 11.2: Credential Issuer Metadata
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2

    The Credential Issuer Metadata contains information on the Credential Issuer's
    technical capabilities, supported Credential types, and (internationalization) data.
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""

        # Check for version in path
        version_path = ""
        if "/v1/" in request.path:
            version_path = "/v1"

        # OID4VCI 1.0 § 11.2.1: credential_configurations_supported is now a JSON object
        # where keys are credential configuration identifiers
        metadata = {
            "credential_issuer": f"{public_url}{subpath}{version_path}",
            "credential_endpoint": f"{public_url}{subpath}{version_path}/credential",
            "token_endpoint": f"{public_url}{subpath}{version_path}/token",
        }

        if config.auth_server_url:
            auth_tenant_subpath = get_tenant_subpath(context.profile)
            metadata["authorization_servers"] = [
                f"{config.auth_server_url}{auth_tenant_subpath}"
            ]

        metadata[
            "notification_endpoint"
        ] = f"{public_url}{subpath}{version_path}/notification"
        metadata["credential_configurations_supported"] = {
            supported.identifier: supported.to_issuer_metadata()
            for supported in credentials_supported
        }

    LOGGER.debug("METADATA: %s", metadata)

    return web.json_response(metadata)


async def credential_issuer_metadata_deprecated(request: web.Request):
    """Deprecated credential issuer metadata endpoint with underscore.

    This endpoint serves the same content as /.well-known/openid-credential-issuer
    but uses the deprecated underscore format for backward compatibility with
    clients that expect the OID4VCI pre-v1.0 naming convention.

    Note: This endpoint is deprecated and not supported by OID4VCI v1.0 protocol.
    Use /.well-known/openid-credential-issuer instead.
    """
    # Get the response from the main function
    response = await credential_issuer_metadata(request)

    # Add deprecation headers
    response.headers["Deprecation"] = "true"
    response.headers["Warning"] = (
        '299 - "This endpoint is deprecated. '
        'Use /.well-known/openid-credential-issuer instead."'
    )
    response.headers[
        "Sunset"
    ] = "Thu, 31 Dec 2026 23:59:59 GMT"  # TODO: Set appropriate sunset date

    return response


async def deprecated_credential_issuer_metadata(request: web.Request):
    """Deprecated endpoint for credential issuer metadata."""
    response = await credential_issuer_metadata(request)
    response.headers["Deprecation"] = "true"
    response.headers["Warning"] = (
        '299 - "This endpoint is deprecated. '
        'Use /.well-known/openid-credential-issuer instead."'
    )
    response.headers[
        "Sunset"
    ] = "Thu, 31 Dec 2026 23:59:59 GMT"  # TODO: Set appropriate sunset date
    return response


@docs(tags=["oid4vc"], summary="Get OpenID Provider configuration")
@response_schema(OpenIDConfigurationSchema())
async def openid_configuration(request: web.Request):
    """OpenID Provider Configuration endpoint.

    OpenID Connect Discovery 1.0 § 4: Obtaining OpenID Provider Configuration Information
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig

    This endpoint serves the standard OpenID Connect Discovery metadata at
    /.well-known/openid-configuration. It combines OpenID Connect Discovery 1.0
    metadata with OAuth 2.0 Authorization Server Metadata (RFC 8414) and
    OID4VCI-specific extensions.

    The response includes:
    - Standard OIDC Discovery fields (issuer, token_endpoint, etc.)
    - OAuth 2.0 AS metadata (grant_types_supported, response_types_supported)
    - OID4VCI extensions (credential_issuer, credential_endpoint, etc.)
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # Get supported credentials for OID4VCI compatibility
        credentials_supported = await SupportedCredential.query(session)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""

        # Check for version in path
        version_path = ""
        if "/v1/" in request.path:
            version_path = "/v1"

        issuer_url = f"{public_url}{subpath}{version_path}"

        # Build OpenID Provider Configuration metadata
        # Per OpenID Connect Discovery 1.0 § 3
        metadata = {
            # REQUIRED fields per OIDC Discovery
            "issuer": issuer_url,
            "token_endpoint": f"{issuer_url}/token",
            "response_types_supported": [
                "code",  # For future Authorization Code Flow support
                "token",  # For pre-authorized code flow
            ],
            # RECOMMENDED fields
            "scopes_supported": ["openid"],
            # OAuth 2.0 AS Metadata (RFC 8414)
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                # "authorization_code",  # TODO: Add when Authorization Code Flow is implemented
            ],
            "response_modes_supported": ["query", "fragment", "direct_post"],
            "token_endpoint_auth_methods_supported": ["none"],
            # PKCE support
            "code_challenge_methods_supported": ["S256"],
            # OID4VCI compatibility - include credential issuer metadata
            "credential_issuer": issuer_url,
            "credential_endpoint": f"{issuer_url}/credential",
            "notification_endpoint": f"{issuer_url}/notification",
            "credential_configurations_supported": {
                supported.identifier: supported.to_issuer_metadata()
                for supported in credentials_supported
            },
        }

        # Add authorization server URL if configured
        if config.auth_server_url:
            auth_tenant_subpath = get_tenant_subpath(context.profile)
            metadata["authorization_servers"] = [
                f"{config.auth_server_url}{auth_tenant_subpath}"
            ]
            # If there's an external auth server, include its authorization endpoint
            metadata["authorization_endpoint"] = (
                f"{config.auth_server_url}{auth_tenant_subpath}/authorize"
            )

    LOGGER.debug("OpenID Configuration: %s", metadata)

    return web.json_response(metadata)
