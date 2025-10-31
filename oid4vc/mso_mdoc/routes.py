"""mso_mdoc admin routes.

Provides REST API endpoints for ISO/IEC 18013-5:2021 compliant mobile document
(mDoc) operations including signing and verification. These endpoints implement
the mobile security object (MSO) format for secure credential issuance and
verification as specified in the ISO 18013-5 standard.

Protocol Compliance:
- ISO/IEC 18013-5:2021: Mobile driving licence (mDL) application
- RFC 8152: CBOR Object Signing and Encryption (COSE)
- RFC 8949: Concise Binary Object Representation (CBOR)
"""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.valid import (
    GENERIC_DID_EXAMPLE,
    GENERIC_DID_VALIDATE,
    Uri,
)
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import fields

from .cred_processor import resolve_signing_key_for_credential
from .key_routes import register_key_management_routes
from .mdoc import isomdl_mdoc_sign
from .mdoc import mdoc_verify as mso_mdoc_verify
from .storage import MdocStorageManager

# OpenID4VCI 1.0 § E.1.1: mso_mdoc Credential Format
# https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
# ISO/IEC 18013-5:2021 official specification URI
SPEC_URI = (
    "https://www.iso.org/obp/ui/#iso:std:iso-iec:18013:-5:dis:ed-1:v1:en"
)
OID4VCI_SPEC_URI = (
    "https://openid.net/specs/openid-4-verifiable-credential-issuance-"
    "1_0.html#appendix-E.1.1"
)
LOGGER = logging.getLogger(__name__)


class MdocPluginResponseSchema(OpenAPISchema):
    """Response schema for mso_mdoc Plugin."""


class MdocCreateSchema(OpenAPISchema):
    """Request schema to create a jws with a particular DID."""

    headers = fields.Dict()
    payload = fields.Dict(required=True)
    did = fields.Str(
        required=False,
        validate=GENERIC_DID_VALIDATE,
        metadata={
            "description": "DID of interest",
            "example": GENERIC_DID_EXAMPLE,
        },
    )
    verification_method = fields.Str(
        data_key="verificationMethod",
        required=False,
        validate=Uri(),
        metadata={
            "description": "Information used for proof verification",
            "example": (
                "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg34"
                "2Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ),
        },
    )


class MdocVerifySchema(OpenAPISchema):
    """Request schema to verify a mso_mdoc."""

    mso_mdoc = fields.Str(
        validate=None, metadata={"example": "a36776657273696f6e63312e..."}
    )


class MdocVerifyResponseSchema(OpenAPISchema):
    """Response schema for mso_mdoc verification result."""

    valid = fields.Bool(required=True)
    error = fields.Str(required=False, metadata={"description": "Error text"})
    kid = fields.Str(required=True, metadata={"description": "kid of signer"})
    headers = fields.Dict(
        required=True,
        metadata={"description": "Headers from verified mso_mdoc."},
    )
    payload = fields.Dict(
        required=True,
        metadata={"description": "Payload from verified mso_mdoc"},
    )


@docs(
    tags=["mso_mdoc"],
    summary=(
        "Creates mso_mdoc CBOR encoded binaries according to ISO 18013-5 and"
        " OpenID4VCI 1.0"
    ),
)
@request_schema(MdocCreateSchema)
@response_schema(MdocPluginResponseSchema(), description="")
async def mdoc_sign(request: web.BaseRequest):
    """Request handler for ISO 18013-5 mDoc credential signing.

    Creates and signs a mobile document (mDoc) credential following both
    ISO 18013-5 mobile document format and OpenID4VCI 1.0 mso_mdoc credential format.
    
    This endpoint implements the complete mDoc issuance workflow including:
    - Credential payload validation and formatting
    - ECDSA key resolution and validation
    - MSO (Mobile Security Object) creation
    - COSE signing with ES256 algorithm
    - CBOR encoding for compact binary representation

    Protocol Compliance:
    - OpenID4VCI 1.0 § E.1.1: mso_mdoc Credential Format
      https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
    - ISO 18013-5 § 8.3: Mobile document structure
    - ISO 18013-5 § 9.1.2: IssuerSigned data structure
    - RFC 8152: COSE signing for cryptographic protection
    - RFC 8949: CBOR encoding for compact binary representation

    Request Body:
        {
            "headers": { Optional headers for the mDoc MSO },
            "payload": { The credential claims per ISO 18013-5 § 8.3 },
            "did": { Optional DID for issuer identification },
            "verificationMethod": { Optional verification method URI }
        }
        
    Returns:
        JSON response with signed mDoc credential or error details
        
    Raises:
        web.HTTPBadRequest: If request payload is invalid or malformed
        web.HTTPUnprocessableEntity: If credential data validation fails
        web.HTTPInternalServerError: If signing operation fails
        
    Example:
        POST /oid4vc/mdoc/sign
        {
            "payload": {
                "doctype": "org.iso.18013.5.1.mDL",
                "claims": {
                    "org.iso.18013.5.1": {
                        "family_name": "Doe",
                        "given_name": "John"
                    }
                }
            }
        }
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()
    verification_method = body.get("verificationMethod")
    headers = body.get("headers", {})
    payload = body.get("payload", {})

    try:
        # Get storage manager for key lookup and use session for storage operations
        storage_manager = MdocStorageManager(context.profile)

        async with context.profile.session() as session:
            jwk = None

            if verification_method:
                # Try to get signing key by verification method
                stored_key = await storage_manager.get_signing_key(
                    session, verification_method=verification_method
                )
                if stored_key and stored_key.get("jwk"):
                    jwk = stored_key["jwk"]
                    LOGGER.info(
                        "Using signing key for verification method: %s",
                        verification_method,
                    )

            if not jwk:
                # Fall back to default signing key
                stored_key = await storage_manager.get_default_signing_key(
                    session
                )
                if stored_key and stored_key.get("jwk"):
                    jwk = stored_key["jwk"]
                    LOGGER.info("Using default signing key for mDoc signing")
                elif verification_method:
                    # Generate and resolve verification method if needed
                    jwk = await resolve_signing_key_for_credential(
                        context.profile,
                        session,
                        verification_method=verification_method,
                    )
                    LOGGER.info(
                        "Generated new signing key for verification method"
                    )
                else:
                    raise ValueError(
                        "No signing key available and no verification method"
                        " provided"
                    )

            if not jwk:
                raise ValueError("Failed to obtain signing key")

        mso_mdoc = isomdl_mdoc_sign(jwk, headers, payload)
    except ValueError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response(mso_mdoc)


@docs(
    tags=["mso_mdoc"],
    summary=(
        "Verify mso_mdoc CBOR encoded binaries according to ISO 18013-5 and"
        " OpenID4VCI 1.0"
    ),
)
@request_schema(MdocVerifySchema())
@response_schema(MdocVerifyResponseSchema(), 200, description="")
async def mdoc_verify(request: web.BaseRequest):
    """Request handler for ISO 18013-5 mDoc verification.

    Performs cryptographic verification of a mobile document (mDoc) including
    validation of the mobile security object (MSO) signature and structure
    compliance with both ISO 18013-5 and OpenID4VCI 1.0 requirements.

    Protocol Compliance:
    - OpenID4VCI 1.0 § E.1.1: mso_mdoc Credential Format verification
      https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
    - ISO 18013-5 § 9.1.4: MSO signature verification procedures
    - ISO 18013-5 § 8.3: Document structure validation
    - RFC 8152: COSE signature verification
    - RFC 8949: CBOR decoding and validation

    Args:
        request: The web request object.

            "mso_mdoc": { CBOR-encoded mDoc per ISO 18013-5 § 8.3 and OID4VCI 1.0 § E.1.1 }
    """
    body = await request.json()
    mso_mdoc = body["mso_mdoc"]
    try:
        # Use new mdoc_verify function (sync, no profile needed)
        result = mso_mdoc_verify(mso_mdoc)
    except ValueError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err
    except Exception as err:
        raise web.HTTPInternalServerError(
            reason=f"Verification failed: {err}"
        ) from err

    return web.json_response(result.serialize())


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/mso_mdoc/sign", mdoc_sign),
            web.post("/mso_mdoc/verify", mdoc_verify),
        ]
    )

    # Register key management routes
    register_key_management_routes(app)


def post_process_routes(app: web.Application):
    """Amend swagger API.

    Adds mso_mdoc plugin documentation with references to both ISO 18013-5
    and OpenID4VCI 1.0 specifications for comprehensive protocol compliance.
    """

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "mso_mdoc",
            "description": (
                "ISO 18013-5 mobile document (mDoc) operations with OpenID4VCI"
                " 1.0 compliance"
            ),
            "externalDocs": [
                {"description": "ISO 18013-5 Specification", "url": SPEC_URI},
                {
                    "description": "OpenID4VCI 1.0 mso_mdoc Format",
                    "url": OID4VCI_SPEC_URI,
                },
            ],
        }
    )
