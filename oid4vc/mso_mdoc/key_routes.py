"""Additional admin routes for mso_mdoc key and certificate management."""

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, response_schema
from marshmallow import fields

from .key_generation import generate_default_keys_and_certs
from .storage import MdocStorageManager


class MdocKeyListSchema(OpenAPISchema):
    """Response schema for listing mDoc keys."""

    keys = fields.List(
        fields.Dict(),
        required=True,
        metadata={"description": "List of stored mDoc keys"},
    )


class MdocCertListSchema(OpenAPISchema):
    """Response schema for listing mDoc certificates."""

    certificates = fields.List(
        fields.Dict(),
        required=True,
        metadata={"description": "List of stored mDoc certificates"},
    )


class MdocKeyGenSchema(OpenAPISchema):
    """Response schema for key generation."""

    key_id = fields.Str(required=True, metadata={"description": "Generated key ID"})
    cert_id = fields.Str(
        required=True, metadata={"description": "Generated certificate ID"}
    )
    message = fields.Str(required=True, metadata={"description": "Success message"})


@docs(
    tags=["mso_mdoc"],
    summary="List all mDoc signing keys",
)
@response_schema(MdocKeyListSchema(), 200)
async def list_keys(request: web.BaseRequest):
    """List all stored mDoc keys."""
    context: AdminRequestContext = request["context"]
    storage_manager = MdocStorageManager(context.profile)

    try:
        async with context.profile.session() as session:
            keys = await storage_manager.list_keys(session)
        # Remove sensitive private key data from response
        safe_keys = []
        for key in keys:
            safe_key = {
                "key_id": key["key_id"],
                "key_type": key["key_type"],
                "created_at": key["created_at"],
                "metadata": {
                    k: v for k, v in key.get("metadata", {}).items() if k != "jwk"
                },
            }
            safe_keys.append(safe_key)

        return web.json_response({"keys": safe_keys})
    except Exception as e:
        raise web.HTTPInternalServerError(reason=f"Failed to list keys: {e}") from e


@docs(
    tags=["mso_mdoc"],
    summary="List all mDoc certificates",
)
@response_schema(MdocCertListSchema(), 200)
async def list_certificates(request: web.BaseRequest):
    """List all stored mDoc certificates."""
    context: AdminRequestContext = request["context"]
    storage_manager = MdocStorageManager(context.profile)

    try:
        async with context.profile.session() as session:
            certificates = await storage_manager.list_certificates(session)
        return web.json_response({"certificates": certificates})
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Failed to list certificates: {e}"
        ) from e


@docs(
    tags=["mso_mdoc"],
    summary="Generate new mDoc signing key and certificate",
)
@response_schema(MdocKeyGenSchema(), 200)
async def generate_keys(request: web.BaseRequest):
    """Generate new mDoc signing key and certificate."""
    context: AdminRequestContext = request["context"]
    storage_manager = MdocStorageManager(context.profile)

    try:
        async with context.profile.session() as session:
            generated = await generate_default_keys_and_certs(storage_manager, session)
        return web.json_response(
            {
                "key_id": generated["key_id"],
                "cert_id": generated["cert_id"],
                "message": (
                    "Successfully generated new mDoc signing key and" " certificate"
                ),
            }
        )
    except Exception as e:
        raise web.HTTPInternalServerError(reason=f"Failed to generate keys: {e}") from e


def register_key_management_routes(app: web.Application):
    """Register key management routes."""
    app.router.add_get("/mso_mdoc/keys", list_keys)
    app.router.add_get("/mso_mdoc/certificates", list_certificates)
    app.router.add_post("/mso_mdoc/generate-keys", generate_keys)
