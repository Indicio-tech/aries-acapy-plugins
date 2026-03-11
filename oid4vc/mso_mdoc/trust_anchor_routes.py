"""Admin routes for mso_mdoc trust anchor management."""

import uuid

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import fields

from .storage import MdocStorageManager


# =============================================================================
# Schemas
# =============================================================================


class TrustAnchorCreateSchema(OpenAPISchema):
    """Request schema for creating a trust anchor."""

    certificate_pem = fields.Str(
        required=True,
        metadata={"description": "PEM-encoded X.509 root CA certificate"},
    )
    anchor_id = fields.Str(
        required=False,
        metadata={"description": "Optional custom ID for the trust anchor"},
    )
    metadata = fields.Dict(
        required=False,
        metadata={"description": "Optional metadata (e.g., issuer name, purpose)"},
    )


class TrustAnchorResponseSchema(OpenAPISchema):
    """Response schema for trust anchor operations."""

    anchor_id = fields.Str(required=True, metadata={"description": "Trust anchor ID"})
    message = fields.Str(required=True, metadata={"description": "Status message"})


class TrustAnchorDetailSchema(OpenAPISchema):
    """Response schema for trust anchor details."""

    anchor_id = fields.Str(required=True, metadata={"description": "Trust anchor ID"})
    certificate_pem = fields.Str(
        required=True, metadata={"description": "PEM-encoded certificate"}
    )
    created_at = fields.Str(required=True, metadata={"description": "Creation timestamp"})
    metadata = fields.Dict(
        required=False, metadata={"description": "Trust anchor metadata"}
    )


class TrustAnchorListSchema(OpenAPISchema):
    """Response schema for listing trust anchors."""

    trust_anchors = fields.List(
        fields.Dict(),
        required=True,
        metadata={"description": "List of stored trust anchors"},
    )


# =============================================================================
# Handlers
# =============================================================================


@docs(
    tags=["mso_mdoc"],
    summary="Add a trust anchor certificate",
)
@request_schema(TrustAnchorCreateSchema())
@response_schema(TrustAnchorResponseSchema(), 200)
async def create_trust_anchor(request: web.BaseRequest):
    """Add a new trust anchor certificate to the wallet.

    Trust anchors are root CA certificates used to verify mDoc issuer
    certificate chains during credential verification.
    """
    context: AdminRequestContext = request["context"]
    storage_manager = MdocStorageManager(context.profile)

    try:
        body = await request.json()
        certificate_pem = body.get("certificate_pem")
        if not certificate_pem:
            raise web.HTTPBadRequest(reason="certificate_pem is required")

        anchor_id = body.get("anchor_id") or f"trust-anchor-{uuid.uuid4().hex[:8]}"
        metadata = body.get("metadata", {})

        async with context.profile.session() as session:
            await storage_manager.store_trust_anchor(
                session=session,
                anchor_id=anchor_id,
                certificate_pem=certificate_pem,
                metadata=metadata,
            )

        return web.json_response(
            {
                "anchor_id": anchor_id,
                "message": "Trust anchor stored successfully",
            }
        )
    except web.HTTPError:
        raise
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Failed to store trust anchor: {e}"
        ) from e


@docs(
    tags=["mso_mdoc"],
    summary="List all trust anchors",
)
@response_schema(TrustAnchorListSchema(), 200)
async def list_trust_anchors(request: web.BaseRequest):
    """List all stored trust anchor certificates."""
    context: AdminRequestContext = request["context"]
    storage_manager = MdocStorageManager(context.profile)

    try:
        async with context.profile.session() as session:
            anchors = await storage_manager.list_trust_anchors(session)
        return web.json_response({"trust_anchors": anchors})
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Failed to list trust anchors: {e}"
        ) from e


@docs(
    tags=["mso_mdoc"],
    summary="Get a trust anchor by ID",
)
@response_schema(TrustAnchorDetailSchema(), 200)
async def get_trust_anchor(request: web.BaseRequest):
    """Retrieve a specific trust anchor certificate."""
    context: AdminRequestContext = request["context"]
    anchor_id = request.match_info["anchor_id"]
    storage_manager = MdocStorageManager(context.profile)

    try:
        async with context.profile.session() as session:
            anchor = await storage_manager.get_trust_anchor(session, anchor_id)

        if not anchor:
            raise web.HTTPNotFound(reason=f"Trust anchor not found: {anchor_id}")

        return web.json_response(anchor)
    except web.HTTPError:
        raise
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Failed to get trust anchor: {e}"
        ) from e


@docs(
    tags=["mso_mdoc"],
    summary="Delete a trust anchor",
)
@response_schema(TrustAnchorResponseSchema(), 200)
async def delete_trust_anchor(request: web.BaseRequest):
    """Delete a trust anchor certificate."""
    context: AdminRequestContext = request["context"]
    anchor_id = request.match_info["anchor_id"]
    storage_manager = MdocStorageManager(context.profile)

    try:
        async with context.profile.session() as session:
            deleted = await storage_manager.delete_trust_anchor(session, anchor_id)

        if not deleted:
            raise web.HTTPNotFound(reason=f"Trust anchor not found: {anchor_id}")

        return web.json_response(
            {
                "anchor_id": anchor_id,
                "message": "Trust anchor deleted successfully",
            }
        )
    except web.HTTPError:
        raise
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Failed to delete trust anchor: {e}"
        ) from e


# =============================================================================
# Route registration
# =============================================================================


def register_trust_anchor_routes(app: web.Application):
    """Register trust anchor management routes."""
    app.router.add_post("/mso_mdoc/trust-anchors", create_trust_anchor)
    app.router.add_get("/mso_mdoc/trust-anchors", list_trust_anchors)
    app.router.add_get("/mso_mdoc/trust-anchors/{anchor_id}", get_trust_anchor)
    app.router.add_delete("/mso_mdoc/trust-anchors/{anchor_id}", delete_trust_anchor)
