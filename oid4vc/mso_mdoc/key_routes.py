"""Additional admin routes for mso_mdoc key and certificate management."""

import uuid

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
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

    anchor_id = fields.Str(
        required=True, metadata={"description": "Trust anchor ID"}
    )
    message = fields.Str(required=True, metadata={"description": "Status message"})


class TrustAnchorDetailSchema(OpenAPISchema):
    """Response schema for trust anchor details."""

    anchor_id = fields.Str(
        required=True, metadata={"description": "Trust anchor ID"}
    )
    certificate_pem = fields.Str(
        required=True, metadata={"description": "PEM-encoded certificate"}
    )
    created_at = fields.Str(
        required=True, metadata={"description": "Creation timestamp"}
    )
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
    """List all stored mDoc certificates.

    Query parameters:
        include_pem: If "true", include the certificate_pem field in results
    """
    context: AdminRequestContext = request["context"]
    storage_manager = MdocStorageManager(context.profile)

    # Check for include_pem query parameter
    include_pem = request.query.get("include_pem", "").lower() == "true"

    try:
        async with context.profile.session() as session:
            certificates = await storage_manager.list_certificates(
                session, include_pem=include_pem
            )
        return web.json_response({"certificates": certificates})
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Failed to list certificates: {e}"
        ) from e


class DefaultCertificateResponseSchema(OpenAPISchema):
    """Response schema for default certificate."""

    cert_id = fields.Str(required=True, metadata={"description": "Certificate ID"})
    key_id = fields.Str(required=True, metadata={"description": "Associated key ID"})
    certificate_pem = fields.Str(
        required=True, metadata={"description": "PEM-encoded certificate"}
    )
    created_at = fields.Str(
        required=True, metadata={"description": "Creation timestamp"}
    )
    metadata = fields.Dict(
        required=False, metadata={"description": "Certificate metadata"}
    )


@docs(
    tags=["mso_mdoc"],
    summary="Get the default signing certificate",
    description="Returns the certificate that will be used for credential signing",
)
@response_schema(DefaultCertificateResponseSchema(), 200)
async def get_default_certificate(request: web.BaseRequest):
    """Get the default signing certificate.

    This returns the certificate that will be used when issuing mDoc credentials.
    The default certificate is associated with the default signing key.
    """
    context: AdminRequestContext = request["context"]
    storage_manager = MdocStorageManager(context.profile)

    try:
        async with context.profile.session() as session:
            # Get the default signing key first
            default_key = await storage_manager.get_default_signing_key(session)

            if not default_key:
                raise web.HTTPNotFound(reason="No default signing key configured")

            key_id = default_key["key_id"]

            # Get the certificate associated with this key
            certificate_pem = await storage_manager.get_certificate_for_key(
                session, key_id
            )

            if not certificate_pem:
                raise web.HTTPNotFound(
                    reason=f"No certificate found for default signing key: {key_id}"
                )

            # Get full certificate info
            certificates = await storage_manager.list_certificates(
                session, include_pem=True
            )

            # Find the certificate for this key
            cert_info = None
            for cert in certificates:
                if cert.get("key_id") == key_id:
                    cert_info = cert
                    break

            if not cert_info:
                # Fall back to basic response
                return web.json_response(
                    {
                        "cert_id": f"cert-for-{key_id}",
                        "key_id": key_id,
                        "certificate_pem": certificate_pem,
                        "created_at": default_key.get("created_at", ""),
                        "metadata": {},
                    }
                )

            return web.json_response(
                {
                    "cert_id": cert_info.get("cert_id"),
                    "key_id": key_id,
                    "certificate_pem": certificate_pem,
                    "created_at": cert_info.get("created_at", ""),
                    "metadata": cert_info.get("metadata", {}),
                }
            )

    except web.HTTPError:
        raise
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Failed to get default certificate: {e}"
        ) from e


@docs(
    tags=["mso_mdoc"],
    summary="Generate new mDoc signing key and certificate",
    description="Generates a new mDoc signing key and self-signed certificate. "
                "If force=false (default) and keys already exist, returns the existing key.",
)
@response_schema(MdocKeyGenSchema(), 200)
async def generate_keys(request: web.BaseRequest):
    """Generate new mDoc signing key and certificate.

    Query parameters:
        force: If "true", always generate new keys even if keys already exist.
               Default is "false" - returns existing keys if present.
    """
    context: AdminRequestContext = request["context"]
    storage_manager = MdocStorageManager(context.profile)

    # Check for force query parameter
    force = request.query.get("force", "").lower() == "true"

    try:
        async with context.profile.session() as session:
            # Check if keys already exist (unless force is set)
            if not force:
                existing_key = await storage_manager.get_default_signing_key(session)
                if existing_key:
                    # Get the associated certificate
                    key_id = existing_key["key_id"]
                    certificates = await storage_manager.list_certificates(session)
                    cert_id = None
                    for cert in certificates:
                        if cert.get("key_id") == key_id:
                            cert_id = cert.get("cert_id")
                            break

                    return web.json_response(
                        {
                            "key_id": key_id,
                            "cert_id": cert_id or f"cert-for-{key_id}",
                            "message": (
                                "Existing mDoc signing key found (use ?force=true to generate new)"
                            ),
                        }
                    )

            # Generate new keys
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


# =============================================================================
# Trust Anchor Routes
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


def register_key_management_routes(app: web.Application):
    """Register key management routes."""
    app.router.add_get("/mso_mdoc/keys", list_keys)
    app.router.add_get("/mso_mdoc/certificates", list_certificates)
    app.router.add_get("/mso_mdoc/certificates/default", get_default_certificate)
    app.router.add_post("/mso_mdoc/generate-keys", generate_keys)

    # Trust anchor routes
    app.router.add_post("/mso_mdoc/trust-anchors", create_trust_anchor)
    app.router.add_get("/mso_mdoc/trust-anchors", list_trust_anchors)
    app.router.add_get("/mso_mdoc/trust-anchors/{anchor_id}", get_trust_anchor)
    app.router.add_delete("/mso_mdoc/trust-anchors/{anchor_id}", delete_trust_anchor)
