"""mso_mdoc extra routes.

Format-specific routes for creating and updating mso_mdoc SupportedCredential
records.  Follows the same pattern as sd_jwt_vc/routes.py.
"""

import logging
from typing import Any, Dict

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    request_schema,
    response_schema,
)
from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from marshmallow import fields

from oid4vc.cred_processor import CredProcessors
from oid4vc.models.supported_cred import SupportedCredential, SupportedCredentialSchema
from oid4vc.utils import supported_cred_is_unique

LOGGER = logging.getLogger(__name__)


class MsoMdocSupportedCredCreateReq(OpenAPISchema):
    """Schema for creating an mso_mdoc SupportedCredential."""

    format = fields.Str(required=True, metadata={"example": "mso_mdoc"})
    identifier = fields.Str(
        data_key="id",
        required=True,
        metadata={"example": "org.iso.18013.5.1.mDL"},
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": ["cose_key"]}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256"]}
    )
    display = fields.List(fields.Dict(), required=False)
    doctype = fields.Str(
        required=True,
        metadata={
            "description": "ISO 18013-5 document type identifier.",
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    claims = fields.Dict(
        keys=fields.Str,
        required=False,
        metadata={
            "description": (
                "Namespace-keyed claims: {namespace: {claim_name: descriptor}}"
            ),
        },
    )
    trust_anchors = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": "PEM-encoded X.509 root CA certificates for verification.",
        },
    )
    signing_key_pem = fields.Str(
        required=False,
        metadata={
            "description": (
                "PEM-encoded EC private key for credential signing. "
                "Alternative to OID4VC_MDOC_SIGNING_KEY_PATH env var."
            ),
        },
    )
    signing_cert_pem = fields.Str(
        required=False,
        metadata={
            "description": (
                "PEM-encoded X.509 certificate for credential signing. "
                "Alternative to OID4VC_MDOC_SIGNING_CERT_PATH env var."
            ),
        },
    )


class SupportedCredentialMatchSchema(OpenAPISchema):
    """Match info for request taking credential supported id."""

    supported_cred_id = fields.Str(
        required=True,
        metadata={"description": "Credential supported identifier"},
    )


@docs(
    tags=["oid4vci"],
    summary="Register a configuration for a supported mso_mdoc credential",
)
@request_schema(MsoMdocSupportedCredCreateReq())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_create(request: web.Request):
    """Create a SupportedCredential record for mso_mdoc format."""
    context = request["context"]
    assert isinstance(context, AdminRequestContext)
    profile = context.profile

    body: Dict[str, Any] = await request.json()

    if not await supported_cred_is_unique(body["id"], profile):
        raise web.HTTPBadRequest(
            reason=f"Record with identifier {body['id']} already exists."
        )

    body["identifier"] = body.pop("id")

    format_data = {}
    format_data["doctype"] = body.pop("doctype")
    format_data["claims"] = body.pop("claims", None)

    vc_additional_data = {}
    vc_additional_data["trust_anchors"] = body.pop("trust_anchors", None)
    vc_additional_data["signing_key_pem"] = body.pop("signing_key_pem", None)
    vc_additional_data["signing_cert_pem"] = body.pop("signing_cert_pem", None)

    record = SupportedCredential(
        **body,
        format_data=format_data,
        vc_additional_data=vc_additional_data,
    )

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


async def supported_cred_update_helper(
    record: SupportedCredential,
    body: Dict[str, Any],
    session: AskarProfileSession,
) -> SupportedCredential:
    """Helper for updating an mso_mdoc SupportedCredential record."""
    format_data = {}
    vc_additional_data = {}

    body["identifier"] = body.pop("id")

    format_data["doctype"] = body.pop("doctype")
    format_data["claims"] = body.pop("claims", None)

    vc_additional_data["trust_anchors"] = body.pop("trust_anchors", None)
    vc_additional_data["signing_key_pem"] = body.pop("signing_key_pem", None)
    vc_additional_data["signing_cert_pem"] = body.pop("signing_cert_pem", None)

    record.identifier = body["identifier"]
    record.format = body["format"]
    record.cryptographic_binding_methods_supported = body.get(
        "cryptographic_binding_methods_supported", None
    )
    record.cryptographic_suites_supported = body.get(
        "cryptographic_suites_supported", None
    )
    record.display = body.get("display", None)
    record.format_data = format_data
    record.vc_additional_data = vc_additional_data

    await record.save(session)
    return record


@docs(
    tags=["oid4vci"],
    summary="Update a supported mso_mdoc credential configuration",
)
@match_info_schema(SupportedCredentialMatchSchema())
@request_schema(MsoMdocSupportedCredCreateReq())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def update_supported_credential_mso_mdoc(request: web.Request):
    """Update an mso_mdoc SupportedCredential record."""
    context: AdminRequestContext = request["context"]
    body: Dict[str, Any] = await request.json()
    supported_cred_id = request.match_info["supported_cred_id"]

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(
                session, supported_cred_id
            )
            assert isinstance(session, AskarProfileSession)
            record = await supported_cred_update_helper(record, body, session)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

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

    return web.json_response(record.serialize())


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post(
                "/oid4vci/credential-supported/create/mso-mdoc",
                supported_credential_create,
            ),
            web.put(
                "/oid4vci/credential-supported/records/mso-mdoc/{supported_cred_id}",
                update_supported_credential_mso_mdoc,
            ),
        ]
    )
