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
from . import trust_anchor_routes

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
    signing_key_id = fields.Str(
        required=False,
        metadata={
            "description": (
                "ID of a MdocSigningKeyRecord to use for signing. "
                "Takes precedence over signing_key_pem/signing_cert_pem."
            ),
        },
    )
    status_list_def_id = fields.Str(
        required=False,
        metadata={
            "description": (
                "Status list definition ID (from the status_list plugin) to use "
                "for assigning revocation entries at credential issuance time."
            ),
        },
    )
    status_list_base_uri = fields.Str(
        required=False,
        metadata={
            "description": (
                "Base URI for published status lists "
                "(e.g. 'https://issuer.example.com/status'). "
                "Combined with the list_number to build the status URI embedded "
                "in issued credentials."
            ),
        },
    )


class MsoMdocSupportedCredUpdateReq(OpenAPISchema):
    """Schema for partial updates to an mso_mdoc SupportedCredential.

    All fields are optional; only supplied fields are changed.
    """

    format = fields.Str(required=False, metadata={"example": "mso_mdoc"})
    identifier = fields.Str(
        data_key="id",
        required=False,
        metadata={"example": "org.iso.18013.5.1.mDL"},
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), required=False, metadata={"example": ["cose_key"]}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), required=False, metadata={"example": ["ES256"]}
    )
    display = fields.List(fields.Dict(), required=False)
    doctype = fields.Str(
        required=False,
        metadata={
            "description": "ISO 18013-5 document type identifier.",
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    claims = fields.Dict(keys=fields.Str, required=False)
    trust_anchors = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": "PEM-encoded X.509 root CA certificates for verification.",
        },
    )
    signing_key_id = fields.Str(
        required=False,
        metadata={
            "description": "ID of a MdocSigningKeyRecord to use for signing.",
        },
    )
    status_list_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Status list definition ID for revocation entry assignment.",
        },
    )
    status_list_base_uri = fields.Str(
        required=False,
        metadata={
            "description": "Base URI for published status lists.",
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
    vc_additional_data["signing_key_id"] = body.pop("signing_key_id", None)
    vc_additional_data["status_list_def_id"] = body.pop("status_list_def_id", None)
    vc_additional_data["status_list_base_uri"] = body.pop("status_list_base_uri", None)

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
    """Helper for updating an mso_mdoc SupportedCredential record.

    Only fields present in *body* are updated; omitted fields retain their
    current values from *record*.
    """
    existing_format_data = record.format_data or {}
    existing_vc_data = record.vc_additional_data or {}

    # Identifier / format — fall back to existing values when not supplied
    if "id" in body:
        record.identifier = body.pop("id")
    else:
        body.pop("id", None)
    if "format" in body:
        record.format = body.pop("format")
    else:
        body.pop("format", None)

    # format_data — merge with existing
    format_data = dict(existing_format_data)
    if "doctype" in body:
        format_data["doctype"] = body.pop("doctype")
    else:
        body.pop("doctype", None)
    if "claims" in body:
        format_data["claims"] = body.pop("claims")
    else:
        body.pop("claims", None)

    # vc_additional_data — merge with existing
    vc_additional_data = dict(existing_vc_data)
    if "trust_anchors" in body:
        vc_additional_data["trust_anchors"] = body.pop("trust_anchors")
    else:
        body.pop("trust_anchors", None)
    if "signing_key_id" in body:
        vc_additional_data["signing_key_id"] = body.pop("signing_key_id")
    else:
        body.pop("signing_key_id", None)
    if "status_list_def_id" in body:
        vc_additional_data["status_list_def_id"] = body.pop("status_list_def_id")
    else:
        body.pop("status_list_def_id", None)
    if "status_list_base_uri" in body:
        vc_additional_data["status_list_base_uri"] = body.pop("status_list_base_uri")
    else:
        body.pop("status_list_base_uri", None)

    if "cryptographic_binding_methods_supported" in body:
        record.cryptographic_binding_methods_supported = body[
            "cryptographic_binding_methods_supported"
        ]
    if "cryptographic_suites_supported" in body:
        record.cryptographic_suites_supported = body["cryptographic_suites_supported"]
    if "display" in body:
        record.display = body["display"]

    record.format_data = format_data
    record.vc_additional_data = vc_additional_data

    await record.save(session)
    return record


@docs(
    tags=["oid4vci"],
    summary="Update a supported mso_mdoc credential configuration",
)
@match_info_schema(SupportedCredentialMatchSchema())
@request_schema(MsoMdocSupportedCredUpdateReq())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def update_supported_credential_mso_mdoc(request: web.Request):
    """Update an mso_mdoc SupportedCredential record."""
    context: AdminRequestContext = request["context"]
    body: Dict[str, Any] = await request.json()
    supported_cred_id = request.match_info["supported_cred_id"]

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(session, supported_cred_id)
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
    await trust_anchor_routes.register(app)
