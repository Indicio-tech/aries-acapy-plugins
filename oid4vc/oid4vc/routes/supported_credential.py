"""Supported credential routes for OID4VCI admin API."""

from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields

from ..cred_processor import CredProcessorError, CredProcessors
from ..models.supported_cred import SupportedCredential, SupportedCredentialSchema
from ..utils import supported_cred_is_unique
from .constants import LOGGER

# Fields allowed in SupportedCredential constructor
_ALLOWED_SUPPORTED_CRED_FIELDS = {
    "format",
    "identifier",
    "cryptographic_binding_methods_supported",
    "cryptographic_suites_supported",
    "proof_types_supported",
    "display",
    "format_data",
    "vc_additional_data",
}


def _move_fields_to_vc_additional_data(body: Dict[str, Any]) -> None:
    """Move top-level type/@context fields into vc_additional_data.

    Args:
        body: The request body (modified in-place)
    """
    vc_additional_data = body.get("vc_additional_data", {})
    for field in ["type", "@context"]:
        if field in body:
            vc_additional_data[field] = body.pop(field)
    if vc_additional_data:
        body["vc_additional_data"] = vc_additional_data


def _derive_jwt_vc_format_data(body: Dict[str, Any]) -> None:
    """Derive format_data for jwt_vc_json from vc_additional_data.

    Args:
        body: The request body (modified in-place)
    """
    if body.get("format") != "jwt_vc_json" or body.get("format_data"):
        return

    derived_format_data = {}
    if "vc_additional_data" in body:
        if "type" in body["vc_additional_data"]:
            derived_format_data["types"] = body["vc_additional_data"]["type"]
        if "@context" in body["vc_additional_data"]:
            derived_format_data["context"] = body["vc_additional_data"]["@context"]

    if "credentialSubject" in body:
        derived_format_data["credentialSubject"] = body.pop("credentialSubject")

    if derived_format_data:
        body["format_data"] = derived_format_data


def _ensure_jwt_vc_additional_data(body: Dict[str, Any]) -> None:
    """Ensure vc_additional_data has required fields for jwt_vc_json.

    Args:
        body: The request body (modified in-place)
    """
    if body.get("format") != "jwt_vc_json" or not body.get("format_data"):
        return

    format_data = body.get("format_data", {})
    if "vc_additional_data" not in body:
        body["vc_additional_data"] = {}

    vc_additional = body["vc_additional_data"]

    # Copy type/types from format_data if not already set
    if "type" not in vc_additional:
        if "type" in format_data:
            vc_additional["type"] = format_data["type"]
        elif "types" in format_data:
            vc_additional["type"] = format_data["types"]

    # Copy @context from format_data if not already set
    if "@context" not in vc_additional:
        if "context" in format_data:
            vc_additional["@context"] = format_data["context"]
        elif "@context" in format_data:
            vc_additional["@context"] = format_data["@context"]
        else:
            vc_additional["@context"] = ["https://www.w3.org/2018/credentials/v1"]


class SupportedCredCreateRequestSchema(OpenAPISchema):
    """Schema for SupportedCredCreateRequestSchema."""

    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    identifier = fields.Str(
        data_key="id", required=True, metadata={"example": "UniversityDegreeCredential"}
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": ["did"]}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256K"]}
    )
    proof_types_supported = fields.Dict(
        required=False,
        metadata={
            "example": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}
        },
    )
    display = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
                        "alt_text": "a square logo of a university",
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF",
                }
            ]
        },
    )
    format_data = fields.Dict(
        required=False,
        metadata={
            "description": (
                "Data specific to the credential format to be included in issuer "
                "metadata."
            ),
            "example": {
                "credentialSubject": {
                    "given_name": {
                        "display": [{"name": "Given Name", "locale": "en-US"}]
                    },
                    "last_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
                    "degree": {},
                    "gpa": {"display": [{"name": "GPA"}]},
                },
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
        },
    )
    vc_additional_data = fields.Dict(
        required=False,
        metadata={
            "description": (
                "Additional data to be included in each credential of this type. "
                "This is for data that is not specific to the subject but required "
                "by the credential format and is included in every credential."
            ),
            "example": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
        },
    )


@docs(tags=["oid4vci"], summary="Register a Oid4vci credential")
@request_schema(SupportedCredCreateRequestSchema())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_create(request: web.Request):
    """Request handler for creating a credential supported record."""
    context: AdminRequestContext = request["context"]
    profile = context.profile

    body: Dict[str, Any] = await request.json()
    LOGGER.info(f"body: {body}")

    if not await supported_cred_is_unique(body["id"], profile):
        raise web.HTTPBadRequest(
            reason=f"Record with identifier {body['id']} already exists."
        )
    body["identifier"] = body.pop("id")

    format_data: dict = body.get("format_data", {})
    if format_data.get("vct") and format_data.get("type"):
        raise web.HTTPBadRequest(
            reason="Cannot have both `vct` and `type`. "
            "`vct` is for SD JWT and `type` is for JWT VC"
        )

    # Process body fields
    _move_fields_to_vc_additional_data(body)
    _derive_jwt_vc_format_data(body)
    _ensure_jwt_vc_additional_data(body)

    # Filter to only allowed fields
    filtered_body = {
        k: v for k, v in body.items() if k in _ALLOWED_SUPPORTED_CRED_FIELDS
    }

    record = SupportedCredential(**filtered_body)

    registered_processors = context.inject(CredProcessors)
    if record.format not in registered_processors.issuers:
        raise web.HTTPBadRequest(
            reason=f"Format {record.format} is not supported by"
            " currently registered processors"
        )

    processor = registered_processors.issuer_for_format(record.format)
    try:
        processor.validate_supported_credential(record)
    except (ValueError, CredProcessorError) as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    async with profile.session() as session:
        await record.save(session, reason="Save credential supported record.")

    return web.json_response(record.serialize())


class JwtSupportedCredCreateRequestSchema(OpenAPISchema):
    """Schema for SupportedCredCreateRequestSchema."""

    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    identifier = fields.Str(
        data_key="id", required=True, metadata={"example": "UniversityDegreeCredential"}
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": ["did"]}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256K"]}
    )
    proof_types_supported = fields.Dict(
        required=False,
        metadata={
            "example": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}
        },
    )
    display = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
                        "alt_text": "a square logo of a university",
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF",
                }
            ]
        },
    )
    type = fields.List(
        fields.Str,
        required=True,
        metadata={
            "description": "List of credential types supported.",
            "example": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    credential_subject = fields.Dict(
        keys=fields.Str,
        data_key="credentialSubject",
        required=False,
        metadata={
            "description": "Metadata about the Credential Subject to help with display.",
            "example": {
                "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
                "last_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
                "degree": {},
                "gpa": {"display": [{"name": "GPA"}]},
            },
        },
    )
    order = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": (
                "The order in which claims should be displayed. This is not well defined "
                "by the spec right now. Best to omit for now."
            )
        },
    )
    context = fields.List(
        fields.Raw,
        data_key="@context",
        required=True,
        metadata={
            "example": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Register a configuration for a supported JWT VC credential",
)
@request_schema(JwtSupportedCredCreateRequestSchema())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_create_jwt(request: web.Request):
    """Request handler for creating a credential supported record."""
    context = request["context"]
    assert isinstance(context, AdminRequestContext)
    profile = context.profile

    body: Dict[str, Any] = await request.json()

    if not await supported_cred_is_unique(body["id"], profile):
        raise web.HTTPBadRequest(
            reason=f"Record with identifier {body['id']} already exists."
        )

    LOGGER.info(f"body: {body}")
    body["identifier"] = body.pop("id")
    format_data = {}
    format_data["types"] = body.pop("type")
    format_data["credentialSubject"] = body.pop("credentialSubject", None)
    format_data["context"] = body.pop("@context")
    format_data["order"] = body.pop("order", None)
    vc_additional_data = {}
    vc_additional_data["@context"] = format_data["context"]
    # In OID4VCI 1.0 metadata, the field is "type" (converted in to_issuer_metadata).
    # In the actual W3C VC, it's also "type" (per VCDM spec).
    vc_additional_data["type"] = format_data["types"]

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
    except (ValueError, CredProcessorError) as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    async with profile.session() as session:
        await record.save(session, reason="Save credential supported record.")

    return web.json_response(record.serialize())


class SupportedCredentialQuerySchema(OpenAPISchema):
    """Query filters for credential supported record list query."""

    supported_cred_id = fields.Str(
        required=False,
        metadata={"description": "Filter by credential supported identifier."},
    )
    format = fields.Str(
        required=False,
        metadata={"description": "Filter by credential format."},
    )


class SupportedCredentialListSchema(OpenAPISchema):
    """Result schema for an credential supported record query."""

    results = fields.Nested(
        SupportedCredentialSchema(),
        many=True,
        metadata={"description": "Credential supported records"},
    )


@docs(
    tags=["oid4vci"],
    summary="Fetch all credential supported records",
)
@querystring_schema(SupportedCredentialQuerySchema())
@response_schema(SupportedCredentialListSchema(), 200)
@tenant_authentication
async def supported_credential_list(request: web.BaseRequest):
    """Request handler for searching credential supported records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context = request["context"]
    try:
        async with context.profile.session() as session:
            if exchange_id := request.query.get("supported_cred_id"):
                record = await SupportedCredential.retrieve_by_id(session, exchange_id)
                results = [record.serialize()]
            else:
                # Only 'format' is indexed as a tag in SupportedCredential.TAG_NAMES.
                # Filtering by cryptographic_binding_methods_supported or
                # cryptographic_suites_supported would require post-query filtering
                # since they are list fields stored in record_value, not tags.
                filter_ = {
                    attr: value
                    for attr in ("format",)
                    if (value := request.query.get(attr))
                }
                records = await SupportedCredential.query(
                    session=session, tag_filter=filter_
                )
                results = [record.serialize() for record in records]
    except (StorageError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response({"results": results})


class SupportedCredentialMatchSchema(OpenAPISchema):
    """Match info for request taking credential supported id."""

    supported_cred_id = fields.Str(
        required=True,
        metadata={
            "description": "Credential supported identifier",
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Get a credential supported record by ID",
)
@match_info_schema(SupportedCredentialMatchSchema())
@response_schema(SupportedCredentialSchema())
async def get_supported_credential_by_id(request: web.Request):
    """Request handler for retrieving an credential supported record by ID."""

    context: AdminRequestContext = request["context"]
    supported_cred_id = request.match_info["supported_cred_id"]

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(
                session, supported_cred_id
            )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response(record.serialize())


class UpdateJwtSupportedCredentialResponseSchema(OpenAPISchema):
    """Response schema for updating a OID4VP PresDef."""

    supported_cred = fields.Dict(
        required=True,
        metadata={"descripton": "The updated Supported Credential"},
    )

    supported_cred_id = fields.Str(
        required=True,
        metadata={
            "description": "Supported Credential identifier",
        },
    )


async def jwt_supported_cred_update_helper(
    record: SupportedCredential,
    body: Dict[str, Any],
    session: AskarProfileSession,
) -> SupportedCredential:
    """Helper method for updating a JWT Supported Credential Record."""
    format_data = {}
    vc_additional_data = {}

    format_data["types"] = body.get("type")
    format_data["credentialSubject"] = body.get("credentialSubject", None)
    format_data["context"] = body.get("@context")
    format_data["order"] = body.get("order", None)
    vc_additional_data["@context"] = format_data["context"]
    # In OID4VCI 1.0 metadata, the field is "type" (converted in to_issuer_metadata).
    # In the actual W3C VC, it's also "type" (per VCDM spec).
    vc_additional_data["type"] = format_data["types"]

    record.identifier = body["id"]
    record.format = body["format"]
    record.cryptographic_binding_methods_supported = body.get(
        "cryptographic_binding_methods_supported", None
    )
    record.cryptographic_suites_supported = body.get(
        "cryptographic_suites_supported", None
    )
    record.proof_types_supported = body.get("proof_types_supported", None)
    record.display = body.get("display", None)
    record.format_data = format_data
    record.vc_additional_data = vc_additional_data

    await record.save(session)
    return record


@docs(
    tags=["oid4vci"],
    summary="Update a Supported Credential. "
    "Expected to be a complete replacement of a JWT Supported Credential record, "
    "i.e., optional values that aren't supplied will be `None`, rather than retaining "
    "their original value.",
)
@match_info_schema(SupportedCredentialMatchSchema())
@request_schema(JwtSupportedCredCreateRequestSchema())
@response_schema(SupportedCredentialSchema())
async def update_supported_credential_jwt_vc(request: web.Request):
    """Update a JWT Supported Credential record."""

    context: AdminRequestContext = request["context"]
    body: Dict[str, Any] = await request.json()
    supported_cred_id = request.match_info["supported_cred_id"]

    LOGGER.info(f"body: {body}")
    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(
                session, supported_cred_id
            )

            assert isinstance(session, AskarProfileSession)
            record = await jwt_supported_cred_update_helper(record, body, session)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

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


@docs(
    tags=["oid4vci"],
    summary="Remove an existing credential supported record",
)
@match_info_schema(SupportedCredentialMatchSchema())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_remove(request: web.Request):
    """Request handler for removing an credential supported record."""

    context: AdminRequestContext = request["context"]
    supported_cred_id = request.match_info["supported_cred_id"]

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(
                session, supported_cred_id
            )
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response(record.serialize())
