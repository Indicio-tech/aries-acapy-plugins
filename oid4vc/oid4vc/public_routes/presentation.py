"""OID4VP presentation endpoints."""

import json
import time
import uuid
from secrets import token_urlsafe

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.protocols.present_proof.dif.pres_exch import PresentationDefinition
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, form_schema, match_info_schema
from marshmallow import fields

from oid4vc.dcql import DCQLQueryEvaluator
from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.jwt import jwt_sign
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.presentation_definition import OID4VPPresDef
from oid4vc.models.request import OID4VPRequest
from oid4vc.pex import (
    PexVerifyResult,
    PresentationExchangeEvaluator,
    PresentationSubmission,
)

from ..config import Config
from ..cred_processor import CredProcessors
from .constants import LOGGER, NONCE_BYTES


class OID4VPRequestIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking request id."""

    request_id = fields.Str(
        required=True,
        metadata={
            "description": "OID4VP Request identifier",
        },
    )


@docs(tags=["oid4vp"], summary="Retrive OID4VP authorization request token")
@match_info_schema(OID4VPRequestIDMatchSchema())
async def get_request(request: web.Request):
    """Get an OID4VP Request token."""
    context: AdminRequestContext = request["context"]
    request_id = request.match_info["request_id"]
    pres_def = None
    dcql_query = None

    try:
        async with context.session() as session:
            record = await OID4VPRequest.retrieve_by_id(session, request_id)
            await record.delete_record(session)

            pres = await OID4VPPresentation.retrieve_by_request_id(
                session=session, request_id=request_id
            )
            pres.state = OID4VPPresentation.REQUEST_RETRIEVED
            pres.nonce = token_urlsafe(NONCE_BYTES)
            await pres.save(session=session, reason="Retrieved presentation request")

            if record.pres_def_id:
                pres_def = await OID4VPPresDef.retrieve_by_id(
                    session, record.pres_def_id
                )
            elif record.dcql_query_id:
                dcql_query = await DCQLQuery.retrieve_by_id(
                    session, record.dcql_query_id
                )
            jwk = await retrieve_or_create_did_jwk(session)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    now = int(time.time())
    config = Config.from_settings(context.settings)
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""

    version_path = ""
    if "/v1/" in request.path:
        version_path = "/v1"

    response_uri = (
        f"{config.endpoint}{subpath}{version_path}"
        f"/oid4vp/response/{pres.presentation_id}"
    )

    payload = {
        "iss": jwk.did,
        "sub": jwk.did,
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": str(uuid.uuid4()),
        "client_id": jwk.did,
        # Note: client_id_scheme is deprecated in OID4VP v1.0 - using DID as client_id
        # is recognized via the "did:" prefix in the client_id itself
        "response_uri": response_uri,
        "state": pres.presentation_id,
        "nonce": pres.nonce,
        "client_metadata": {
            "id_token_signing_alg_values_supported": ["ES256", "EdDSA"],
            "request_object_signing_alg_values_supported": ["ES256", "EdDSA"],
            "response_types_supported": ["id_token", "vp_token"],
            "scopes_supported": ["openid"],
            "subject_types_supported": ["pairwise"],
            "subject_syntax_types_supported": ["urn:ietf:params:oauth:jwk-thumbprint"],
            "vp_formats": record.vp_formats,
        },
        "response_type": "vp_token",
        "response_mode": "direct_post",
    }
    # According to OID4VP spec, exactly one of presentation_definition,
    # presentation_definition_uri, dcql_query, or scope MUST be present.
    # Do not include scope when presentation_definition or dcql_query is provided.
    if pres_def is not None:
        payload["presentation_definition"] = pres_def.pres_def
    elif dcql_query is not None:
        payload["dcql_query"] = dcql_query.record_value

    LOGGER.error(f"DEBUG: Generated JWT payload: {payload}")

    headers = {
        "kid": f"{jwk.did}#0",
        "typ": "oauth-authz-req+jwt",
    }

    token = await jwt_sign(
        profile=context.profile,
        payload=payload,
        headers=headers,
        verification_method=f"{jwk.did}#0",
    )

    LOGGER.debug("TOKEN: %s", token)

    return web.Response(text=token, content_type="application/oauth-authz-req+jwt")


class OID4VPPresentationIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking request id."""

    presentation_id = fields.Str(
        required=True,
        metadata={
            "description": "OID4VP Presentation identifier",
        },
    )


class PostOID4VPResponseSchema(OpenAPISchema):
    """Schema for ..."""

    presentation_submission = fields.Str(required=False, metadata={"description": ""})

    vp_token = fields.Str(
        required=True,
        metadata={
            "description": "",
        },
    )

    state = fields.Str(
        required=False, metadata={"description": "State describing the presentation"}
    )


async def verify_dcql_presentation(
    profile: Profile,
    vp_token: dict,
    dcql_query_id: str,
    presentation: OID4VPPresentation,
):
    """Verify a received presentation."""

    LOGGER.debug("Got: %s", vp_token)

    async with profile.session() as session:
        dcql_query = await DCQLQuery.retrieve_by_id(
            session,
            dcql_query_id,
        )

    evaluator = DCQLQueryEvaluator.compile(dcql_query)
    result = await evaluator.verify(profile, vp_token, presentation)
    return result


async def verify_pres_def_presentation(
    profile: Profile,
    submission: PresentationSubmission,
    vp_token: str,
    pres_def_id: str,
    presentation: OID4VPPresentation,
):
    """Verify a received presentation.

    Supports presentations with multiple descriptor maps, allowing for
    multi-credential presentations where a single VP contains multiple VCs.
    """

    LOGGER.debug("Got: %s %s", submission, vp_token)

    processors = profile.inject(CredProcessors)
    if not submission.descriptor_maps:
        raise web.HTTPBadRequest(
            reason="Descriptor map of submission must not be empty"
        )

    # Determine the presentation format from descriptor maps
    # All descriptor maps should use the same presentation format at the top level
    descriptor_formats = {dm.fmt for dm in submission.descriptor_maps}
    if len(descriptor_formats) > 1:
        LOGGER.warning(
            "Multiple presentation formats in descriptor maps: %s. "
            "Using first format for VP verification.",
            descriptor_formats,
        )

    LOGGER.info(f"Available pres_verifiers: {list(processors.pres_verifiers.keys())}")
    LOGGER.info(
        f"Processing {len(submission.descriptor_maps)} descriptor map(s)"
    )
    
    # Use the first format for VP-level verification
    verifier = processors.pres_verifier_for_format(submission.descriptor_maps[0].fmt)
    LOGGER.debug("VERIFIER: %s", verifier)

    vp_result = await verifier.verify_presentation(
        profile=profile,
        presentation=vp_token,
        presentation_record=presentation,
    )

    async with profile.session() as session:
        pres_def_entry = await OID4VPPresDef.retrieve_by_id(
            session,
            pres_def_id,
        )

        # Keep raw dict for format extraction (ACA-Py < 1.5 doesn't have fmt attribute)
        raw_pres_def = pres_def_entry.pres_def
        LOGGER.info(f"DEBUG: raw_pres_def = {raw_pres_def}")
        pres_def = PresentationDefinition.deserialize(raw_pres_def)

    evaluator = PresentationExchangeEvaluator.compile(pres_def, raw_pres_def)
    result = await evaluator.verify(profile, submission, vp_result.payload)
    return result


@docs(tags=["oid4vp"], summary="Provide OID4VP presentation")
@match_info_schema(OID4VPPresentationIDMatchSchema())
@form_schema(PostOID4VPResponseSchema())
async def post_response(request: web.Request):
    """Post an OID4VP Response.

    Handles two response formats per OID4VP spec:
    1. Presentation Exchange (PEX): Uses `presentation_submission` + `vp_token` (string)
    2. DCQL: Uses only `vp_token` as JSON object {credential_id: [presentations...]}
    """
    context: AdminRequestContext = request["context"]
    presentation_id = request.match_info["presentation_id"]

    form = await request.post()

    raw_submission = form.get("presentation_submission")
    vp_token = form.get("vp_token")
    state = form.get("state")

    if state and state != presentation_id:
        raise web.HTTPBadRequest(reason="`state` must match the presentation id")

    async with context.session() as session:
        record = await OID4VPPresentation.retrieve_by_id(session, presentation_id)

    try:
        if record.pres_def_id:
            # Presentation Exchange (PEX) response format
            # Requires presentation_submission and vp_token as string
            if not isinstance(raw_submission, str):
                LOGGER.error(
                    "PEX response missing presentation_submission for presentation %s",
                    presentation_id,
                )
                raise web.HTTPBadRequest(
                    reason="presentation_submission required for PEX responses"
                )
            if not isinstance(vp_token, str):
                LOGGER.error(
                    "PEX response missing vp_token string for presentation %s",
                    presentation_id,
                )
                raise web.HTTPBadRequest(
                    reason="vp_token required as string for PEX responses"
                )

            presentation_submission = PresentationSubmission.from_json(raw_submission)
            verify_result = await verify_pres_def_presentation(
                profile=context.profile,
                submission=presentation_submission,
                vp_token=vp_token,
                pres_def_id=record.pres_def_id,
                presentation=record,
            )
        elif record.dcql_query_id:
            # DCQL response format per OID4VP Section 8
            # vp_token is JSON object: {credential_query_id: [presentation_strings...]}
            # No presentation_submission is used
            if not isinstance(vp_token, str):
                LOGGER.error(
                    "DCQL response missing vp_token for presentation %s",
                    presentation_id,
                )
                raise web.HTTPBadRequest(reason="vp_token required for DCQL responses")

            try:
                parsed_vp_token = json.loads(vp_token)
            except json.JSONDecodeError as err:
                LOGGER.error("Failed to parse DCQL vp_token as JSON: %s", err)
                raise web.HTTPBadRequest(
                    reason="vp_token must be valid JSON for DCQL responses"
                ) from err

            LOGGER.debug(
                "Processing DCQL response for presentation %s with vp_token keys: %s",
                presentation_id,
                list(parsed_vp_token.keys())
                if isinstance(parsed_vp_token, dict)
                else "not a dict",
            )

            verify_result = await verify_dcql_presentation(
                profile=context.profile,
                vp_token=parsed_vp_token,
                dcql_query_id=record.dcql_query_id,
                presentation=record,
            )
        else:
            LOGGER.error("Record %s has neither pres_def_id or dcql_query_id", record)
            raise web.HTTPInternalServerError(reason="Something went wrong")

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if verify_result.verified:
        record.state = OID4VPPresentation.PRESENTATION_VALID
    else:
        record.state = OID4VPPresentation.PRESENTATION_INVALID
        assert verify_result.details
        record.errors = [verify_result.details]

    record.verified = verify_result.verified
    record.matched_credentials = (
        verify_result.descriptor_id_to_claims
        if isinstance(verify_result, PexVerifyResult)
        else verify_result.cred_query_id_to_claims
    )

    async with context.session() as session:
        await record.save(
            session,
            reason=f"Presentation verified: {verify_result.verified}",
        )

    LOGGER.debug("Presentation result: %s", record.verified)
    return web.json_response({})
