"""OID4VP presentation verification endpoints."""

import json
import logging
import time
import uuid
from secrets import token_urlsafe
from typing import Any, Dict, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import ProfileSession
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    PresentationDefinition,
)
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    form_schema,
    match_info_schema,
)
from marshmallow import fields
from jwcrypto import jwe, jwk as jose_jwk

from oid4vc.dcql import DCQLQueryEvaluator
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
from ..did_utils import retrieve_or_create_did_jwk
from .constants import NONCE_BYTES

LOGGER = logging.getLogger(__name__)


class OID4VPRequestIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking request id."""

    request_id = fields.Str(
        required=True,
        metadata={
            "description": "OID4VP Request identifier",
        },
    )


# ---------------------------------------------------------------------------
# X.509 identity – stores a certificate chain + signing key for x509_san_dns
# client_id_scheme in OID4VP request objects (JAR, RFC 9101).
# ---------------------------------------------------------------------------

X509_IDENTITY_RECORD_TYPE = "OID4VP.x509_identity"
X509_IDENTITY_RECORD_ID = "OID4VP.x509_identity"


async def _get_x509_identity(session: ProfileSession) -> Optional[Dict[str, Any]]:
    """Return stored X.509 identity dict, or None if not configured.

    The dict has the shape::

        {
            "cert_chain": ["<base64DER_leaf>", ...],  # leaf-first
            "verification_method": "did:jwk:...#0",
            "client_id": "acapy-verifier.example.com",
        }
    """
    storage = session.inject(BaseStorage)
    try:
        record = await storage.get_record(
            X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
        )
        return json.loads(record.value)
    except StorageNotFoundError:
        return None


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

            if record.pres_def_id:
                pres_def = await OID4VPPresDef.retrieve_by_id(session, record.pres_def_id)
            elif record.dcql_query_id:
                dcql_query = await DCQLQuery.retrieve_by_id(session, record.dcql_query_id)
            jwk = await retrieve_or_create_did_jwk(session)
            x509_id = await _get_x509_identity(session)

            pres.state = OID4VPPresentation.REQUEST_RETRIEVED
            pres.nonce = token_urlsafe(NONCE_BYTES)
            # Use x509 client_id when configured (x509_san_dns scheme).
            # OID4VP Final (ID3+) encodes the scheme as a URI prefix in client_id:
            #   x509_san_dns:{dns_name}  (e.g. "x509_san_dns:acapy-tls-proxy.local")
            # This replaces the old separate client_id_scheme parameter.
            if x509_id:
                effective_client_id = f"x509_san_dns:{x509_id['client_id']}"
            else:
                effective_client_id = jwk.did
            pres.client_id = effective_client_id

            # HAIP requires a fresh P-256 response-encryption key for every
            # Authorization Request. Persist the private half only on the
            # presentation record; publish only the public half below.
            response_encryption_key = None
            if dcql_query is not None:
                response_encryption_key = jose_jwk.JWK.generate(kty="EC", crv="P-256")
                response_encryption_key.update(
                    kid=response_encryption_key.thumbprint(),
                    use="enc",
                    alg="ECDH-ES",
                )
                pres.response_encryption_jwk = json.loads(
                    response_encryption_key.export(private_key=True)
                )
            await pres.save(session=session, reason="Retrieved presentation request")

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
    # Use OID4VP_ENDPOINT when available (may differ from the OID4VCI endpoint;
    # e.g. behind a dedicated TLS-terminating proxy for conformance tests).
    oid4vp_base = config.oid4vp_endpoint or config.endpoint
    payload = {
        "iss": effective_client_id,
        # NOTE: Do NOT include 'sub' equal to client_id in OID4VP JAR.
        # RFC 7519: sub identifies the principal that is the subject of the JWT,
        # but the JAR does not have a meaningful 'subject'.  Including sub=client_id
        # triggers a security warning (potential for use as client auth assertion).
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": str(uuid.uuid4()),
        # client_id: when using x509_san_dns the value is a DNS name that
        # matches the SAN of the leaf certificate.  For did:jwk the value is
        # the DID itself (scheme inferred from prefix, no explicit
        # client_id_scheme — see note below).
        # NOTE: Do NOT include "client_id_scheme" in OID4VP Final (ID3+): the
        # scheme is encoded as a URI prefix in client_id itself.
        # For x509_san_dns: client_id = "x509_san_dns:{dns_name}".
        # For did:jwk: client_id = the DID itself ("did:jwk:...").
        # The x5c cert chain in the JWT header establishes the x509 binding.
        # Do NOT add a separate client_id_scheme parameter — it causes failures.
        "client_id": effective_client_id,
        # Static Discovery Request Objects use the Self-Issued OP audience.
        # OID4VP 1.0 section 5.8 requires this claim.
        "aud": "https://self-issued.me/v2",
        "response_uri": (
            f"{oid4vp_base}{subpath}/oid4vp/response/{pres.presentation_id}"
        ),
        "state": pres.presentation_id,
        "nonce": pres.nonce,
        "id_token_signing_alg_values_supported": ["ES256", "EdDSA"],
        "request_object_signing_alg_values_supported": ["ES256", "EdDSA"],
        "response_types_supported": ["id_token", "vp_token"],
        "scopes_supported": ["openid", "vp_token"],
        "subject_types_supported": ["pairwise"],
        "subject_syntax_types_supported": ["urn:ietf:params:oauth:jwk-thumbprint"],
        # OID4VP 1.0 requires verifier format capabilities in
        # client_metadata.vp_formats_supported. mdoc algorithms are COSE
        # identifiers rather than JOSE algorithm names.
        "client_metadata": (
            {
                "jwks": {
                    "keys": [
                        json.loads(response_encryption_key.export(private_key=False))
                    ]
                },
                "authorization_encrypted_response_alg": "ECDH-ES",
                "authorization_encrypted_response_enc": "A256GCM",
                "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
                "vp_formats_supported": {
                    "mso_mdoc": {
                        "issuerauth_alg_values": [-7, -9],
                        "deviceauth_alg_values": [-7, -9],
                    }
                }
            }
            if dcql_query is not None and "mso_mdoc" in record.vp_formats
            else {
                "vp_formats": record.vp_formats,
                "authorization_signed_response_alg": "ES256",
            }
        ),
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt" if dcql_query is not None else "direct_post",
        # NOTE: Do NOT include "scope" here. The @openid4vc/openid4vp library
        # validates that EXACTLY ONE of {scope, presentation_definition,
        # presentation_definition_uri, dcql_query} is present. Including scope
        # alongside presentation_definition or dcql_query causes a validation error.
    }
    if pres_def is not None:
        payload["presentation_definition"] = pres_def.pres_def
    if dcql_query is not None:
        # These are verifier/authorization-server metadata, not Authorization
        # Request parameters. Keep them only on the legacy Presentation
        # Exchange path for compatibility with existing wallets.
        for metadata_key in (
            "id_token_signing_alg_values_supported",
            "request_object_signing_alg_values_supported",
            "response_types_supported",
            "scopes_supported",
            "subject_types_supported",
            "subject_syntax_types_supported",
        ):
            payload.pop(metadata_key, None)
        payload["dcql_query"] = dcql_query.record_value
    else:
        payload["vp_formats"] = record.vp_formats

    if x509_id:
        headers = {
            "x5c": x509_id["cert_chain"],
            "typ": "oauth-authz-req+jwt",
            "alg": "ES256",
        }
        signing_vm = x509_id["verification_method"]
    else:
        headers = {
            "kid": f"{jwk.did}#0",
            "typ": "oauth-authz-req+jwt",
        }
        signing_vm = f"{jwk.did}#0"

    token = await jwt_sign(
        profile=context.profile,
        payload=payload,
        headers=headers,
        verification_method=signing_vm,
    )

    LOGGER.debug("TOKEN: %s", token)

    return web.Response(
        body=token.encode("ascii"),
        content_type="application/oauth-authz-req+jwt",
    )


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

    response = fields.Str(
        required=False,
        metadata={"description": "Encrypted direct_post.jwt Authorization Response"},
    )

    vp_token = fields.Str(
        required=False,
        metadata={
            "description": "",
        },
    )

    state = fields.Str(
        required=False, metadata={"description": "State describing the presentation"}
    )


async def verify_dcql_presentation(
    profile,
    vp_token: Dict[str, Any],
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
    profile,
    submission: PresentationSubmission,
    vp_token: str,
    pres_def_id: str,
    presentation: OID4VPPresentation,
):
    """Verify a received presentation."""

    LOGGER.debug("Got: %s %s", submission, vp_token)

    processors = profile.inject(CredProcessors)
    if not submission.descriptor_maps:
        raise web.HTTPBadRequest(reason="Descriptor map of submission must not be empty")

    # TODO: Support longer descriptor map arrays
    if len(submission.descriptor_maps) != 1:
        raise web.HTTPBadRequest(
            reason="Descriptor map of length greater than 1 is not supported at this time"
        )

    verifier = processors.pres_verifier_for_format(submission.descriptor_maps[0].fmt)
    LOGGER.debug("VERIFIER: %s", verifier)

    vp_result = await verifier.verify_presentation(
        profile=profile,
        presentation=vp_token,
        presentation_record=presentation,
    )

    if not vp_result.verified:
        error_msg = (
            vp_result.payload.get("error", "Presentation verification failed")
            if isinstance(vp_result.payload, dict)
            else "Presentation verification failed"
        )
        if isinstance(error_msg, list):
            error_msg = "; ".join(str(e) for e in error_msg)
        return PexVerifyResult(details=str(error_msg))

    async with profile.session() as session:
        pres_def_entry = await OID4VPPresDef.retrieve_by_id(
            session,
            pres_def_id,
        )

        pres_def = PresentationDefinition.deserialize(pres_def_entry.pres_def)

    evaluator = PresentationExchangeEvaluator.compile(pres_def)

    # For mso_mdoc presentations, vp_result.payload is an already-decoded claims
    # dict.  The presentation_submission from wallets (e.g. waltid) typically
    # references $.documents[N] which is a path into the raw DeviceResponse CBOR,
    # not the decoded dict.  Wrap the decoded payload so that $.documents[0]
    # correctly resolves to the pre-verified claims.
    item = submission.descriptor_maps[0]
    if (
        item.path_nested
        and item.path_nested.path
        and ".documents[" in item.path_nested.path
    ):
        eval_presentation: dict = {"documents": [vp_result.payload]}
    else:
        eval_presentation = vp_result.payload

    result = await evaluator.verify(profile, submission, eval_presentation)
    return result


@docs(tags=["oid4vp"], summary="Provide OID4VP presentation")
@match_info_schema(OID4VPPresentationIDMatchSchema())
@form_schema(PostOID4VPResponseSchema())
async def post_response(request: web.Request):
    """Post an OID4VP Response."""
    context: AdminRequestContext = request["context"]
    presentation_id = request.match_info["presentation_id"]

    form = await request.post()

    LOGGER.debug("OID4VP POST form keys: %s", list(form.keys()))

    async with context.session() as session:
        record = await OID4VPPresentation.retrieve_by_id(session, presentation_id)

    try:
        encrypted_response = form.get("response")
        if encrypted_response is not None:
            if not isinstance(encrypted_response, str):
                raise web.HTTPBadRequest(reason="response must be a string")
            if not record.response_encryption_jwk:
                raise web.HTTPBadRequest(
                    reason="No response-encryption key exists for this presentation"
                )

            response_token = jwe.JWE()
            response_token.deserialize(
                encrypted_response,
                key=jose_jwk.JWK(**record.response_encryption_jwk),
            )
            if response_token.jose_header.get("alg") != "ECDH-ES":
                raise web.HTTPBadRequest(reason="Unsupported response JWE alg")
            if response_token.jose_header.get("enc") not in ("A128GCM", "A256GCM"):
                raise web.HTTPBadRequest(reason="Unsupported response JWE enc")
            response_payload = json.loads(response_token.payload.decode("utf-8"))
            if not isinstance(response_payload, dict):
                raise web.HTTPBadRequest(reason="Response payload must be a JSON object")
        else:
            response_payload = form

        # presentation_submission is only present for PEX presentations. DCQL
        # responses carry a credential-query-id keyed vp_token object.
        raw_submission = response_payload.get("presentation_submission")
        presentation_submission = (
            PresentationSubmission.deserialize(raw_submission)
            if isinstance(raw_submission, dict)
            else PresentationSubmission.from_json(raw_submission)
            if isinstance(raw_submission, str)
            else None
        )
        vp_token = response_payload.get("vp_token")
        state = response_payload.get("state")

        if state and state != presentation_id:
            raise web.HTTPBadRequest(reason="`state` must match the presentation id")

        if record.pres_def_id:
            if not isinstance(vp_token, str):
                raise web.HTTPBadRequest(reason="vp_token must be a string")
            if presentation_submission is None:
                raise web.HTTPBadRequest(
                    reason="presentation_submission is required for PEX presentations"
                )
            verify_result = await verify_pres_def_presentation(
                profile=context.profile,
                submission=presentation_submission,
                vp_token=vp_token,
                pres_def_id=record.pres_def_id,
                presentation=record,
            )
        elif record.dcql_query_id:
            if isinstance(vp_token, str):
                vp_token = json.loads(vp_token)
            if not isinstance(vp_token, dict):
                raise web.HTTPBadRequest(reason="DCQL vp_token must be a JSON object")
            verify_result = await verify_dcql_presentation(
                profile=context.profile,
                vp_token=vp_token,
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
    except Exception as err:
        # Catch all other exceptions (e.g. CredProcessorError, unsupported format),
        # save the record as invalid so the holder gets a response and callers can
        # observe the failure rather than timing out on request-retrieved.
        error_msg = str(err)
        LOGGER.exception(
            "Unexpected error processing presentation %s: %s",
            presentation_id,
            error_msg,
        )
        record.state = OID4VPPresentation.PRESENTATION_INVALID
        record.errors = [f"Processing error: {error_msg}"]
        record.verified = False
        record.matched_credentials = {}
        record.response_encryption_jwk = None
        async with context.session() as session:
            await record.save(session, reason="Presentation processing failed")
        return web.json_response({})

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
    record.response_encryption_jwk = None

    async with context.session() as session:
        await record.save(
            session,
            reason=f"Presentation verified: {verify_result.verified}",
        )

    LOGGER.debug("Presentation result: %s", record.verified)
    # OID4VP Final §6.2: verifier MUST return a JSON response body.
    # If no redirect_uri is required, return an empty JSON object.
    return web.json_response({})
