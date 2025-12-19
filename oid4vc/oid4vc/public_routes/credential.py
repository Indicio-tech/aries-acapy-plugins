"""Credential issuance endpoints for OID4VCI."""

import datetime
import json
from secrets import token_urlsafe
from typing import List, Optional
from urllib.parse import quote

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.util import datetime_now, datetime_to_str
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, querystring_schema, request_schema, response_schema
from marshmallow import fields

from ..cred_processor import CredProcessorError, CredProcessors
from ..models.exchange import OID4VCIExchangeRecord
from ..models.nonce import Nonce
from ..models.supported_cred import SupportedCredential
from ..pop_result import PopResult
from ..routes.credential_offer import CredOfferQuerySchema, CredOfferResponseSchemaVal
from ..utils import _parse_cred_offer
from .constants import EXPIRES_IN, LOGGER, NONCE_BYTES
from .proof import handle_proof_of_posession
from .token import check_token


@docs(tags=["oid4vci"], summary="Dereference a credential offer.")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaVal(), 200)
async def dereference_cred_offer(request: web.Request):
    """Dereference a credential offer.

    Reference URI is acquired from the /oid4vci/credential-offer-by-ref endpoint
    (see routes.get_cred_offer_by_ref()).
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]

    offer = await _parse_cred_offer(context, exchange_id)
    return web.json_response(
        {
            "offer": offer,
            "credential_offer": f"openid-credential-offer://?credential_offer={quote(json.dumps(offer))}",
        }
    )


async def create_nonce(profile: Profile, nbytes: int, ttl: int) -> Nonce:
    """Create and store a fresh nonce."""
    nonce = token_urlsafe(nbytes)
    issued_at = datetime_now()
    expires_at = issued_at + datetime.timedelta(seconds=ttl)
    issued_at_str = datetime_to_str(issued_at)
    expires_at_str = datetime_to_str(expires_at)

    if issued_at_str is None or expires_at_str is None:
        raise web.HTTPInternalServerError(reason="Could not generate timestamps")

    nonce_record = Nonce(
        nonce_value=nonce,
        used=False,
        issued_at=issued_at_str,
        expires_at=expires_at_str,
    )
    async with profile.session() as session:
        await nonce_record.save(session=session, reason="Created new nonce")

    return nonce_record


@docs(tags=["oid4vci"], summary="Get a fresh nonce for proof of possession")
async def get_nonce(request: web.Request):
    """Get a fresh nonce for proof of possession."""
    context: AdminRequestContext = request["context"]
    nonce = await create_nonce(context.profile, NONCE_BYTES, EXPIRES_IN)

    return web.json_response(
        {
            "c_nonce": nonce.nonce_value,
            "expires_in": EXPIRES_IN,
        }
    )


class NotificationSchema(OpenAPISchema):
    """Schema for notification endpoint."""

    notification_id = fields.Str(
        required=True,
        metadata={"description": "Notification identifier", "example": "3fwe98js"},
    )
    event = fields.Str(
        required=True,
        metadata={
            "description": (
                "Type of the notification event, value is one of: "
                "'credential_accepted', 'credential_failure', or 'credential_deleted'"
            ),
            "example": "credential_accepted",
        },
    )
    event_description = fields.Str(
        required=False, metadata={"description": "Human-readable ASCII [USASCII] text"}
    )


@docs(tags=["oid4vci"], summary="Send a notification to the user")
@request_schema(NotificationSchema())
async def receive_notification(request: web.Request):
    """Send a notification to the user."""
    body = await request.json()
    LOGGER.debug(f"Notification request: {body}")

    context: AdminRequestContext = request["context"]
    if not await check_token(context, request.headers.get("Authorization")):
        raise web.HTTPUnauthorized(reason="invalid_token")

    async with context.profile.session() as session:
        try:
            record = await OID4VCIExchangeRecord.retrieve_by_notification_id(
                session, body.get("notification_id", None)
            )
            if not record:
                raise web.HTTPBadRequest(reason="invalid_notification_id")
            event = body.get("event", None)
            event_desc = body.get("event_description", None)
            if event == "credential_accepted":
                record.state = OID4VCIExchangeRecord.STATE_ACCEPTED
            elif event == "credential_failure":
                record.state = OID4VCIExchangeRecord.STATE_FAILED
            elif event == "credential_deleted":
                record.state = OID4VCIExchangeRecord.STATE_DELETED
            else:
                raise web.HTTPBadRequest(reason="invalid_notification_request")
            record.notification_event = {"event": event, "description": event_desc}
            await record.save(session, reason="Updated by notification")
        except (StorageError, BaseModelError, StorageNotFoundError) as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)


def types_are_subset(request: Optional[List[str]], supported: Optional[List[str]]):
    """Compare types."""
    if request is None:
        return False
    if supported is None:
        return False
    return set(request).issubset(set(supported))


class ExchangeContext:
    """Container for exchange-related data retrieved during credential issuance."""

    def __init__(
        self,
        ex_record: OID4VCIExchangeRecord,
        supported: SupportedCredential,
        is_offer: bool,
    ):
        """Initialize exchange context."""
        self.ex_record = ex_record
        self.supported = supported
        self.is_offer = is_offer


async def _retrieve_exchange_and_supported(
    context: AdminRequestContext, refresh_id: str
) -> ExchangeContext:
    """Retrieve exchange record and supported credential.

    Args:
        context: The admin request context
        refresh_id: The refresh ID from the token

    Returns:
        ExchangeContext with exchange record, supported credential, and is_offer flag

    Raises:
        web.HTTPNotFound: If no exchange record found
        web.HTTPBadRequest: If storage error or missing format
    """
    try:
        async with context.profile.session() as session:
            ex_record = await OID4VCIExchangeRecord.retrieve_by_refresh_id(
                session, refresh_id=refresh_id
            )
            if not ex_record:
                raise StorageNotFoundError("No exchange record found")
            is_offer = ex_record.state == OID4VCIExchangeRecord.STATE_OFFER_CREATED
            supported = await SupportedCredential.retrieve_by_id(
                session, ex_record.supported_cred_id
            )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason="No credential offer available.") from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not supported.format:
        LOGGER.error("SupportedCredential missing format identifier.")
        raise web.HTTPBadRequest(
            reason="SupportedCredential missing format identifier."
        )

    return ExchangeContext(ex_record, supported, is_offer)


def _validate_authorization(
    token_payload: dict, supported_identifier: str, format_param: Optional[str]
) -> None:
    """Validate authorization details from token.

    Args:
        token_payload: The decoded token payload
        supported_identifier: The supported credential identifier
        format_param: The format parameter from request

    Raises:
        web.HTTPBadRequest: If authorization validation fails
    """
    authorization_details = token_payload.get("authorization_details", None)
    if authorization_details:
        found = any(
            isinstance(ad, dict)
            and ad.get("credential_configuration_id") == supported_identifier
            for ad in authorization_details
        )
        if not found:
            LOGGER.error(f"{supported_identifier} is not authorized by the token.")
            raise web.HTTPBadRequest(
                reason=f"{supported_identifier} is not authorized by the token."
            )


def _validate_credential_request(
    credential_identifier: Optional[str], format_param: Optional[str]
) -> Optional[web.Response]:
    """Validate credential_identifier and format parameters.

    Args:
        credential_identifier: The credential identifier from request
        format_param: The format parameter from request

    Returns:
        Error response if validation fails, None if valid
    """
    if not credential_identifier and not format_param:
        LOGGER.error("Either credential_identifier or format parameter must be present")
        return web.json_response(
            {
                "message": "Either credential_identifier or format parameter "
                "must be present"
            },
            status=400,
        )

    if credential_identifier and format_param:
        LOGGER.error("credential_identifier and format are mutually exclusive")
        return web.json_response(
            {"message": "credential_identifier and format are mutually exclusive"},
            status=400,
        )

    return None


def _derive_jwt_vc_format_data(supported: SupportedCredential) -> Optional[dict]:
    """Derive format_data for jwt_vc_json format.

    Args:
        supported: The supported credential

    Returns:
        Derived format_data dict, or None if cannot derive
    """
    derived = {}
    vad = getattr(supported, "vc_additional_data", None)
    if isinstance(vad, dict):
        if "type" in vad:
            derived["types"] = vad["type"]
        if "@context" in vad:
            derived["context"] = vad["@context"]
    return derived if derived else None


def _ensure_format_data(
    supported: SupportedCredential, body: dict
) -> Optional[web.Response]:
    """Ensure format_data exists, deriving it if necessary.

    Args:
        supported: The supported credential (may be modified)
        body: The request body

    Returns:
        Error response if format_data cannot be derived, None if successful
    """
    if supported.format_data is not None:
        return None

    if supported.format == "jwt_vc_json":
        derived = _derive_jwt_vc_format_data(supported)
        if derived:
            supported.format_data = derived
        else:
            LOGGER.error(
                "No format_data for supported credential jwt_vc_json and "
                "could not derive from vc_additional_data."
            )
            return web.json_response(
                {"message": "No format_data for supported credential jwt_vc_json"},
                status=400,
            )
    elif supported.format == "mso_mdoc":
        req_doctype = body.get("doctype")
        if req_doctype:
            supported.format_data = {"doctype": req_doctype}
        else:
            LOGGER.error(
                "No format_data for supported credential mso_mdoc and "
                "missing doctype in request."
            )
            return web.json_response(
                {
                    "message": (
                        "No format_data for supported credential mso_mdoc and "
                        "missing doctype in request"
                    )
                },
                status=400,
            )
    else:
        LOGGER.error(
            f"No format_data for supported credential {supported.format}."
        )
        return web.json_response(
            {
                "message": (
                    f"No format_data for supported credential {supported.format}"
                )
            },
            status=400,
        )

    return None


async def _handle_proof(
    context: AdminRequestContext,
    proof_obj: Optional[dict],
    c_nonce: str,
    format_type: str,
    ex_record: OID4VCIExchangeRecord,
) -> tuple[Optional[PopResult], Optional[web.Response]]:
    """Handle proof of possession verification.

    Args:
        context: The admin request context
        proof_obj: The proof object from request
        c_nonce: The challenge nonce
        format_type: The credential format type
        ex_record: The exchange record

    Returns:
        Tuple of (PopResult, None) on success, or (None, error_response) on failure
    """
    if format_type == "mso_mdoc":
        if not isinstance(proof_obj, dict):
            LOGGER.error("proof is required for mso_mdoc")
            return None, web.json_response(
                {"message": "proof is required for mso_mdoc"}, status=400
            )

        if "jwt" in proof_obj:
            try:
                pop = await handle_proof_of_posession(
                    context.profile, proof_obj, c_nonce
                )
                return pop, None
            except web.HTTPBadRequest as exc:
                LOGGER.error(f"Proof verification failed (mso_mdoc/jwt): {exc.reason}")
                return None, web.json_response({"message": exc.reason}, status=400)
        elif "cwt" in proof_obj or proof_obj.get("proof_type") == "cwt":
            try:
                pop = await handle_proof_of_posession(
                    context.profile, proof_obj, c_nonce
                )
                return pop, None
            except web.HTTPBadRequest as exc:
                LOGGER.error(f"Proof verification failed (mso_mdoc/cwt): {exc.reason}")
                return None, web.json_response({"message": exc.reason}, status=400)
        else:
            LOGGER.error("Unsupported proof type")
            return None, web.json_response(
                {"message": "Unsupported proof type"}, status=400
            )
    else:
        # jwt_vc_json and other formats: proof is optional
        if isinstance(proof_obj, dict) and "jwt" in proof_obj:
            try:
                pop = await handle_proof_of_posession(
                    context.profile, proof_obj, c_nonce
                )
                return pop, None
            except web.HTTPBadRequest as exc:
                LOGGER.error(f"Proof verification failed (jwt_vc_json): {exc.reason}")
                return None, web.json_response({"message": exc.reason}, status=400)

        # No proof or no holder key material - use exchange's verification method
        return PopResult(
            headers={},
            payload={},
            verified=True,
            holder_kid=ex_record.verification_method,
            holder_jwk=None,
        ), None


class IssueCredentialRequestSchema(OpenAPISchema):
    """Request schema for the /credential endpoint.

    OpenID4VCI 1.0 § 7: Credential Request
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7
    """

    credential_identifier = fields.Str(
        required=False,
        metadata={
            "description": "String identifying a Credential Configuration supported "
            "by the Credential Issuer. REQUIRED if format parameter is not present.",
            "example": "UniversityDegreeCredential",
        },
    )
    format = fields.Str(
        required=False,
        metadata={
            "description": "Format of the Credential to be issued. This parameter "
            "MUST NOT be used if credential_identifier parameter is present.",
            "example": "mso_mdoc",
        },
    )
    doctype = fields.Str(
        required=False,
        metadata={
            "description": "String identifying the credential type. REQUIRED when "
            "using mso_mdoc format.",
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    proof = fields.Dict(
        required=True,
        metadata={
            "description": "JSON object containing the proof of possession of the "
            "cryptographic key material the issued Credential shall be bound to."
        },
    )
    credential_response_encryption = fields.Dict(
        required=False,
        metadata={
            "description": "Object containing information for encrypting the "
            "Credential Response. OPTIONAL."
        },
    )
    type = fields.List(
        fields.Str(),
        metadata={"description": ""},
    )


@docs(tags=["oid4vc"], summary="Issue a credential")
async def issue_cred(request: web.Request):
    """The Credential Endpoint issues a Credential.

    OpenID4VCI 1.0 § 7: Credential Request
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7

    This endpoint issues a credential as validated upon presentation of a valid
    Access Token. The request MUST contain either a credential_identifier OR a
    format parameter, but not both.
    """
    context: AdminRequestContext = request["context"]
    token_result = await check_token(context, request.headers.get("Authorization"))
    refresh_id = token_result.payload["sub"]
    body = await request.json()
    LOGGER.info(f"request: {body}")

    credential_identifier = body.get("credential_identifier")
    format_param = body.get("format")

    # Retrieve exchange record and supported credential
    exchange_ctx = await _retrieve_exchange_and_supported(context, refresh_id)
    ex_record = exchange_ctx.ex_record
    supported = exchange_ctx.supported
    is_offer = exchange_ctx.is_offer

    # Validate format matches
    if format_param and supported.format != format_param:
        LOGGER.error(
            f"Requested format {format_param} does not match offer {supported.format}."
        )
        raise web.HTTPBadRequest(reason="Requested format does not match offer.")

    # Validate authorization details
    _validate_authorization(token_result.payload, supported.identifier, format_param)

    # Validate nonce exists
    c_nonce = token_result.payload.get("c_nonce") or ex_record.nonce
    if c_nonce is None:
        LOGGER.error("Invalid exchange; no offer created for this request")
        raise web.HTTPBadRequest(
            reason="Invalid exchange; no offer created for this request"
        )

    # Validate credential_identifier and format parameters
    error_response = _validate_credential_request(credential_identifier, format_param)
    if error_response:
        return error_response

    # Select the supported credential to issue based on the request
    selected_supported = await _select_supported_credential(
        context, credential_identifier, supported
    )

    if not selected_supported.format:
        LOGGER.error("Supported credential has no format")
        return web.json_response(
            {"message": "Supported credential has no format"}, status=500
        )

    # Validate credential_identifier matches selected credential
    if credential_identifier and credential_identifier != selected_supported.identifier:
        LOGGER.error(
            f"Requested credential_identifier {credential_identifier} "
            f"does not match offered credential {selected_supported.identifier}"
        )
        return web.json_response(
            {
                "error": "invalid_request",
                "message": f"Requested credential_identifier {credential_identifier} "
                f"does not match offered credential {selected_supported.identifier}",
            },
            status=400,
        )

    # Ensure format_data exists
    error_response = _ensure_format_data(selected_supported, body)
    if error_response:
        return error_response

    # Handle proof of possession
    proof_obj = body.get("proof")
    pop, error_response = await _handle_proof(
        context, proof_obj, c_nonce, selected_supported.format, ex_record
    )
    if error_response:
        return error_response

    # Issue the credential
    try:
        processors = context.inject(CredProcessors)
        processor = processors.issuer_for_format(selected_supported.format)

        credential = await processor.issue(
            body, selected_supported, ex_record, pop, context
        )
    except CredProcessorError as e:
        LOGGER.error(f"Credential processing failed: {e}")
        return web.json_response({"message": str(e)}, status=400)
    except Exception as e:
        LOGGER.exception("Unexpected error during credential issuance")
        return web.json_response({"message": str(e)}, status=500)

    # Update exchange record state
    async with context.session() as session:
        ex_record.state = OID4VCIExchangeRecord.STATE_ISSUED
        await ex_record.save(session, reason="Credential issued")

    cred_response = {
        "format": supported.format,
        "credential": credential,
        "notification_id": ex_record.notification_id,
    }
    if is_offer:
        cred_response["refresh_id"] = ex_record.refresh_id

    LOGGER.info(f"Sending credential response: {cred_response}")
    return web.json_response(cred_response)


async def _select_supported_credential(
    context: AdminRequestContext,
    credential_identifier: Optional[str],
    default_supported: SupportedCredential,
) -> SupportedCredential:
    """Select the supported credential based on credential_identifier.

    Args:
        context: The admin request context
        credential_identifier: The credential identifier from request
        default_supported: The default supported credential from exchange

    Returns:
        The selected SupportedCredential
    """
    if not credential_identifier:
        return default_supported

    async with context.profile.session() as session:
        try:
            matches = await SupportedCredential.query(
                session, tag_filter={"identifier": credential_identifier}
            )
            if matches:
                return matches[0]
        except Exception:
            pass

    return default_supported
