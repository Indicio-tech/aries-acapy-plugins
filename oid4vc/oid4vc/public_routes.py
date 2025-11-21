"""Public routes for OID4VC."""

import datetime
import json
import logging
import time
import uuid
from secrets import token_urlsafe
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import cwt
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.util import datetime_now, datetime_to_str
from acapy_agent.protocols.present_proof.dif.pres_exch import \
    PresentationDefinition
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet, WalletError
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.util import b64_to_bytes, bytes_to_b64
from aiohttp import web
from aiohttp_apispec import (docs, form_schema, match_info_schema,
                             querystring_schema, request_schema,
                             response_schema)
from aries_askar import Key, KeyAlg
from base58 import b58decode
from marshmallow import fields, pre_load

from oid4vc.dcql import DCQLQueryEvaluator
from oid4vc.jwk import DID_JWK
from oid4vc.jwt import (JWTVerifyResult, jwt_sign, jwt_verify,
                        key_material_for_kid)
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.presentation_definition import OID4VPPresDef
from oid4vc.models.request import OID4VPRequest
from oid4vc.pex import (PexVerifyResult, PresentationExchangeEvaluator,
                        PresentationSubmission)

from .app_resources import AppResources
from .config import Config
from .cred_processor import CredProcessorError, CredProcessors
from .models.exchange import OID4VCIExchangeRecord
from .models.nonce import Nonce
from .models.supported_cred import SupportedCredential
from .pop_result import PopResult
from .routes import (CredOfferQuerySchema, CredOfferResponseSchemaVal,
                     _parse_cred_offer)
from .status_handler import StatusHandler
from .utils import get_auth_header, get_tenant_subpath

LOGGER = logging.getLogger(__name__)
PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
NONCE_BYTES = 16
EXPIRES_IN = 86400


@docs(tags=["oid4vci"], summary="Dereference a credential offer.")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaVal(), 200)
async def dereference_cred_offer(request: web.BaseRequest):
    """Dereference a credential offer.

    Reference URI is acquired from the /oid4vci/credential-offer-by-ref endpoint
    (see routes.get_cred_offer_by_ref()).
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]

    offer = await _parse_cred_offer(context, exchange_id)
    return web.json_response(
        {
            "credential_offer": offer,
            "credential_offer_uri": f"openid-credential-offer://?credential_offer={quote(json.dumps(offer))}",
        }
    )


class BatchCredentialIssuanceSchema(OpenAPISchema):
    """Batch credential issuance schema."""

    batch_size = fields.Int(
        required=True, metadata={"description": "The maximum array size for the proofs"}
    )


class CredentialIssuerMetadataSchema(OpenAPISchema):
    """Credential issuer metadata schema.

    OpenID4VCI 1.0 § 11.2.1: Credential Issuer Metadata
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2.1
    """

    credential_issuer = fields.Str(
        required=True,
        metadata={
            "description": "The credential issuer identifier. REQUIRED. "
            "URL using the https scheme with no query or fragment component."
        },
    )
    authorization_servers = fields.List(
        fields.Str(),
        required=False,
        metadata={"description": "The authorization server endpoint."},
    )
    credential_endpoint = fields.Str(
        required=True,
        metadata={
            "description": "URL of the Credential Endpoint. REQUIRED. "
            "This URL MUST use the https scheme."
        },
    )
    credential_configurations_supported = fields.Dict(
        required=True,
        metadata={
            "description": "A JSON object containing a list of key-value pairs, "
            "where the key is a string serving as an identifier "
            "of the Credential Configuration, and the value is a JSON object. REQUIRED."
        },
    )
    authorization_servers = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "Array of strings that identify the OAuth 2.0 "
            "Authorization Servers (as defined in [RFC8414]) the Credential "
            "Issuer relies on for authorization. OPTIONAL."
        },
    )
    batch_credential_endpoint = fields.Str(
        required=False,
        metadata={
            "description": "URL of the Batch Credential Endpoint. OPTIONAL. "
            "This URL MUST use the https scheme."
        },
    )
    deferred_credential_endpoint = fields.Str(
        required=False,
        metadata={
            "description": "URL of the Deferred Credential Endpoint. OPTIONAL. "
            "This URL MUST use the https scheme."
        },
    )
    nonce_endpoint = fields.Str(
        required=False,
        metadata={"description": "The nonce endpoint."},
    )
    batch_credential_issuance = fields.Nested(
        BatchCredentialIssuanceSchema,
        required=False,
        metadata={"description": "The batch credential issuance. Currently ignored."},
    )


@docs(tags=["oid4vc"], summary="Get credential issuer metadata")
@response_schema(CredentialIssuerMetadataSchema())
async def credential_issuer_metadata(request: web.Request):
    """Credential issuer metadata endpoint.

    OpenID4VCI 1.0 § 11.2: Credential Issuer Metadata
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2

    The Credential Issuer Metadata contains information on the Credential Issuer's
    technical capabilities, supported Credential types, and (internationalization) data.
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""

        # OID4VCI 1.0 § 11.2.1: credential_configurations_supported is now a JSON object
        # where keys are credential configuration identifiers
        metadata = {
            "credential_issuer": f"{public_url}{subpath}",
            "credential_endpoint": f"{public_url}{subpath}/credential",
        }

        if config.auth_server_url:
            auth_tenant_subpath = get_tenant_subpath(context.profile)
            metadata["authorization_servers"] = [
                f"{config.auth_server_url}{auth_tenant_subpath}"
            ]

        metadata["notification_endpoint"] = f"{public_url}{subpath}/notification"
        metadata["credential_configurations_supported"] = {
            supported.identifier: supported.to_issuer_metadata()
            for supported in credentials_supported
        }

    LOGGER.debug("METADATA: %s", metadata)

    return web.json_response(metadata)


async def credential_issuer_metadata_deprecated(request: web.Request):
    """Deprecated credential issuer metadata endpoint with underscore.

    This endpoint serves the same content as /.well-known/openid-credential-issuer
    but uses the deprecated underscore format for backward compatibility with
    clients that expect the OID4VCI pre-v1.0 naming convention.

    Note: This endpoint is deprecated and not supported by OID4VCI v1.0 protocol.
    Use /.well-known/openid-credential-issuer instead.
    """
    # Get the response from the main function
    response = await credential_issuer_metadata(request)

    # Add deprecation headers
    response.headers["Deprecation"] = "true"
    response.headers["Warning"] = (
        '299 - "This endpoint is deprecated. '
        'Use /.well-known/openid-credential-issuer instead."'
    )
    response.headers[
        "Sunset"
    ] = "Thu, 31 Dec 2026 23:59:59 GMT"  # TODO: Set appropriate sunset date

    return response


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


class GetTokenSchema(OpenAPISchema):
    """Schema for the token endpoint.

    Accept both 'pre-authorized_code' (OID4VCI v1.0) and legacy
    'pre_authorized_code' (underscore) for compatibility by normalizing input.
    """

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        data_key="pre-authorized_code",
        required=True,
        metadata={"description": "", "example": ""},
    )
    user_pin = fields.Str(required=False)

    @pre_load
    def normalize_fields(self, data, **kwargs):
        """Normalize legacy field names to OID4VCI v1.0 keys.

        Accept 'pre_authorized_code' by mapping it to 'pre-authorized_code'.
        """
        # webargs may pass a MultiDictProxy; make a writable copy first
        try:
            mutable = dict(data)
        except Exception:
            mutable = data
        # Map legacy underscore field to the hyphenated v1.0 key if needed
        if "pre_authorized_code" in mutable and "pre-authorized_code" not in mutable:
            mutable["pre-authorized_code"] = mutable.get("pre_authorized_code")
        return mutable


@docs(tags=["oid4vci"], summary="Get credential issuance token")
@form_schema(GetTokenSchema())
async def token(request: web.Request):
    """Token endpoint to exchange pre-authorized codes for access tokens.

    OID4VCI v1.0: This step MUST NOT require DID or verification method.
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    if config.auth_server_url:
        subpath = get_tenant_subpath(context.profile)
        token_url = f"{config.auth_server_url}{subpath}/token"
        raise web.HTTPFound(location=token_url)
    form = await request.post()
    LOGGER.debug("Token request form: %s", dict(form))

    if (form.get("grant_type")) != PRE_AUTHORIZED_CODE_GRANT_TYPE:
        return web.json_response(
            {
                "error": "unsupported_grant_type",
                "error_description": "grant_type not supported",
            },
            status=400,
        )

    # Accept both hyphenated and underscored keys
    pre_authorized_code = form.get("pre-authorized_code") or form.get(
        "pre_authorized_code"
    )
    if not pre_authorized_code or not isinstance(pre_authorized_code, str):
        return web.json_response(
            {
                "error": "invalid_request",
                "error_description": "pre-authorized_code is missing or invalid",
            },
            status=400,
        )

    user_pin = form.get("user_pin")
    try:
        async with context.profile.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_code(
                session, pre_authorized_code
            )
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        return web.json_response(
            {"error": "invalid_grant", "error_description": err.roll_up}, status=400
        )

    if record.pin is not None:
        if user_pin is None:
            return web.json_response(
                {
                    "error": "invalid_request",
                    "error_description": "user_pin is required",
                },
                status=400,
            )
        if user_pin != record.pin:
            return web.json_response(
                {"error": "invalid_grant", "error_description": "pin is invalid"},
                status=400,
            )

    payload = {
        "sub": record.refresh_id,
        "exp": int(time.time()) + EXPIRES_IN,
    }

    # v1 compliance: do not require DID/verification method at token step.
    # Sign with a default did:jwk under this wallet to produce a JWT access token.
    async with context.profile.session() as session:
        try:
            jwk_info = await retrieve_or_create_did_jwk(session)
            vm = f"{jwk_info.did}#0"
            token_jwt = await jwt_sign(
                context.profile,
                headers={"kid": vm, "typ": "JWT"},
                payload=payload,
                verification_method=vm,
            )
        except (WalletNotFoundError, WalletError, ValueError) as err:
            return web.json_response(
                {
                    "error": "server_error",
                    "error_description": f"Unable to sign access token: {str(err)}",
                },
                status=500,
            )

        record.token = token_jwt
        record.nonce = token_urlsafe(NONCE_BYTES)
        await record.save(
            session,
            reason="Created new token",
        )

    return web.json_response(
        {
            "access_token": record.token,
            "token_type": "Bearer",
            "expires_in": EXPIRES_IN,
            "c_nonce": record.nonce,
            "c_nonce_expires_in": EXPIRES_IN,
        }
    )


async def check_token(
    context: AdminRequestContext,
    bearer: Optional[str] = None,
) -> JWTVerifyResult:
    """Validate the OID4VCI token."""
    if not bearer or not bearer.lower().startswith("bearer "):
        raise web.HTTPUnauthorized()
    try:
        scheme, cred = bearer.split(" ", 1)
    except ValueError:
        raise web.HTTPUnauthorized()
    if scheme.lower() != "bearer":
        raise web.HTTPUnauthorized()

    config = Config.from_settings(context.settings)
    profile = context.profile

    if config.auth_server_url:
        subpath = get_tenant_subpath(profile, tenant_prefix="/tenant")
        issuer_server_url = f"{config.endpoint}{subpath}"
        auth_server_url = f"{config.auth_server_url}{get_tenant_subpath(profile)}"
        introspect_endpoint = f"{auth_server_url}/introspect"
        auth_header = await get_auth_header(
            profile, config, issuer_server_url, introspect_endpoint
        )
        resp = await AppResources.get_http_client().post(
            introspect_endpoint,
            data={"token": cred},
            headers={"Authorization": auth_header},
        )
        introspect = await resp.json()
        if not introspect.get("active"):
            raise web.HTTPUnauthorized(reason="invalid_token")
        else:
            result = JWTVerifyResult(headers={}, payload=introspect, verified=True)
            return result

    result = await jwt_verify(context.profile, cred)
    if not result.verified:
        raise web.HTTPUnauthorized(
            text='{"error": "invalid_token", '
            '"error_description": "Token verification failed"}',
            headers={"Content-Type": "application/json"},
        )

    if result.payload["exp"] < datetime.datetime.utcnow().timestamp():
        raise web.HTTPUnauthorized(
            text='{"error": "invalid_token", "error_description": "Token expired"}',
            headers={"Content-Type": "application/json"},
        )

    return result


async def handle_proof_of_posession(
    profile: Profile, proof: Dict[str, Any], c_nonce: str | None = None
):
    """Handle proof of possession.

    OpenID4VCI 1.0 § 7.2.1: Proof of Possession of Key Material
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2.1

    The Credential Request MAY contain a proof of possession of the key material
    the issued Credential shall be bound to. This is REQUIRED for mso_mdoc format.
    """
    # OID4VCI 1.0 § 7.2.1: Support both JWT and CWT proof types
    if "jwt" in proof:
        return await _handle_jwt_proof(profile, proof, c_nonce)
    elif "cwt" in proof:
        return await _handle_cwt_proof(profile, proof, c_nonce)
    else:
        raise web.HTTPBadRequest(
            reason="JWT or CWT proof is required for proof of possession"
        )


async def _handle_jwt_proof(
    profile: Profile, proof: Dict[str, Any], c_nonce: str | None = None
):
    """Handle JWT proof of possession."""
    encoded_headers, encoded_payload, encoded_signature = proof["jwt"].split(".", 3)
    headers = b64_to_dict(encoded_headers)

    # OID4VCI 1.0 § 7.2.1.1: typ MUST be "openid4vci-proof+jwt"
    if headers.get("typ") != "openid4vci-proof+jwt":
        raise web.HTTPBadRequest(
            reason="Invalid proof: typ must be 'openid4vci-proof+jwt' "
            "(OID4VCI 1.0 § 7.2.1.1)"
        )

    # OID4VCI 1.0 § 7.2.1.1: Key material identification
    if "kid" in headers:
        try:
            key = await key_material_for_kid(profile, headers["kid"])
        except ValueError as exc:
            raise web.HTTPBadRequest(reason="Invalid kid") from exc
    elif "jwk" in headers:
        key = Key.from_jwk(headers["jwk"])
    elif "x5c" in headers:
        # OID4VCI 1.0 § 7.2.1.1: X.509 certificate chain support
        raise web.HTTPBadRequest(reason="x5c certificate chains not yet supported")
    else:
        raise web.HTTPBadRequest(
            reason="No key material in proof (kid, jwk, or x5c required)"
        )

    payload = b64_to_dict(encoded_payload)
    nonce = payload.get("nonce")
    if c_nonce:
        if c_nonce != nonce:
            raise web.HTTPBadRequest(reason="Invalid proof: wrong nonce.")
    else:
        redeemed = await Nonce.redeem_by_value(profile.session(), nonce)
        if not redeemed:
            raise web.HTTPBadRequest(reason="Invalid proof: wrong or used nonce.")

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    verified = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
        sig_type=headers.get("alg", ""),
    )
    return PopResult(
        headers,
        payload,
        verified,
        holder_kid=headers.get("kid"),
        holder_jwk=headers.get("jwk"),
    )


async def _handle_cwt_proof(
    profile: Profile, proof: Dict[str, Any], c_nonce: str | None = None
):
    """Handle CWT proof of possession."""
    encoded_cwt = proof.get("cwt")
    if not encoded_cwt:
        raise web.HTTPBadRequest(reason="Missing 'cwt' in proof")

    try:
        # Decode base64url
        cwt_bytes = b64_to_bytes(encoded_cwt, urlsafe=True)
    except Exception:
        raise web.HTTPBadRequest(reason="Invalid base64 encoding for CWT")

    try:
        # Parse COSE message to get headers
        msg = cwt.COSEMessage.loads(cwt_bytes)
    except Exception as e:
        raise web.HTTPBadRequest(reason=f"Invalid CWT format: {e}")

    # Extract headers
    # 4: kid, 1: alg
    kid_bytes = msg.headers.get(4)
    if not kid_bytes:
        kid_bytes = msg.unprotected.get(4)
    
    if not kid_bytes:
        raise web.HTTPBadRequest(reason="Missing 'kid' in CWT header")
        
    kid = kid_bytes.decode("utf-8") if isinstance(kid_bytes, bytes) else str(kid_bytes)

    # Resolve key
    try:
        key = await key_material_for_kid(profile, kid)
    except ValueError as exc:
        raise web.HTTPBadRequest(reason="Invalid kid") from exc

    # Convert key to COSEKey
    try:
        jwk = json.loads(key.get_jwk_public())
        cose_key = cwt.COSEKey.from_jwk(jwk)
        # Ensure kid is set in cose_key if not present
        if not cose_key.kid:
            cose_key.kid = kid_bytes if isinstance(kid_bytes, bytes) else kid.encode()
    except Exception as e:
        raise web.HTTPBadRequest(reason=f"Failed to convert key to COSEKey: {e}")

    # Verify
    try:
        decoded = cwt.decode(cwt_bytes, keys=[cose_key])
    except Exception as e:
        raise web.HTTPBadRequest(reason=f"CWT verification failed: {e}")

    # Check nonce
    # OID4VCI: nonce is claim 10? Or string "nonce"?
    # The spec says "nonce" (string) in JSON, but in CWT it's usually mapped.
    # However, OID4VCI draft 13 says:
    # "The CWT MUST contain the following claims: ... nonce (label: 10)"
    nonce = decoded.get(10)
    if not nonce:
        # Fallback to string key if present (non-standard but possible)
        nonce = decoded.get("nonce")
        
    if not nonce:
        raise web.HTTPBadRequest(reason="Missing nonce in CWT")

    if c_nonce:
        if c_nonce != nonce:
            raise web.HTTPBadRequest(reason="Invalid proof: wrong nonce.")
    else:
        redeemed = await Nonce.redeem_by_value(profile.session(), nonce)
        if not redeemed:
            raise web.HTTPBadRequest(reason="Invalid proof: wrong or used nonce.")

    return PopResult(
        headers=msg.headers,
        payload=decoded,
        verified=True,
        holder_kid=kid,
        holder_jwk=jwk,
    )


def types_are_subset(request: Optional[List[str]], supported: Optional[List[str]]):
    """Compare types."""
    if request is None:
        return False
    if supported is None:
        return False
    return set(request).issubset(set(supported))


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

    try:
        async with context.profile.session() as session:
            ex_record = await OID4VCIExchangeRecord.retrieve_by_refresh_id(
                session, refresh_id=refresh_id
            )
            if not ex_record:
                raise StorageNotFoundError("No exchange record found")
            is_offer = (
                True
                if ex_record.state == OID4VCIExchangeRecord.STATE_OFFER_CREATED
                else False
            )
            supported = await SupportedCredential.retrieve_by_id(
                session, ex_record.supported_cred_id
            )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason="No credential offer available.") from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not supported.format:
        raise web.HTTPBadRequest(
            reason="SupportedCredential missing format identifier."
        )

    if supported.format != body.get("format"):
        raise web.HTTPBadRequest(reason="Requested format does not match offer.")

    authorization_details = token_result.payload.get("authorization_details", None)
    if authorization_details:
        found = any(
            isinstance(ad, dict)
            and ad.get("credential_configuration_id") == supported.identifier
            for ad in authorization_details
        )
        if not found:
            raise web.HTTPBadRequest(
                reason=f"{supported.identifier} is not authorized by the token."
            )

    c_nonce = token_result.payload.get("c_nonce") or ex_record.nonce
    if c_nonce is None:
        raise web.HTTPBadRequest(
            reason="Invalid exchange; no offer created for this request"
        )

    if not credential_identifier and not format_param:
        return web.json_response(
            {
                "message": "Either credential_identifier or format parameter "
                "must be present"
            },
            status=400,
        )

    # Select the supported credential to issue based on the request, if possible.
    # If not found, fall back to the exchange's supported credential.
    async with context.profile.session() as session:
        selected_supported = supported
        if credential_identifier:
            try:
                matches = await SupportedCredential.query(
                    session, tag_filter={"identifier": credential_identifier}
                )
                if matches:
                    selected_supported = matches[0]
            except Exception:
                selected_supported = supported
        elif format_param:
            try:
                matches = await SupportedCredential.query(
                    session, tag_filter={"format": format_param}
                )
                if matches:
                    selected_supported = matches[0]
            except Exception:
                selected_supported = supported

    selected_supported = supported
    if not selected_supported.format:
        return web.json_response(
            {"message": "SupportedCredential missing format identifier"}, status=400
        )

    if c_nonce is None:
        return web.json_response(
            {"message": "Invalid exchange; no offer created for this request"},
            status=400,
        )

    # Ensure format_data exists; derive minimal data for known formats if missing
    if selected_supported.format_data is None:
        if selected_supported.format == "jwt_vc_json":
            derived = {}
            # Try to derive from vc_additional_data if available
            vad = getattr(selected_supported, "vc_additional_data", None)
            if isinstance(vad, dict):
                if "type" in vad:
                    derived["types"] = vad["type"]
                if "@context" in vad:
                    derived["context"] = vad["@context"]
            if derived:
                selected_supported.format_data = derived
            else:
                LOGGER.error(
                    "No format_data for supported credential jwt_vc_json and "
                    "could not derive from vc_additional_data."
                )
                return web.json_response(
                    {
                        "message": "No format_data for supported credential jwt_vc_json",
                    },
                    status=400,
                )
        elif selected_supported.format == "mso_mdoc":
            # For mso_mdoc, derive minimal format_data from request doctype if present
            req_doctype = body.get("doctype")
            if req_doctype:
                selected_supported.format_data = {"doctype": req_doctype}
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
                f"No format_data for supported credential {selected_supported.format}."
            )
            return web.json_response(
                {
                    "message": (
                        "No format_data for supported credential "
                        f"{selected_supported.format}"
                    )
                },
                status=400,
            )

    # OID4VCI 1.0 § 7.2.1: Proof of possession handling
    # - For mso_mdoc: proof is REQUIRED, but we currently do not parse CWT in detail.
    # - For jwt_vc_json: proof MAY be provided. When a JWT is present, enforce
    #   full OID4VCI v1.0 verification (typ, nonce, and signature).
    from .pop_result import PopResult as _PopResult

    proof_obj = body.get("proof")
    pop = None  # type: Optional[_PopResult]

    if selected_supported.format == "mso_mdoc":
        # Require a proof object for mso_mdoc
        if not isinstance(proof_obj, dict):
            return web.json_response(
                {"message": "proof is required for mso_mdoc"}, status=400
            )
        # Accept either JWT (with proper typ) or CWT placeholder without deep verification
        if "jwt" in proof_obj:
            # Strictly verify the JWT proof (typ, nonce, signature)
            try:
                pop = await handle_proof_of_posession(
                    context.profile, proof_obj, c_nonce
                )
            except web.HTTPBadRequest as exc:
                return web.json_response({"message": exc.reason}, status=400)
        elif "cwt" in proof_obj or proof_obj.get("proof_type") == "cwt":
            # Strictly verify the CWT proof
            try:
                pop = await handle_proof_of_posession(
                    context.profile, proof_obj, c_nonce
                )
            except web.HTTPBadRequest as exc:
                return web.json_response({"message": exc.reason}, status=400)
        else:
            return web.json_response({"message": "Unsupported proof type"}, status=400)
    else:
        # jwt_vc_json and other formats: proof is optional.
        if isinstance(proof_obj, dict) and "jwt" in proof_obj:
            # Strictly verify the JWT proof (typ, nonce, signature)
            try:
                pop = await handle_proof_of_posession(
                    context.profile, proof_obj, c_nonce
                )
            except web.HTTPBadRequest as exc:
                return web.json_response({"message": exc.reason}, status=400)
        # If no proof or no holder key material, fall back to using the exchange's
        # verification method
        if pop is None:
            pop = _PopResult(
                headers={},
                payload={},
                verified=True,
                holder_kid=ex_record.verification_method,
                holder_jwk=None,
            )

    try:
        processors = context.inject(CredProcessors)
        processor = processors.issuer_for_format(selected_supported.format)

        credential = await processor.issue(
            body, selected_supported, ex_record, pop, context
        )
    except CredProcessorError as e:
        # Ensure the underlying error text is returned for debugging
        return web.json_response({"message": str(e)}, status=400)
    except Exception as e:  # Ensure JSON error body for unexpected failures
        LOGGER.exception("Unexpected error during credential issuance")
        return web.json_response({"message": str(e)}, status=500)

    async with context.session() as session:
        ex_record.state = OID4VCIExchangeRecord.STATE_ISSUED
        # Cause webhook to be emitted
        await ex_record.save(session, reason="Credential issued")
        # Exchange is completed, record can be cleaned up
        # But we'll leave it to the controller
        # await ex_record.delete_record(session)

    cred_response = {
        "format": supported.format,
        "credential": credential,
        "notification_id": ex_record.notification_id,
    }
    if is_offer:
        cred_response["refresh_id"] = ex_record.refresh_id

    return web.json_response(cred_response)


class OID4VPRequestIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking request id."""

    request_id = fields.Str(
        required=True,
        metadata={
            "description": "OID4VP Request identifier",
        },
    )


async def _retrieve_default_did(session: ProfileSession) -> Optional[DIDInfo]:
    """Retrieve default DID from the store.

    Args:
        session: An active profile session

    Returns:
        Optional[DIDInfo]: retrieved DID info or None if not found

    """
    storage = session.inject(BaseStorage)
    wallet = session.inject(BaseWallet)
    try:
        record = await storage.get_record(
            record_type="OID4VP.default",
            record_id="OID4VP.default",
        )
        info = json.loads(record.value)
        info.update(record.tags)
        did_info = await wallet.get_local_did(record.tags["did"])

        return did_info
    except StorageNotFoundError:
        return None


async def _create_default_did(session: ProfileSession) -> DIDInfo:
    """Create default DID.

    Args:
        session: An active profile session

    Returns:
        DIDInfo: created default DID info

    """
    wallet = session.inject(BaseWallet)
    storage = session.inject(BaseStorage)
    key = await wallet.create_key(ED25519)
    jwk = json.loads(
        Key.from_public_bytes(KeyAlg.ED25519, b58decode(key.verkey)).get_jwk_public()
    )
    jwk["use"] = "sig"
    jwk = json.dumps(jwk)

    did_jwk = f"did:jwk:{bytes_to_b64(jwk.encode(), urlsafe=True, pad=False)}"

    did_info = DIDInfo(did_jwk, key.verkey, {}, DID_JWK, ED25519)
    info = await wallet.store_did(did_info)

    record = StorageRecord(
        type="OID4VP.default",
        value=json.dumps({"verkey": info.verkey, "metadata": info.metadata}),
        tags={"did": info.did},
        id="OID4VP.default",
    )
    await storage.add_record(record)
    return info


async def retrieve_or_create_did_jwk(session: ProfileSession):
    """Retrieve default did:jwk info, or create it."""

    key = await _retrieve_default_did(session)
    if key:
        return key

    return await _create_default_did(session)


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
    payload = {
        "iss": jwk.did,
        "sub": jwk.did,
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": str(uuid.uuid4()),
        "client_id": config.endpoint,
        "response_uri": (
            f"{config.endpoint}{subpath}/oid4vp/response/{pres.presentation_id}"
        ),
        "state": pres.presentation_id,
        "nonce": pres.nonce,
        "id_token_signing_alg_values_supported": ["ES256", "EdDSA"],
        "request_object_signing_alg_values_supported": ["ES256", "EdDSA"],
        "response_types_supported": ["id_token", "vp_token"],
        "scopes_supported": ["openid", "vp_token"],
        "subject_types_supported": ["pairwise"],
        "subject_syntax_types_supported": ["urn:ietf:params:oauth:jwk-thumbprint"],
        "vp_formats": record.vp_formats,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "scope": "vp_token",
    }
    if pres_def is not None:
        payload["presentation_definition"] = pres_def.pres_def
    if dcql_query is not None:
        payload["dcql_query"] = dcql_query.record_value

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

    return web.Response(text=token)


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
    vp_token: Dict[str, Any],
    dcql_query_id: str,
    presentation: OID4VPPresentation,
):
    """Verify a received presentation."""

    LOGGER.debug("Got: %s", vp_token)

    async with profile.session() as session:
        pres_def_entry = await DCQLQuery.retrieve_by_id(
            session,
            dcql_query_id,
        )

        dcql_query = DCQLQuery.deserialize(pres_def_entry)

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
    """Verify a received presentation."""

    LOGGER.debug("Got: %s %s", submission, vp_token)

    processors = profile.inject(CredProcessors)
    if not submission.descriptor_maps:
        raise web.HTTPBadRequest(
            reason="Descriptor map of submission must not be empty"
        )

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

    async with profile.session() as session:
        pres_def_entry = await OID4VPPresDef.retrieve_by_id(
            session,
            pres_def_id,
        )

        pres_def = PresentationDefinition.deserialize(pres_def_entry.pres_def)

    evaluator = PresentationExchangeEvaluator.compile(pres_def)
    result = await evaluator.verify(profile, submission, vp_result.payload)
    return result


@docs(tags=["oid4vp"], summary="Provide OID4VP presentation")
@match_info_schema(OID4VPPresentationIDMatchSchema())
@form_schema(PostOID4VPResponseSchema())
async def post_response(request: web.Request):
    """Post an OID4VP Response."""
    context: AdminRequestContext = request["context"]
    presentation_id = request.match_info["presentation_id"]

    form = await request.post()

    raw_submission = form.get("presentation_submission")
    assert isinstance(raw_submission, str)
    presentation_submission = PresentationSubmission.from_json(raw_submission)

    vp_token = form.get("vp_token")
    state = form.get("state")

    if state and state != presentation_id:
        raise web.HTTPBadRequest(reason="`state` must match the presentation id")

    async with context.session() as session:
        record = await OID4VPPresentation.retrieve_by_id(session, presentation_id)

    try:
        assert isinstance(vp_token, str)

        if record.pres_def_id:
            verify_result = await verify_pres_def_presentation(
                profile=context.profile,
                submission=presentation_submission,
                vp_token=vp_token,
                pres_def_id=record.pres_def_id,
                presentation=record,
            )
        elif record.dcql_query_id:
            verify_result = await verify_dcql_presentation(
                profile=context.profile,
                vp_token=json.loads(vp_token),
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
    return web.Response(status=200)


class StatusListMatchSchema(OpenAPISchema):
    """Path parameters and validators for status list request."""

    list_number = fields.Str(
        required=True,
        metadata={
            "description": "Status list number",
        },
    )


@docs(tags=["status-list"], summary="Get status list by list number")
@match_info_schema(StatusListMatchSchema())
async def get_status_list(request: web.Request):
    """Get status list."""

    context: AdminRequestContext = request["context"]
    list_number = request.match_info["list_number"]

    status_handler = context.inject_or(StatusHandler)
    if status_handler:
        status_list = await status_handler.get_status_list(context, list_number)
        return web.Response(text=status_list)
    raise web.HTTPNotFound(reason="Status handler not available")


async def register(app: web.Application, multitenant: bool, context: InjectionContext):
    """Register routes with support for multitenant mode.

    Adds the subpath with Wallet ID as a path parameter if multitenant is True.
    """
    subpath = "/tenant/{wallet_id}" if multitenant else ""
    routes = [
        web.get(
            f"{subpath}/oid4vci/dereference-credential-offer",
            dereference_cred_offer,
            allow_head=False,
        ),
        web.get(
            f"{subpath}/.well-known/openid-credential-issuer",
            credential_issuer_metadata,
            allow_head=False,
        ),
        # TODO Add .well-known/did-configuration.json
        # Spec: https://identity.foundation/.well-known/resources/did-configuration/
        web.post(f"{subpath}/token", token),
        web.post(f"{subpath}/notification", receive_notification),
        web.post(f"{subpath}/credential", issue_cred),
        web.get(f"{subpath}/oid4vp/request/{{request_id}}", get_request),
        web.post(f"{subpath}/oid4vp/response/{{presentation_id}}", post_response),
    ]
    # Conditionally add status route
    if context.inject_or(StatusHandler):
        routes.append(
            web.get(
                f"{subpath}/status/{{list_number}}", get_status_list, allow_head=False
            )
        )
    # Add the routes to the application
    app.add_routes(routes)
