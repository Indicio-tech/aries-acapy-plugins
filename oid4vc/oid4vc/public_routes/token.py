"""Token endpoint for OID4VCI."""

import base64
import datetime
import hashlib
import hmac
import json
import time
from datetime import UTC
from typing import Any, Dict
from urllib.parse import urlparse

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageDuplicateError, StorageError, StorageNotFoundError
from acapy_agent.wallet.base import WalletError
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.util import b64_to_bytes
from aiohttp import web
from aiohttp_apispec import docs, form_schema
from aries_askar import Key
from marshmallow import fields, pre_load

from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.jwt import (
    JWTVerifyResult,
    jwt_sign,
    jwt_verify,
    key_from_x5c,
    key_material_for_kid,
)

from ..app_resources import AppResources
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.nonce import Nonce
from ..pop_result import PopResult
from ..utils import get_auth_header, get_tenant_subpath
from .constants import (
    DPOP_PROOF_MAX_AGE_SECONDS,
    EXPIRES_IN,
    LOGGER,
    NONCE_BYTES,
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
)
from .nonce import create_nonce


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
    def normalize_fields(self, data, **_kwargs):
        """Normalize legacy field names to OID4VCI v1.0 keys.

        Accept 'pre_authorized_code' by mapping it to 'pre-authorized_code'.
        """
        # webargs may pass a MultiDictProxy; make a writable copy first
        try:
            mutable = dict(data)
        except (TypeError, ValueError):
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

    # Accept both legacy user_pin and OID4VCI 1.0 final tx_code in token requests.
    user_pin = form.get("tx_code") or form.get("user_pin")
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
        if not hmac.compare_digest(user_pin, record.pin):
            return web.json_response(
                {"error": "invalid_grant", "error_description": "pin is invalid"},
                status=400,
            )

    # Check if pre-authorized code has already been used
    if record.token is not None:
        return web.json_response(
            {
                "error": "invalid_grant",
                "error_description": "pre-authorized code has already been used",
            },
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
        await record.save(
            session,
            reason="Created new token",
        )

    # Create a nonce for the wallet to use in its credential proof.
    # The /nonce endpoint also serves nonces (OID4VCI 1.0 §8); both are valid.
    c_nonce_record = await create_nonce(context.profile, NONCE_BYTES, EXPIRES_IN)

    return web.json_response(
        {
            "access_token": record.token,
            "token_type": "Bearer",
            "expires_in": EXPIRES_IN,
            "c_nonce": c_nonce_record.nonce_value,
            "c_nonce_expires_in": EXPIRES_IN,
        }
    )


async def _verify_dpop_proof(
    profile: Profile,
    dpop_proof: str,
    access_token: str,
    method: str,
    url: str,
) -> None:
    """Verify a DPoP proof JWT per RFC 9449 §4.3.

    Raises ``web.HTTPUnauthorized`` with a descriptive reason if any check
    fails.  On success returns ``None``.
    """

    # --- 1. Parse header and payload (before signature verification) ---
    try:
        parts = dpop_proof.split(".", 2)
        if len(parts) != 3:
            raise ValueError("wrong number of JWT parts")
        dpop_headers = b64_to_dict(parts[0])
        dpop_payload = b64_to_dict(parts[1])
    except Exception:
        raise web.HTTPUnauthorized(reason="invalid DPoP proof: malformed JWT")

    # --- 2. typ MUST be "dpop+jwt" (RFC 9449 §4.2) ---
    if dpop_headers.get("typ", "").lower() != "dpop+jwt":
        raise web.HTTPUnauthorized(
            reason=(
                f"DPoP proof typ must be 'dpop+jwt', got {dpop_headers.get('typ')!r}"
            )
        )

    # --- 3. alg MUST be an asymmetric algorithm (not 'none') ---
    alg = dpop_headers.get("alg", "")
    if not alg or alg.lower() == "none":
        raise web.HTTPUnauthorized(
            reason="DPoP proof alg must be a non-trivial asymmetric algorithm"
        )

    # --- 4. Embedded public key in jwk header claim is mandatory (RFC 9449 §4.2) ---
    jwk_header = dpop_headers.get("jwk")
    if not jwk_header:
        raise web.HTTPUnauthorized(
            reason="DPoP proof must include the public key as a 'jwk' header claim"
        )
    try:
        dpop_key = Key.from_jwk(jwk_header)
    except Exception:
        raise web.HTTPUnauthorized(
            reason="DPoP proof 'jwk' header claim is not a valid JWK"
        )

    # --- 5. Verify signature using the embedded key ---
    try:
        sig_bytes = b64_to_bytes(parts[2], urlsafe=True)
        signature_ok = dpop_key.verify_signature(
            f"{parts[0]}.{parts[1]}".encode(),
            sig_bytes,
            sig_type=alg,
        )
    except Exception:
        signature_ok = False
    if not signature_ok:
        raise web.HTTPUnauthorized(
            reason="DPoP proof signature verification failed"
        )

    # --- 6. htm MUST match the request HTTP method (RFC 9449 §4.3) ---
    htm = dpop_payload.get("htm", "")
    if htm.upper() != method.upper():
        raise web.HTTPUnauthorized(
            reason=f"DPoP proof htm '{htm}' does not match request method '{method}'"
        )

    # --- 7. htu MUST match the request URI (scheme + host + path, no query/fragment) ---
    htu = dpop_payload.get("htu", "")
    try:
        htu_parsed = urlparse(htu)
        url_parsed = urlparse(url)
        # RFC 9449 §4.3: compare without query string or fragment
        htu_base = f"{htu_parsed.scheme}://{htu_parsed.netloc}{htu_parsed.path}".rstrip("/")
        url_base = f"{url_parsed.scheme}://{url_parsed.netloc}{url_parsed.path}".rstrip("/")
    except Exception:
        raise web.HTTPUnauthorized(reason="DPoP proof htu claim is invalid")
    if htu_base != url_base:
        raise web.HTTPUnauthorized(
            reason=f"DPoP proof htu '{htu_base}' does not match request URL '{url_base}'"
        )

    # --- 8. ath MUST be BASE64URL(SHA-256(ASCII(access_token))) (RFC 9449 §4.2) ---
    ath = dpop_payload.get("ath", "")
    expected_ath = (
        base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )
    if ath != expected_ath:
        raise web.HTTPUnauthorized(
            reason="DPoP proof ath claim does not match the access token hash"
        )

    # --- 9. iat must be within the acceptable clock-skew window ---
    iat = dpop_payload.get("iat")
    now = int(time.time())
    if iat is None or abs(now - iat) > DPOP_PROOF_MAX_AGE_SECONDS:
        raise web.HTTPUnauthorized(
            reason="DPoP proof iat is missing or outside the acceptable time window"
        )

    # --- 10. jti replay protection: reject a jti that was already used ---
    jti = dpop_payload.get("jti")
    if not jti:
        raise web.HTTPUnauthorized(reason="DPoP proof jti claim is required")

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        try:
            await storage.add_record(
                StorageRecord(
                    type="oid4vc.dpop_jti",
                    value=str(iat),
                    id=jti,
                )
            )
        except StorageDuplicateError:
            raise web.HTTPUnauthorized(
                reason="DPoP proof jti has already been used (replay detected)"
            )


async def check_token(
    context: AdminRequestContext,
    bearer: str | None = None,
    dpop_header: str | None = None,
    method: str | None = None,
    url: str | None = None,
) -> JWTVerifyResult:
    """Validate the OID4VCI token and (when present) the DPoP proof.

    Accepts both ``Bearer`` and ``DPoP`` Authorization schemes.  When the
    scheme is ``DPoP`` the caller SHOULD supply the ``dpop_header``,
    ``method``, and ``url`` arguments so the DPoP proof can be fully
    verified per RFC 9449 §4.3.  If they are omitted the DPoP proof is
    accepted without cryptographic binding (backward-compat only).
    """
    if not bearer:
        raise web.HTTPUnauthorized()
    try:
        scheme, cred = bearer.split(" ", 1)
    except ValueError:
        raise web.HTTPUnauthorized() from None
    if scheme.lower() not in ("bearer", "dpop"):
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

    if result.payload["exp"] < datetime.datetime.now(UTC).timestamp():
        raise web.HTTPUnauthorized(
            text='{"error": "invalid_token", "error_description": "Token expired"}',
            headers={"Content-Type": "application/json"},
        )

    # DPoP binding check (RFC 9449 §4.3): when the client presented a DPoP-bound
    # access token and supplied a DPoP proof, verify the proof against the token.
    if scheme.lower() == "dpop":
        if dpop_header and method and url:
            await _verify_dpop_proof(
                context.profile,
                dpop_proof=dpop_header,
                access_token=cred,
                method=method,
                url=url,
            )
        else:
            LOGGER.debug(
                "DPoP scheme used but dpop_header/method/url not supplied; "
                "skipping DPoP proof binding check (backward-compat mode)"
            )

    return result


async def handle_proof_of_posession(
    profile: Profile, proof: Dict[str, Any], c_nonce: str | None = None
):
    """Handle proof of posession."""
    encoded_headers, encoded_payload, encoded_signature = proof["jwt"].split(".", 3)
    headers = b64_to_dict(encoded_headers)

    # OID4VCI 1.0 requires typ="openid4vci-proof+jwt"
    # But accept common draft spec values for backward compatibility
    typ = headers.get("typ")
    valid_typ_values = ["openid4vci-proof+jwt", "JWT", "jwt", "openid4vci-jwt"]
    if typ and typ not in valid_typ_values:
        LOGGER.warning("Proof JWT has unexpected typ header: %s", typ)
        raise web.HTTPBadRequest(
            text=json.dumps(
                {
                    "error": "invalid_proof",
                    "error_description": f"unsupported typ: {typ}",
                }
            ),
            content_type="application/json",
        )

    if "jwk" in headers:
        # Prefer inline JWK over kid-based DID resolution (OID4VCI spec §7.2.1).
        # Wallets such as walt.id send both kid and jwk in the proof header;
        # resolving the kid as a DID URL fails when the key is not registered in
        # a resolvable DID document, causing a spurious "invalid kid in proof".
        key = Key.from_jwk(headers["jwk"])
    elif "kid" in headers:
        try:
            key = await key_material_for_kid(profile, headers["kid"])
        except ValueError as exc:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "invalid kid in proof",
                    }
                ),
                content_type="application/json",
            ) from exc
    elif "x5c" in headers:
        # OID4VCI 1.0: wallet may use x5c (certificate-based) key binding.
        # Extract the public key from the leaf cert for signature verification.
        try:
            key = key_from_x5c(headers["x5c"])
        except Exception as exc:
            LOGGER.debug("Failed to extract key from x5c cert chain: %s", exc)
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "invalid x5c certificate in proof header",
                    }
                ),
                content_type="application/json",
            ) from exc
    else:
        # No key material in the header. Some draft-era wallets (e.g. walt.id)
        # omit jwk/kid/x5c from the proof header and instead put the DID in the
        # payload `iss` claim. Decode the payload first and attempt resolution.
        payload_for_iss = b64_to_dict(encoded_payload)
        iss = payload_for_iss.get("iss")
        if iss:
            # key_material_for_kid expects a DID URL (with fragment), not a bare
            # DID.  For did:jwk and did:key the first verification method is #0.
            kid_url = iss if "#" in iss else f"{iss}#0"
            try:
                key = await key_material_for_kid(profile, kid_url)
                LOGGER.debug("Resolved proof key from payload iss: %s", iss)
            except (ValueError, Exception) as exc:
                LOGGER.debug("Could not resolve key from iss '%s': %s", iss, exc)
                raise web.HTTPBadRequest(
                    text=json.dumps(
                        {
                            "error": "invalid_proof",
                            "error_description": "no key material in proof header and"
                            " iss could not be resolved",
                        }
                    ),
                    content_type="application/json",
                ) from exc
        else:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "no key material in proof header",
                    }
                ),
                content_type="application/json",
            )

    payload = b64_to_dict(encoded_payload)

    # OID4VCI 1.0 § 7.2.2: the proof JWT MUST contain an `aud` claim equal to
    # the Credential Issuer Identifier (the issuer's base URL).  Omitting this
    # check allows proof replay across issuers.
    aud = payload.get("aud")
    if aud is not None:
        issuer_endpoint = Config.from_settings(profile.settings).endpoint
        # aud may be a string or a list of strings (per RFC 7519 § 4.1.3)
        aud_values = [aud] if isinstance(aud, str) else list(aud)

        def _strip_default_port(url: str) -> str:
            """Remove explicit default ports (https:443, http:80) for comparison."""
            try:
                p = urlparse(url)
                if (p.scheme == "https" and p.port == 443) or (
                    p.scheme == "http" and p.port == 80
                ):
                    netloc = p.hostname or ""
                    return p._replace(netloc=netloc).geturl()
            except Exception:
                pass
            return url

        norm_endpoint = _strip_default_port(issuer_endpoint) if issuer_endpoint else ""
        if issuer_endpoint and not any(
            _strip_default_port(av) == norm_endpoint
            or _strip_default_port(av).startswith(norm_endpoint + "/tenant/")
            for av in aud_values
        ):
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": (
                            f"proof JWT aud '{aud}' does not match "
                            f"issuer endpoint '{issuer_endpoint}'"
                        ),
                    }
                ),
                content_type="application/json",
            )

    # OID4VCI 1.0 final spec uses "nonce"; older draft wallets may use "c_nonce".
    nonce = payload.get("nonce") or payload.get("c_nonce")
    if c_nonce:
        if c_nonce != nonce:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "nonce mismatch",
                    }
                ),
                content_type="application/json",
            )
    else:
        # OID4VCI 1.0: nonce was obtained from the /nonce endpoint.
        # Open a session to redeem it (marks it used for replay protection).
        async with profile.session() as session:
            redeemed = await Nonce.redeem_by_value(session, nonce)
        if not redeemed:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "invalid or already-used nonce",
                    }
                ),
                content_type="application/json",
            )

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    verified = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
        sig_type=headers.get("alg", ""),
    )

    # If the wallet sent a kid-based proof (no jwk in header), derive the public
    # JWK from the resolved key so credential processors that need the raw JWK
    # (e.g. mso_mdoc for holder key binding in DeviceKey) can access it.
    holder_jwk = headers.get("jwk")
    if holder_jwk is None and (
        "kid" in headers or not any(k in headers for k in ("jwk", "kid", "x5c"))
    ):
        try:
            holder_jwk = json.loads(key.get_jwk_public())
        except Exception:
            LOGGER.debug("Could not derive holder JWK from resolved key")

    return PopResult(
        headers,
        payload,
        verified,
        holder_kid=headers.get("kid"),
        holder_jwk=holder_jwk,
        holder_x5c=headers.get("x5c"),
    )
