"""Proof of possession handlers for OID4VCI."""

import json
from typing import Any, Dict

import cwt
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.util import b64_to_bytes
from aiohttp import web
from aries_askar import Key

from oid4vc.jwt import key_material_for_kid

from ..models.nonce import Nonce
from ..pop_result import PopResult


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
    try:
        encoded_headers, encoded_payload, encoded_signature = proof["jwt"].split(".", 3)
    except ValueError:
        raise web.HTTPBadRequest(reason="Invalid JWT format")

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

    if not verified:
        raise web.HTTPBadRequest(reason="Proof verification failed: invalid signature")

    holder_jwk = headers.get("jwk")
    if not holder_jwk:
        holder_jwk = json.loads(key.get_jwk_public())

    return PopResult(
        headers,
        payload,
        verified,
        holder_kid=headers.get("kid"),
        holder_jwk=holder_jwk,
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
    kid_bytes = msg.protected.get(4)
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
        # Ensure kid is set in JWK so it propagates to COSEKey
        if "kid" not in jwk:
            jwk["kid"] = kid
        cose_key = cwt.COSEKey.from_jwk(jwk)
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

    # Combine protected and unprotected headers
    headers = {}
    if msg.protected:
        headers.update(msg.protected)
    if msg.unprotected:
        headers.update(msg.unprotected)

    return PopResult(
        headers=headers,
        payload=decoded,
        verified=True,
        holder_kid=kid,
        holder_jwk=jwk,
    )
