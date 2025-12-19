"""Utility functions for OID4VCI plugin."""

import argparse
import json
import secrets
import sys
from types import SimpleNamespace
from typing import Dict

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.util import datetime_now
from acapy_agent.storage.error import StorageError
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b64, str_to_b64
from aiohttp import web

from oid4vc.config import Config
from oid4vc.jwt import jwt_sign

EXPIRES_IN = 300
CODE_BYTES = 16


def get_tenant_subpath(profile: Profile, tenant_prefix: str = "/tenants") -> str:
    """Get the tenant path for the current wallet, if any."""

    wallet_id = (
        profile.settings.get("wallet.id")
        if profile.settings.get("multitenant.enabled")
        else None
    )
    tenant_subpath = f"{tenant_prefix}/{wallet_id}" if wallet_id else ""
    return tenant_subpath


def verkey_to_jwk(verkey: str) -> Dict:
    """Convert a base58 verkey (Ed25519) to a JWK dict."""

    key_bytes = b58_to_bytes(verkey)
    x = bytes_to_b64(key_bytes)
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    }
    return jwk


async def get_auth_header(
    profile: Profile, config: Config, issuer: str, audience: str
) -> str:
    """Create a JWT auth token for the given type and verification method."""

    if not config.auth_server_client:
        raise ValueError("auth_server_client setting is required.")

    auth_client = json.loads(
        config.auth_server_client, object_hook=lambda d: SimpleNamespace(**d)
    )

    if auth_client.auth_type == "client_secret_basic":
        cred = f"{auth_client.client_id}:{auth_client.client_secret}"
        b64_cred = str_to_b64(cred)
        auth_header = f"Basic {b64_cred}"

    elif auth_client.auth_type == "private_key_jwt":
        utcnow = datetime_now()
        payload = {
            "iss": f"{issuer}",
            "sub": f"{auth_client.client_id}",
            "aud": f"{audience}",
            "iat": int(utcnow.timestamp()),
            "exp": int(utcnow.timestamp()) + EXPIRES_IN,
        }
        headers = {}
        token = await jwt_sign(
            profile,
            headers,
            payload,
            did=getattr(auth_client, "did", None),
            verification_method=getattr(auth_client, "verification_method", None),
        )
        auth_header = f"Bearer {token}"

    else:
        auth_header = ""

    return auth_header


async def _create_pre_auth_code(
    profile: Profile,
    config: Config,
    subject_id: str,
    credential_configuration_id: str | None = None,
    user_pin: str | None = None,
) -> str:
    """Create a secure random pre-authorized code."""
    from .app_resources import AppResources

    if config.auth_server_url:
        subpath = get_tenant_subpath(profile, tenant_prefix="/tenant")
        issuer_server_url = f"{config.endpoint}{subpath}"

        auth_server_url = f"{config.auth_server_url}{get_tenant_subpath(profile)}"
        grants_endpoint = f"{auth_server_url}/grants/pre-authorized-code"

        auth_header = await get_auth_header(
            profile, config, issuer_server_url, grants_endpoint
        )
        user_pin_required = user_pin is not None
        resp = await AppResources.get_http_client().post(
            grants_endpoint,
            json={
                "subject_id": subject_id,
                "user_pin_required": user_pin_required,
                "user_pin": user_pin,
                "authorization_details": [
                    {
                        "type": "openid_credential",
                        "credential_configuration_id": credential_configuration_id,
                    }
                ],
            },
            headers={"Authorization": f"{auth_header}"},
        )
        data = await resp.json()
        code = data["pre_authorized_code"]
    else:
        code = secrets.token_urlsafe(CODE_BYTES)
    return code


async def _parse_cred_offer(context: AdminRequestContext, exchange_id: str) -> dict:
    """Helper function for cred_offer request parsing.

    Used in get_cred_offer and public_routes.dereference_cred_offer endpoints.
    """
    from .models.exchange import OID4VCIExchangeRecord
    from .models.supported_cred import SupportedCredential

    config = Config.from_settings(context.settings)
    try:
        async with context.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            supported = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )
            record.code = await _create_pre_auth_code(
                context.profile,
                config,
                record.refresh_id,
                supported.identifier,
                record.pin,
            )
            record.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
            await record.save(session, reason="Credential offer created")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    user_pin_required: bool = record.pin is not None
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    return {
        "credential_issuer": f"{config.endpoint}{subpath}",
        "credential_configuration_ids": [supported.identifier],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": record.code,
                "user_pin_required": user_pin_required,
            }
        },
    }


async def supported_cred_is_unique(identifier: str, profile: Profile) -> bool:
    """Check whether a record exists with a given identifier."""
    from .models.supported_cred import SupportedCredential

    async with profile.session() as session:
        records = await SupportedCredential.query(
            session, tag_filter={"identifier": identifier}
        )

    if len(records) > 0:
        return False
    return True


if __name__ == "__main__":
    """Run as script to convert base58 verkey to JWK."""
    parser = argparse.ArgumentParser(description="Convert base58 verkey to JWK.")
    parser.add_argument("verkey", help="Base58-encoded Ed25519 public key")
    args = parser.parse_args()

    jwk = verkey_to_jwk(args.verkey)
    jwks = {"keys": [jwk]}
    sys.stdout.write(json.dumps(jwks))
    sys.stdout.write("\n")
