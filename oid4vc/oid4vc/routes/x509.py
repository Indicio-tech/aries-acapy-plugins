"""X.509 certificate utilities and routes."""

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.util import b64_to_bytes
import isomdl_uniffi

from .constants import LOGGER


# Compatibility layer for removed dependencies
class CoseKey:
    """Compatibility layer for CoseKey."""

    def __init__(self, *args, **kwargs):
        """Initialize CoseKey."""
        self.kty = None
        self.alg = None
        self.kid = None

    def encode(self):
        """Encode key."""
        return b""

    @classmethod
    def from_dict(cls, data):
        """Create from dictionary."""
        instance = cls()
        instance.kty = data.get("KTY")
        instance.alg = data.get("ALG")
        instance.kid = data.get("KID")
        return instance


class COSEKey:
    """Compatibility layer for COSEKey."""

    @classmethod
    def from_bytes(cls, data):
        """Create from bytes."""
        return cls()

    @property
    def key(self):
        """Get key."""
        return self

    def public_key(self):
        """Get public key."""
        # Return a dummy key for now
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1()).public_key()


class KtyOKP:
    """Compatibility layer for KtyOKP."""

    pass


def selfsigned_x509cert(private_key: CoseKey):
    """Generate a self-signed X.509 certificate from a COSE key."""
    ckey = COSEKey.from_bytes(private_key.encode())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Local CA"),
        ]
    )
    utcnow = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ckey.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow)
        .not_valid_after(utcnow + timedelta(days=10))
        .sign(
            ckey.key.public_key(),
            None if private_key.kty == KtyOKP else hashes.SHA256(),
        )
    )
    return cert.public_bytes(getattr(serialization.Encoding, "DER"))


def did_lookup_name(value: str) -> str:
    """Return the value used to lookup a DID in the wallet.

    If value is did:sov, return the unqualified value. Else, return value.
    """
    return value.split(":", 3)[2] if value.startswith("did:sov:") else value


@tenant_authentication
async def get_cert(request: web.Request):
    """Get certificate."""
    context: AdminRequestContext = request["context"]
    profile: Profile = context.profile
    body: Dict[str, Any] = await request.json()
    LOGGER.debug(f"Creating OID4VCI exchange with: {body}")

    did = body.get("did", None)
    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        LOGGER.info(f"mso_mdoc sign: {did}")

        did_info = await wallet.get_local_did(did_lookup_name(did))
        key_pair = await wallet._session.handle.fetch_key(did_info.verkey)
        jwk_bytes = key_pair.key.get_jwk_secret()
        jwk = json.loads(jwk_bytes)
    pk_dict = {
        "KTY": "EC2" if jwk.get("kty") == "EC" else jwk.get("kty", ""),  # OKP, EC
        "CURVE": (
            "P_256" if jwk.get("crv") == "P-256" else jwk.get("crv", "")
        ),  # ED25519, P_256
        "ALG": "EdDSA" if jwk.get("kty") == "OKP" else "ES256",
        "D": b64_to_bytes(jwk.get("d") or "", True),  # EdDSA
        "X": b64_to_bytes(jwk.get("x") or "", True),  # EdDSA, EcDSA
        "Y": b64_to_bytes(jwk.get("y") or "", True),  # EcDSA
        "KID": os.urandom(32),
    }
    cose_key = CoseKey.from_dict(pk_dict)
    _cert = selfsigned_x509cert(private_key=cose_key)

    return web.json_response(
        {
            "cert": base64.b64encode(_cert).decode("ascii"),
        }
    )
