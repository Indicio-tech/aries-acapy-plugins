"""JWT utilities."""
import logging
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import ResolverError
from acapy_agent.resolver.did_resolver import DIDResolver, DIDUrl
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.jwt import (
    BadJWSHeaderError,
    BaseVerificationKeyStrategy,
    b64_to_bytes,
    b64_to_dict,
    dict_to_b64,
    did_lookup_name,
    nym_to_did,
)
from acapy_agent.wallet.key_type import ED25519, P256, KeyTypes
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b64
from aries_askar import Key, KeyAlg

LOGGER = logging.getLogger(__name__)


@dataclass
class JWTVerifyResult:
    """JWT Verification Result."""

    def __init__(
        self,
        headers: Mapping[str, Any],
        payload: Mapping[str, Any],
        verified: bool,
    ):
        """Initialize a JWTVerifyResult instance."""
        self.headers = headers
        self.payload = payload
        self.verified = verified


async def key_material_for_kid(profile: Profile, kid: str):
    """Resolve key material for a kid."""
    try:
        LOGGER.info("Resolving key material for kid: %s", kid)
        # DIDUrl(kid) # This line seems useless and might be causing issues

        resolver = profile.inject(DIDResolver)
        vm = None
        try:
            vm = await resolver.dereference_verification_method(profile, kid)
        except (ValueError, ResolverError):
            # If kid is a DID, try to resolve it and get the first verification method
            LOGGER.info(
                "dereference_verification_method failed for %s, trying to resolve as DID",
                kid,
            )
            try:
                did_doc_dict = await resolver.resolve(profile, kid)
                # We assume the first verification method is the one we want
                # if no fragment is provided.
                # This is a heuristic for did:key where the kid is often just the DID
                if did_doc_dict:
                    import pydid

                    did_doc = pydid.deserialize_document(did_doc_dict)
                    if did_doc.verification_method:
                        vm = did_doc.verification_method[0]
            except Exception as e:
                LOGGER.warning("Failed to resolve DID %s: %s", kid, e)

        LOGGER.info("Dereferenced VM: %s", vm)
        if not vm:
            raise ValueError(f"Could not dereference verification method: {kid}")

        LOGGER.info("VM Type: %s", vm.type)

        if vm.type == "JsonWebKey2020" and vm.public_key_jwk:
            return Key.from_jwk(vm.public_key_jwk)
        if vm.type == "Ed25519VerificationKey2018" and vm.public_key_base58:
            key_bytes = b58_to_bytes(vm.public_key_base58)
            return Key.from_public_bytes(KeyAlg.ED25519, key_bytes)
        if vm.type == "Ed25519VerificationKey2020" and vm.public_key_multibase:
            key_bytes = b58_to_bytes(vm.public_key_multibase[1:])
            if len(key_bytes) == 32:
                pass
            elif len(key_bytes) == 34:
                # Trim off the multicodec header, if present
                key_bytes = key_bytes[2:]
            return Key.from_public_bytes(KeyAlg.ED25519, key_bytes)

        if vm.type == "Multikey" and vm.public_key_multibase:
            LOGGER.info("Processing Multikey: %s", vm.public_key_multibase)
            key_bytes = b58_to_bytes(vm.public_key_multibase[1:])
            key_types = KeyTypes()
            key_type = key_types.from_prefixed_bytes(key_bytes)
            if not key_type:
                LOGGER.error("Unknown key type in Multikey")
                raise ValueError("Unknown key type in Multikey")

            LOGGER.info("Detected key type: %s", key_type.key_type)
            prefix_len = len(key_type.multicodec_prefix)
            key_bytes = key_bytes[prefix_len:]

            if key_type == P256:
                return Key.from_public_bytes(KeyAlg.P256, key_bytes)
            elif key_type == ED25519:
                return Key.from_public_bytes(KeyAlg.ED25519, key_bytes)
            else:
                LOGGER.error("Unsupported key type in Multikey: %s", key_type.key_type)
                raise ValueError(
                    f"Unsupported key type in Multikey: {key_type.key_type}"
                )

        LOGGER.error("Unsupported verification method type: %s", vm.type)
        raise ValueError("Unsupported verification method type")
    except Exception as e:
        LOGGER.error("Error in key_material_for_kid: %s", e, exc_info=True)
        raise


async def jwt_sign(
    profile: Profile,
    headers: Dict[str, Any],
    payload: Mapping[str, Any],
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
) -> str:
    """Create a signed JWT given headers, payload, and signing DID or DID URL."""
    if verification_method is None:
        if did is None:
            raise ValueError("did or verificationMethod required.")

        did = nym_to_did(did)

        verkey_strat = profile.inject(BaseVerificationKeyStrategy)
        verification_method = await verkey_strat.get_verification_method_id_for_did(
            did, profile
        )
        if not verification_method:
            raise ValueError("Could not determine verification method from DID")
    else:
        # We look up keys by did for now
        did = DIDUrl.parse(verification_method).did
        if not did:
            raise ValueError("DID URL must be absolute")

    encoded_payload = dict_to_b64(payload)

    if not headers.get("typ", None):
        headers["typ"] = "JWT"

    headers = {
        **headers,
        "kid": verification_method,
    }

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        did_info = await wallet.get_local_did(did_lookup_name(did))

        if did_info.key_type == ED25519:
            headers["alg"] = "EdDSA"
        elif did_info.key_type == P256:
            headers["alg"] = "ES256"
        else:
            raise ValueError("Unable to determine JWT signing alg")

        encoded_headers = dict_to_b64(headers)
        sig_bytes = await wallet.sign_message(
            f"{encoded_headers}.{encoded_payload}".encode(), did_info.verkey
        )

    sig = bytes_to_b64(sig_bytes, urlsafe=True, pad=False)
    return f"{encoded_headers}.{encoded_payload}.{sig}"


async def jwt_verify(
    profile: Profile, jwt: str, *, cnf: Optional[dict] = None
) -> JWTVerifyResult:
    """Verify a JWT and return the headers and payload."""
    encoded_headers, encoded_payload, encoded_signature = jwt.split(".", 3)
    headers = b64_to_dict(encoded_headers)
    payload = b64_to_dict(encoded_payload)
    if cnf:
        if "jwk" in cnf:
            key = Key.from_jwk(cnf["jwk"])
        elif "kid" in cnf:
            verification_method = headers["kid"]
            key = await key_material_for_kid(profile, verification_method)
        else:
            raise ValueError("Unsupported cnf")
    else:
        verification_method = headers["kid"]
        key = await key_material_for_kid(profile, verification_method)

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    alg = headers.get("alg")
    if alg == "EdDSA" and key.algorithm != KeyAlg.ED25519:
        raise BadJWSHeaderError("Expected ed25519 key")
    elif alg == "ES256" and key.algorithm != KeyAlg.P256:
        raise BadJWSHeaderError("Expected p256 key")

    valid = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
    )

    return JWTVerifyResult(headers, payload, valid)
