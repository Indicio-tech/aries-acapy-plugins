"""DID utility functions for OID4VC plugin."""

import json

from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.util import bytes_to_b64
from aries_askar import Key, KeyAlg
from base58 import b58decode

from oid4vc.jwk import DID_JWK


async def _retrieve_default_did(session: ProfileSession):
    """Retrieve default DID from storage.

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
