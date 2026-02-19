"""DID utilities for OID4VC."""

import json

from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import ED25519


async def _retrieve_default_did(session: ProfileSession):
    """Retrieve default DID from storage."""
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
    """Create default DID using create_local_did for proper wallet registration."""
    wallet = session.inject(BaseWallet)
    storage = session.inject(BaseStorage)

    did_info = await wallet.create_local_did(method="jwk", key_type=ED25519)

    record = StorageRecord(
        type="OID4VP.default",
        value=json.dumps({"verkey": did_info.verkey, "metadata": did_info.metadata}),
        tags={"did": did_info.did},
        id="OID4VP.default",
    )
    await storage.add_record(record)

    return did_info


async def retrieve_or_create_did_jwk(
    session: ProfileSession, key_type=ED25519
) -> DIDInfo:
    """Retrieve existing did:jwk or create a new one."""
    key = await _retrieve_default_did(session)
    if key:
        return key

    return await _create_default_did(session)
