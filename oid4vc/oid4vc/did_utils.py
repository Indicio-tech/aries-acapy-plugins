"""DID utilities for OID4VC."""

from acapy_agent.core.profile import ProfileSession
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import ED25519


async def retrieve_or_create_did_jwk(
    session: ProfileSession, key_type=ED25519
) -> DIDInfo:
    """Retrieve existing did:jwk or create a new one."""
    wallet = session.inject(BaseWallet)

    # Try to find an existing did:jwk
    # Note: get_local_dids usually returns a list of DIDInfo
    dids = await wallet.get_local_dids()
    for did in dids:
        if did.method == "jwk" or did.did.startswith("did:jwk:"):
            return did

    # Create new one
    did_info = await wallet.create_local_did(
        method="jwk",
        key_type=key_type,
    )
    return did_info
