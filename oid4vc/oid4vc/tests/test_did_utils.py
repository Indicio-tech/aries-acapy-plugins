from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.askar.profile_anon import AskarAnonCredsProfileSession
from acapy_agent.storage.base import BaseStorage
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.utils.testing import create_test_profile

from oid4vc.did_utils import _create_default_did, retrieve_or_create_did_jwk


@pytest.mark.asyncio
async def test_create_default_did_supports_askar_anoncreds_session():
    session = MagicMock(spec=AskarAnonCredsProfileSession)
    session.handle = MagicMock()
    session.handle.insert_key = AsyncMock()
    wallet = MagicMock()
    wallet.store_did = AsyncMock()
    storage = MagicMock()
    storage.add_record = AsyncMock()
    session.inject.side_effect = lambda dependency: {
        BaseWallet: wallet,
        BaseStorage: storage,
    }[dependency]

    did_info = await _create_default_did(session)

    assert did_info.did.startswith("did:jwk:")
    session.handle.insert_key.assert_awaited_once()
    wallet.store_did.assert_awaited_once_with(did_info)
    storage.add_record.assert_awaited_once()


@pytest.mark.asyncio
async def test_retrieve_or_create_did_jwk_with_askar_anoncreds_profile():
    profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
    profile.context.injector.bind_instance(DIDMethods, DIDMethods())
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    try:
        async with profile.session() as session:
            assert isinstance(session, AskarAnonCredsProfileSession)
            created = await retrieve_or_create_did_jwk(session)

        async with profile.session() as session:
            retrieved = await retrieve_or_create_did_jwk(session)

        assert created.did.startswith("did:jwk:")
        assert retrieved.did == created.did
        assert retrieved.verkey == created.verkey
    finally:
        await profile.close()


@pytest.mark.asyncio
async def test_create_default_did_rejects_non_askar_session():
    session = MagicMock()
    session.handle = None
    session.inject.return_value = MagicMock()

    with pytest.raises(WalletError, match="Askar-backed profile session"):
        await _create_default_did(session)
