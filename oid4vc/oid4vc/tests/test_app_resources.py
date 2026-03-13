import asyncio
import time
from datetime import timedelta

import aiohttp
import pytest
from acapy_agent.messaging.util import datetime_now, datetime_to_str
from acapy_agent.storage.base import BaseStorage, StorageRecord

from oid4vc.app_resources import AppResources, cleanup_expired_nonces
from oid4vc.models.nonce import Nonce


@pytest.mark.asyncio
async def test_startup_and_shutdown(monkeypatch, config):
    await AppResources.startup(config)
    client = AppResources.get_http_client()
    assert isinstance(client, aiohttp.ClientSession)
    await AppResources.shutdown()
    # After shutdown, client should be None
    with pytest.raises(RuntimeError):
        AppResources.get_http_client()


@pytest.mark.asyncio
async def test_background_cleanup(monkeypatch):
    # Patch cleanup_expired_nonces to track calls
    called = {}

    async def fake_cleanup(profile):
        called["ran"] = True

    monkeypatch.setattr("oid4vc.app_resources.cleanup_expired_nonces", fake_cleanup)
    # Run the background cleanup task for one iteration
    task = asyncio.create_task(AppResources._background_cleanup())
    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert called.get("ran")


@pytest.mark.asyncio
async def test_cleanup_expired_nonces_none_profile():
    """cleanup_expired_nonces with None profile returns immediately."""
    await cleanup_expired_nonces(None)  # should not raise


@pytest.mark.asyncio
async def test_cleanup_expired_nonces_removes_used_and_expired(profile):
    """Used and expired nonces are deleted; live nonces are kept."""
    now = datetime_now()

    async with profile.session() as session:
        # Create a used nonce
        used_nonce = Nonce(
            nonce_value="used-nonce-1",
            used=True,
            issued_at=datetime_to_str(now - timedelta(hours=2)),
            expires_at=datetime_to_str(now + timedelta(hours=1)),
        )
        await used_nonce.save(session)

        # Create an expired nonce (not used, but past expiry)
        expired_nonce = Nonce(
            nonce_value="expired-nonce-1",
            used=False,
            issued_at=datetime_to_str(now - timedelta(hours=2)),
            expires_at=datetime_to_str(now - timedelta(seconds=1)),
        )
        await expired_nonce.save(session)

        # Create a live nonce (not used, not expired)
        live_nonce = Nonce(
            nonce_value="live-nonce-1",
            used=False,
            issued_at=datetime_to_str(now),
            expires_at=datetime_to_str(now + timedelta(hours=1)),
        )
        await live_nonce.save(session)

    await cleanup_expired_nonces(profile)

    async with profile.session() as session:
        remaining = await Nonce.query(session)
        values = {n.nonce_value for n in remaining}
        assert "live-nonce-1" in values
        assert "used-nonce-1" not in values
        assert "expired-nonce-1" not in values


@pytest.mark.asyncio
async def test_cleanup_removes_stale_dpop_jtis(profile):
    """DPoP JTI records older than 24 hours are deleted."""
    old_iat = str(int(time.time()) - 90000)  # ~25 hours ago
    fresh_iat = str(int(time.time()) - 30)  # 30 seconds ago

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        await storage.add_record(
            StorageRecord(type="oid4vc.dpop_jti", value=old_iat, id="jti-old")
        )
        await storage.add_record(
            StorageRecord(type="oid4vc.dpop_jti", value=fresh_iat, id="jti-fresh")
        )

    await cleanup_expired_nonces(profile)

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        remaining = await storage.find_all_records("oid4vc.dpop_jti")
        ids = {r.id for r in remaining}
        assert "jti-fresh" in ids
        assert "jti-old" not in ids


@pytest.mark.asyncio
async def test_cleanup_removes_malformed_dpop_jtis(profile):
    """DPoP JTI records with non-integer values are deleted."""
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        await storage.add_record(
            StorageRecord(type="oid4vc.dpop_jti", value="not-a-number", id="jti-bad")
        )

    await cleanup_expired_nonces(profile)

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        remaining = await storage.find_all_records("oid4vc.dpop_jti")
        ids = {r.id for r in remaining}
        assert "jti-bad" not in ids
