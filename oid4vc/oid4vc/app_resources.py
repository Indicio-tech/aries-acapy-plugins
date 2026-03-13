"""App resources."""

import asyncio
import logging
import threading
import time

import aiohttp
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.util import datetime_now, str_to_datetime
from acapy_agent.storage.base import BaseStorage

from .config import Config
from .models.nonce import Nonce

LOGGER = logging.getLogger(__name__)


class AppResources:
    """Application-wide resources like HTTP client and cleanup tasks."""

    _auth_server_url: str | None = None
    _http_client: aiohttp.ClientSession | None = None
    _cleanup_task: asyncio.Task | None = None
    _client_shutdown: bool = False
    _lock = threading.Lock()
    _profile: Profile | None = None

    @classmethod
    async def startup(cls, config: Config | None = None, profile: Profile | None = None):
        """Initialize resources."""
        with cls._lock:
            # Prevent multiple initializations
            if cls._http_client is not None:
                LOGGER.debug("HTTP client already initialized")
                return

            cls._profile = profile

            if config and config.auth_server_url:
                cls._auth_server_url = config.auth_server_url
                LOGGER.info("Initializing HTTP client...")
                cls._http_client = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30, connect=10),
                    connector=aiohttp.TCPConnector(
                        limit=100, limit_per_host=10, ttl_dns_cache=300
                    ),
                )

            if profile:
                LOGGER.info("Starting up cleanup task...")
                cls._cleanup_task = asyncio.create_task(cls._background_cleanup())

    @classmethod
    async def shutdown(cls):
        """Clean up resources."""
        if cls._cleanup_task:
            LOGGER.info("Shutting down cleanup task...")
            cls._cleanup_task.cancel()
            try:
                await cls._cleanup_task
            except asyncio.CancelledError:
                pass
            cls._cleanup_task = None
        if cls._http_client:
            LOGGER.info("Closing HTTP client...")
            await cls._http_client.close()
            cls._http_client = None
        cls._client_shutdown = True

    @classmethod
    def get_http_client(cls) -> aiohttp.ClientSession:
        """Get the initialized HTTP client."""
        if cls._client_shutdown:
            raise RuntimeError("HTTP client was shut down and cannot be re-initialized")
        if cls._auth_server_url and cls._http_client is None:
            LOGGER.warning("Warning: HTTP client was None, re-initializing.")
            with cls._lock:
                if cls._http_client is None:  # Double-check after acquiring lock
                    cls._http_client = aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=30, connect=10),
                        connector=aiohttp.TCPConnector(
                            limit=100, limit_per_host=10, ttl_dns_cache=300
                        ),
                    )
        if cls._http_client is None:
            raise RuntimeError("HTTP client is not initialized")
        return cls._http_client

    @classmethod
    async def _background_cleanup(cls):
        """Background task for periodic cleanup."""
        while True:
            try:
                await cleanup_expired_nonces(cls._profile)
            except Exception as e:
                LOGGER.exception(f"Nonce cleanup error: {e}")

            await asyncio.sleep(3600)  # Run every hour


async def cleanup_expired_nonces(profile: Profile | None):
    """Cleanup expired nonces and stale DPoP JTIs from storage.

    Deletes:
    - Nonce records whose ``expires_at`` is in the past or that are already used.
    - ``oid4vc.dpop_jti`` storage records whose ``value`` (iat timestamp) is
      older than 24 hours, well beyond the DPOP_PROOF_MAX_AGE_SECONDS window.
    """
    if profile is None:
        return

    now = datetime_now()
    removed_nonces = 0
    removed_jtis = 0

    async with profile.session() as session:
        # --- Expired / used nonces ---
        try:
            all_nonces = await Nonce.query(session)
            for nonce in all_nonces:
                should_delete = False
                if nonce.used:
                    should_delete = True
                else:
                    try:
                        expires_at = str_to_datetime(nonce.expires_at)
                        if expires_at <= now:
                            should_delete = True
                    except (ValueError, TypeError):
                        should_delete = True

                if should_delete:
                    await nonce.delete_record(session)
                    removed_nonces += 1
        except Exception:
            LOGGER.exception("Error cleaning up expired nonces")

        # --- Stale DPoP JTI records ---
        jti_max_age_seconds = 86400  # 24 hours
        cutoff = int(time.time()) - jti_max_age_seconds
        try:
            storage = session.inject(BaseStorage)
            jti_records = await storage.find_all_records("oid4vc.dpop_jti")
            for rec in jti_records:
                try:
                    iat = int(rec.value)
                    if iat < cutoff:
                        await storage.delete_record(rec)
                        removed_jtis += 1
                except (ValueError, TypeError):
                    # Malformed value — remove it
                    await storage.delete_record(rec)
                    removed_jtis += 1
        except Exception:
            LOGGER.exception("Error cleaning up stale DPoP JTI records")

    if removed_nonces or removed_jtis:
        LOGGER.info(
            "Cleanup: removed %d expired nonces, %d stale DPoP JTIs",
            removed_nonces,
            removed_jtis,
        )
