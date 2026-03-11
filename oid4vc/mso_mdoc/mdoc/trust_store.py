"""Trust store implementations for mso_mdoc issuer certificate chain validation."""

import logging
from abc import abstractmethod
from typing import List, Optional, Protocol

from acapy_agent.core.profile import Profile

from ..storage import MdocStorageManager

LOGGER = logging.getLogger(__name__)


class TrustStore(Protocol):
    """Protocol for retrieving trust anchors."""

    @abstractmethod
    def get_trust_anchors(self) -> List[str]:
        """Retrieve trust anchors as PEM strings."""


class WalletTrustStore:
    """Trust store implementation backed by Askar wallet storage.

    This implementation stores trust anchor certificates in the ACA-Py
    wallet using the MdocStorageManager, providing secure storage that
    doesn't require filesystem access or static certificate files.
    """

    def __init__(self, profile: Profile):
        """Initialize the wallet trust store.

        Args:
            profile: ACA-Py profile for accessing wallet storage
        """
        self.profile = profile
        self._cached_anchors: Optional[List[str]] = None

    def get_trust_anchors(self) -> List[str]:
        """Retrieve trust anchors from wallet storage.

        This method is synchronous to satisfy the TrustStore protocol
        expected by the isomdl-uniffi Rust layer.  The cache **must**
        be populated by ``await refresh_cache()`` before calling this
        method (all ACA-Py verification paths do this).

        Returns:
            List of PEM-encoded trust anchor certificates

        Raises:
            RuntimeError: If called before ``refresh_cache()`` has been
                awaited.  Always call ``await refresh_cache()`` before
                any verification operation.
        """
        if self._cached_anchors is not None:
            return self._cached_anchors

        raise RuntimeError(
            "WalletTrustStore.get_trust_anchors() called before cache was "
            "populated.  Always await refresh_cache() before verification."
        )

    async def refresh_cache(self) -> List[str]:
        """Refresh the cached trust anchors from wallet storage.

        This method should be called before verification operations
        when running in an async context.

        Returns:
            List of PEM-encoded trust anchor certificates
        """
        self._cached_anchors = await self._fetch_trust_anchors()
        return self._cached_anchors

    async def _fetch_trust_anchors(self) -> List[str]:
        """Fetch trust anchors from wallet storage.

        Returns:
            List of PEM-encoded trust anchor certificates
        """
        storage_manager = MdocStorageManager(self.profile)
        async with self.profile.session() as session:
            anchors = await storage_manager.get_all_trust_anchor_pems(session)
            LOGGER.debug("Loaded %d trust anchors from wallet", len(anchors))
            return anchors

    def clear_cache(self) -> None:
        """Clear the cached trust anchors."""
        self._cached_anchors = None
