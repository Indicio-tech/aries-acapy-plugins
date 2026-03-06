"""Base storage utilities for mso_mdoc.

This module provides shared constants and base functionality for mDoc storage
operations. All storage record types and the base storage accessor are defined here.

Key Protocol Compliance:
- ISO/IEC 18013-5:2021 § 7.2.4 - Issuer authentication mechanisms
- RFC 7517 - JSON Web Key (JWK) storage format
- NIST SP 800-57 - Key management best practices
"""

import logging
from typing import TYPE_CHECKING

from acapy_agent.config.base import InjectionError
from acapy_agent.storage.base import BaseStorage

if TYPE_CHECKING:
    from acapy_agent.core.profile import ProfileSession

LOGGER = logging.getLogger(__name__)

# Storage record types for mDoc operations
MDOC_KEY_RECORD_TYPE = "mdoc_key"
MDOC_CERT_RECORD_TYPE = "mdoc_certificate"
MDOC_CONFIG_RECORD_TYPE = "mdoc_config"
MDOC_TRUST_ANCHOR_RECORD_TYPE = "mdoc_trust_anchor"


def get_storage(session: "ProfileSession") -> BaseStorage:
    """Get storage instance from session.

    Retrieves the configured storage backend from the session context
    for performing persistent storage operations.

    Args:
        session: Active database session with storage context

    Returns:
        BaseStorage instance for record operations

    Raises:
        StorageError: If storage backend is not available
    """
    LOGGER.debug("Attempting to inject BaseStorage from session: %s", session)
    try:
        storage = session.inject(BaseStorage)
        LOGGER.debug("Successfully injected BaseStorage: %s", storage)
        return storage
    except InjectionError as e:
        LOGGER.error("Failed to inject BaseStorage from session %s: %s", session, e)
        raise
