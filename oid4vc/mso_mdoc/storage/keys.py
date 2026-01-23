"""Key storage for mso_mdoc.

This module provides storage capabilities for ECDSA signing keys in JWK format
following RFC 7517 specifications and NIST SP 800-57 key lifecycle management.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from acapy_agent.config.base import InjectionError
from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from .base import MDOC_KEY_RECORD_TYPE, get_storage

LOGGER = logging.getLogger(__name__)


async def store_key(
    session: ProfileSession,
    key_id: str,
    jwk: Dict[str, Any],
    purpose: str = "signing",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Store a JSON Web Key (JWK) for mDoc operations.

    Persistently stores an ECDSA key in JWK format following RFC 7517
    specifications. Keys are indexed by purpose and can include additional
    metadata for key management operations.

    Args:
        session: Active database session for storage operations
        key_id: Unique identifier for the key (used as storage record ID)
        jwk: JSON Web Key dictionary with EC parameters
        purpose: Key usage purpose (default: "signing")
        metadata: Optional additional key metadata and attributes

    Raises:
        StorageError: If key storage operation fails
        ValueError: If key_id or jwk parameters are invalid

    Example:
        >>> jwk = {"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "d": "..."}
        >>> await store_key(session, "key-123", jwk, "signing")
    """
    try:
        storage = get_storage(session)
    except StorageError as e:
        LOGGER.error("Storage backend unavailable for storing key %s: %s", key_id, e)
        raise StorageError(f"Cannot store key {key_id}: storage unavailable") from e

    record_data = {
        "jwk": jwk,
        "purpose": purpose,
        "created_at": datetime.utcnow().isoformat(),
        "metadata": metadata or {},
    }

    record = StorageRecord(
        type=MDOC_KEY_RECORD_TYPE,
        id=key_id,
        value=json.dumps(record_data),
        tags={"purpose": purpose},
    )

    await storage.add_record(record)
    LOGGER.info("Stored mDoc key: %s", key_id)


async def get_key(session: ProfileSession, key_id: str) -> Optional[Dict]:
    """Retrieve a stored key by ID."""
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning("Storage not available for getting key %s: %s", key_id, e)
        return None

    try:
        record = await storage.get_record(MDOC_KEY_RECORD_TYPE, key_id)
        data = json.loads(record.value)
        return data["jwk"]
    except StorageNotFoundError:
        LOGGER.warning("Key not found: %s", key_id)
        return None
    except (StorageError, json.JSONDecodeError) as e:
        LOGGER.warning("Failed to retrieve key %s: %s", key_id, e)
        return None


async def list_keys(
    session: ProfileSession, purpose: Optional[str] = None
) -> List[Dict]:
    """List stored keys, optionally filtered by purpose."""
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning("Storage not available for listing keys: %s", e)
        return []

    search_tags = {}
    if purpose:
        search_tags["purpose"] = purpose

    try:
        records = await storage.find_all_records(
            type_filter=MDOC_KEY_RECORD_TYPE, tag_query=search_tags
        )

        keys = []
        for record in records:
            data = json.loads(record.value)
            keys.append(
                {
                    "key_id": record.id,
                    "jwk": data["jwk"],
                    "purpose": data["purpose"],
                    "created_at": data["created_at"],
                    "metadata": data.get("metadata", {}),
                }
            )

        return keys
    except (StorageError, StorageNotFoundError) as e:
        LOGGER.warning("Failed to list keys: %s", e)
        return []


async def delete_key(session: ProfileSession, key_id: str) -> bool:
    """Delete a stored key."""
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning("Storage not available for deleting key %s: %s", key_id, e)
        return False

    try:
        record = await storage.get_record(MDOC_KEY_RECORD_TYPE, key_id)
        await storage.delete_record(record)
        LOGGER.info("Deleted mDoc key: %s", key_id)
        return True
    except (StorageNotFoundError, StorageError) as e:
        LOGGER.warning("Failed to delete key %s: %s", key_id, e)
        return False


async def store_signing_key(
    session: ProfileSession, key_id: str, key_metadata: Dict
) -> None:
    """Store a signing key with metadata.

    Args:
        session: Profile session for storage access
        key_id: Unique identifier for the key
        key_metadata: Dictionary containing jwk and other metadata
    """
    jwk = key_metadata.get("jwk")
    if not jwk:
        raise ValueError("key_metadata must contain 'jwk' field")

    await store_key(
        session,
        key_id=key_id,
        jwk=jwk,
        purpose="signing",
        metadata=key_metadata,
    )
