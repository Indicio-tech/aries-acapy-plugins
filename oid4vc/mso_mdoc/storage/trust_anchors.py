"""Trust anchor storage for mso_mdoc.

This module provides storage capabilities for X.509 trust anchor certificates
used to verify mDoc issuer certificate chains during credential verification.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from .base import MDOC_TRUST_ANCHOR_RECORD_TYPE, get_storage

LOGGER = logging.getLogger(__name__)


async def store_trust_anchor(
    session: ProfileSession,
    anchor_id: str,
    certificate_pem: str,
    metadata: Optional[Dict] = None,
) -> None:
    """Store an X.509 trust anchor certificate.

    Trust anchors are root CA certificates used to verify mDoc issuer
    certificate chains during credential verification.

    Args:
        session: Active database session for storage operations
        anchor_id: Unique identifier for the trust anchor
        certificate_pem: PEM-encoded X.509 certificate
        metadata: Optional metadata (e.g., issuer name, expiry, purpose)

    Raises:
        StorageError: If storage operation fails
    """
    try:
        storage = get_storage(session)
    except StorageError as e:
        LOGGER.error(
            "Storage backend unavailable for storing trust anchor %s: %s",
            anchor_id,
            e,
        )
        raise StorageError(
            f"Cannot store trust anchor {anchor_id}: storage unavailable"
        ) from e

    record_data = {
        "certificate_pem": certificate_pem,
        "created_at": datetime.utcnow().isoformat(),
        "metadata": metadata or {},
    }

    record = StorageRecord(
        type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
        id=anchor_id,
        value=json.dumps(record_data),
        tags={"type": "trust_anchor"},
    )

    await storage.add_record(record)
    LOGGER.info("Stored mDoc trust anchor: %s", anchor_id)


async def get_trust_anchor(
    session: ProfileSession, anchor_id: str
) -> Optional[Dict[str, Any]]:
    """Retrieve a trust anchor by ID.

    Args:
        session: Active database session
        anchor_id: Unique identifier for the trust anchor

    Returns:
        Dictionary containing certificate_pem, created_at, and metadata,
        or None if not found
    """
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning(
            "Storage not available for getting trust anchor %s: %s",
            anchor_id,
            e,
        )
        return None

    try:
        record = await storage.get_record(MDOC_TRUST_ANCHOR_RECORD_TYPE, anchor_id)
        data = json.loads(record.value)
        return {
            "anchor_id": anchor_id,
            "certificate_pem": data["certificate_pem"],
            "created_at": data["created_at"],
            "metadata": data.get("metadata", {}),
        }
    except StorageNotFoundError:
        LOGGER.warning("Trust anchor not found: %s", anchor_id)
        return None
    except (StorageError, json.JSONDecodeError) as e:
        LOGGER.warning("Failed to retrieve trust anchor %s: %s", anchor_id, e)
        return None


async def list_trust_anchors(session: ProfileSession) -> List[Dict[str, Any]]:
    """List all stored trust anchors.

    Args:
        session: Active database session

    Returns:
        List of trust anchor dictionaries with anchor_id, created_at, metadata
    """
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning("Storage not available for listing trust anchors: %s", e)
        return []

    try:
        records = await storage.find_all_records(
            type_filter=MDOC_TRUST_ANCHOR_RECORD_TYPE
        )

        anchors = []
        for record in records:
            data = json.loads(record.value)
            anchors.append(
                {
                    "anchor_id": record.id,
                    "created_at": data["created_at"],
                    "metadata": data.get("metadata", {}),
                }
            )

        return anchors
    except (StorageError, StorageNotFoundError) as e:
        LOGGER.warning("Failed to list trust anchors: %s", e)
        return []


async def get_all_trust_anchor_pems(session: ProfileSession) -> List[str]:
    """Retrieve all trust anchor certificates as PEM strings.

    This method is optimized for use by TrustStore implementations
    that need all certificates for chain validation.

    Args:
        session: Active database session

    Returns:
        List of PEM-encoded certificate strings
    """
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning("Storage not available for getting trust anchor PEMs: %s", e)
        return []

    try:
        records = await storage.find_all_records(
            type_filter=MDOC_TRUST_ANCHOR_RECORD_TYPE
        )

        pems = []
        for record in records:
            data = json.loads(record.value)
            pems.append(data["certificate_pem"])

        return pems
    except (StorageError, StorageNotFoundError) as e:
        LOGGER.warning("Failed to retrieve trust anchor PEMs: %s", e)
        return []


async def delete_trust_anchor(session: ProfileSession, anchor_id: str) -> bool:
    """Delete a trust anchor by ID.

    Args:
        session: Active database session
        anchor_id: Unique identifier for the trust anchor

    Returns:
        True if deleted successfully, False otherwise
    """
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning(
            "Storage not available for deleting trust anchor %s: %s",
            anchor_id,
            e,
        )
        return False

    try:
        record = await storage.get_record(MDOC_TRUST_ANCHOR_RECORD_TYPE, anchor_id)
        await storage.delete_record(record)
        LOGGER.info("Deleted mDoc trust anchor: %s", anchor_id)
        return True
    except (StorageNotFoundError, StorageError) as e:
        LOGGER.warning("Failed to delete trust anchor %s: %s", anchor_id, e)
        return False
