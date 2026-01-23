"""Certificate storage for mso_mdoc.

This module provides storage capabilities for X.509 certificates used in
mDoc issuer authentication following ISO/IEC 18013-5:2021 § 7.2.4.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from acapy_agent.config.base import InjectionError
from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from .base import MDOC_CERT_RECORD_TYPE, get_storage

LOGGER = logging.getLogger(__name__)


async def store_certificate(
    session: ProfileSession,
    cert_id: str,
    certificate_pem: str,
    key_id: str,
    metadata: Optional[Dict] = None,
) -> None:
    """Store a PEM certificate."""
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning(
            "Storage not available for storing certificate %s: %s",
            cert_id,
            e,
        )
        return

    record_data = {
        "certificate_pem": certificate_pem,
        "key_id": key_id,
        "created_at": datetime.utcnow().isoformat(),
        "metadata": metadata or {},
    }

    record = StorageRecord(
        type=MDOC_CERT_RECORD_TYPE,
        id=cert_id,
        value=json.dumps(record_data),
        tags={"key_id": key_id},
    )

    await storage.add_record(record)
    LOGGER.info("Stored mDoc certificate: %s", cert_id)


async def get_certificate(
    session: ProfileSession, cert_id: str
) -> Optional[Tuple[str, str]]:
    """Retrieve certificate PEM and associated key ID."""
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning(
            "Storage not available for getting certificate %s: %s",
            cert_id,
            e,
        )
        return None

    try:
        record = await storage.get_record(MDOC_CERT_RECORD_TYPE, cert_id)
        data = json.loads(record.value)
        return data["certificate_pem"], data["key_id"]
    except StorageNotFoundError:
        LOGGER.warning("Certificate not found: %s", cert_id)
        return None
    except (StorageError, json.JSONDecodeError) as e:
        LOGGER.warning("Failed to retrieve certificate %s: %s", cert_id, e)
        return None


async def list_certificates(
    session: ProfileSession, include_pem: bool = False
) -> List[Dict]:
    """List all stored certificates.

    Args:
        session: Profile session for storage access
        include_pem: If True, include the certificate_pem field in results

    Returns:
        List of certificate dictionaries
    """
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning("Storage not available for listing certificates: %s", e)
        return []

    try:
        records = await storage.find_all_records(type_filter=MDOC_CERT_RECORD_TYPE)

        certificates = []
        for record in records:
            data = json.loads(record.value)
            cert_entry = {
                "cert_id": record.id,
                "key_id": data["key_id"],
                "created_at": data["created_at"],
                "metadata": data.get("metadata", {}),
            }
            if include_pem:
                cert_entry["certificate_pem"] = data.get("certificate_pem")
            certificates.append(cert_entry)

        return certificates
    except (StorageError, StorageNotFoundError) as e:
        LOGGER.warning("Failed to list certificates: %s", e)
        return []


async def get_certificate_for_key(
    session: ProfileSession, key_id: str
) -> Optional[str]:
    """Retrieve certificate PEM associated with a key ID."""
    try:
        storage = get_storage(session)
    except Exception as e:
        LOGGER.warning(
            "Storage not available for getting certificate for key %s: %s",
            key_id,
            e,
        )
        return None

    try:
        records = await storage.find_all_records(
            type_filter=MDOC_CERT_RECORD_TYPE,
            tag_query={"key_id": key_id},
        )
        if not records:
            return None

        # Assuming one certificate per key for now, or take the most recent
        record = records[0]
        data = json.loads(record.value)
        return data["certificate_pem"]
    except (StorageError, StorageNotFoundError) as e:
        LOGGER.warning("Failed to retrieve certificate for key %s: %s", key_id, e)
        return None
