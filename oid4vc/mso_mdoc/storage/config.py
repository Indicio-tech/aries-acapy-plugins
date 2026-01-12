"""Configuration storage for mso_mdoc.

This module provides storage capabilities for mDoc configuration data
including default signing key and certificate settings.
"""

import json
import logging
from typing import Dict, Optional

from acapy_agent.config.base import InjectionError
from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import StorageRecord
from acapy_agent.storage.error import StorageError

from .base import MDOC_CONFIG_RECORD_TYPE, get_storage

LOGGER = logging.getLogger(__name__)


async def store_config(
    session: ProfileSession, config_id: str, config_data: Dict
) -> None:
    """Store configuration data."""
    try:
        storage = get_storage(session)
    except InjectionError as e:
        LOGGER.warning("Storage not available for storing config %s: %s", config_id, e)
        return

    record = StorageRecord(
        type=MDOC_CONFIG_RECORD_TYPE,
        id=config_id,
        value=json.dumps(config_data),
    )

    try:
        await storage.add_record(record)
    except StorageError:
        # Record might exist, try updating
        try:
            await storage.update_record(record, record.value, record.tags)
        except StorageError as update_error:
            LOGGER.error(
                "Failed to store/update config %s: %s",
                config_id,
                update_error,
            )
            raise

    LOGGER.info("Stored mDoc config: %s", config_id)


async def get_config(session: ProfileSession, config_id: str) -> Optional[Dict]:
    """Retrieve configuration data."""
    try:
        storage = get_storage(session)
    except InjectionError as e:
        LOGGER.warning("Storage not available for getting config %s: %s", config_id, e)
        return None

    try:
        record = await storage.get_record(MDOC_CONFIG_RECORD_TYPE, config_id)
        return json.loads(record.value)
    except (StorageError, json.JSONDecodeError):
        return None
