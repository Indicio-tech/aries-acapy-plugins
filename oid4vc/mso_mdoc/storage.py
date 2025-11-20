"""Storage manager for mso_mdoc keys and certificates.

This module provides persistent storage capabilities for mDoc-related
cryptographic materials, certificates, and configuration data. It implements
secure storage patterns following ISO 18013-5 requirements for key management
and credential issuance operations.

Key Protocol Compliance:
- ISO/IEC 18013-5:2021 § 7.2.4 - Issuer authentication mechanisms
- ISO/IEC 18013-5:2021 § 9.1.3.5 - Cryptographic algorithms
- RFC 7517 - JSON Web Key (JWK) storage format
- NIST SP 800-57 - Key management best practices

Storage Types:
- ECDSA signing keys with P-256 curve parameters
- X.509 certificates for issuer authentication
- mDoc configuration and metadata
- Device authentication public keys
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError

LOGGER = logging.getLogger(__name__)

# Storage record types for mDoc operations
MDOC_KEY_RECORD_TYPE = "mdoc_key"
MDOC_CERT_RECORD_TYPE = "mdoc_certificate"
MDOC_CONFIG_RECORD_TYPE = "mdoc_config"


class MdocStorageManager:
    """Storage manager for mDoc keys, certificates, and configuration.

    Provides secure storage operations for cryptographic materials used in
    mDoc issuance and verification processes. Implements proper key lifecycle
    management following NIST SP 800-57 guidelines.

    Attributes:
        profile: ACA-Py profile for accessing storage backend
    """

    def __init__(self, profile: Profile) -> None:
        """Initialize storage manager with profile.

        Args:
            profile: ACA-Py profile containing storage configuration
        """
        self.profile = profile

    def get_storage(self, session: ProfileSession) -> BaseStorage:
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
        except Exception as e:
            LOGGER.error("Failed to inject BaseStorage from session %s: %s", session, e)
            raise

    async def store_key(
        self,
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
            >>> await storage.store_key(session, "key-123", jwk, "signing")
        """
        try:
            storage = self.get_storage(session)
        except StorageError as e:
            LOGGER.error(
                "Storage backend unavailable for storing key %s: %s", key_id, e
            )
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

    async def get_key(self, session: ProfileSession, key_id: str) -> Optional[Dict]:
        """Retrieve a stored key by ID."""
        try:
            storage = self.get_storage(session)
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
        self, session: ProfileSession, purpose: Optional[str] = None
    ) -> List[Dict]:
        """List stored keys, optionally filtered by purpose."""
        try:
            storage = self.get_storage(session)
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

    async def delete_key(self, session: ProfileSession, key_id: str) -> bool:
        """Delete a stored key."""
        try:
            storage = self.get_storage(session)
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
        self, session: ProfileSession, key_id: str, key_metadata: Dict
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

        await self.store_key(
            session,
            key_id=key_id,
            jwk=jwk,
            purpose="signing",
            metadata=key_metadata,
        )

    async def store_certificate(
        self,
        session: ProfileSession,
        cert_id: str,
        certificate_pem: str,
        key_id: str,
        metadata: Optional[Dict] = None,
    ) -> None:
        """Store a PEM certificate."""
        try:
            storage = self.get_storage(session)
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
        self, session: ProfileSession, cert_id: str
    ) -> Optional[Tuple[str, str]]:
        """Retrieve certificate PEM and associated key ID."""
        try:
            storage = self.get_storage(session)
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

    async def list_certificates(self, session: ProfileSession) -> List[Dict]:
        """List all stored certificates."""
        try:
            storage = self.get_storage(session)
        except Exception as e:
            LOGGER.warning("Storage not available for listing certificates: %s", e)
            return []

        try:
            records = await storage.find_all_records(type_filter=MDOC_CERT_RECORD_TYPE)

            certificates = []
            for record in records:
                data = json.loads(record.value)
                certificates.append(
                    {
                        "cert_id": record.id,
                        "key_id": data["key_id"],
                        "created_at": data["created_at"],
                        "metadata": data.get("metadata", {}),
                    }
                )

            return certificates
        except (StorageError, StorageNotFoundError) as e:
            LOGGER.warning("Failed to list certificates: %s", e)
            return []

    async def get_signing_key(
        self,
        session: ProfileSession,
        identifier: Optional[str] = None,
        verification_method: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Get a signing key by identifier or verification method.

        Args:
            session: Profile session for storage access
            identifier: Key ID to look up
            verification_method: Verification method URI to match

        Returns:
            Dictionary containing key data including jwk, metadata, etc.
            None if not found
        """
        keys = await self.list_keys(session, purpose="signing")

        if not keys:
            return None

        # If no identifier provided, return default
        if not identifier and not verification_method:
            return await self.get_default_signing_key(session)

        # Search by identifier or verification method
        for key in keys:
            key_id = key["key_id"]
            metadata = key.get("metadata", {})

            # Match by key_id
            if identifier and key_id == identifier:
                return key

            # Match by verification method
            if verification_method:
                if metadata.get("verification_method") == verification_method:
                    return key
                # Also check if identifier matches key fragment from verification method
                if "#" in verification_method:
                    _, key_fragment = verification_method.split("#", 1)
                    if metadata.get("key_id") == key_fragment or key_id == key_fragment:
                        return key

        return None

    async def get_signing_key_and_cert(
        self, session: ProfileSession
    ) -> List[Dict[str, Any]]:
        """Get all signing keys with their associated certificates.

        Args:
            session: Profile session for database access

        Returns:
            List of dictionaries containing key and certificate data
        """
        keys = await self.list_keys(purpose="signing")
        if not keys:
            return []

        result = []
        certificates = await self.list_certificates()

        for key_data in keys:
            key_id = key_data["key_id"]

            # Try to find associated certificate
            cert_pem = None
            for cert in certificates:
                if cert["key_id"] == key_id:
                    cert_result = await self.get_certificate(session, cert["cert_id"])
                    if cert_result:
                        cert_pem = cert_result[0]
                        break

            result.append(
                {
                    "key_id": key_id,
                    "jwk": key_data["jwk"],
                    "metadata": key_data.get("metadata", {}),
                    "certificate_pem": cert_pem,
                    "created_at": key_data["created_at"],
                }
            )

        return result

    async def store_config(
        self, session: ProfileSession, config_id: str, config_data: Dict
    ) -> None:
        """Store configuration data."""
        try:
            storage = self.get_storage(session)
        except Exception as e:
            LOGGER.warning(
                "Storage not available for storing config %s: %s", config_id, e
            )
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

    async def get_config(
        self, session: ProfileSession, config_id: str
    ) -> Optional[Dict]:
        """Retrieve configuration data."""
        try:
            storage = self.get_storage(session)
        except Exception as e:
            LOGGER.warning(
                "Storage not available for getting config %s: %s", config_id, e
            )
            return None

        try:
            record = await storage.get_record(MDOC_CONFIG_RECORD_TYPE, config_id)
            return json.loads(record.value)
        except StorageNotFoundError:
            return None
        except (StorageError, json.JSONDecodeError) as e:
            LOGGER.warning("Failed to get config %s: %s", config_id, e)
            return None

    async def get_default_signing_key(
        self, session: ProfileSession
    ) -> Optional[Dict[str, Any]]:
        """Get the default signing key."""
        config = await self.get_config(session, "default_signing_key")
        if not config:
            # Try to auto-select first available signing key
            keys = await self.list_keys(session, purpose="signing")
            if keys:
                default_key = keys[0]
                await self.store_config(
                    session,
                    "default_signing_key",
                    {"key_id": default_key["key_id"]},
                )
                return default_key
            return None

        key_id = config.get("key_id")
        if key_id:
            # Return full key data
            keys = await self.list_keys(session, purpose="signing")
            for key in keys:
                if key["key_id"] == key_id:
                    return key

        return None

    async def get_default_certificate(
        self, session: ProfileSession
    ) -> Optional[Dict[str, Any]]:
        """Get the default certificate."""
        config = await self.get_config(session, "default_certificate")
        if not config:
            # Try to auto-select first available certificate
            certificates = await self.list_certificates(session)
            if certificates:
                default_cert = certificates[0]
                # Check if certificate is still valid
                now = datetime.utcnow()
                valid_from = datetime.fromisoformat(
                    default_cert["metadata"].get("valid_from", now.isoformat())
                )
                valid_to = datetime.fromisoformat(
                    default_cert["metadata"].get("valid_to", now.isoformat())
                )

                if valid_from <= now <= valid_to:
                    await self.store_config(
                        session,
                        "default_certificate",
                        {"cert_id": default_cert["cert_id"]},
                    )
                    return default_cert
            return None

        return None

    async def get_certificate_for_key(
        self, session: ProfileSession, key_id: str
    ) -> Optional[str]:
        """Retrieve certificate PEM associated with a key ID."""
        try:
            storage = self.get_storage(session)
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
