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

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.storage.base import BaseStorage

from . import certificates, config, keys, trust_anchors

# Re-export constants for backward compatibility
from .base import (
    MDOC_CERT_RECORD_TYPE,
    MDOC_CONFIG_RECORD_TYPE,
    MDOC_KEY_RECORD_TYPE,
    MDOC_TRUST_ANCHOR_RECORD_TYPE,
    get_storage,
)

__all__ = [
    "MdocStorageManager",
    "MDOC_KEY_RECORD_TYPE",
    "MDOC_CERT_RECORD_TYPE",
    "MDOC_CONFIG_RECORD_TYPE",
    "MDOC_TRUST_ANCHOR_RECORD_TYPE",
]


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
        return get_storage(session)

    # =========================================================================
    # Key Storage Methods
    # =========================================================================

    async def store_key(
        self,
        session: ProfileSession,
        key_id: str,
        jwk: Dict[str, Any],
        purpose: str = "signing",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Store a JSON Web Key (JWK) for mDoc operations."""
        await keys.store_key(session, key_id, jwk, purpose, metadata)

    async def get_key(self, session: ProfileSession, key_id: str) -> Optional[Dict]:
        """Retrieve a stored key by ID."""
        return await keys.get_key(session, key_id)

    async def list_keys(
        self, session: ProfileSession, purpose: Optional[str] = None
    ) -> List[Dict]:
        """List stored keys, optionally filtered by purpose."""
        return await keys.list_keys(session, purpose)

    async def delete_key(self, session: ProfileSession, key_id: str) -> bool:
        """Delete a stored key."""
        return await keys.delete_key(session, key_id)

    async def store_signing_key(
        self, session: ProfileSession, key_id: str, key_metadata: Dict
    ) -> None:
        """Store a signing key with metadata."""
        await keys.store_signing_key(session, key_id, key_metadata)

    async def get_signing_key(
        self,
        session: ProfileSession,
        identifier: Optional[str] = None,
        verification_method: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Get a signing key by identifier or verification method."""
        key_list = await keys.list_keys(session, purpose="signing")

        if not key_list:
            return None

        # If no identifier provided, return default
        if not identifier and not verification_method:
            return await self.get_default_signing_key(session)

        # Search by identifier or verification method
        for key in key_list:
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
        """Get all signing keys with their associated certificates."""
        key_list = await keys.list_keys(session, purpose="signing")
        if not key_list:
            return []

        result = []
        cert_list = await certificates.list_certificates(session)

        for key_data in key_list:
            key_id = key_data["key_id"]

            # Try to find associated certificate
            cert_pem = None
            for cert in cert_list:
                if cert["key_id"] == key_id:
                    cert_result = await certificates.get_certificate(
                        session, cert["cert_id"]
                    )
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

    async def get_default_signing_key(
        self, session: ProfileSession
    ) -> Optional[Dict[str, Any]]:
        """Get the default signing key."""
        cfg = await config.get_config(session, "default_signing_key")
        if not cfg:
            # Try to auto-select first available signing key
            key_list = await keys.list_keys(session, purpose="signing")
            if key_list:
                default_key = key_list[0]
                await config.store_config(
                    session,
                    "default_signing_key",
                    {"key_id": default_key["key_id"]},
                )
                return default_key
            return None

        key_id = cfg.get("key_id")
        if key_id:
            # Return full key data
            key_list = await keys.list_keys(session, purpose="signing")
            for key in key_list:
                if key["key_id"] == key_id:
                    return key

        return None

    # =========================================================================
    # Certificate Storage Methods
    # =========================================================================

    async def store_certificate(
        self,
        session: ProfileSession,
        cert_id: str,
        certificate_pem: str,
        key_id: str,
        metadata: Optional[Dict] = None,
    ) -> None:
        """Store a PEM certificate."""
        await certificates.store_certificate(
            session, cert_id, certificate_pem, key_id, metadata
        )

    async def get_certificate(
        self, session: ProfileSession, cert_id: str
    ) -> Optional[Tuple[str, str]]:
        """Retrieve certificate PEM and associated key ID."""
        return await certificates.get_certificate(session, cert_id)

    async def list_certificates(
        self, session: ProfileSession, include_pem: bool = False
    ) -> List[Dict]:
        """List all stored certificates."""
        return await certificates.list_certificates(session, include_pem)

    async def get_certificate_for_key(
        self, session: ProfileSession, key_id: str
    ) -> Optional[str]:
        """Retrieve certificate PEM associated with a key ID."""
        return await certificates.get_certificate_for_key(session, key_id)

    async def get_default_certificate(
        self, session: ProfileSession
    ) -> Optional[Dict[str, Any]]:
        """Get the default certificate."""

        def _is_valid(cert: Dict[str, Any]) -> bool:
            now = datetime.utcnow()
            valid_from = datetime.fromisoformat(
                cert.get("metadata", {}).get("valid_from", now.isoformat())
            )
            valid_to = datetime.fromisoformat(
                cert.get("metadata", {}).get("valid_to", now.isoformat())
            )
            return valid_from <= now <= valid_to

        cfg = await config.get_config(session, "default_certificate")
        if not cfg:
            # Try to auto-select first available certificate
            cert_list = await certificates.list_certificates(session)
            if cert_list:
                default_cert = cert_list[0]
                if _is_valid(default_cert):
                    await config.store_config(
                        session,
                        "default_certificate",
                        {"cert_id": default_cert["cert_id"]},
                    )
                    return default_cert
            return None

        cert_id = cfg.get("cert_id")
        if not cert_id:
            return None

        cert_list = await certificates.list_certificates(session)
        for certificate in cert_list:
            if certificate["cert_id"] == cert_id and _is_valid(certificate):
                return certificate

        return None

    # =========================================================================
    # Configuration Storage Methods
    # =========================================================================

    async def store_config(
        self, session: ProfileSession, config_id: str, config_data: Dict
    ) -> None:
        """Store configuration data."""
        await config.store_config(session, config_id, config_data)

    async def get_config(
        self, session: ProfileSession, config_id: str
    ) -> Optional[Dict]:
        """Retrieve configuration data."""
        return await config.get_config(session, config_id)

    # =========================================================================
    # Trust Anchor Storage Methods
    # =========================================================================

    async def store_trust_anchor(
        self,
        session: ProfileSession,
        anchor_id: str,
        certificate_pem: str,
        metadata: Optional[Dict] = None,
    ) -> None:
        """Store an X.509 trust anchor certificate."""
        await trust_anchors.store_trust_anchor(
            session, anchor_id, certificate_pem, metadata
        )

    async def get_trust_anchor(
        self, session: ProfileSession, anchor_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a trust anchor by ID."""
        return await trust_anchors.get_trust_anchor(session, anchor_id)

    async def list_trust_anchors(self, session: ProfileSession) -> List[Dict[str, Any]]:
        """List all stored trust anchors."""
        return await trust_anchors.list_trust_anchors(session)

    async def get_all_trust_anchor_pems(self, session: ProfileSession) -> List[str]:
        """Retrieve all trust anchor certificates as PEM strings."""
        return await trust_anchors.get_all_trust_anchor_pems(session)

    async def delete_trust_anchor(
        self, session: ProfileSession, anchor_id: str
    ) -> bool:
        """Delete a trust anchor by ID."""
        return await trust_anchors.delete_trust_anchor(session, anchor_id)
