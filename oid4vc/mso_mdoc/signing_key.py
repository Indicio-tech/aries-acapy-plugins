"""Signing key resolution and certificate validation for mso_mdoc issuance.

Provides two public helpers:

- ``check_certificate_not_expired`` — validates that a PEM certificate is
  currently within its validity window (NotBefore ≤ now ≤ NotAfter).
- ``resolve_signing_key_for_credential`` — looks up the registered signing key
  for a credential by verification method or falls back to the configured
  default.  Raises ``CredProcessorError`` when no key is found; never
  auto-generates keys.
"""

import logging
from datetime import UTC, datetime
from typing import Optional

from cryptography import x509 as _x509

from acapy_agent.core.profile import Profile, ProfileSession

from oid4vc.cred_processor import CredProcessorError

from .storage import MdocStorageManager

LOGGER = logging.getLogger(__name__)


def check_certificate_not_expired(cert_pem: str) -> None:
    """Validate that a PEM-encoded X.509 certificate is currently valid.

    Raises ``CredProcessorError`` when the certificate is expired, not yet
    valid, or cannot be parsed.  Returns ``None`` silently on success.

    Args:
        cert_pem: PEM-encoded X.509 certificate string.

    Raises:
        CredProcessorError: If the certificate is expired, not yet valid, or
            cannot be parsed from PEM.
    """
    if not cert_pem or not cert_pem.strip():
        raise CredProcessorError("Empty certificate PEM string")

    try:
        cert = _x509.load_pem_x509_certificate(cert_pem.strip().encode())
    except Exception as exc:
        raise CredProcessorError(
            f"Invalid certificate PEM — could not parse: {exc}"
        ) from exc

    now = datetime.now(UTC)
    if cert.not_valid_before_utc > now:
        nb = cert.not_valid_before_utc.isoformat()
        raise CredProcessorError(f"Certificate is not yet valid (NotBefore={nb})")
    if cert.not_valid_after_utc < now:
        na = cert.not_valid_after_utc.isoformat()
        raise CredProcessorError(f"Certificate has expired (NotAfter={na})")


async def resolve_signing_key_for_credential(
    profile: Profile,
    session: ProfileSession,
    verification_method: Optional[str] = None,
) -> dict:
    """Resolve a signing key for credential issuance.

    Looks up a registered signing key from storage.  When
    ``verification_method`` is supplied the key registered for that method is
    returned; otherwise the configured default key is returned.

    Raises ``CredProcessorError`` — never auto-generates keys.  Operators must
    register keys via the mso_mdoc key management API before issuing.

    Protocol Compliance:
    - ISO 18013-5 § 7.2.4: Issuer authentication mechanisms
    - ISO 18013-5 § 9.1.3.5: Cryptographic algorithms for mDoc
    - RFC 7517: JSON Web Key (JWK) format

    Args:
        profile: The active profile.
        session: The active profile session.
        verification_method: Optional verification method DID URL.

    Returns:
        JWK dictionary for the resolved signing key.

    Raises:
        CredProcessorError: If no matching key is registered.
    """
    storage_manager = MdocStorageManager(profile)

    if verification_method:
        if "#" in verification_method:
            _, key_id = verification_method.split("#", 1)
        else:
            key_id = verification_method

        stored_key = await storage_manager.get_signing_key(
            session,
            identifier=key_id,
            verification_method=verification_method,
        )

        if stored_key and stored_key.get("jwk"):
            return stored_key["jwk"]

        raise CredProcessorError(
            f"Signing key not found for verification method {verification_method!r}. "
            "Register the key via the mso_mdoc key management API before issuing."
        )

    stored_key = await storage_manager.get_default_signing_key(session)
    if stored_key and stored_key.get("jwk"):
        return stored_key["jwk"]

    raise CredProcessorError(
        "No default signing key is configured. "
        "Register a signing key via the mso_mdoc key management API before issuing."
    )
