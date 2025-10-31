"""Key and certificate generation utilities for mso_mdoc.

This module provides cryptographic key generation functions that comply with
ISO 18013-5 requirements for mDoc issuance and verification. All generated
keys use ECDSA with P-256 curve as specified in ISO 18013-5 § 9.1.3.5.

Key Protocol Compliance:
- ISO/IEC 18013-5:2021 § 9.1.3.5 - Cryptographic algorithms for mDoc
- RFC 7517 - JSON Web Key (JWK) format
- RFC 7518 § 3.4 - ES256 signature algorithm
- RFC 8152 - CBOR Object Signing and Encryption (COSE)
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

LOGGER = logging.getLogger(__name__)


def generate_ec_key_pair() -> Tuple[str, str, Dict[str, Any]]:
    """Generate an ECDSA key pair for mDoc signing.

    Generates a P-256 (secp256r1) elliptic curve key pair compliant with
    ISO 18013-5 § 9.1.3.5 requirements for mDoc cryptographic operations.
    The generated key supports ES256 algorithm as specified in RFC 7518 § 3.4.

    Returns:
        Tuple containing:
        - private_key_pem: PEM-encoded private key string
        - public_key_pem: PEM-encoded public key string
        - jwk: JSON Web Key dictionary with EC parameters

    Raises:
        ValueError: If key generation parameters are invalid
        RuntimeError: If cryptographic operation fails

    Example:
        >>> private_pem, public_pem, jwk = generate_ec_key_pair()
        >>> print(jwk['kty'])  # 'EC'
        >>> print(jwk['crv'])  # 'P-256'
    """
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Serialize public key to PEM
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Create JWK representation
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    # Convert to JWK format
    def int_to_base64url_uint(val: int) -> str:
        """Convert integer to base64url unsigned integer.

        Converts an elliptic curve coordinate integer to base64url encoding
        as required by RFC 7517 for EC JWK format.

        Args:
            val: Integer value to encode

        Returns:
            Base64url-encoded string without padding
        """
        import base64

        # Convert to bytes, ensuring proper length for P-256 (32 bytes)
        val_bytes = val.to_bytes(32, byteorder="big")
        return base64.urlsafe_b64encode(val_bytes).decode("ascii").rstrip("=")

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": int_to_base64url_uint(public_numbers.x),
        "y": int_to_base64url_uint(public_numbers.y),
        "d": int_to_base64url_uint(private_numbers.private_value),
    }

    return private_pem, public_pem, jwk


def generate_self_signed_certificate(
    private_key_pem: str,
    subject_name: str = "CN=mDoc Test Issuer",
    issuer_name: Optional[str] = None,
    validity_days: int = 365,
) -> str:
    """Generate a self-signed X.509 certificate for mDoc issuer.

    Creates a self-signed certificate compliant with ISO 18013-5 requirements
    for mDoc issuer authentication. The certificate uses SHA-256 with ECDSA
    signature algorithm as specified in ISO 18013-5 § 9.1.3.5.

    Args:
        private_key_pem: Private key in PEM format for signing
        subject_name: Subject Distinguished Name (default: CN=mDoc Test Issuer)
        issuer_name: Issuer DN (uses subject_name if None)
        validity_days: Certificate validity period in days (default: 365)

    Returns:
        PEM-encoded X.509 certificate string

    Raises:
        ValueError: If private key format is invalid or parameters are invalid
        RuntimeError: If certificate generation fails

    Example:
        >>> private_pem, _, _ = generate_ec_key_pair()
        >>> cert = generate_self_signed_certificate(private_pem)
        >>> print("-----BEGIN CERTIFICATE-----" in cert)  # True
        issuer_name: Issuer DN (defaults to subject_name for self-signed)
        validity_days: Certificate validity in days

    Returns:
        Certificate in PEM format
    """
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )

    if issuer_name is None:
        issuer_name = subject_name

    # Parse subject and issuer names
    def parse_dn(dn_string):
        """Parse a simple DN string like 'CN=Test,O=Org'."""
        name_parts = []
        for part in dn_string.split(","):
            part = part.strip()
            if "=" in part:
                attr, value = part.split("=", 1)
                attr = attr.strip().upper()
                value = value.strip()

                if attr == "CN":
                    name_parts.append(x509.NameAttribute(NameOID.COMMON_NAME, value))
                elif attr == "O":
                    name_parts.append(
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, value)
                    )
                elif attr == "C":
                    name_parts.append(x509.NameAttribute(NameOID.COUNTRY_NAME, value))
                elif attr == "ST":
                    name_parts.append(
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value)
                    )
                elif attr == "L":
                    name_parts.append(x509.NameAttribute(NameOID.LOCALITY_NAME, value))
        return x509.Name(name_parts)

    subject = parse_dn(subject_name)
    issuer = parse_dn(issuer_name)

    # Generate certificate
    now = datetime.utcnow()
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.serial_number(int(uuid.uuid4()))
    cert_builder = cert_builder.not_valid_before(now)
    cert_builder = cert_builder.not_valid_after(now + timedelta(days=validity_days))

    # Add extensions
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Sign the certificate
    certificate = cert_builder.sign(private_key, hashes.SHA256())

    # Return PEM encoded certificate
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


async def generate_default_keys_and_certs(
    storage_manager: Any, session: Any
) -> Dict[str, Any]:
    """Generate default keys and certificates for mDoc operations.

    Creates a complete set of cryptographic materials for mDoc issuance
    including ECDSA signing keys and X.509 certificates. All materials
    are generated according to ISO 18013-5 specifications and stored
    in the configured storage backend.

    Args:
        storage_manager: MdocStorageManager instance for persistent storage
        session: Database session for storage operations

    Returns:
        Dictionary containing generated identifiers:
        - key_id: Identifier for the signing key
        - cert_id: Identifier for the X.509 certificate
        - jwk: JSON Web Key for the generated key pair

    Raises:
        StorageError: If key/certificate storage fails
        RuntimeError: If key generation fails

    Example:
        >>> storage = MdocStorageManager(profile)
        >>> result = await generate_default_keys_and_certs(storage, session)
        >>> print(result['key_id'])  # 'mdoc-key-abc12345'
    """
    LOGGER.info("Generating default mDoc keys and certificates")

    # Generate key pair
    private_pem, public_pem, jwk = generate_ec_key_pair()
    key_id = f"mdoc-key-{uuid.uuid4().hex[:8]}"

    # Store the key
    await storage_manager.store_key(
        session,
        key_id=key_id,
        jwk=jwk,
        purpose="signing",
        metadata={
            "private_key_pem": private_pem,
            "public_key_pem": public_pem,
            "key_type": "EC",
            "curve": "P-256",
        },
    )

    # Generate certificate
    cert_pem = generate_self_signed_certificate(
        private_key_pem=private_pem,
        subject_name="CN=mDoc Test Issuer,O=ACA-Py,C=US",
        validity_days=365,
    )

    cert_id = f"mdoc-cert-{uuid.uuid4().hex[:8]}"

    # Store the certificate
    await storage_manager.store_certificate(
        session,
        cert_id=cert_id,
        certificate_pem=cert_pem,
        key_id=key_id,
        metadata={
            "self_signed": True,
            "purpose": "mdoc_issuing",
            "issuer_dn": "CN=mDoc Test Issuer,O=ACA-Py,C=US",
            "subject_dn": "CN=mDoc Test Issuer,O=ACA-Py,C=US",
            "valid_from": datetime.now().isoformat(),
            "valid_to": (datetime.now() + timedelta(days=365)).isoformat(),
        },
    )

    # Set as defaults
    await storage_manager.store_config(
        session, "default_signing_key", {"key_id": key_id}
    )
    await storage_manager.store_config(
        session, "default_certificate", {"cert_id": cert_id}
    )

    LOGGER.info("Generated default mDoc key: %s and certificate: %s", key_id, cert_id)

    return {
        "key_id": key_id,
        "cert_id": cert_id,
        "jwk": jwk,
        "private_key_pem": private_pem,
        "public_key_pem": public_pem,
        "certificate_pem": cert_pem,
    }
