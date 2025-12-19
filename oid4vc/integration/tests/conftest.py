"""Simplified integration test fixtures for OID4VC v1 flows.

This module provides pytest fixtures for testing the complete OID4VC v1 flow:
ACA-Py Issues → Credo Receives → Credo Presents → ACA-Py Verifies

Certificate Strategy:
- Certificates are generated dynamically in-memory at test setup time
- Trust anchors are uploaded to both ACA-Py verifier and Credo via their HTTP APIs
- NO filesystem-based certificate storage is used
- This approach avoids triggering security scanning tools on static cert files
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acapy_controller import Controller

# Environment configuration
CREDO_AGENT_URL = os.getenv("CREDO_AGENT_URL", "http://localhost:3020")
SPHEREON_WRAPPER_URL = os.getenv("SPHEREON_WRAPPER_URL", "http://localhost:3010")
ACAPY_ISSUER_ADMIN_URL = os.getenv("ACAPY_ISSUER_ADMIN_URL", "http://localhost:8021")
ACAPY_ISSUER_OID4VCI_URL = os.getenv(
    "ACAPY_ISSUER_OID4VCI_URL", "http://localhost:8022"
)
ACAPY_VERIFIER_ADMIN_URL = os.getenv(
    "ACAPY_VERIFIER_ADMIN_URL", "http://localhost:8031"
)
ACAPY_VERIFIER_OID4VP_URL = os.getenv(
    "ACAPY_VERIFIER_OID4VP_URL", "http://localhost:8032"
)


@pytest_asyncio.fixture
async def credo_client():
    """HTTP client for Credo agent service."""
    async with httpx.AsyncClient(base_url=CREDO_AGENT_URL, timeout=30.0) as client:
        # Wait for service to be ready
        for _ in range(5):  # Reduced since services should already be ready
            response = await client.get("/health")
            if response.status_code == 200:
                break
            await asyncio.sleep(1)
        else:
            raise RuntimeError("Credo agent service not available")

        yield client


@pytest_asyncio.fixture
async def sphereon_client():
    """HTTP client for Sphereon wrapper service."""
    async with httpx.AsyncClient(base_url=SPHEREON_WRAPPER_URL, timeout=30.0) as client:
        # Wait for service to be ready
        for _ in range(5):
            try:
                response = await client.get("/health")
                if response.status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            await asyncio.sleep(1)
        else:
            raise RuntimeError("Sphereon wrapper service not available")

        yield client


@pytest_asyncio.fixture
async def acapy_issuer_admin():
    """ACA-Py issuer admin API controller."""
    controller = Controller(ACAPY_ISSUER_ADMIN_URL)

    # Wait for ACA-Py issuer to be ready
    for _ in range(30):
        status = await controller.get("/status/ready")
        if status.get("ready") is True:
            break
        await asyncio.sleep(1)
    else:
        raise RuntimeError("ACA-Py issuer service not available")

    yield controller


@pytest_asyncio.fixture
async def acapy_verifier_admin():
    """ACA-Py verifier admin API controller."""
    controller = Controller(ACAPY_VERIFIER_ADMIN_URL)

    # Wait for ACA-Py verifier to be ready
    for _ in range(30):
        status = await controller.get("/status/ready")
        if status.get("ready") is True:
            break
        await asyncio.sleep(1)
    else:
        raise RuntimeError("ACA-Py verifier service not available")

    yield controller


# Legacy fixture for backward compatibility
@pytest_asyncio.fixture
async def acapy_admin(acapy_verifier_admin):
    """Legacy alias for acapy_verifier_admin to maintain backward compatibility."""
    yield acapy_verifier_admin


# Controller fixture for DCQL tests
@pytest_asyncio.fixture
async def controller(acapy_verifier_admin):
    """Controller fixture for DCQL tests - uses verifier admin API."""
    yield acapy_verifier_admin


# =============================================================================
# Certificate Generation Fixtures
# =============================================================================


def _generate_ec_key():
    """Generate an EC P-256 key."""
    return ec.generate_private_key(ec.SECP256R1())


def _get_name(cn: str) -> x509.Name:
    """Create an X.509 name with a common name."""
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "UT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _add_iaca_extensions(builder, key, issuer_key, is_ca=True, is_root=False):
    """Add IACA-compliant extensions to certificate builder."""
    if is_ca:
        path_length = 1 if is_root else 0
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")]),
            critical=True,
        )

    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )

    # Authority Key Identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    )

    # CRL Distribution Points
    builder = builder.add_extension(
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier("https://example.com/test.crl")
                    ],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                )
            ]
        ),
        critical=False,
    )

    # Issuer Alternative Name
    builder = builder.add_extension(
        x509.IssuerAlternativeName(
            [x509.UniformResourceIdentifier("https://example.com")]
        ),
        critical=False,
    )

    return builder


def _generate_root_ca(key):
    """Generate a self-signed root CA certificate."""
    name = _get_name("Test Root CA")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.not_valid_before(datetime.now(UTC))
    builder = builder.not_valid_after(datetime.now(UTC) + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = _add_iaca_extensions(builder, key, key, is_ca=True, is_root=True)
    return builder.sign(key, hashes.SHA256())


def _generate_intermediate_ca(key, issuer_key, issuer_name):
    """Generate an intermediate CA certificate."""
    name = _get_name("Test Intermediate CA")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.now(UTC))
    builder = builder.not_valid_after(datetime.now(UTC) + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = _add_iaca_extensions(builder, key, issuer_key, is_ca=True, is_root=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _generate_leaf_ds(key, issuer_key, issuer_name):
    """Generate a leaf document signer certificate."""
    name = _get_name("Test Leaf DS")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.now(UTC))
    builder = builder.not_valid_after(datetime.now(UTC) + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = _add_iaca_extensions(builder, key, issuer_key, is_ca=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _key_to_pem(key) -> str:
    """Convert a private key to PEM string."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _cert_to_pem(cert) -> str:
    """Convert a certificate to PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture(scope="session")
def generated_test_certs() -> dict[str, Any]:
    """Generate an ephemeral test certificate chain.

    This fixture generates a complete PKI hierarchy for testing:
    - Root CA (trust anchor)
    - Intermediate CA
    - Leaf DS (document signer) certificate

    Returns:
        Dictionary containing:
        - root_ca_pem: Root CA certificate PEM
        - root_ca_key_pem: Root CA private key PEM
        - intermediate_ca_pem: Intermediate CA certificate PEM
        - intermediate_ca_key_pem: Intermediate CA private key PEM
        - leaf_cert_pem: Leaf certificate PEM
        - leaf_key_pem: Leaf private key PEM
        - leaf_chain_pem: Leaf + Intermediate chain PEM (for x5chain)
    """
    # Generate Root CA
    root_key = _generate_ec_key()
    root_cert = _generate_root_ca(root_key)

    # Generate Intermediate CA
    inter_key = _generate_ec_key()
    inter_cert = _generate_intermediate_ca(inter_key, root_key, root_cert.subject)

    # Generate Leaf DS
    leaf_key = _generate_ec_key()
    leaf_cert = _generate_leaf_ds(leaf_key, inter_key, inter_cert.subject)

    # Create chain PEM (leaf + intermediate for x5chain)
    leaf_pem = _cert_to_pem(leaf_cert)
    inter_pem = _cert_to_pem(inter_cert)
    chain_pem = leaf_pem + inter_pem

    return {
        "root_ca_pem": _cert_to_pem(root_cert),
        "root_ca_key_pem": _key_to_pem(root_key),
        "intermediate_ca_pem": inter_pem,
        "intermediate_ca_key_pem": _key_to_pem(inter_key),
        "leaf_cert_pem": leaf_pem,
        "leaf_key_pem": _key_to_pem(leaf_key),
        "leaf_chain_pem": chain_pem,
    }


@pytest_asyncio.fixture
async def setup_issuer_certs(acapy_issuer_admin):
    """Ensure the issuer has signing keys and certificates.

    This fixture:
    1. Checks if a default certificate already exists
    2. If not, generates a signing key with proper ISO 18013-5 compliant extensions
    3. Retrieves the DEFAULT certificate that will be used for signing

    Note: We avoid using force=true to prevent regenerating keys between tests
    in the same session, which would cause certificate mismatch errors.

    Args:
        acapy_issuer_admin: ACA-Py issuer admin controller

    Yields:
        Dictionary with key_id, cert_id, and certificate_pem
    """
    # First, check if a default certificate already exists
    # If it does, use it instead of regenerating
    try:
        default_cert = await acapy_issuer_admin.get("/mso_mdoc/certificates/default")
        certificate_pem = default_cert.get("certificate_pem")

        if certificate_pem:
            yield {
                "key_id": default_cert.get("key_id"),
                "cert_id": default_cert.get("cert_id"),
                "certificate_pem": certificate_pem,
            }
            return
    except Exception:
        # No default cert exists, we'll need to generate one
        pass

    # Generate keys via admin API (without force=true, so it only creates if needed)
    # This ensures we get certificates with the required ISO 18013-5 extensions
    # (SubjectKeyIdentifier, CRLDistributionPoints, IssuerAlternativeName)
    try:
        result = await acapy_issuer_admin.post("/mso_mdoc/generate-keys", json={})
        key_id = result.get("key_id")
        cert_id = result.get("cert_id")
    except Exception:
        # Keys may already exist, that's OK
        key_id = None
        cert_id = None

    # Get the DEFAULT signing certificate - this is the one that will be used
    # for credential issuance, not just any certificate in the wallet
    try:
        default_cert = await acapy_issuer_admin.get("/mso_mdoc/certificates/default")
        certificate_pem = default_cert.get("certificate_pem")

        if not certificate_pem:
            raise RuntimeError(
                "Certificate PEM not found in default certificate response"
            )

        yield {
            "key_id": default_cert.get("key_id"),
            "cert_id": default_cert.get("cert_id"),
            "certificate_pem": certificate_pem,
        }
    except Exception as e:
        # Fall back to listing certificates if default endpoint fails
        certs_response = await acapy_issuer_admin.get(
            "/mso_mdoc/certificates?include_pem=true"
        )
        certificates = certs_response.get("certificates", [])

        if not certificates:
            raise RuntimeError(
                f"No certificates found on issuer after key generation: {e}"
            ) from e

        # Use the first certificate (fallback)
        issuer_cert = certificates[0]
        certificate_pem = issuer_cert.get("certificate_pem")

        if not certificate_pem:
            raise RuntimeError("Certificate PEM not found in issuer certificate")

        yield {
            "key_id": key_id or issuer_cert.get("key_id"),
            "cert_id": cert_id or issuer_cert.get("cert_id"),
            "certificate_pem": certificate_pem,
        }


@pytest_asyncio.fixture
async def setup_verifier_trust_anchors(acapy_verifier_admin, setup_issuer_certs):
    """Upload trust anchors to the verifier wallet via admin API.

    This fixture uploads the issuer's signing certificate as a trust anchor
    to the verifier's wallet for mDoc verification.

    Args:
        acapy_verifier_admin: ACA-Py verifier admin controller
        setup_issuer_certs: Issuer certificate fixture (provides the actual cert)

    Yields:
        Dictionary with anchor_id
    """
    # Upload issuer's certificate as trust anchor
    try:
        result = await acapy_verifier_admin.post(
            "/mso_mdoc/trust-anchors",
            json={
                "certificate_pem": setup_issuer_certs["certificate_pem"],
                "anchor_id": "issuer-signing-cert",
                "metadata": {
                    "description": "Issuer signing certificate",
                    "purpose": "integration-testing",
                },
            },
        )
        yield {"anchor_id": result.get("anchor_id")}

        # Cleanup after test
        try:
            await acapy_verifier_admin.delete(
                f"/mso_mdoc/trust-anchors/{result.get('anchor_id')}"
            )
        except Exception:
            pass  # Cleanup failure is not critical

    except Exception as e:
        # Trust anchor may already exist
        anchors = await acapy_verifier_admin.get("/mso_mdoc/trust-anchors")
        if anchors.get("trust_anchors"):
            yield {"anchor_id": anchors["trust_anchors"][0]["anchor_id"]}
        else:
            raise RuntimeError(f"Failed to setup trust anchors: {e}") from e


@pytest_asyncio.fixture
async def setup_credo_trust_anchors(credo_client, setup_issuer_certs):
    """Upload trust anchors to Credo agent via HTTP API.

    This fixture uploads the issuer's signing certificate as a trust anchor
    to Credo's X509 module for mDoc verification.

    Args:
        credo_client: HTTP client for Credo agent
        setup_issuer_certs: Issuer certificate fixture (provides the actual cert)

    Yields:
        Dictionary with status
    """
    # Upload issuer certificate as trust anchor to Credo
    try:
        response = await credo_client.post(
            "/x509/trust-anchors",
            json={
                "certificate_pem": setup_issuer_certs["certificate_pem"],
            },
        )
        response.raise_for_status()
        result = response.json()
        print(f"Uploaded trust anchor to Credo: {result}")
        yield {"status": "success"}

    except Exception as e:
        # Check if trust anchors were set
        try:
            response = await credo_client.get("/x509/trust-anchors")
            anchors = response.json()
            if anchors.get("count", 0) > 0:
                yield {"status": "already_configured"}
            else:
                raise RuntimeError(f"Failed to setup Credo trust anchors: {e}") from e
        except Exception:
            raise RuntimeError(f"Failed to setup Credo trust anchors: {e}") from e


@pytest_asyncio.fixture
async def setup_all_trust_anchors(
    setup_verifier_trust_anchors, setup_credo_trust_anchors, setup_issuer_certs
):
    """Convenience fixture that sets up trust anchors in all agents.

    This fixture ensures both ACA-Py verifier and Credo have the same
    trust anchor configured before tests run. The trust anchor is the
    actual certificate used by the issuer for signing mDocs.

    Args:
        setup_verifier_trust_anchors: ACA-Py verifier trust anchor fixture
        setup_credo_trust_anchors: Credo trust anchor fixture
        setup_issuer_certs: Issuer certificate fixture

    Yields:
        Dictionary with all setup results
    """
    yield {
        "verifier": setup_verifier_trust_anchors,
        "credo": setup_credo_trust_anchors,
        "issuer_cert_pem": setup_issuer_certs["certificate_pem"],
    }


@pytest_asyncio.fixture
async def setup_pki_chain_trust_anchor(acapy_verifier_admin, generated_test_certs):
    """Upload the generated root CA as trust anchor for PKI chain tests.

    This fixture is specifically for tests that manually create mDocs
    using the leaf certificate from generated_test_certs. It uploads
    the root CA so the verifier can validate the full PKI chain.

    Args:
        acapy_verifier_admin: ACA-Py verifier admin controller
        generated_test_certs: Generated test certificate chain

    Yields:
        Dictionary with anchor_id
    """
    # Upload root CA as trust anchor
    try:
        result = await acapy_verifier_admin.post(
            "/mso_mdoc/trust-anchors",
            json={
                "certificate_pem": generated_test_certs["root_ca_pem"],
                "anchor_id": "pki-test-root-ca",
                "metadata": {
                    "description": "Ephemeral test root CA for PKI chain tests",
                    "purpose": "pki-chain-testing",
                },
            },
        )
        yield {"anchor_id": result.get("anchor_id")}

        # Cleanup after test
        try:
            await acapy_verifier_admin.delete(
                f"/mso_mdoc/trust-anchors/{result.get('anchor_id')}"
            )
        except Exception:
            pass  # Cleanup failure is not critical

    except Exception as e:
        # Trust anchor may already exist
        anchors = await acapy_verifier_admin.get("/mso_mdoc/trust-anchors")
        if anchors.get("trust_anchors"):
            # Look for existing PKI chain anchor or use first one
            for anchor in anchors["trust_anchors"]:
                if anchor.get("anchor_id") == "pki-test-root-ca":
                    yield {"anchor_id": anchor["anchor_id"]}
                    return
            yield {"anchor_id": anchors["trust_anchors"][0]["anchor_id"]}
        else:
            raise RuntimeError(f"Failed to setup PKI chain trust anchor: {e}") from e
