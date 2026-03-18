"""Tests for certificate management and trust-registry auto-registration.

These tests verify that:
1. Storing a certificate automatically registers it as a trust anchor.
2. The list_certificates API returns PEMs by default.
3. Certificate chains are split and each cert is registered individually.
4. Duplicate certificates are not re-registered.
5. Key generation auto-populates the trust registry.
6. [BUG] generate_keys early-return path (existing key) also back-fills the
   trust registry so deployments upgraded from pre-auto-register are healed.
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from acapy_agent.storage.base import StorageRecord

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..storage import (
    MDOC_CERT_RECORD_TYPE,
    MDOC_TRUST_ANCHOR_RECORD_TYPE,
    MdocStorageManager,
    certificates,
    config,
    keys,
    trust_anchors,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gen_self_signed_pem() -> str:
    """Generate a self-signed P-256 certificate and return its PEM string."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _gen_chain_pems() -> tuple[str, str, str]:
    """Generate a root → leaf certificate chain.

    Returns (root_pem, leaf_pem, chain_pem) where chain_pem = leaf + root.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf DS")]))
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(root_key, hashes.SHA256())
    )

    root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
    return root_pem, leaf_pem, leaf_pem + root_pem


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def storage_manager():
    return MdocStorageManager(MagicMock())


@pytest.fixture
def session():
    return MagicMock()


@pytest.fixture
def storage(monkeypatch):
    mock_storage = AsyncMock()
    monkeypatch.setattr(keys, "get_storage", MagicMock(return_value=mock_storage))
    monkeypatch.setattr(certificates, "get_storage", MagicMock(return_value=mock_storage))
    monkeypatch.setattr(
        trust_anchors, "get_storage", MagicMock(return_value=mock_storage)
    )
    monkeypatch.setattr(config, "get_storage", MagicMock(return_value=mock_storage))
    return mock_storage


# =========================================================================
# auto_register_trust_anchors
# =========================================================================


@pytest.mark.asyncio
async def test_auto_register_single_cert(storage_manager, session, storage):
    """A single PEM cert is registered as a trust anchor."""
    pem = _gen_self_signed_pem()
    # No existing trust anchors
    storage.find_all_records = AsyncMock(return_value=[])

    created = await storage_manager.auto_register_trust_anchors(session, pem)

    assert len(created) == 1
    assert created[0].startswith("auto-")
    # add_record called once for the new trust anchor
    storage.add_record.assert_awaited_once()
    record = storage.add_record.await_args.args[0]
    assert record.type == MDOC_TRUST_ANCHOR_RECORD_TYPE
    payload = json.loads(record.value)
    assert payload["metadata"]["auto_registered"] is True


@pytest.mark.asyncio
async def test_auto_register_chain_pem_creates_two_anchors(
    storage_manager, session, storage
):
    """A chain PEM (leaf + root) adds one trust anchor per cert."""
    _root, _leaf, chain = _gen_chain_pems()
    storage.find_all_records = AsyncMock(return_value=[])

    created = await storage_manager.auto_register_trust_anchors(session, chain)

    assert len(created) == 2
    assert storage.add_record.await_count == 2


@pytest.mark.asyncio
async def test_auto_register_skips_duplicates(storage_manager, session, storage):
    """Certs already in the trust registry are not re-added."""
    pem = _gen_self_signed_pem()

    # Simulate existing trust anchor with the same PEM
    existing_record = StorageRecord(
        type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
        id="existing-anchor",
        value=json.dumps({"certificate_pem": pem.strip(), "created_at": "t"}),
        tags={},
    )
    storage.find_all_records = AsyncMock(return_value=[existing_record])

    created = await storage_manager.auto_register_trust_anchors(session, pem)

    assert created == []
    storage.add_record.assert_not_awaited()


@pytest.mark.asyncio
async def test_auto_register_non_pem_input_returns_empty(
    storage_manager, session, storage
):
    """Non-PEM text is ignored."""
    created = await storage_manager.auto_register_trust_anchors(session, "not a cert")
    assert created == []
    storage.add_record.assert_not_awaited()


# =========================================================================
# store_certificate → auto trust-anchor registration
# =========================================================================


@pytest.mark.asyncio
async def test_store_certificate_auto_adds_trust_anchor(
    storage_manager, session, storage
):
    """Storing a certificate with a valid PEM auto-registers a trust anchor."""
    pem = _gen_self_signed_pem()
    # No existing trust anchors
    storage.find_all_records = AsyncMock(return_value=[])

    await storage_manager.store_certificate(
        session,
        cert_id="cert-1",
        certificate_pem=pem,
        key_id="key-1",
    )

    # Two add_record calls: one for the cert, one for the trust anchor
    assert storage.add_record.await_count == 2
    types = [storage.add_record.await_args_list[i].args[0].type for i in range(2)]
    assert MDOC_CERT_RECORD_TYPE in types
    assert MDOC_TRUST_ANCHOR_RECORD_TYPE in types


@pytest.mark.asyncio
async def test_store_certificate_non_pem_does_not_add_trust_anchor(
    storage_manager, session, storage
):
    """Storing a cert with non-PEM data only creates the cert record."""
    await storage_manager.store_certificate(
        session,
        cert_id="cert-1",
        certificate_pem="raw-data-not-pem",
        key_id="key-1",
    )

    # Only the certificate record is stored
    storage.add_record.assert_awaited_once()
    record = storage.add_record.await_args.args[0]
    assert record.type == MDOC_CERT_RECORD_TYPE


# =========================================================================
# list_certificates — PEM returned by default
# =========================================================================


@pytest.mark.asyncio
async def test_list_certificates_includes_pem_by_default(
    storage_manager, session, storage
):
    """list_certificates(include_pem=True) returns certificate_pem field."""
    records = [
        StorageRecord(
            type=MDOC_CERT_RECORD_TYPE,
            id="cert-1",
            value=json.dumps(
                {
                    "certificate_pem": "pem-data",
                    "key_id": "key-1",
                    "created_at": "2024-01-01T00:00:00",
                    "metadata": {},
                }
            ),
            tags={"key_id": "key-1"},
        )
    ]
    storage.find_all_records = AsyncMock(return_value=records)

    result = await storage_manager.list_certificates(session, include_pem=True)

    assert len(result) == 1
    assert "certificate_pem" in result[0]
    assert result[0]["certificate_pem"] == "pem-data"


@pytest.mark.asyncio
async def test_list_certificates_omits_pem_when_requested(
    storage_manager, session, storage
):
    """list_certificates(include_pem=False) omits certificate_pem field."""
    records = [
        StorageRecord(
            type=MDOC_CERT_RECORD_TYPE,
            id="cert-1",
            value=json.dumps(
                {
                    "certificate_pem": "pem-data",
                    "key_id": "key-1",
                    "created_at": "2024-01-01T00:00:00",
                    "metadata": {},
                }
            ),
            tags={"key_id": "key-1"},
        )
    ]
    storage.find_all_records = AsyncMock(return_value=records)

    result = await storage_manager.list_certificates(session, include_pem=False)

    assert "certificate_pem" not in result[0]


# =========================================================================
# generate_default_keys_and_certs → trust-anchor auto-registration
# =========================================================================


@pytest.mark.asyncio
async def test_generate_keys_auto_registers_trust_anchor(session, storage):
    """generate_default_keys_and_certs adds the cert to the trust registry."""
    from ..key_generation import generate_default_keys_and_certs

    storage.find_all_records = AsyncMock(return_value=[])
    manager = MdocStorageManager(MagicMock())

    result = await generate_default_keys_and_certs(manager, session)

    # Should have add_record calls for: key, certificate, config×2, trust anchor
    assert result["key_id"]
    assert result["cert_id"]
    assert result["certificate_pem"]

    # Verify trust anchor was created
    add_calls = storage.add_record.await_args_list
    record_types = [call.args[0].type for call in add_calls]
    assert MDOC_TRUST_ANCHOR_RECORD_TYPE in record_types, (
        "Trust anchor should be auto-registered during key generation"
    )

    # Find the trust anchor record and verify its content
    for call in add_calls:
        rec = call.args[0]
        if rec.type == MDOC_TRUST_ANCHOR_RECORD_TYPE:
            payload = json.loads(rec.value)
            assert "-----BEGIN CERTIFICATE-----" in payload["certificate_pem"]
            assert payload["metadata"]["auto_registered"] is True
            break


# =========================================================================
# BUG: generate_keys early-return path skips trust-anchor back-fill
# =========================================================================


@pytest.mark.asyncio
async def test_generate_keys_existing_key_still_backfills_trust_registry():
    """When generate_keys finds a pre-existing key it MUST still register the
    cert as a trust anchor.

    REGRESSION: Before the fix, the early-return path returned immediately
    after finding an existing key without calling auto_register_trust_anchors.
    This left the trust registry empty for any deployment that had keys created
    before the auto-register feature was merged, causing every presentation
    verification to fail with:
        "IACA certificate error: no valid trust anchor found"

    This test FAILS before the fix and PASSES after.
    """
    from contextlib import asynccontextmanager

    from ..key_routes import generate_keys

    cert_pem = _gen_self_signed_pem()
    key_id = "existing-key-001"
    cert_id = "existing-cert-001"

    manager_mock = MagicMock()
    manager_mock.get_default_signing_key = AsyncMock(
        return_value={
            "key_id": key_id,
            "purpose": "signing",
            "metadata": {"is_default": True},
        }
    )
    # list_certificates returns certs WITHOUT PEM (default include_pem=False)
    manager_mock.list_certificates = AsyncMock(
        return_value=[{"key_id": key_id, "cert_id": cert_id}]
    )
    # get_certificate_for_key returns the actual PEM
    manager_mock.get_certificate_for_key = AsyncMock(return_value=cert_pem)
    manager_mock.auto_register_trust_anchors = AsyncMock(return_value=["auto-anchor-1"])

    session_mock = MagicMock()

    @asynccontextmanager
    async def _mock_session():
        yield session_mock

    mock_profile = MagicMock()
    mock_profile.session = _mock_session
    mock_context = MagicMock()
    mock_context.profile = mock_profile

    mock_request = MagicMock()
    mock_request.query.get = MagicMock(return_value="")  # force=false
    mock_request.__getitem__ = MagicMock(return_value=mock_context)

    with patch("mso_mdoc.key_routes.MdocStorageManager", return_value=manager_mock):
        response = await generate_keys(mock_request)

    assert response.status == 200

    # The critical assertion: auto_register_trust_anchors MUST be called even
    # when the route returns early (existing key found).
    manager_mock.auto_register_trust_anchors.assert_awaited_once_with(
        session_mock, cert_pem
    )
