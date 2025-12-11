"""Unit tests for MdocStorageManager."""

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from acapy_agent.storage.base import StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from ..storage import (
    MDOC_CERT_RECORD_TYPE,
    MDOC_KEY_RECORD_TYPE,
    MDOC_TRUST_ANCHOR_RECORD_TYPE,
    MdocStorageManager,
)
from ..storage import keys, certificates, trust_anchors, config


@pytest.fixture
def storage_manager():
    return MdocStorageManager(MagicMock())


@pytest.fixture
def session():
    return MagicMock()


@pytest.fixture
def storage(monkeypatch):
    mock_storage = AsyncMock()
    # Patch get_storage in all submodules so they return our mock
    monkeypatch.setattr(keys, "get_storage", MagicMock(return_value=mock_storage))
    monkeypatch.setattr(certificates, "get_storage", MagicMock(return_value=mock_storage))
    monkeypatch.setattr(trust_anchors, "get_storage", MagicMock(return_value=mock_storage))
    monkeypatch.setattr(config, "get_storage", MagicMock(return_value=mock_storage))
    return mock_storage


@pytest.fixture
def sample_jwk():
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": "x-coordinate",
        "y": "y-coordinate",
        "d": "private",
    }


@pytest.mark.asyncio
async def test_store_key_persists_record_and_metadata(
    storage_manager, session, storage, sample_jwk
):
    await storage_manager.store_key(session, "key-123", sample_jwk, purpose="signing")

    storage.add_record.assert_awaited_once()
    record = storage.add_record.await_args.args[0]
    assert record.type == MDOC_KEY_RECORD_TYPE
    assert record.id == "key-123"

    payload = json.loads(record.value)
    assert payload["jwk"] == sample_jwk
    assert payload["purpose"] == "signing"
    assert "created_at" in payload
    assert payload["metadata"] == {}
    assert record.tags == {"purpose": "signing"}


@pytest.mark.asyncio
async def test_get_key_returns_jwk(storage_manager, session, storage, sample_jwk):
    record = StorageRecord(
        type=MDOC_KEY_RECORD_TYPE,
        id="key-123",
        value=json.dumps({"jwk": sample_jwk, "purpose": "signing"}),
        tags={"purpose": "signing"},
    )
    storage.get_record = AsyncMock(return_value=record)

    result = await storage_manager.get_key(session, "key-123")

    assert result == sample_jwk
    storage.get_record.assert_awaited_once_with(MDOC_KEY_RECORD_TYPE, "key-123")


@pytest.mark.asyncio
async def test_get_key_returns_none_when_not_found(storage_manager, session, storage):
    storage.get_record = AsyncMock(side_effect=StorageNotFoundError())

    result = await storage_manager.get_key(session, "missing")

    assert result is None


@pytest.mark.asyncio
async def test_list_keys_filters_by_purpose_and_shapes_output(
    storage_manager, session, storage, sample_jwk
):
    stored = {
        "jwk": sample_jwk,
        "purpose": "signing",
        "created_at": "2024-01-01T00:00:00",
        "metadata": {"verification_method": "did:example#1"},
    }
    records = [
        StorageRecord(
            type=MDOC_KEY_RECORD_TYPE,
            id="key-1",
            value=json.dumps(stored),
            tags={"purpose": "signing"},
        )
    ]
    storage.find_all_records = AsyncMock(return_value=records)

    result = await storage_manager.list_keys(session, purpose="signing")

    storage.find_all_records.assert_awaited_once_with(
        type_filter=MDOC_KEY_RECORD_TYPE,
        tag_query={"purpose": "signing"},
    )
    assert result == [
        {
            "key_id": "key-1",
            "jwk": sample_jwk,
            "purpose": "signing",
            "created_at": "2024-01-01T00:00:00",
            "metadata": {"verification_method": "did:example#1"},
        }
    ]


@pytest.mark.asyncio
async def test_delete_key_removes_record(storage_manager, session, storage):
    record = StorageRecord(type=MDOC_KEY_RECORD_TYPE, id="key-1", value="{}", tags={})
    storage.get_record = AsyncMock(return_value=record)
    storage.delete_record = AsyncMock()

    result = await storage_manager.delete_key(session, "key-1")

    assert result is True
    storage.delete_record.assert_awaited_once_with(record)


@pytest.mark.asyncio
async def test_delete_key_returns_false_when_missing(storage_manager, session, storage):
    storage.get_record = AsyncMock(side_effect=StorageNotFoundError())

    result = await storage_manager.delete_key(session, "missing")

    assert result is False


@pytest.mark.asyncio
async def test_store_signing_key_requires_jwk(storage_manager, session, storage, sample_jwk):
    with pytest.raises(ValueError):
        await storage_manager.store_signing_key(session, "key-1", {})

    # With the storage fixture, the module-level store_key will use the mock storage
    metadata = {"jwk": sample_jwk, "key_id": "key-1"}
    await storage_manager.store_signing_key(session, "key-1", metadata)

    # Verify the storage was called correctly
    storage.add_record.assert_awaited_once()
    record = storage.add_record.await_args.args[0]
    payload = json.loads(record.value)
    assert payload["purpose"] == "signing"


@pytest.mark.asyncio
async def test_store_config_updates_when_record_exists(storage_manager, session, storage):
    storage.add_record = AsyncMock(side_effect=StorageError("duplicate"))
    storage.update_record = AsyncMock()

    await storage_manager.store_config(session, "default_certificate", {"cert_id": "cert-1"})

    storage.update_record.assert_awaited_once()
    update_record, value, tags = storage.update_record.await_args.args
    assert update_record.id == "default_certificate"
    assert json.loads(value) == {"cert_id": "cert-1"}
    # Tags can be None or empty dict depending on StorageRecord defaults
    assert tags is None or tags == {}


@pytest.mark.asyncio
async def test_store_certificate_persists_record(storage_manager, session, storage):
    await storage_manager.store_certificate(
        session,
        cert_id="cert-1",
        certificate_pem="pem-data",
        key_id="key-1",
        metadata={"issuer": "test"},
    )

    storage.add_record.assert_awaited_once()
    record = storage.add_record.await_args.args[0]
    assert record.type == MDOC_CERT_RECORD_TYPE
    assert record.id == "cert-1"

    payload = json.loads(record.value)
    assert payload["certificate_pem"] == "pem-data"
    assert payload["key_id"] == "key-1"
    assert payload["metadata"] == {"issuer": "test"}


@pytest.mark.asyncio
async def test_get_certificate_returns_pem_and_key(storage_manager, session, storage):
    record = StorageRecord(
        type=MDOC_CERT_RECORD_TYPE,
        id="cert-1",
        value=json.dumps({"certificate_pem": "pem", "key_id": "key-1"}),
        tags={"key_id": "key-1"},
    )
    storage.get_record = AsyncMock(return_value=record)

    result = await storage_manager.get_certificate(session, "cert-1")

    assert result == ("pem", "key-1")
    storage.get_record.assert_awaited_once_with(MDOC_CERT_RECORD_TYPE, "cert-1")


@pytest.mark.asyncio
async def test_list_certificates_returns_formatted_data(storage_manager, session, storage):
    records = [
        StorageRecord(
            type=MDOC_CERT_RECORD_TYPE,
            id="cert-1",
            value=json.dumps(
                {
                    "certificate_pem": "pem",
                    "key_id": "key-1",
                    "created_at": "2024-01-01T00:00:00",
                    "metadata": {"issuer": "test"},
                }
            ),
            tags={"key_id": "key-1"},
        )
    ]
    storage.find_all_records = AsyncMock(return_value=records)

    result = await storage_manager.list_certificates(session)

    assert result == [
        {
            "cert_id": "cert-1",
            "key_id": "key-1",
            "created_at": "2024-01-01T00:00:00",
            "metadata": {"issuer": "test"},
        }
    ]


@pytest.mark.asyncio
async def test_get_default_signing_key_auto_selects_when_missing_config(
    storage_manager, session, storage, sample_jwk
):
    # Mock get_config to return None (no default configured)
    storage.get_record = AsyncMock(side_effect=StorageNotFoundError())
    
    # Mock list_keys to return a key
    key_record = StorageRecord(
        type=MDOC_KEY_RECORD_TYPE,
        id="key-1",
        value=json.dumps({
            "jwk": sample_jwk,
            "purpose": "signing",
            "created_at": "ts",
            "metadata": {},
        }),
        tags={"purpose": "signing"},
    )
    storage.find_all_records = AsyncMock(return_value=[key_record])
    storage.add_record = AsyncMock()
    storage.update_record = AsyncMock()

    key = await storage_manager.get_default_signing_key(session)

    assert key["key_id"] == "key-1"


@pytest.mark.asyncio
async def test_get_signing_key_matches_verification_method_fragment(
    storage_manager, session, storage, sample_jwk
):
    # Mock list_keys to return keys with verification method metadata
    records = [
        StorageRecord(
            type=MDOC_KEY_RECORD_TYPE,
            id="key-1",
            value=json.dumps({
                "jwk": sample_jwk,
                "purpose": "signing",
                "created_at": "ts",
                "metadata": {"verification_method": "did:example#key-1"},
            }),
            tags={"purpose": "signing"},
        ),
        StorageRecord(
            type=MDOC_KEY_RECORD_TYPE,
            id="key-2",
            value=json.dumps({
                "jwk": sample_jwk,
                "purpose": "signing",
                "created_at": "ts",
                "metadata": {"key_id": "frag-key"},
            }),
            tags={"purpose": "signing"},
        ),
    ]
    storage.find_all_records = AsyncMock(return_value=records)

    result = await storage_manager.get_signing_key(
        session, verification_method="did:example#frag-key"
    )

    assert result["key_id"] == "key-2"


@pytest.mark.asyncio
async def test_get_default_certificate_returns_configured_certificate(storage_manager, session, storage):
    now = datetime.utcnow()
    cert_data = {
        "certificate_pem": "pem-data",
        "key_id": "key-1",
        "created_at": now.isoformat(),
        "metadata": {
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_to": (now + timedelta(days=1)).isoformat(),
        },
    }
    
    # Mock get_config to return the cert_id
    config_record = StorageRecord(
        type="mdoc_config",
        id="default_certificate",
        value=json.dumps({"cert_id": "cert-1"}),
        tags={},
    )
    
    # Mock list_certificates to return the certificate
    cert_record = StorageRecord(
        type=MDOC_CERT_RECORD_TYPE,
        id="cert-1",
        value=json.dumps(cert_data),
        tags={"key_id": "key-1"},
    )
    
    storage.get_record = AsyncMock(return_value=config_record)
    storage.find_all_records = AsyncMock(return_value=[cert_record])

    result = await storage_manager.get_default_certificate(session)

    assert result["cert_id"] == "cert-1"


@pytest.mark.asyncio
async def test_get_signing_key_and_cert_combines_key_and_certificate(
    storage_manager, session, storage, sample_jwk
):
    # Mock keys
    key_records = [
        StorageRecord(
            type=MDOC_KEY_RECORD_TYPE,
            id="key-1",
            value=json.dumps({
                "jwk": sample_jwk,
                "purpose": "signing",
                "created_at": "t1",
                "metadata": {},
            }),
            tags={"purpose": "signing"},
        ),
        StorageRecord(
            type=MDOC_KEY_RECORD_TYPE,
            id="key-2",
            value=json.dumps({
                "jwk": sample_jwk,
                "purpose": "signing",
                "created_at": "t2",
                "metadata": {},
            }),
            tags={"purpose": "signing"},
        ),
    ]
    
    # Mock certificates - only key-1 has a cert
    cert_records = [
        StorageRecord(
            type=MDOC_CERT_RECORD_TYPE,
            id="cert-1",
            value=json.dumps({
                "certificate_pem": "pem-1",
                "key_id": "key-1",
                "created_at": "tc",
                "metadata": {},
            }),
            tags={"key_id": "key-1"},
        )
    ]
    
    # Set up storage mock to return different records based on type filter
    async def find_records_side_effect(type_filter, tag_query=None):
        if type_filter == MDOC_KEY_RECORD_TYPE:
            return key_records
        elif type_filter == MDOC_CERT_RECORD_TYPE:
            return cert_records
        return []
    
    storage.find_all_records = AsyncMock(side_effect=find_records_side_effect)
    storage.get_record = AsyncMock(return_value=cert_records[0])

    result = await storage_manager.get_signing_key_and_cert(session)

    assert result[0]["certificate_pem"] == "pem-1"
    assert result[1]["certificate_pem"] is None


@pytest.mark.asyncio
async def test_get_certificate_for_key_returns_pem(storage_manager, session, storage):
    record_value = json.dumps({"certificate_pem": "pem-data", "key_id": "key-1"})
    storage.find_all_records = AsyncMock(
        return_value=[
            StorageRecord(
                type=MDOC_CERT_RECORD_TYPE,
                id="cert-1",
                value=record_value,
                tags={"key_id": "key-1"},
            )
        ]
    )

    result = await storage_manager.get_certificate_for_key(session, "key-1")

    storage.find_all_records.assert_awaited_once_with(
        type_filter=MDOC_CERT_RECORD_TYPE,
        tag_query={"key_id": "key-1"},
    )
    assert result == "pem-data"


# =============================================================================
# Trust Anchor Storage Tests
# =============================================================================


@pytest.fixture
def sample_trust_anchor_pem():
    return """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpXQCWDVMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBlRl
c3RDQTCB0ACAAAGVFDAxOEwxMTAwMzA1OEwxLTAwMzA1RQQJxAw0SkBGAAGVFDAx
OEwxMTAwMzA1RQQJxAw0SkBGAAGVFDAxOEwxMTAwMzA1OEwxMTAwMzA1OEwxMTAw
MzA1RQQJxAw0SkBGAAGVFDAxOEwxMTAwMzA1OEwxMTAwMzA1RQQJxAw0SkBGAAGV
-----END CERTIFICATE-----"""


@pytest.mark.asyncio
async def test_store_trust_anchor_persists_record(
    storage_manager, session, storage, sample_trust_anchor_pem
):
    await storage_manager.store_trust_anchor(
        session,
        anchor_id="anchor-1",
        certificate_pem=sample_trust_anchor_pem,
        metadata={"issuer": "Test CA"},
    )

    storage.add_record.assert_awaited_once()
    record = storage.add_record.await_args.args[0]
    assert record.type == MDOC_TRUST_ANCHOR_RECORD_TYPE
    assert record.id == "anchor-1"

    payload = json.loads(record.value)
    assert payload["certificate_pem"] == sample_trust_anchor_pem
    assert payload["metadata"] == {"issuer": "Test CA"}
    assert "created_at" in payload


@pytest.mark.asyncio
async def test_get_trust_anchor_returns_data(
    storage_manager, session, storage, sample_trust_anchor_pem
):
    record_value = json.dumps({
        "certificate_pem": sample_trust_anchor_pem,
        "created_at": "2024-01-01T00:00:00",
        "metadata": {"issuer": "Test CA"},
    })
    storage.get_record = AsyncMock(
        return_value=StorageRecord(
            type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
            id="anchor-1",
            value=record_value,
            tags={"type": "trust_anchor"},
        )
    )

    result = await storage_manager.get_trust_anchor(session, "anchor-1")

    assert result is not None
    assert result["anchor_id"] == "anchor-1"
    assert result["certificate_pem"] == sample_trust_anchor_pem
    assert result["metadata"] == {"issuer": "Test CA"}


@pytest.mark.asyncio
async def test_get_trust_anchor_returns_none_when_not_found(
    storage_manager, session, storage
):
    storage.get_record = AsyncMock(side_effect=StorageNotFoundError())

    result = await storage_manager.get_trust_anchor(session, "nonexistent")

    assert result is None


@pytest.mark.asyncio
async def test_list_trust_anchors_returns_all(
    storage_manager, session, storage, sample_trust_anchor_pem
):
    records = [
        StorageRecord(
            type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
            id="anchor-1",
            value=json.dumps({
                "certificate_pem": sample_trust_anchor_pem,
                "created_at": "2024-01-01T00:00:00",
                "metadata": {"issuer": "CA1"},
            }),
            tags={"type": "trust_anchor"},
        ),
        StorageRecord(
            type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
            id="anchor-2",
            value=json.dumps({
                "certificate_pem": sample_trust_anchor_pem,
                "created_at": "2024-01-02T00:00:00",
                "metadata": {"issuer": "CA2"},
            }),
            tags={"type": "trust_anchor"},
        ),
    ]
    storage.find_all_records = AsyncMock(return_value=records)

    result = await storage_manager.list_trust_anchors(session)

    assert len(result) == 2
    assert result[0]["anchor_id"] == "anchor-1"
    assert result[1]["anchor_id"] == "anchor-2"


@pytest.mark.asyncio
async def test_get_all_trust_anchor_pems_returns_pems(
    storage_manager, session, storage, sample_trust_anchor_pem
):
    records = [
        StorageRecord(
            type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
            id="anchor-1",
            value=json.dumps({
                "certificate_pem": sample_trust_anchor_pem,
                "created_at": "2024-01-01T00:00:00",
            }),
            tags={},
        ),
    ]
    storage.find_all_records = AsyncMock(return_value=records)

    result = await storage_manager.get_all_trust_anchor_pems(session)

    assert len(result) == 1
    assert result[0] == sample_trust_anchor_pem


@pytest.mark.asyncio
async def test_delete_trust_anchor_removes_record(storage_manager, session, storage):
    record = StorageRecord(
        type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
        id="anchor-1",
        value="{}",
        tags={},
    )
    storage.get_record = AsyncMock(return_value=record)
    storage.delete_record = AsyncMock()

    result = await storage_manager.delete_trust_anchor(session, "anchor-1")

    assert result is True
    storage.delete_record.assert_awaited_once_with(record)


@pytest.mark.asyncio
async def test_delete_trust_anchor_returns_false_when_not_found(
    storage_manager, session, storage
):
    storage.get_record = AsyncMock(side_effect=StorageNotFoundError())

    result = await storage_manager.delete_trust_anchor(session, "nonexistent")

    assert result is False
