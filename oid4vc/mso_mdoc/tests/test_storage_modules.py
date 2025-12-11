"""Unit tests for storage submodules.

These tests cover the standalone functions in the storage submodules
(keys, certificates, trust_anchors, config, base) to ensure they work
correctly independent of MdocStorageManager.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from acapy_agent.storage.base import StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from ..storage import (
    MDOC_CERT_RECORD_TYPE,
    MDOC_CONFIG_RECORD_TYPE,
    MDOC_KEY_RECORD_TYPE,
    MDOC_TRUST_ANCHOR_RECORD_TYPE,
)
from ..storage import keys, certificates, trust_anchors, config
from ..storage.base import get_storage


# =============================================================================
# Base Module Tests
# =============================================================================


class TestGetStorage:
    """Tests for base.get_storage function."""

    def test_get_storage_injects_from_session(self):
        """Test that get_storage injects BaseStorage from session."""
        mock_storage = MagicMock()
        mock_session = MagicMock()
        mock_session.inject.return_value = mock_storage

        result = get_storage(mock_session)

        assert result == mock_storage
        mock_session.inject.assert_called_once()

    def test_get_storage_raises_on_injection_failure(self):
        """Test that get_storage raises when injection fails."""
        mock_session = MagicMock()
        mock_session.inject.side_effect = Exception("Injection failed")

        with pytest.raises(Exception, match="Injection failed"):
            get_storage(mock_session)


# =============================================================================
# Keys Module Tests
# =============================================================================


class TestKeysModule:
    """Tests for keys module functions."""

    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def mock_storage(self):
        return AsyncMock()

    @pytest.fixture
    def sample_jwk(self):
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": "test-x",
            "y": "test-y",
            "d": "test-d",
        }

    @pytest.mark.asyncio
    async def test_store_key_with_metadata(self, mock_session, mock_storage, sample_jwk):
        """Test storing key with custom metadata."""
        with patch.object(keys, "get_storage", return_value=mock_storage):
            await keys.store_key(
                mock_session,
                "key-1",
                sample_jwk,
                purpose="encryption",
                metadata={"custom": "data"},
            )

            mock_storage.add_record.assert_awaited_once()
            record = mock_storage.add_record.await_args.args[0]
            payload = json.loads(record.value)
            assert payload["purpose"] == "encryption"
            assert payload["metadata"] == {"custom": "data"}

    @pytest.mark.asyncio
    async def test_store_key_raises_on_storage_error(self, mock_session, sample_jwk):
        """Test that store_key raises StorageError when storage unavailable."""
        with patch.object(keys, "get_storage", side_effect=StorageError("unavailable")):
            with pytest.raises(StorageError, match="Cannot store key"):
                await keys.store_key(mock_session, "key-1", sample_jwk)

    @pytest.mark.asyncio
    async def test_get_key_handles_json_decode_error(self, mock_session, mock_storage):
        """Test get_key returns None on invalid JSON."""
        record = StorageRecord(
            type=MDOC_KEY_RECORD_TYPE,
            id="key-1",
            value="invalid-json",
            tags={},
        )
        mock_storage.get_record = AsyncMock(return_value=record)

        with patch.object(keys, "get_storage", return_value=mock_storage):
            result = await keys.get_key(mock_session, "key-1")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_key_handles_storage_unavailable(self, mock_session):
        """Test get_key returns None when storage unavailable."""
        with patch.object(keys, "get_storage", side_effect=Exception("unavailable")):
            result = await keys.get_key(mock_session, "key-1")
            assert result is None

    @pytest.mark.asyncio
    async def test_list_keys_without_purpose_filter(self, mock_session, mock_storage, sample_jwk):
        """Test listing all keys without purpose filter."""
        records = [
            StorageRecord(
                type=MDOC_KEY_RECORD_TYPE,
                id="key-1",
                value=json.dumps({
                    "jwk": sample_jwk,
                    "purpose": "signing",
                    "created_at": "2024-01-01T00:00:00",
                    "metadata": {},
                }),
                tags={"purpose": "signing"},
            ),
        ]
        mock_storage.find_all_records = AsyncMock(return_value=records)

        with patch.object(keys, "get_storage", return_value=mock_storage):
            result = await keys.list_keys(mock_session)

            mock_storage.find_all_records.assert_awaited_once_with(
                type_filter=MDOC_KEY_RECORD_TYPE,
                tag_query={},
            )
            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_keys_handles_storage_unavailable(self, mock_session):
        """Test list_keys returns empty list when storage unavailable."""
        with patch.object(keys, "get_storage", side_effect=Exception("unavailable")):
            result = await keys.list_keys(mock_session)
            assert result == []

    @pytest.mark.asyncio
    async def test_list_keys_handles_storage_error(self, mock_session, mock_storage):
        """Test list_keys returns empty list on StorageError."""
        mock_storage.find_all_records = AsyncMock(side_effect=StorageError("error"))

        with patch.object(keys, "get_storage", return_value=mock_storage):
            result = await keys.list_keys(mock_session)
            assert result == []

    @pytest.mark.asyncio
    async def test_delete_key_handles_storage_unavailable(self, mock_session):
        """Test delete_key returns False when storage unavailable."""
        with patch.object(keys, "get_storage", side_effect=Exception("unavailable")):
            result = await keys.delete_key(mock_session, "key-1")
            assert result is False

    @pytest.mark.asyncio
    async def test_store_signing_key_validates_jwk_field(self, mock_session):
        """Test store_signing_key raises ValueError without jwk."""
        with pytest.raises(ValueError, match="must contain 'jwk' field"):
            await keys.store_signing_key(mock_session, "key-1", {"other": "data"})

    @pytest.mark.asyncio
    async def test_store_signing_key_success(self, mock_session, mock_storage, sample_jwk):
        """Test store_signing_key delegates to store_key correctly."""
        with patch.object(keys, "get_storage", return_value=mock_storage):
            await keys.store_signing_key(
                mock_session,
                "key-1",
                {"jwk": sample_jwk, "key_id": "key-1"},
            )

            mock_storage.add_record.assert_awaited_once()
            record = mock_storage.add_record.await_args.args[0]
            payload = json.loads(record.value)
            assert payload["purpose"] == "signing"


# =============================================================================
# Certificates Module Tests
# =============================================================================


class TestCertificatesModule:
    """Tests for certificates module functions."""

    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def mock_storage(self):
        return AsyncMock()

    @pytest.fixture
    def sample_pem(self):
        return "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"

    @pytest.mark.asyncio
    async def test_store_certificate_handles_storage_unavailable(
        self, mock_session, sample_pem
    ):
        """Test store_certificate silently handles unavailable storage."""
        with patch.object(certificates, "get_storage", side_effect=Exception("unavailable")):
            # Should not raise, just log warning
            await certificates.store_certificate(
                mock_session, "cert-1", sample_pem, "key-1"
            )

    @pytest.mark.asyncio
    async def test_store_certificate_with_metadata(
        self, mock_session, mock_storage, sample_pem
    ):
        """Test storing certificate with metadata."""
        with patch.object(certificates, "get_storage", return_value=mock_storage):
            await certificates.store_certificate(
                mock_session,
                "cert-1",
                sample_pem,
                "key-1",
                metadata={"issuer": "Test CA"},
            )

            record = mock_storage.add_record.await_args.args[0]
            payload = json.loads(record.value)
            assert payload["metadata"] == {"issuer": "Test CA"}
            assert record.tags == {"key_id": "key-1"}

    @pytest.mark.asyncio
    async def test_get_certificate_handles_storage_unavailable(self, mock_session):
        """Test get_certificate returns None when storage unavailable."""
        with patch.object(certificates, "get_storage", side_effect=Exception("unavailable")):
            result = await certificates.get_certificate(mock_session, "cert-1")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_certificate_handles_json_error(self, mock_session, mock_storage):
        """Test get_certificate handles invalid JSON."""
        record = StorageRecord(
            type=MDOC_CERT_RECORD_TYPE,
            id="cert-1",
            value="invalid-json",
            tags={},
        )
        mock_storage.get_record = AsyncMock(return_value=record)

        with patch.object(certificates, "get_storage", return_value=mock_storage):
            result = await certificates.get_certificate(mock_session, "cert-1")
            assert result is None

    @pytest.mark.asyncio
    async def test_list_certificates_with_pem(self, mock_session, mock_storage, sample_pem):
        """Test list_certificates includes PEM when requested."""
        records = [
            StorageRecord(
                type=MDOC_CERT_RECORD_TYPE,
                id="cert-1",
                value=json.dumps({
                    "certificate_pem": sample_pem,
                    "key_id": "key-1",
                    "created_at": "2024-01-01T00:00:00",
                    "metadata": {},
                }),
                tags={"key_id": "key-1"},
            ),
        ]
        mock_storage.find_all_records = AsyncMock(return_value=records)

        with patch.object(certificates, "get_storage", return_value=mock_storage):
            result = await certificates.list_certificates(mock_session, include_pem=True)

            assert len(result) == 1
            assert "certificate_pem" in result[0]
            assert result[0]["certificate_pem"] == sample_pem

    @pytest.mark.asyncio
    async def test_list_certificates_without_pem(self, mock_session, mock_storage, sample_pem):
        """Test list_certificates excludes PEM by default."""
        records = [
            StorageRecord(
                type=MDOC_CERT_RECORD_TYPE,
                id="cert-1",
                value=json.dumps({
                    "certificate_pem": sample_pem,
                    "key_id": "key-1",
                    "created_at": "2024-01-01T00:00:00",
                    "metadata": {},
                }),
                tags={"key_id": "key-1"},
            ),
        ]
        mock_storage.find_all_records = AsyncMock(return_value=records)

        with patch.object(certificates, "get_storage", return_value=mock_storage):
            result = await certificates.list_certificates(mock_session, include_pem=False)

            assert len(result) == 1
            assert "certificate_pem" not in result[0]

    @pytest.mark.asyncio
    async def test_list_certificates_handles_storage_unavailable(self, mock_session):
        """Test list_certificates returns empty list when storage unavailable."""
        with patch.object(certificates, "get_storage", side_effect=Exception("unavailable")):
            result = await certificates.list_certificates(mock_session)
            assert result == []

    @pytest.mark.asyncio
    async def test_get_certificate_for_key_no_records(self, mock_session, mock_storage):
        """Test get_certificate_for_key returns None when no records found."""
        mock_storage.find_all_records = AsyncMock(return_value=[])

        with patch.object(certificates, "get_storage", return_value=mock_storage):
            result = await certificates.get_certificate_for_key(mock_session, "key-1")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_certificate_for_key_handles_storage_unavailable(self, mock_session):
        """Test get_certificate_for_key returns None when storage unavailable."""
        with patch.object(certificates, "get_storage", side_effect=Exception("unavailable")):
            result = await certificates.get_certificate_for_key(mock_session, "key-1")
            assert result is None


# =============================================================================
# Trust Anchors Module Tests
# =============================================================================


class TestTrustAnchorsModule:
    """Tests for trust_anchors module functions."""

    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def mock_storage(self):
        return AsyncMock()

    @pytest.fixture
    def sample_anchor_pem(self):
        return "-----BEGIN CERTIFICATE-----\nROOT CA\n-----END CERTIFICATE-----"

    @pytest.mark.asyncio
    async def test_store_trust_anchor_raises_on_storage_error(
        self, mock_session, sample_anchor_pem
    ):
        """Test store_trust_anchor raises StorageError when storage unavailable."""
        with patch.object(trust_anchors, "get_storage", side_effect=StorageError("unavailable")):
            with pytest.raises(StorageError, match="Cannot store trust anchor"):
                await trust_anchors.store_trust_anchor(
                    mock_session, "anchor-1", sample_anchor_pem
                )

    @pytest.mark.asyncio
    async def test_store_trust_anchor_with_metadata(
        self, mock_session, mock_storage, sample_anchor_pem
    ):
        """Test storing trust anchor with metadata."""
        with patch.object(trust_anchors, "get_storage", return_value=mock_storage):
            await trust_anchors.store_trust_anchor(
                mock_session,
                "anchor-1",
                sample_anchor_pem,
                metadata={"issuer": "Root CA", "purpose": "mdoc"},
            )

            record = mock_storage.add_record.await_args.args[0]
            payload = json.loads(record.value)
            assert payload["metadata"] == {"issuer": "Root CA", "purpose": "mdoc"}
            assert record.tags == {"type": "trust_anchor"}

    @pytest.mark.asyncio
    async def test_get_trust_anchor_handles_storage_unavailable(self, mock_session):
        """Test get_trust_anchor returns None when storage unavailable."""
        with patch.object(trust_anchors, "get_storage", side_effect=Exception("unavailable")):
            result = await trust_anchors.get_trust_anchor(mock_session, "anchor-1")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_trust_anchor_handles_json_error(self, mock_session, mock_storage):
        """Test get_trust_anchor returns None on invalid JSON."""
        record = StorageRecord(
            type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
            id="anchor-1",
            value="invalid-json",
            tags={},
        )
        mock_storage.get_record = AsyncMock(return_value=record)

        with patch.object(trust_anchors, "get_storage", return_value=mock_storage):
            result = await trust_anchors.get_trust_anchor(mock_session, "anchor-1")
            assert result is None

    @pytest.mark.asyncio
    async def test_list_trust_anchors_handles_storage_unavailable(self, mock_session):
        """Test list_trust_anchors returns empty list when storage unavailable."""
        with patch.object(trust_anchors, "get_storage", side_effect=Exception("unavailable")):
            result = await trust_anchors.list_trust_anchors(mock_session)
            assert result == []

    @pytest.mark.asyncio
    async def test_list_trust_anchors_handles_storage_error(self, mock_session, mock_storage):
        """Test list_trust_anchors returns empty list on StorageError."""
        mock_storage.find_all_records = AsyncMock(side_effect=StorageError("error"))

        with patch.object(trust_anchors, "get_storage", return_value=mock_storage):
            result = await trust_anchors.list_trust_anchors(mock_session)
            assert result == []

    @pytest.mark.asyncio
    async def test_get_all_trust_anchor_pems_handles_storage_unavailable(self, mock_session):
        """Test get_all_trust_anchor_pems returns empty list when unavailable."""
        with patch.object(trust_anchors, "get_storage", side_effect=Exception("unavailable")):
            result = await trust_anchors.get_all_trust_anchor_pems(mock_session)
            assert result == []

    @pytest.mark.asyncio
    async def test_get_all_trust_anchor_pems_handles_storage_error(
        self, mock_session, mock_storage
    ):
        """Test get_all_trust_anchor_pems returns empty list on StorageError."""
        mock_storage.find_all_records = AsyncMock(side_effect=StorageError("error"))

        with patch.object(trust_anchors, "get_storage", return_value=mock_storage):
            result = await trust_anchors.get_all_trust_anchor_pems(mock_session)
            assert result == []

    @pytest.mark.asyncio
    async def test_delete_trust_anchor_handles_storage_unavailable(self, mock_session):
        """Test delete_trust_anchor returns False when storage unavailable."""
        with patch.object(trust_anchors, "get_storage", side_effect=Exception("unavailable")):
            result = await trust_anchors.delete_trust_anchor(mock_session, "anchor-1")
            assert result is False

    @pytest.mark.asyncio
    async def test_delete_trust_anchor_handles_storage_error(self, mock_session, mock_storage):
        """Test delete_trust_anchor returns False on StorageError during delete."""
        record = StorageRecord(
            type=MDOC_TRUST_ANCHOR_RECORD_TYPE,
            id="anchor-1",
            value="{}",
            tags={},
        )
        mock_storage.get_record = AsyncMock(return_value=record)
        mock_storage.delete_record = AsyncMock(side_effect=StorageError("delete failed"))

        with patch.object(trust_anchors, "get_storage", return_value=mock_storage):
            result = await trust_anchors.delete_trust_anchor(mock_session, "anchor-1")
            assert result is False


# =============================================================================
# Config Module Tests
# =============================================================================


class TestConfigModule:
    """Tests for config module functions."""

    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def mock_storage(self):
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_store_config_handles_storage_unavailable(self, mock_session):
        """Test store_config silently handles unavailable storage."""
        with patch.object(config, "get_storage", side_effect=Exception("unavailable")):
            # Should not raise, just log warning
            await config.store_config(mock_session, "test-config", {"key": "value"})

    @pytest.mark.asyncio
    async def test_store_config_creates_new_record(self, mock_session, mock_storage):
        """Test store_config creates a new record."""
        with patch.object(config, "get_storage", return_value=mock_storage):
            await config.store_config(mock_session, "test-config", {"key": "value"})

            mock_storage.add_record.assert_awaited_once()
            record = mock_storage.add_record.await_args.args[0]
            assert record.type == MDOC_CONFIG_RECORD_TYPE
            assert record.id == "test-config"
            assert json.loads(record.value) == {"key": "value"}

    @pytest.mark.asyncio
    async def test_store_config_updates_existing_record(self, mock_session, mock_storage):
        """Test store_config updates when record exists."""
        mock_storage.add_record = AsyncMock(side_effect=StorageError("duplicate"))
        mock_storage.update_record = AsyncMock()

        with patch.object(config, "get_storage", return_value=mock_storage):
            await config.store_config(mock_session, "test-config", {"updated": "value"})

            mock_storage.update_record.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_store_config_raises_on_update_failure(self, mock_session, mock_storage):
        """Test store_config raises when both add and update fail."""
        mock_storage.add_record = AsyncMock(side_effect=StorageError("duplicate"))
        mock_storage.update_record = AsyncMock(side_effect=StorageError("update failed"))

        with patch.object(config, "get_storage", return_value=mock_storage):
            with pytest.raises(StorageError, match="update failed"):
                await config.store_config(mock_session, "test-config", {"key": "value"})

    @pytest.mark.asyncio
    async def test_get_config_handles_storage_unavailable(self, mock_session):
        """Test get_config returns None when storage unavailable."""
        with patch.object(config, "get_storage", side_effect=Exception("unavailable")):
            result = await config.get_config(mock_session, "test-config")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_config_returns_data(self, mock_session, mock_storage):
        """Test get_config returns stored configuration."""
        record = StorageRecord(
            type=MDOC_CONFIG_RECORD_TYPE,
            id="test-config",
            value=json.dumps({"key": "value"}),
            tags={},
        )
        mock_storage.get_record = AsyncMock(return_value=record)

        with patch.object(config, "get_storage", return_value=mock_storage):
            result = await config.get_config(mock_session, "test-config")
            assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_get_config_returns_none_on_not_found(self, mock_session, mock_storage):
        """Test get_config returns None when config not found."""
        mock_storage.get_record = AsyncMock(side_effect=StorageNotFoundError())

        with patch.object(config, "get_storage", return_value=mock_storage):
            result = await config.get_config(mock_session, "missing")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_config_returns_none_on_json_error(self, mock_session, mock_storage):
        """Test get_config returns None on invalid JSON."""
        record = StorageRecord(
            type=MDOC_CONFIG_RECORD_TYPE,
            id="test-config",
            value="invalid-json",
            tags={},
        )
        mock_storage.get_record = AsyncMock(return_value=record)

        with patch.object(config, "get_storage", return_value=mock_storage):
            result = await config.get_config(mock_session, "test-config")
            assert result is None
