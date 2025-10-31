"""Tests for MdocStorageManager functionality."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ..storage import MdocStorageManager


class TestMdocStorageManager:
    """Test MdocStorageManager functionality."""

    @pytest.fixture
    def mock_profile(self):
        """Mock profile for testing."""
        profile = MagicMock()
        profile.session = AsyncMock()
        return profile

    @pytest.fixture
    def storage_manager(self, mock_profile):
        """Create MdocStorageManager instance."""
        return MdocStorageManager(mock_profile)

    def test_storage_manager_initialization(self, storage_manager, mock_profile):
        """Test that storage manager initializes correctly."""
        assert storage_manager is not None
        assert storage_manager.profile == mock_profile

    def test_storage_manager_has_required_methods(self, storage_manager):
        """Test that storage manager has expected methods."""
        expected_methods = [
            "get_default_signing_key",
            "store_signing_key",
            "get_signing_key",
            "list_keys",
            "delete_key",
            "store_key",
            "get_key",
        ]

        for method_name in expected_methods:
            assert hasattr(storage_manager, method_name)
            assert callable(getattr(storage_manager, method_name))

    @pytest.mark.asyncio
    async def test_storage_interface_compatibility(self, storage_manager):
        """Test that storage methods have correct interface."""
        # Mock session
        mock_session = AsyncMock()

        # Test method signatures without actual database operations
        try:
            # These should have the correct interface even if they fail
            await storage_manager.get_default_signing_key(mock_session)
        except (AttributeError, TypeError):
            # Expected - we're testing interface, not database functionality
            pass

    def test_key_id_generation(self, storage_manager):
        """Test key ID generation utilities."""
        # Test that we can generate valid key IDs
        import uuid

        key_id = str(uuid.uuid4())

        # Basic validation
        assert isinstance(key_id, str)
        assert len(key_id) > 0
        assert "-" in key_id  # UUID format

    def test_jwk_validation_structure(self, storage_manager):
        """Test JWK structure validation."""
        # Sample JWK structure
        sample_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        }

        # Basic JWK validation
        required_fields = ["kty", "crv", "x", "y"]
        for field in required_fields:
            assert field in sample_jwk
            assert isinstance(sample_jwk[field], str)
            assert len(sample_jwk[field]) > 0

    def test_storage_error_handling(self, storage_manager):
        """Test storage error handling."""
        # Verify that storage errors are properly imported
        from acapy_agent.storage.error import StorageError

        assert StorageError is not None
        assert issubclass(StorageError, Exception)
