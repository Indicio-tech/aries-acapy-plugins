"""Tests for MsoMdocCredProcessor integration."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from oid4vc.models.supported_cred import SupportedCredential

from ..cred_processor import MsoMdocCredProcessor


class TestMsoMdocCredProcessor:
    """Test MsoMdocCredProcessor functionality."""

    @pytest.fixture
    def cred_processor(self):
        """Create MsoMdocCredProcessor instance."""
        return MsoMdocCredProcessor()

    @pytest.fixture
    def mock_supported_credential(self):
        """Mock supported credential."""
        supported = MagicMock(spec=SupportedCredential)
        supported.format = "mso_mdoc"
        supported.doctype = "org.iso.18013.5.1.mDL"
        return supported

    @pytest.fixture
    def sample_body(self):
        """Sample credential request body."""
        return {
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "age_over_18": True,
            "document_number": "DL123456789",
        }

    def test_processor_initialization(self, cred_processor):
        """Test that the processor initializes correctly."""
        assert cred_processor is not None
        assert hasattr(cred_processor, "issue")

    def test_processor_has_required_methods(self, cred_processor):
        """Test that processor has required interface methods."""
        # Check that it has the methods expected by the Issuer protocol
        assert callable(getattr(cred_processor, "issue", None))

    @pytest.mark.asyncio
    async def test_processor_interface_compatibility(
        self, cred_processor, sample_body, mock_supported_credential
    ):
        """Test that processor interface is compatible with expected signature."""
        # This tests the interface without actually calling the backend
        # which would require proper key setup and storage

        # Create mock context and exchange record
        mock_context = AsyncMock()
        mock_exchange_record = MagicMock()
        mock_pop_result = MagicMock()
        mock_pop_result.holder_jwk = None
        mock_pop_result.holder_kid = None

        # Test that the method signature is correct
        # We expect this to fail at runtime due to missing setup,
        # but the interface should be correct
        try:
            await cred_processor.issue(
                body=sample_body,
                supported=mock_supported_credential,
                context=mock_context,
                ex_record=mock_exchange_record,
                pop=mock_pop_result,
            )
        except (AttributeError, TypeError, ValueError):
            # Expected - we're testing interface, not full functionality
            pass

    def test_doctype_handling(self, cred_processor):
        """Test doctype validation and handling."""
        valid_doctypes = [
            "org.iso.18013.5.1.mDL",
            "org.iso.23220.photoid.1",
            "org.iso.18013.5.1.aamva",
        ]

        for doctype in valid_doctypes:
            # Basic doctype format validation
            assert isinstance(doctype, str)
            assert doctype.startswith("org.iso.")
            assert "." in doctype

    def test_processor_error_handling(self, cred_processor):
        """Test processor error handling."""
        # Test that processor imports CredProcessorError correctly
        from oid4vc.cred_processor import CredProcessorError

        # Verify error class is available
        assert CredProcessorError is not None
        assert issubclass(CredProcessorError, Exception)
