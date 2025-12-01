"""Tests for MsoMdoc Verifier implementation."""

import sys
from unittest.mock import MagicMock, mock_open, patch

import pytest

from oid4vc.models.presentation import OID4VPPresentation

from ..mdoc.verifier import (
    FileTrustStore,
    MsoMdocCredVerifier,
    MsoMdocPresVerifier,
    VerifyResult,
)

# Mock acapy_agent and dependencies before importing module under test
sys.modules["pydid"] = MagicMock()
sys.modules["acapy_agent"] = MagicMock()
sys.modules["acapy_agent.core"] = MagicMock()
sys.modules["acapy_agent.core.profile"] = MagicMock()

# Mock isomdl_uniffi since it's a native extension
sys.modules["isomdl_uniffi"] = MagicMock()


@pytest.fixture(autouse=True)
def mock_isomdl_module():
    """Mock isomdl_uniffi module."""
    # It's already mocked in sys.modules, but we can yield it for configuration
    return sys.modules["isomdl_uniffi"]


class TestFileTrustStore:
    """Test FileTrustStore functionality."""

    def test_get_trust_anchors_success(self):
        """Test retrieving trust anchors successfully."""
        with patch("os.path.isdir", return_value=True), patch(
            "os.listdir", return_value=["cert1.pem", "cert2.crt", "ignore.txt"]
        ), patch("builtins.open", mock_open(read_data="CERT_CONTENT")):
            store = FileTrustStore("/path/to/certs")
            anchors = store.get_trust_anchors()

            assert len(anchors) == 2
            assert anchors == ["CERT_CONTENT", "CERT_CONTENT"]

    def test_get_trust_anchors_no_dir(self):
        """Test handling of missing directory."""
        with patch("os.path.isdir", return_value=False):
            store = FileTrustStore("/invalid/path")
            anchors = store.get_trust_anchors()
            assert anchors == []

    def test_get_trust_anchors_read_error(self):
        """Test handling of file read errors."""
        with patch("os.path.isdir", return_value=True), patch(
            "os.listdir", return_value=["cert1.pem"]
        ), patch("builtins.open", side_effect=Exception("Read error")):
            store = FileTrustStore("/path/to/certs")
            anchors = store.get_trust_anchors()
            assert anchors == []


class TestMsoMdocCredVerifier:
    """Test MsoMdocCredVerifier functionality."""

    @pytest.mark.asyncio
    async def test_verify_credential_stub(self):
        """Test the stub implementation of verify_credential."""
        verifier = MsoMdocCredVerifier()
        profile = MagicMock()

        # Patch isomdl_uniffi in the verifier module
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl:
            # Test string input
            mock_isomdl.Mdoc.from_string.return_value = MagicMock()
            result = await verifier.verify_credential(profile, "credential_string")

            assert isinstance(result, VerifyResult)
            assert result.verified is True
            mock_isomdl.Mdoc.from_string.assert_called_once_with("credential_string")


class TestMsoMdocPresVerifier:
    """Test MsoMdocPresVerifier functionality."""

    @pytest.fixture
    def verifier(self):
        """Create verifier instance."""
        return MsoMdocPresVerifier()

    @pytest.fixture
    def mock_presentation(self):
        """Create mock presentation."""
        pres = MagicMock(spec=OID4VPPresentation)
        pres.verifiable_presentation = "base64_encoded_vp"
        pres.pres_def_id = "mock_pres_def_id"
        pres.presentation_submission = MagicMock()
        pres.presentation_submission.descriptor_map = [
            MagicMock(path="$.vp_token", format="mso_mdoc")
        ]
        pres.nonce = "test_nonce"
        return pres

    @pytest.mark.asyncio
    async def test_verify_presentation_success(self, verifier, mock_presentation):
        """Test successful presentation verification."""
        profile = MagicMock()
        presentation_data = "mock_presentation_data"

        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl, patch(
            "mso_mdoc.mdoc.verifier.Config"
        ) as mock_config:
            mock_config.from_settings.return_value.endpoint = "http://test-endpoint"

            # Setup Enum constants
            mock_isomdl.AuthenticationStatus.VALID = "VALID"

            # Mock verify_oid4vp_response result
            mock_response_data = MagicMock()
            mock_response_data.issuer_authentication = "VALID"
            mock_response_data.device_authentication = "VALID"
            mock_response_data.errors = []
            mock_response_data.verified_response_as_json.return_value = {
                "data": "verified"
            }

            mock_isomdl.verify_oid4vp_response.return_value = mock_response_data

            result = await verifier.verify_presentation(
                profile, presentation_data, mock_presentation
            )

            assert isinstance(result, VerifyResult)
            assert result.verified is True
            assert result.payload == {"data": "verified"}

            mock_isomdl.verify_oid4vp_response.assert_called_once()
            mock_response_data.verified_response_as_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_presentation_failure(self, verifier, mock_presentation):
        """Test failed presentation verification."""
        profile = MagicMock()
        presentation_data = "mock_presentation_data"

        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl, patch(
            "mso_mdoc.mdoc.verifier.Config"
        ) as mock_config:
            mock_config.from_settings.return_value.endpoint = "http://test-endpoint"

            # Setup Enum constants
            mock_isomdl.AuthenticationStatus.VALID = "VALID"
            mock_isomdl.AuthenticationStatus.INVALID = "INVALID"

            # Mock verify_oid4vp_response failure
            mock_response_data = MagicMock()
            mock_response_data.issuer_authentication = "INVALID"
            mock_response_data.device_authentication = "VALID"
            mock_response_data.errors = ["Issuer auth failed"]
            mock_response_data.verified_response_as_json.return_value = {}

            mock_isomdl.verify_oid4vp_response.return_value = mock_response_data

            result = await verifier.verify_presentation(
                profile, presentation_data, mock_presentation
            )

            assert result.verified is False
            assert "Issuer auth failed" in result.payload["error"]

    @pytest.mark.asyncio
    async def test_verify_presentation_exception(self, verifier, mock_presentation):
        """Test exception handling during verification."""
        profile = MagicMock()
        presentation_data = "mock_presentation_data"

        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl, patch(
            "mso_mdoc.mdoc.verifier.Config"
        ) as mock_config:
            mock_config.from_settings.return_value.endpoint = "http://test-endpoint"

            mock_isomdl.verify_oid4vp_response.side_effect = Exception("Native error")

            result = await verifier.verify_presentation(
                profile, presentation_data, mock_presentation
            )

            assert result.verified is False
            assert "Native error" in str(result.payload["error"])
