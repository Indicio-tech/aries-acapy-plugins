"""Tests for MsoMdoc Verifier signature verification."""

import sys
from unittest.mock import MagicMock, patch
import pytest

# Mock dependencies before importing module under test
sys.modules["pydid"] = MagicMock()
sys.modules["acapy_agent"] = MagicMock()
sys.modules["acapy_agent.core"] = MagicMock()
sys.modules["acapy_agent.core.profile"] = MagicMock()
sys.modules["isomdl_uniffi"] = MagicMock()

from ..mdoc.verifier import MsoMdocCredVerifier, VerifyResult


# Helper to create a mock Mdoc with JSON-serializable return values
def create_mock_mdoc_class(verification_result):
    """Create a mock Mdoc class that returns JSON-serializable values."""
    class MockMdoc:
        def doctype(self):
            return "org.iso.18013.5.1.mDL"
        
        def id(self):
            return "mock_id_12345"
        
        def details(self):
            return {}
        
        def verify_issuer_signature(self, trust_anchors, enable_chaining):
            return verification_result
    
    return MockMdoc


@pytest.mark.asyncio
class TestMsoMdocVerifierSignature:
    """Tests for MsoMdoc Verifier signature verification."""

    async def test_verify_credential_verifies_issuer_signature(self):
        """
        Test that verify_credential verifies the issuer signature.
        
        This verifies that cryptographic verification of the issuer signature
        IS performed using the verify_issuer_signature method.
        """
        verifier = MsoMdocCredVerifier()
        profile = MagicMock()
        
        # Mock isomdl_uniffi to simulate successful parsing and verification
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl:
            # Create a proper exception class for MdocVerificationError
            class MockMdocVerificationError(Exception):
                pass
            mock_isomdl.MdocVerificationError = MockMdocVerificationError
            
            # Create verification result with JSON-serializable values
            class MockVerificationResult:
                verified = True
                common_name = "Test Issuer"
                error = None
            
            MockMdoc = create_mock_mdoc_class(MockVerificationResult())
            mock_isomdl.Mdoc.from_string.return_value = MockMdoc()
            
            # Use hex-encoded credential string to pass through hex parsing path
            hex_credential = "a1b2c3d4e5f6"
            
            result = await verifier.verify_credential(profile, hex_credential)
            
            # ASSERTION: The verification passes only after signature verification
            assert result.verified is True
            assert result.payload["status"] == "verified"
            assert result.payload["issuer_common_name"] == "Test Issuer"
            
            # Verify that we called Mdoc.from_string
            mock_isomdl.Mdoc.from_string.assert_called_once_with(hex_credential)

    async def test_verify_credential_fails_on_invalid_signature(self):
        """Test that verification fails if signature verification fails."""
        verifier = MsoMdocCredVerifier()
        profile = MagicMock()
        
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl:
            # Create a proper exception class for MdocVerificationError
            class MockMdocVerificationError(Exception):
                pass
            mock_isomdl.MdocVerificationError = MockMdocVerificationError
            
            # Create verification result indicating failure
            class MockVerificationResult:
                verified = False
                common_name = None
                error = "Signature verification failed"
            
            MockMdoc = create_mock_mdoc_class(MockVerificationResult())
            mock_isomdl.Mdoc.from_string.return_value = MockMdoc()
            
            # Use hex-encoded credential string
            hex_credential = "abcdef123456"
            
            result = await verifier.verify_credential(profile, hex_credential)
            
            # Verification should fail due to signature
            assert result.verified is False
            assert "Signature verification failed" in result.payload["error"]

    async def test_verify_credential_fails_on_verification_error(self):
        """Test that verification fails if verify_issuer_signature raises an error."""
        verifier = MsoMdocCredVerifier()
        profile = MagicMock()
        
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl:
            # Create a proper exception class for MdocVerificationError
            class MockMdocVerificationError(Exception):
                pass
            mock_isomdl.MdocVerificationError = MockMdocVerificationError
            
            # Create a mock Mdoc that raises an exception on verify_issuer_signature
            class MockMdocWithError:
                def doctype(self):
                    return "org.iso.18013.5.1.mDL"
                
                def id(self):
                    return "mock_id_12345"
                
                def details(self):
                    return {}
                
                def verify_issuer_signature(self, trust_anchors, enable_chaining):
                    raise MockMdocVerificationError("X5Chain header missing from issuer_auth")
            
            mock_isomdl.Mdoc.from_string.return_value = MockMdocWithError()
            
            # Use hex-encoded credential string
            hex_credential = "1234567890ab"
            
            result = await verifier.verify_credential(profile, hex_credential)
            
            # Verification should fail
            assert result.verified is False
            assert "X5Chain" in result.payload["error"]

    async def test_verify_credential_fails_on_structural_error(self):
        """Test that verification fails if parsing fails (structural error)."""
        verifier = MsoMdocCredVerifier()
        profile = MagicMock()
        
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl:
            # Create a proper exception class for MdocVerificationError
            class MockMdocVerificationError(Exception):
                pass
            mock_isomdl.MdocVerificationError = MockMdocVerificationError
            
            # Simulate parsing error on ALL parsing methods
            mock_isomdl.Mdoc.from_string.side_effect = Exception("CBOR error")
            mock_isomdl.Mdoc.new_from_base64url_encoded_issuer_signed.side_effect = Exception("CBOR error")
            
            # Use hex-encoded credential string
            hex_credential = "fedcba987654"
            
            result = await verifier.verify_credential(profile, hex_credential)
            
            assert result.verified is False
            assert "CBOR error" in result.payload["error"]
