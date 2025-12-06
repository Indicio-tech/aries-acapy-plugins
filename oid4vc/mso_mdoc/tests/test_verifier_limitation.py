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
            mock_mdoc = MagicMock()
            mock_mdoc.doctype.return_value = "org.iso.18013.5.1.mDL"
            mock_mdoc.id.return_value = "mock_id"
            
            # Mock the verification result
            mock_verification_result = MagicMock()
            mock_verification_result.verified = True
            mock_verification_result.common_name = "Test Issuer"
            mock_verification_result.error = None
            mock_mdoc.verify_issuer_signature.return_value = mock_verification_result
            
            mock_isomdl.Mdoc.from_string.return_value = mock_mdoc
            
            credential = "valid_signed_mdoc"
            
            result = await verifier.verify_credential(profile, credential)
            
            # ASSERTION: The verification passes only after signature verification
            assert result.verified is True
            assert result.payload["status"] == "verified"
            assert result.payload["issuer_common_name"] == "Test Issuer"
            
            # Verify that we called verify_issuer_signature
            mock_mdoc.verify_issuer_signature.assert_called_once()
            # Check that it was called with chaining enabled (True)
            args, _ = mock_mdoc.verify_issuer_signature.call_args
            assert args[1] is True

    async def test_verify_credential_fails_on_invalid_signature(self):
        """Test that verification fails if signature verification fails."""
        verifier = MsoMdocCredVerifier()
        profile = MagicMock()
        
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl:
            mock_mdoc = MagicMock()
            mock_mdoc.doctype.return_value = "org.iso.18013.5.1.mDL"
            mock_mdoc.id.return_value = "mock_id"
            
            # Mock verification failure
            mock_verification_result = MagicMock()
            mock_verification_result.verified = False
            mock_verification_result.common_name = None
            mock_verification_result.error = "Signature verification failed"
            mock_mdoc.verify_issuer_signature.return_value = mock_verification_result
            
            mock_isomdl.Mdoc.from_string.return_value = mock_mdoc
            
            result = await verifier.verify_credential(profile, "invalid_signature_mdoc")
            
            # Verification should fail due to signature
            assert result.verified is False
            assert "Signature verification failed" in result.payload["error"]

    async def test_verify_credential_fails_on_verification_error(self):
        """Test that verification fails if verify_issuer_signature raises an error."""
        verifier = MsoMdocCredVerifier()
        profile = MagicMock()
        
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl:
            mock_mdoc = MagicMock()
            mock_mdoc.doctype.return_value = "org.iso.18013.5.1.mDL"
            mock_mdoc.id.return_value = "mock_id"
            
            # Create a mock exception class
            mock_isomdl.MdocVerificationError = type("MdocVerificationError", (Exception,), {})
            
            # Mock verification to raise an error (e.g., X5ChainMissing)
            mock_mdoc.verify_issuer_signature.side_effect = mock_isomdl.MdocVerificationError(
                "X5Chain header missing from issuer_auth"
            )
            
            mock_isomdl.Mdoc.from_string.return_value = mock_mdoc
            
            result = await verifier.verify_credential(profile, "mdoc_without_x5chain")
            
            # Verification should fail
            assert result.verified is False
            assert "X5Chain" in result.payload["error"]

    async def test_verify_credential_fails_on_structural_error(self):
        """Test that verification fails if parsing fails (structural error)."""
        verifier = MsoMdocCredVerifier()
        profile = MagicMock()
        
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_isomdl:
            # Simulate parsing error
            mock_isomdl.Mdoc.from_string.side_effect = Exception("CBOR error")
            
            result = await verifier.verify_credential(profile, "invalid_structure")
            
            assert result.verified is False
            assert "CBOR error" in result.payload["error"]
