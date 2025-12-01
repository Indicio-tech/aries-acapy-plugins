import pytest
import json
from unittest.mock import MagicMock, AsyncMock, patch
from mso_mdoc.cred_processor import MsoMdocCredProcessor
from mso_mdoc.key_generation import generate_ec_key_pair, generate_self_signed_certificate
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.pop_result import PopResult

# Check if isomdl is available
try:
    import isomdl_uniffi
    ISOMDL_AVAILABLE = True
except ImportError:
    ISOMDL_AVAILABLE = False

@pytest.mark.skipif(not ISOMDL_AVAILABLE, reason="isomdl_uniffi not available")
@pytest.mark.asyncio
async def test_issue_credential_functional():
    """
    Functional test for MsoMdocCredProcessor.issue().
    Uses real isomdl library and generated keys, but mocks storage/profile.
    """
    # 1. Setup Keys
    private_key_pem, public_key_pem, jwk = generate_ec_key_pair()
    cert_pem = generate_self_signed_certificate(private_key_pem)
    
    # 2. Mock Storage Manager
    # We patch the class in the module where it is used
    with patch("mso_mdoc.cred_processor.MdocStorageManager") as MockStorageManager:
        mock_storage = MockStorageManager.return_value
        
        # Mock get_signing_key to return our generated key
        mock_storage.get_signing_key = AsyncMock(return_value={
            "jwk": jwk,
            "key_id": "test-key-id",
            "metadata": {"private_key_pem": private_key_pem}
        })
        
        # Mock get_certificate_for_key
        mock_storage.get_certificate_for_key = AsyncMock(return_value=cert_pem)
        
        # 3. Setup Context
        mock_context = MagicMock()
        # Mock the session context manager
        mock_session = AsyncMock()
        mock_session.__aenter__.return_value = MagicMock()
        mock_context.profile.session.return_value = mock_session
        
        # 4. Setup Input Data
        processor = MsoMdocCredProcessor()
        
        supported = MagicMock(spec=SupportedCredential)
        supported.format = "mso_mdoc"
        supported.format_data = {"doctype": "org.example.test"}
        
        ex_record = MagicMock(spec=OID4VCIExchangeRecord)
        ex_record.verification_method = "did:example:123#test-key-id"
        ex_record.credential_subject = {
            "given_name": "John",
            "family_name": "Doe",
            "birth_date": "1990-01-01",
            "issuing_authority": "Test Authority",
            "issuing_country": "US",
            "issue_date": "2024-01-01",
            "expiry_date": "2029-01-01",
            "document_number": "123456789",
            "portrait": b"dummy_portrait_data",
            "driving_privileges": [
                {
                    "vehicle_category_code": "A",
                    "issue_date": "2023-01-01",
                    "expiry_date": "2028-01-01"
                }
            ]
        }
        
        # Holder Key (for PoP)
        holder_priv, holder_pub, holder_jwk = generate_ec_key_pair()
        pop = MagicMock(spec=PopResult)
        pop.holder_jwk = holder_jwk
        pop.holder_kid = None
        
        # 5. Execute Issue
        # Try a generic doctype to see if isomdl supports it or if it enforces mDL
        credential = await processor.issue(
            body={"doctype": "org.example.test"},
            supported=supported,
            ex_record=ex_record,
            pop=pop,
            context=mock_context
        )
        
        # 6. Verify Result
        assert credential is not None
        assert isinstance(credential, str)
        assert len(credential) > 0
        
        # Verify it looks like a stringified CBOR (isomdl specific format)
        # It usually looks like a hex string or similar representation
        assert len(credential) > 10

    @pytest.mark.skipif(not ISOMDL_AVAILABLE, reason="isomdl_uniffi not available")
    @pytest.mark.asyncio
    async def test_issue_mdl_functional(self):
        """
        Functional test for MsoMdocCredProcessor.issue() with mDL doctype.
        """
        # 1. Setup Keys
        private_key_pem, public_key_pem, jwk = generate_ec_key_pair()
        cert_pem = generate_self_signed_certificate(private_key_pem)
        
        # 2. Mock Storage Manager
        with patch("mso_mdoc.cred_processor.MdocStorageManager") as MockStorageManager:
            mock_storage = MockStorageManager.return_value
            mock_storage.get_signing_key = AsyncMock(return_value={
                "jwk": jwk,
                "key_id": "test-key-id-mdl",
                "metadata": {"private_key_pem": private_key_pem}
            })
            mock_storage.get_certificate_for_key = AsyncMock(return_value=cert_pem)
            
            # 3. Setup Context
            mock_context = MagicMock()
            mock_session = AsyncMock()
            mock_session.__aenter__.return_value = MagicMock()
            mock_context.profile.session.return_value = mock_session
            
            # 4. Setup Input Data
            processor = MsoMdocCredProcessor()
            
            supported = MagicMock(spec=SupportedCredential)
            supported.format = "mso_mdoc"
            supported.format_data = {"doctype": "org.iso.18013.5.1.mDL"}
            
            ex_record = MagicMock(spec=OID4VCIExchangeRecord)
            ex_record.verification_method = "did:example:123#test-key-id-mdl"
            ex_record.credential_subject = {
                "family_name": "Doe",
                "given_name": "Jane",
                "birth_date": "1992-02-02",
                "issue_date": "2024-01-01",
                "expiry_date": "2029-01-01",
                "issuing_country": "US",
                "issuing_authority": "DMV",
                "document_number": "987654321",
                "portrait": b"dummy_portrait_bytes",
                "driving_privileges": [
                    {
                        "vehicle_category_code": "B",
                        "issue_date": "2023-01-01",
                        "expiry_date": "2028-01-01"
                    }
                ]
            }
            
            # Holder Key
            holder_priv, holder_pub, holder_jwk = generate_ec_key_pair()
            pop = MagicMock(spec=PopResult)
            pop.holder_jwk = holder_jwk
            pop.holder_kid = None
            
            # 5. Execute Issue
            credential = await processor.issue(
                body={"doctype": "org.iso.18013.5.1.mDL"},
                supported=supported,
                ex_record=ex_record,
                pop=pop,
                context=mock_context
            )
            
            # 6. Verify Result
            assert credential is not None
            assert isinstance(credential, str)
            assert len(credential) > 10
        print(f"Generated Credential: {credential[:50]}...")

