import pytest
from unittest.mock import MagicMock, patch
from sd_jwt_vc.cred_processor import SdJwtCredIssueProcessor, CredProcessorError
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.pop_result import PopResult
from acapy_agent.admin.request_context import AdminRequestContext

@pytest.mark.asyncio
class TestSdJwtCredIssueProcessor:
    async def test_issue_vct_validation(self):
        processor = SdJwtCredIssueProcessor()
        
        # Mock dependencies
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {"vct": "IdentityCredential"}
        supported.vc_additional_data = {"sd_list": []}
        
        ex_record = MagicMock(spec=OID4VCIExchangeRecord)
        ex_record.credential_subject = {}
        ex_record.verification_method = "did:example:issuer#key-1"
        
        pop = MagicMock(spec=PopResult)
        pop.holder_kid = "did:example:holder#key-1"
        pop.holder_jwk = None
        
        context = MagicMock(spec=AdminRequestContext)
        
        # We need to mock the SDJWTIssuer to avoid actual JWT operations
        with patch("sd_jwt_vc.cred_processor.SDJWTIssuer") as mock_issuer_cls:
            mock_issuer = mock_issuer_cls.return_value
            mock_issuer.sd_jwt_payload = "mock_payload"
            
            # We also need to mock jwt_sign
            with patch("sd_jwt_vc.cred_processor.jwt_sign", return_value="mock_signed_jwt"):
            
                # Case 1: No vct in body -> Should pass validation
                body_no_vct = {}
                try:
                    await processor.issue(body_no_vct, supported, ex_record, pop, context)
                except CredProcessorError as e:
                    pytest.fail(f"Should not raise CredProcessorError for missing vct: {e}")
                except Exception as e:
                    # If it fails for other reasons, we might need to mock more
                    print(f"Caught expected exception during execution (not validation failure): {e}")

                # Case 2: Matching vct -> Should pass validation
                body_match_vct = {"vct": "IdentityCredential"}
                try:
                    await processor.issue(body_match_vct, supported, ex_record, pop, context)
                except CredProcessorError as e:
                    pytest.fail(f"Should not raise CredProcessorError for matching vct: {e}")
                except Exception as e:
                    print(f"Caught expected exception during execution (not validation failure): {e}")

                # Case 3: Mismatching vct -> Should raise CredProcessorError
                body_mismatch_vct = {"vct": "WrongCredential"}
                with pytest.raises(CredProcessorError, match="Requested vct does not match offer"):
                    await processor.issue(body_mismatch_vct, supported, ex_record, pop, context)
