from typing import Any

import pytest
from acapy_agent.admin.request_context import AdminRequestContext

from jwt_vc_json.cred_processor import JwtVcJsonCredProcessor
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult


class TestCredentialProcessor:
    """Tests for CredentialProcessor."""

    @pytest.mark.asyncio
    async def test_issue_credential(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Test issue_credential method."""

        cred_processor = JwtVcJsonCredProcessor()

        jws = cred_processor.issue(body, supported, ex_record, pop, context)

        assert jws

    def test_validate_supported_credential(self):
        processor = JwtVcJsonCredProcessor()

        # Valid
        valid_supported = SupportedCredential(
            format_data={"types": ["VerifiableCredential", "ExampleCredential"]}
        )
        processor.validate_supported_credential(valid_supported)

        # Missing format_data
        with pytest.raises(ValueError, match="format_data is required"):
            processor.validate_supported_credential(
                SupportedCredential(format_data=None)
            )

        # Missing types
        with pytest.raises(ValueError, match="types is required"):
            processor.validate_supported_credential(
                SupportedCredential(format_data={"other": "value"})
            )

    def test_validate_credential_subject(self):
        processor = JwtVcJsonCredProcessor()
        supported = SupportedCredential(format_data={"types": ["VerifiableCredential"]})

        # Valid
        processor.validate_credential_subject(supported, {"key": "value"})

        # Invalid type
        with pytest.raises(ValueError, match="Credential subject must be a dictionary"):
            processor.validate_credential_subject(supported, "not a dict")
