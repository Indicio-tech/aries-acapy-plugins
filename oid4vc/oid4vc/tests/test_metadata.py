"""Tests for the credential issuer metadata endpoints."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from oid4vc.public_routes.metadata import SUPPORTED_CRED_QUERY_LIMIT


class TestSupportedCredQueryLimit:
    """Tests for the SUPPORTED_CRED_QUERY_LIMIT cap on metadata endpoints."""

    def test_limit_is_a_positive_int(self):
        """SUPPORTED_CRED_QUERY_LIMIT must be a positive integer."""
        assert isinstance(SUPPORTED_CRED_QUERY_LIMIT, int)
        assert SUPPORTED_CRED_QUERY_LIMIT > 0

    @pytest.mark.asyncio
    async def test_metadata_caps_credentials_at_limit(self, context):
        """credential_issuer_metadata must not return more than SUPPORTED_CRED_QUERY_LIMIT creds."""
        from oid4vc.models.supported_cred import SupportedCredential
        from oid4vc.public_routes.metadata import credential_issuer_metadata

        n = SUPPORTED_CRED_QUERY_LIMIT + 5
        large_list = [
            MagicMock(
                spec=SupportedCredential,
                format="jwt_vc_json",
                identifier=f"Cred{i}",
                format_data={"credentialSubject": {}},
                to_issuer_metadata=MagicMock(return_value={"format": "jwt_vc_json"}),
            )
            for i in range(n)
        ]

        request = MagicMock()
        request.__getitem__ = (
            lambda _, k: context if k == "context" else (_ for _ in ()).throw(KeyError(k))
        )
        request.match_info = {"wallet_id": "test-wallet"}
        request.headers = MagicMock()
        request.headers.get = MagicMock(return_value="")

        with patch(
            "oid4vc.public_routes.metadata.SupportedCredential.query",
            AsyncMock(return_value=large_list),
        ):
            response = await credential_issuer_metadata(request)

        body = json.loads(response.body)
        cred_configs = body.get("credential_configurations_supported", {})
        assert len(cred_configs) <= SUPPORTED_CRED_QUERY_LIMIT
