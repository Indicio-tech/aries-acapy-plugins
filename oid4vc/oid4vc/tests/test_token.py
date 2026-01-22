"""Tests for token endpoint."""

from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from multidict import MultiDict

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.public_routes.token import token


@pytest.fixture
def token_request(context):
    """Create a mock token request."""

    class TokenRequest:
        def __init__(self, form_data=None, match_info=None):
            self._form = form_data or MultiDict(
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": "test_code_123",
                }
            )
            self.match_info = match_info or {}

        async def post(self):
            return self._form

        def __getitem__(self, key):
            if key == "context":
                return context
            raise KeyError(key)

    return TokenRequest


@pytest.mark.asyncio
async def test_token_pre_authorized_code_reuse_prevented(
    monkeypatch, context, token_request
):
    """Test that pre-authorized codes cannot be reused."""

    # Create a mock exchange record that already has a token (code already used)
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = None
    mock_record.token = "existing_token_jwt"  # Code already used!
    mock_record.refresh_id = "refresh_123"

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config.from_settings to return no auth_server_url
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    request = token_request()
    response = await token(cast(web.Request, request))

    # Should return error indicating code was already used
    assert response.status == 400
    assert response.content_type == "application/json"

    # Parse response body
    import json

    body = json.loads(response.body)
    assert body["error"] == "invalid_grant"
    assert "already been used" in body["error_description"]


@pytest.mark.asyncio
async def test_token_pre_authorized_code_first_use_success(
    monkeypatch, context, token_request
):
    """Test that pre-authorized codes work on first use."""

    # Create a mock exchange record without a token (first use)
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = None
    mock_record.token = None  # No token yet - first use
    mock_record.refresh_id = "refresh_123"
    mock_record.save = AsyncMock()

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config.from_settings
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    # Mock wallet operations to avoid did:jwk creation
    mock_wallet = MagicMock()
    mock_wallet.get_local_dids = AsyncMock(return_value=[])
    mock_did_info = MagicMock()
    mock_did_info.did = "did:jwk:test123"
    mock_did_info.method = "jwk"
    mock_wallet.create_local_did = AsyncMock(return_value=mock_did_info)
    
    # Mock session as an async context manager
    mock_session = MagicMock()
    mock_session.inject = MagicMock(return_value=mock_wallet)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    
    context.profile.session = MagicMock(return_value=mock_session)

    # Mock retrieve_or_create_did_jwk and jwt_sign using patch
    with patch(
        "oid4vc.public_routes.token.retrieve_or_create_did_jwk",
        AsyncMock(return_value=mock_did_info),
    ), patch(
        "oid4vc.public_routes.token.jwt_sign",
        AsyncMock(return_value="new_token_jwt"),
    ):
        request = token_request()
        response = await token(cast(web.Request, request))

        # Should succeed and return token
        assert response.status == 200
        assert response.content_type == "application/json"

        # Parse response body
        import json

        body = json.loads(response.body)
        assert body["access_token"] == "new_token_jwt"
        assert body["token_type"] == "Bearer"
        assert "c_nonce" in body

        # Verify record was saved with new token
        mock_record.save.assert_called_once()


@pytest.mark.asyncio
async def test_token_with_pin_validation_before_reuse_check(
    monkeypatch, context, token_request
):
    """Test that PIN validation happens before reuse check."""

    # Create a mock exchange record with pin required and already used
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = "1234"
    mock_record.token = "existing_token"  # Already used
    mock_record.refresh_id = "refresh_123"

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    # Request without pin
    request = token_request()
    response = await token(cast(web.Request, request))

    # Should fail on missing PIN before checking reuse
    assert response.status == 400
    import json

    body = json.loads(response.body)
    assert body["error"] == "invalid_request"
    assert "user_pin is required" in body["error_description"]


@pytest.mark.asyncio
async def test_token_with_wrong_pin_before_reuse_check(
    monkeypatch, context, token_request
):
    """Test that wrong PIN is caught before reuse check."""

    # Create a mock exchange record with pin required and already used
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = "1234"
    mock_record.token = "existing_token"  # Already used
    mock_record.refresh_id = "refresh_123"

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    # Request with wrong pin
    request = token_request(
        form_data=MultiDict(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": "test_code_123",
                "user_pin": "9999",  # Wrong PIN
            }
        )
    )
    response = await token(cast(web.Request, request))

    # Should fail on wrong PIN before checking reuse
    assert response.status == 400
    import json

    body = json.loads(response.body)
    assert body["error"] == "invalid_grant"
    assert "pin is invalid" in body["error_description"]


@pytest.mark.asyncio
async def test_token_with_correct_pin_but_code_reused(
    monkeypatch, context, token_request
):
    """Test that even with correct PIN, reused codes are rejected."""

    # Create a mock exchange record with correct pin and already used
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = "1234"
    mock_record.token = "existing_token"  # Already used
    mock_record.refresh_id = "refresh_123"

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    # Request with correct pin
    request = token_request(
        form_data=MultiDict(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": "test_code_123",
                "user_pin": "1234",  # Correct PIN
            }
        )
    )
    response = await token(cast(web.Request, request))

    # Should fail on reuse check even though PIN was correct
    assert response.status == 400
    import json

    body = json.loads(response.body)
    assert body["error"] == "invalid_grant"
    assert "already been used" in body["error_description"]
