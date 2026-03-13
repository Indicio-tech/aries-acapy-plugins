"""Tests for _issue_cred_inner error paths.

Covers validation and error-handling branches in the credential issuance
handler that do NOT require end-to-end proof verification.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes.credential import _issue_cred_inner


# ---------------------------------------------------------------------------
# Helpers (reusable factory functions)
# ---------------------------------------------------------------------------


def _make_token_result(sub="refresh-001", c_nonce="nonce-abc"):
    result = MagicMock()
    result.payload = {"sub": sub, "c_nonce": c_nonce, "exp": 9999999999}
    result.verified = True
    return result


def _make_supported(fmt="jwt_vc_json", identifier="TestCred", format_data=None):
    sup = MagicMock(spec=SupportedCredential)
    sup.format = fmt
    sup.identifier = identifier
    sup.format_data = format_data or {"type": ["VerifiableCredential"]}
    return sup


def _make_ex_record(
    supported_cred_id="TestCred",
    nonce="nonce-abc",
):
    ex = MagicMock(spec=OID4VCIExchangeRecord)
    ex.supported_cred_id = supported_cred_id
    ex.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
    ex.nonce = nonce
    ex.verification_method = "did:key:test#0"
    ex.credential_subject = {"name": "Alice"}
    ex.notification_id = None
    ex.save = AsyncMock()
    return ex


def _make_context():
    ctx = MagicMock()
    ctx.profile = MagicMock()
    ctx.settings = MagicMock()
    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    ctx.session = MagicMock(return_value=mock_session)
    ctx.profile.session = MagicMock(return_value=mock_session)
    return ctx, mock_session


def _exc_json(exc):
    return json.loads(exc.value.text)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMutualExclusivity:
    """credential_identifier and format are mutually exclusive."""

    @pytest.mark.asyncio
    async def test_both_credential_identifier_and_format_rejected(self):
        ctx, _ = _make_context()
        token = _make_token_result()
        body = {
            "credential_identifier": "TestCred",
            "format": "jwt_vc_json",
            "proof": {"proof_type": "jwt", "jwt": "a.b.c"},
        }
        with pytest.raises(web.HTTPBadRequest) as exc:
            await _issue_cred_inner(ctx, token, "refresh-001", body)
        err = _exc_json(exc)
        assert err["error"] == "invalid_credential_request"
        assert "mutually exclusive" in err["error_description"]

    @pytest.mark.asyncio
    async def test_neither_credential_identifier_nor_format_rejected(self):
        ctx, _ = _make_context()
        token = _make_token_result()
        body = {"proof": {"proof_type": "jwt", "jwt": "a.b.c"}}
        with pytest.raises(web.HTTPBadRequest) as exc:
            await _issue_cred_inner(ctx, token, "refresh-001", body)
        err = _exc_json(exc)
        assert err["error"] == "invalid_credential_request"
        assert "required" in err["error_description"]


class TestExchangeRecordLookup:
    """Exchange record not found → clear error codes."""

    @pytest.mark.asyncio
    async def test_no_exchange_returns_invalid_credential_request(self):
        from acapy_agent.storage.error import StorageNotFoundError

        ctx, mock_session = _make_context()
        token = _make_token_result()

        mock_session.inject = MagicMock()

        with (
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_refresh_id",
                AsyncMock(side_effect=StorageNotFoundError("not found")),
            ),
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_tag_filter",
                AsyncMock(return_value=None),
            ),
        ):
            body = {
                "credential_identifier": "X",
                "proof": {"proof_type": "jwt", "jwt": "a.b.c"},
            }
            with pytest.raises(web.HTTPBadRequest) as exc:
                await _issue_cred_inner(ctx, token, "refresh-001", body)
            err = _exc_json(exc)
            assert err["error"] == "invalid_credential_request"

    @pytest.mark.asyncio
    async def test_already_issued_returns_invalid_nonce(self):
        from acapy_agent.storage.error import StorageNotFoundError

        ctx, mock_session = _make_context()
        token = _make_token_result()

        issued_record = MagicMock()
        issued_record.state = OID4VCIExchangeRecord.STATE_ISSUED

        with (
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_refresh_id",
                AsyncMock(side_effect=StorageNotFoundError("not found")),
            ),
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_tag_filter",
                AsyncMock(return_value=issued_record),
            ),
        ):
            body = {
                "credential_identifier": "X",
                "proof": {"proof_type": "jwt", "jwt": "a.b.c"},
            }
            with pytest.raises(web.HTTPBadRequest) as exc:
                await _issue_cred_inner(ctx, token, "refresh-001", body)
            err = _exc_json(exc)
            assert err["error"] == "invalid_nonce"


class TestIdentifierMismatch:
    """Mismatched credential_identifier yields spec-correct error codes."""

    @pytest.mark.asyncio
    async def test_credential_identifier_mismatch(self):
        ctx, mock_session = _make_context()
        token = _make_token_result()
        supported = _make_supported(identifier="RealCred")
        ex_record = _make_ex_record(supported_cred_id="RealCred")

        with (
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch.object(
                SupportedCredential,
                "retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            body = {
                "credential_identifier": "WrongCred",
                "proof": {"proof_type": "jwt", "jwt": "a.b.c"},
            }
            with pytest.raises(web.HTTPBadRequest) as exc:
                await _issue_cred_inner(ctx, token, "refresh-001", body)
            err = _exc_json(exc)
            assert err["error"] == "invalid_credential_identifier"

    @pytest.mark.asyncio
    async def test_credential_configuration_id_mismatch(self):
        ctx, mock_session = _make_context()
        token = _make_token_result()
        supported = _make_supported(identifier="RealCred")
        ex_record = _make_ex_record(supported_cred_id="RealCred")

        with (
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch.object(
                SupportedCredential,
                "retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            body = {
                "credential_configuration_id": "WrongConfig",
                "proof": {"proof_type": "jwt", "jwt": "a.b.c"},
            }
            with pytest.raises(web.HTTPBadRequest) as exc:
                await _issue_cred_inner(ctx, token, "refresh-001", body)
            err = _exc_json(exc)
            assert err["error"] == "invalid_credential_configuration"

    @pytest.mark.asyncio
    async def test_format_mismatch(self):
        ctx, mock_session = _make_context()
        token = _make_token_result()
        supported = _make_supported(fmt="jwt_vc_json")
        ex_record = _make_ex_record()

        with (
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch.object(
                SupportedCredential,
                "retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            body = {
                "format": "sd_jwt_vc",
                "proof": {"proof_type": "jwt", "jwt": "a.b.c"},
            }
            with pytest.raises(web.HTTPBadRequest) as exc:
                await _issue_cred_inner(ctx, token, "refresh-001", body)
            err = _exc_json(exc)
            assert err["error"] == "invalid_credential_request"
            assert "format" in err["error_description"].lower()


class TestMissingFormatData:
    """No format_data on supported credential → 500."""

    @pytest.mark.asyncio
    async def test_missing_format_data_returns_500(self):
        ctx, mock_session = _make_context()
        token = _make_token_result()
        supported = _make_supported()
        supported.format_data = None
        ex_record = _make_ex_record()

        with (
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch.object(
                SupportedCredential,
                "retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            body = {
                "credential_identifier": "TestCred",
                "proof": {"proof_type": "jwt", "jwt": "a.b.c"},
            }
            with pytest.raises(web.HTTPInternalServerError):
                await _issue_cred_inner(ctx, token, "refresh-001", body)


class TestMissingProof:
    """No proof or proofs in the request body."""

    @pytest.mark.asyncio
    async def test_no_proof_key_returns_invalid_proof(self):
        ctx, mock_session = _make_context()
        token = _make_token_result()
        supported = _make_supported()
        ex_record = _make_ex_record()

        with (
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch.object(
                SupportedCredential,
                "retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            body = {"credential_identifier": "TestCred"}
            with pytest.raises(web.HTTPBadRequest) as exc:
                await _issue_cred_inner(ctx, token, "refresh-001", body)
            err = _exc_json(exc)
            assert err["error"] == "invalid_proof"


class TestAuthorizationDetails:
    """authorization_details mismatch rejects the request."""

    @pytest.mark.asyncio
    async def test_authorization_details_mismatch(self):
        ctx, mock_session = _make_context()
        token = _make_token_result()
        token.payload["authorization_details"] = [
            {"credential_configuration_id": "OtherCred"}
        ]
        supported = _make_supported(identifier="TestCred")
        ex_record = _make_ex_record(supported_cred_id="TestCred")

        with (
            patch.object(
                OID4VCIExchangeRecord,
                "retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch.object(
                SupportedCredential,
                "retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            body = {
                "credential_identifier": "TestCred",
                "proof": {"proof_type": "jwt", "jwt": "a.b.c"},
            }
            with pytest.raises(web.HTTPBadRequest) as exc:
                await _issue_cred_inner(ctx, token, "refresh-001", body)
            err = _exc_json(exc)
            assert "not authorized" in err["error_description"]
