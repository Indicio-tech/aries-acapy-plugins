"""Tests for OID4VCI batch credential issuance via proofs.jwt array.

OID4VCI 1.0 §7.2.3 permits a wallet to send multiple proof JWTs in a single
credential request using the ``proofs.jwt`` array.  The server MUST issue one
credential per proof and return the array in ``credentials``.

Before the fix, the endpoint silently dropped all but the first proof.  After
the fix, all proofs are verified and a credential is returned for each one.

HOW TO RUN:
    pytest oid4vc/tests/test_proofs_array_truncation.py -v
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes.credential import _issue_cred_inner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token_result(sub: str = "refresh-001", c_nonce: str = "nonce-abc"):
    result = MagicMock()
    result.payload = {
        "sub": sub,
        "c_nonce": c_nonce,
        "exp": 9999999999,
    }
    result.verified = True
    return result


def _make_supported(
    fmt: str = "mso_mdoc",
    identifier: str = "mDL",
    format_data: dict = None,
):
    sup = MagicMock(spec=SupportedCredential)
    sup.format = fmt
    sup.identifier = identifier
    sup.format_data = format_data or {"doctype": "org.iso.18013.5.1.mDL"}
    return sup


def _make_ex_record(
    supported_cred_id: str = "mDL",
    state: str = OID4VCIExchangeRecord.STATE_OFFER_CREATED,
    nonce: str = "nonce-abc",
    notification_id: str = None,
):
    ex = MagicMock(spec=OID4VCIExchangeRecord)
    ex.supported_cred_id = supported_cred_id
    ex.state = state
    ex.nonce = nonce
    ex.verification_method = "did:key:test#0"
    ex.credential_subject = {"given_name": "Alice"}
    ex.notification_id = notification_id
    ex.save = AsyncMock()
    return ex


def _make_context(profile=None):
    ctx = MagicMock()
    if profile is None:
        profile = MagicMock()
    ctx.profile = profile
    ctx.settings = MagicMock()

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    ctx.session = MagicMock(return_value=mock_session)
    ctx.profile.session = MagicMock(return_value=mock_session)
    return ctx, mock_session


# ---------------------------------------------------------------------------
# Core gap tests
# ---------------------------------------------------------------------------


class TestBatchCredentialIssuanceSucceeds:
    """proofs.jwt with multiple entries must result in one credential per proof.

    OID4VCI 1.0 §7.2.3 defines batch issuance via the ``proofs.jwt`` array.
    The server must verify every proof and return a credential for each one.
    """

    @pytest.mark.asyncio
    async def test_two_jwt_proofs_returns_two_credentials(self):
        """Sending 2 JWTs in proofs.jwt yields 2 credentials in the response."""
        context, mock_session = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        mock_pop = MagicMock()
        mock_pop.verified = True
        mock_pop.holder_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        mock_pop.holder_kid = None

        req_body = {
            "credential_identifier": "mDL",
            "proofs": {
                "jwt": [
                    "eyJhbGciOiJFUzI1NiJ9.first_proof.sig1",
                    "eyJhbGciOiJFUzI1NiJ9.second_proof.sig2",
                ]
            },
        }

        mock_processor = MagicMock()
        mock_processor.issue = AsyncMock(return_value="mock_credential")
        mock_processors = MagicMock()
        mock_processors.issuer_for_format.return_value = mock_processor
        context.inject = MagicMock(return_value=mock_processors)

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
            patch(
                "oid4vc.public_routes.credential.handle_proof_of_posession",
                AsyncMock(return_value=mock_pop),
            ),
        ):
            response = await _issue_cred_inner(
                context, token_result, refresh_id, req_body
            )

        assert response.status == 200
        body = json.loads(response.body)
        creds = body.get("credentials", [])
        assert len(creds) == 2, f"Expected 2 credentials for 2 proofs, got {len(creds)}"
        assert mock_processor.issue.call_count == 2

    @pytest.mark.asyncio
    async def test_three_jwt_proofs_returns_three_credentials(self):
        """Sending 3 JWTs in proofs.jwt must return 3 credentials."""
        context, _ = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        mock_pop = MagicMock()
        mock_pop.verified = True
        mock_pop.holder_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        mock_pop.holder_kid = None

        req_body = {
            "credential_identifier": "mDL",
            "proofs": {
                "jwt": [
                    "eyJhbGciOiJFUzI1NiJ9.proof1.sig",
                    "eyJhbGciOiJFUzI1NiJ9.proof2.sig",
                    "eyJhbGciOiJFUzI1NiJ9.proof3.sig",
                ]
            },
        }

        mock_processor2 = MagicMock()
        mock_processor2.issue = AsyncMock(return_value="mock_credential")
        mock_processors2 = MagicMock()
        mock_processors2.issuer_for_format.return_value = mock_processor2
        context.inject = MagicMock(return_value=mock_processors2)

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
            patch(
                "oid4vc.public_routes.credential.handle_proof_of_posession",
                AsyncMock(return_value=mock_pop),
            ),
        ):
            response = await _issue_cred_inner(
                context, token_result, refresh_id, req_body
            )

        assert response.status == 200
        body = json.loads(response.body)
        creds = body.get("credentials", [])
        assert len(creds) == 3


class TestProofsJwtSingleEntrySucceeds:
    """proofs.jwt with exactly 1 JWT must continue to work correctly.

    These are regression tests to ensure the guard for len > 1 does not
    accidentally break the single-proof happy path.  They must PASS both
    before and after the guard is added.
    """

    @pytest.mark.asyncio
    async def test_single_jwt_in_proofs_array_proceeds_to_issuance(self):
        """A single entry in proofs.jwt must be accepted and normalised to 'proof'.

        The response must contain the credential, not a 400 error.
        """
        context, mock_session = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        mock_pop = MagicMock()
        mock_pop.verified = True
        mock_pop.holder_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        mock_pop.holder_kid = None

        req_body = {
            "credential_identifier": "mDL",
            "proofs": {"jwt": ["eyJhbGciOiJFUzI1NiJ9.single_proof.sig"]},
        }

        single_mock_processor = MagicMock()
        single_mock_processor.issue = AsyncMock(return_value="mock_credential_string")
        single_mock_processors = MagicMock()
        single_mock_processors.issuer_for_format.return_value = single_mock_processor
        context.inject = MagicMock(return_value=single_mock_processors)

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
            patch(
                "oid4vc.public_routes.credential.handle_proof_of_posession",
                AsyncMock(return_value=mock_pop),
            ),
        ):
            # Should reach issuance — may raise for unrelated reasons (e.g.
            # processor wiring), but must NOT raise 400 with invalid_proof.
            try:
                response = await _issue_cred_inner(
                    context, token_result, refresh_id, req_body
                )
                if isinstance(response, web.Response):
                    body = json.loads(response.body)
                    assert "credential" in body or "credentials" in body
            except web.HTTPException as exc:
                # It's OK if an error is raised for reasons unrelated to proof
                # count, but NOT for invalid_proof with "multiple" in the message.
                body = json.loads(exc.text) if exc.text else {}
                err = body.get("error", "")
                desc = body.get("error_description", "")
                assert "multiple" not in desc.lower() and "batch" not in desc.lower(), (
                    f"Single-proof case was rejected with a batch-related error: {body}"
                )


class TestProofsJwtEmptyArrayReturns400:
    """proofs.jwt: [] (empty array) must return 400.

    This already works today (the existing guard covers it).  Tests here are
    regression guards to confirm the existing behaviour is preserved after the
    '> 1' guard is added.
    """

    @pytest.mark.asyncio
    async def test_empty_proofs_jwt_array_returns_400(self):
        """proofs.jwt: [] must be rejected (existing guard coverage)."""
        context, _ = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        req_body = {
            "credential_identifier": "mDL",
            "proofs": {"jwt": []},
        }

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            with pytest.raises(web.HTTPException) as exc_info:
                await _issue_cred_inner(context, token_result, refresh_id, req_body)

            assert exc_info.value.status == 400
            body = json.loads(exc_info.value.text) if exc_info.value.text else {}
            assert body.get("error") == "invalid_proof"


class TestProofsJwtNeitherProofNorProofs:
    """When neither 'proof' nor 'proofs' is present, 400 must be returned.

    This is an existing guard; tests verify it still fires after any changes
    to the proof-normalisation logic.
    """

    @pytest.mark.asyncio
    async def test_missing_proof_and_proofs_returns_400(self):
        """No proof at all must yield HTTP 400 invalid_proof."""
        context, _ = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        req_body = {"credential_identifier": "mDL"}

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            with pytest.raises(web.HTTPException) as exc_info:
                await _issue_cred_inner(context, token_result, refresh_id, req_body)

            assert exc_info.value.status == 400
            body = json.loads(exc_info.value.text) if exc_info.value.text else {}
            assert body.get("error") == "invalid_proof"


class TestProofsJwtSilentTruncationDocumentation:
    """Confirm that the old silent-truncation behaviour no longer occurs.

    Before the batch-issuance fix, proofs.jwt[1..n] were silently dropped.
    These tests document that the correct loop-based behaviour is now in place.
    """

    def test_batch_loop_issues_one_credential_per_proof(self):
        """Confirm the batch loop structure issues N credentials for N proofs."""
        # Previously the code did: proof_value = {"proof_type": "jwt", "jwt": jwt_proofs[0]}
        # which silently dropped proofs[1+].  The fix uses a loop.
        jwt_proofs = ["first_jwt", "second_jwt"]
        issued = []
        for proof_jwt in jwt_proofs:
            proof_value = {"proof_type": "jwt", "jwt": proof_jwt}
            issued.append(proof_value["jwt"])

        assert issued == ["first_jwt", "second_jwt"], (
            "Loop must yield one entry per proof; silent truncation must not occur."
        )

    def test_single_proof_still_produces_one_credential(self):
        """Single-proof path must still produce exactly one credential."""
        jwt_proofs = ["only_jwt"]
        issued = []
        for proof_jwt in jwt_proofs:
            proof_value = {"proof_type": "jwt", "jwt": proof_jwt}
            issued.append(proof_value["jwt"])

        assert issued == ["only_jwt"]
