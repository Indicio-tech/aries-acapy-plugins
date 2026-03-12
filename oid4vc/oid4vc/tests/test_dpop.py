"""Tests for DPoP RFC 9449 proof verification.

Covers _verify_dpop_proof (unit) and check_token DPoP integration.
"""

import base64
import hashlib
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aries_askar import Key, KeyAlg

from oid4vc.public_routes.token import _verify_dpop_proof


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_dpop_proof(
    key: Key,
    alg: str,
    htm: str = "POST",
    htu: str = "https://issuer.example/credential",
    ath: str | None = None,
    jti: str = "unique-jti-001",
    iat: int | None = None,
    typ: str = "dpop+jwt",
    access_token: str = "test-access-token",
) -> str:
    """Build and sign a DPoP proof JWT."""
    jwk = json.loads(key.get_jwk_public())
    header = {"typ": typ, "alg": alg, "jwk": jwk}

    if ath is None:
        ath = (
            base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode()
        )

    payload_data = {
        "jti": jti,
        "htm": htm,
        "htu": htu,
        "ath": ath,
        "iat": iat if iat is not None else int(time.time()),
    }

    h_enc = _b64url(json.dumps(header).encode())
    p_enc = _b64url(json.dumps(payload_data).encode())
    sig = key.sign_message(f"{h_enc}.{p_enc}".encode(), sig_type=alg)
    return f"{h_enc}.{p_enc}.{_b64url(sig)}"


def _make_mock_profile_with_storage():
    """Return a mock profile whose session yields a BaseStorage that
    raises StorageDuplicateError on the second add of the same jti."""
    from acapy_agent.storage.error import StorageDuplicateError

    profile = MagicMock()
    session_mock = MagicMock()
    session_mock.__aenter__ = AsyncMock(return_value=session_mock)
    session_mock.__aexit__ = AsyncMock(return_value=None)

    storage_mock = MagicMock()
    storage_mock.add_record = AsyncMock()  # succeeds by default
    session_mock.inject = MagicMock(return_value=storage_mock)

    profile.session = MagicMock(return_value=session_mock)
    return profile, storage_mock, StorageDuplicateError


# ---------------------------------------------------------------------------
# _verify_dpop_proof unit tests
# ---------------------------------------------------------------------------


class TestVerifyDpopProof:
    """Unit tests for the _verify_dpop_proof helper."""

    @pytest.fixture
    def key(self):
        return Key.generate(KeyAlg.P256)

    @pytest.fixture
    def access_token(self):
        return "test-access-token-abc"

    @pytest.mark.asyncio
    async def test_valid_proof_passes(self, key, access_token):
        """A fully valid DPoP proof must not raise."""
        profile, _, _ = _make_mock_profile_with_storage()
        proof = _make_dpop_proof(key, "ES256", access_token=access_token)
        await _verify_dpop_proof(
            profile,
            dpop_proof=proof,
            access_token=access_token,
            method="POST",
            url="https://issuer.example/credential",
        )

    @pytest.mark.asyncio
    async def test_wrong_htm_rejected(self, key, access_token):
        """DPoP proof with wrong htm must be rejected (RFC 9449 §4.3)."""
        profile, _, _ = _make_mock_profile_with_storage()
        proof = _make_dpop_proof(key, "ES256", htm="GET", access_token=access_token)
        with pytest.raises(web.HTTPUnauthorized, match="htm"):
            await _verify_dpop_proof(
                profile,
                dpop_proof=proof,
                access_token=access_token,
                method="POST",
                url="https://issuer.example/credential",
            )

    @pytest.mark.asyncio
    async def test_wrong_htu_rejected(self, key, access_token):
        """DPoP proof with wrong htu must be rejected."""
        profile, _, _ = _make_mock_profile_with_storage()
        proof = _make_dpop_proof(
            key,
            "ES256",
            htu="https://other.example/credential",
            access_token=access_token,
        )
        with pytest.raises(web.HTTPUnauthorized, match="htu"):
            await _verify_dpop_proof(
                profile,
                dpop_proof=proof,
                access_token=access_token,
                method="POST",
                url="https://issuer.example/credential",
            )

    @pytest.mark.asyncio
    async def test_wrong_ath_rejected(self, key, access_token):
        """DPoP proof ath not matching the access token must be rejected."""
        profile, _, _ = _make_mock_profile_with_storage()
        proof = _make_dpop_proof(
            key, "ES256", ath="wrong-ath-value", access_token=access_token
        )
        with pytest.raises(web.HTTPUnauthorized, match="ath"):
            await _verify_dpop_proof(
                profile,
                dpop_proof=proof,
                access_token=access_token,
                method="POST",
                url="https://issuer.example/credential",
            )

    @pytest.mark.asyncio
    async def test_replayed_jti_rejected(self, key, access_token):
        """A DPoP proof whose jti was already stored must be rejected."""
        from acapy_agent.storage.error import StorageDuplicateError

        profile, storage_mock, _ = _make_mock_profile_with_storage()
        storage_mock.add_record = AsyncMock(side_effect=StorageDuplicateError("dup"))

        proof = _make_dpop_proof(key, "ES256", access_token=access_token)
        with pytest.raises(web.HTTPUnauthorized, match="replay"):
            await _verify_dpop_proof(
                profile,
                dpop_proof=proof,
                access_token=access_token,
                method="POST",
                url="https://issuer.example/credential",
            )

    @pytest.mark.asyncio
    async def test_stale_iat_rejected(self, key, access_token):
        """DPoP proof with iat far in the past must be rejected."""
        profile, _, _ = _make_mock_profile_with_storage()
        old_iat = int(time.time()) - 3600
        proof = _make_dpop_proof(key, "ES256", iat=old_iat, access_token=access_token)
        with pytest.raises(web.HTTPUnauthorized, match="iat"):
            await _verify_dpop_proof(
                profile,
                dpop_proof=proof,
                access_token=access_token,
                method="POST",
                url="https://issuer.example/credential",
            )

    @pytest.mark.asyncio
    async def test_tampered_signature_rejected(self, key, access_token):
        """A proof with a tampered payload must fail signature verification."""
        profile, _, _ = _make_mock_profile_with_storage()
        proof = _make_dpop_proof(key, "ES256", access_token=access_token)
        tampered = proof[:-4] + "XXXX"
        with pytest.raises(web.HTTPUnauthorized):
            await _verify_dpop_proof(
                profile,
                dpop_proof=tampered,
                access_token=access_token,
                method="POST",
                url="https://issuer.example/credential",
            )

    @pytest.mark.asyncio
    async def test_wrong_typ_rejected(self, key, access_token):
        """DPoP proof with typ != 'dpop+jwt' must be rejected."""
        profile, _, _ = _make_mock_profile_with_storage()
        proof = _make_dpop_proof(key, "ES256", typ="JWT", access_token=access_token)
        with pytest.raises(web.HTTPUnauthorized, match="typ"):
            await _verify_dpop_proof(
                profile,
                dpop_proof=proof,
                access_token=access_token,
                method="POST",
                url="https://issuer.example/credential",
            )

    @pytest.mark.asyncio
    async def test_missing_jwk_header_rejected(self, key, access_token):
        """DPoP proof without jwk header claim must be rejected."""
        profile, _, _ = _make_mock_profile_with_storage()
        ath = (
            base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        header = {"typ": "dpop+jwt", "alg": "ES256"}  # no jwk
        payload_data = {
            "jti": "test-jti",
            "htm": "POST",
            "htu": "https://issuer.example/credential",
            "ath": ath,
            "iat": int(time.time()),
        }
        h_enc = _b64url(json.dumps(header).encode())
        p_enc = _b64url(json.dumps(payload_data).encode())
        sig = key.sign_message(f"{h_enc}.{p_enc}".encode(), sig_type="ES256")
        proof = f"{h_enc}.{p_enc}.{_b64url(sig)}"

        with pytest.raises(web.HTTPUnauthorized, match="jwk"):
            await _verify_dpop_proof(
                profile,
                dpop_proof=proof,
                access_token=access_token,
                method="POST",
                url="https://issuer.example/credential",
            )

    @pytest.mark.asyncio
    async def test_htu_query_params_ignored(self, key, access_token):
        """htu comparison ignores query string and fragment (RFC 9449 §4.3)."""
        profile, _, _ = _make_mock_profile_with_storage()
        proof = _make_dpop_proof(
            key,
            "ES256",
            htu="https://issuer.example/credential",
            access_token=access_token,
        )
        # URL with query params must still match
        await _verify_dpop_proof(
            profile,
            dpop_proof=proof,
            access_token=access_token,
            method="POST",
            url="https://issuer.example/credential?foo=bar",
        )


# ---------------------------------------------------------------------------
# check_token DPoP integration tests
# ---------------------------------------------------------------------------


class TestCheckTokenDpop:
    """Integration tests ensuring check_token enforces DPoP per RFC 9449."""

    def _mock_config(self):
        cfg = MagicMock()
        cfg.auth_server_url = None
        cfg.endpoint = "https://issuer.example"
        return cfg

    @pytest.mark.asyncio
    async def test_dpop_scheme_triggers_proof_verification(self, context):
        """check_token must call _verify_dpop_proof when DPoP scheme is used."""
        with (
            patch(
                "oid4vc.public_routes.token.Config.from_settings",
                return_value=self._mock_config(),
            ),
            patch(
                "oid4vc.public_routes.token.jwt_verify",
                AsyncMock(
                    return_value=MagicMock(
                        verified=True,
                        payload={"sub": "test", "exp": 9999999999},
                    )
                ),
            ),
            patch(
                "oid4vc.public_routes.token._verify_dpop_proof",
                AsyncMock(),
            ) as mock_dpop,
        ):
            from oid4vc.public_routes.token import check_token

            await check_token(
                context,
                "DPoP some-access-token",
                dpop_header="some-dpop-jwt",
                method="POST",
                url="https://issuer.example/credential",
            )
            mock_dpop.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bearer_scheme_skips_dpop_verification(self, context):
        """Bearer tokens must NOT invoke DPoP proof verification."""
        with (
            patch(
                "oid4vc.public_routes.token.Config.from_settings",
                return_value=self._mock_config(),
            ),
            patch(
                "oid4vc.public_routes.token.jwt_verify",
                AsyncMock(
                    return_value=MagicMock(
                        verified=True,
                        payload={"sub": "test", "exp": 9999999999},
                    )
                ),
            ),
            patch(
                "oid4vc.public_routes.token._verify_dpop_proof",
                AsyncMock(),
            ) as mock_dpop,
        ):
            from oid4vc.public_routes.token import check_token

            await check_token(
                context,
                "Bearer some-access-token",
                dpop_header="some-dpop-jwt",
                method="POST",
                url="https://issuer.example/credential",
            )
            mock_dpop.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_dpop_without_proof_header_raises_401(self, context):
        """DPoP scheme without a DPoP proof header MUST be rejected (RFC 9449 §4.3)."""
        with (
            patch(
                "oid4vc.public_routes.token.Config.from_settings",
                return_value=self._mock_config(),
            ),
            patch(
                "oid4vc.public_routes.token.jwt_verify",
                AsyncMock(
                    return_value=MagicMock(
                        verified=True,
                        payload={"sub": "test", "exp": 9999999999},
                    )
                ),
            ),
            patch(
                "oid4vc.public_routes.token._verify_dpop_proof",
                AsyncMock(),
            ) as mock_dpop,
        ):
            from oid4vc.public_routes.token import check_token

            with pytest.raises(web.HTTPUnauthorized):
                await check_token(
                    context,
                    "DPoP some-access-token",
                    dpop_header=None,
                    method="POST",
                    url="https://issuer.example/credential",
                )
            mock_dpop.assert_not_awaited()
