"""Tests for all P0/P1/P2 improvements implemented in feat/oid4vc-bugfixes.

Covers:
  - P0: DPoP RFC 9449 proof verification (_verify_dpop_proof, check_token)
  - P1: .well-known/did-configuration.json endpoint
  - P1: JWT VP outer wrapper verification in PEX evaluator
  - P2: SupportedCredential.query() result cap (SUPPORTED_CRED_QUERY_LIMIT)
"""

import base64
import hashlib
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aries_askar import Key, KeyAlg

from oid4vc.public_routes.metadata import SUPPORTED_CRED_QUERY_LIMIT
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
# P0: _verify_dpop_proof unit tests
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
        # Must not raise
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
        # Second add raises StorageDuplicateError (replay)
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
        old_iat = int(time.time()) - 3600  # 1 hour ago
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
        # Flip the last byte of the signature
        parts = proof.rsplit(".", 1)
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
        # Build a proof without the jwk header field
        ath = (
            base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        header = {"typ": "dpop+jwt", "alg": "ES256"}  # no jwk!
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
        # DPoP proof has htu without query; request URL has query params
        proof = _make_dpop_proof(
            key,
            "ES256",
            htu="https://issuer.example/credential",
            access_token=access_token,
        )
        # Request URL with query params — should still match
        await _verify_dpop_proof(
            profile,
            dpop_proof=proof,
            access_token=access_token,
            method="POST",
            url="https://issuer.example/credential?foo=bar",
        )


# ---------------------------------------------------------------------------
# P0: check_token DPoP integration tests
# ---------------------------------------------------------------------------


class TestCheckTokenDpop:
    """Integration tests ensuring check_token calls _verify_dpop_proof."""

    def _mock_config(self):
        """Return a mock Config with no auth_server_url so jwt_verify path is used."""
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

            result = await check_token(
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
    async def test_dpop_without_proof_header_logs_and_continues(self, context):
        """DPoP scheme without dpop_header should log a warning and not raise."""
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

            # dpop_header=None: backward-compat mode, should not raise
            result = await check_token(
                context,
                "DPoP some-access-token",
                dpop_header=None,
                method="POST",
                url="https://issuer.example/credential",
            )
            mock_dpop.assert_not_awaited()
            assert result.verified is True


# ---------------------------------------------------------------------------
# P1: .well-known/did-configuration.json endpoint
# ---------------------------------------------------------------------------


class TestDidConfiguration:
    """Tests for the DIF Well-Known DID Configuration endpoint."""

    @pytest.mark.asyncio
    async def test_did_configuration_returns_valid_document(self, context):
        """Endpoint must return a JSON document with @context and linked_dids."""
        from oid4vc.public_routes.did_configuration import did_configuration

        mock_did_info = MagicMock()
        mock_did_info.did = "did:jwk:test123"

        request = MagicMock()
        request.__getitem__ = (
            lambda _, k: context if k == "context" else (_ for _ in ()).throw(KeyError(k))
        )
        request.match_info = {}

        with (
            patch(
                "oid4vc.public_routes.did_configuration.retrieve_or_create_did_jwk",
                AsyncMock(return_value=mock_did_info),
            ),
            patch(
                "oid4vc.public_routes.did_configuration.jwt_sign",
                AsyncMock(return_value="signed.jwt.token"),
            ),
        ):
            response = await did_configuration(request)

        assert response.status == 200
        body = json.loads(response.body)
        assert "@context" in body
        assert body["@context"] == (
            "https://identity.foundation/.well-known/did-configuration/v1"
        )
        assert "linked_dids" in body
        assert isinstance(body["linked_dids"], list)
        assert len(body["linked_dids"]) == 1
        assert body["linked_dids"][0] == "signed.jwt.token"

    @pytest.mark.asyncio
    async def test_did_configuration_cache_control_header(self, context):
        """Response must carry Cache-Control: no-store."""
        from oid4vc.public_routes.did_configuration import did_configuration

        mock_did_info = MagicMock()
        mock_did_info.did = "did:jwk:test123"

        request = MagicMock()
        request.__getitem__ = (
            lambda _, k: context if k == "context" else (_ for _ in ()).throw(KeyError(k))
        )
        request.match_info = {}

        with (
            patch(
                "oid4vc.public_routes.did_configuration.retrieve_or_create_did_jwk",
                AsyncMock(return_value=mock_did_info),
            ),
            patch(
                "oid4vc.public_routes.did_configuration.jwt_sign",
                AsyncMock(return_value="signed.jwt.token"),
            ),
        ):
            response = await did_configuration(request)

        assert response.headers.get("Cache-Control") == "no-store"

    @pytest.mark.asyncio
    async def test_did_configuration_registered_in_routes(self):
        """The .well-known/did-configuration.json route must be registered."""
        from oid4vc.public_routes.registration import register

        app = web.Application()
        app.router.freeze = lambda: None

        context_mock = MagicMock()
        await register(app, multitenant=False, context=context_mock)

        routes = [resource.canonical for resource in app.router.resources()]
        assert "/.well-known/did-configuration.json" in routes, (
            "/.well-known/did-configuration.json route must be registered"
        )


# ---------------------------------------------------------------------------
# P1: JWT VP outer wrapper verification in PEX evaluator
# ---------------------------------------------------------------------------


class TestJwtVpOuterWrapper:
    """Tests for the JWT VP outer wrapper signature check in PEX.verify()."""

    @pytest.mark.asyncio
    async def test_jwt_vp_with_tampered_signature_returns_unverified(self, profile):
        """A jwt_vp with an invalid outer signature must produce verified=False."""
        from oid4vc.pex import PresentationExchangeEvaluator

        _DEF = {
            "id": "4a5b6c7d-0001-4000-8000-000000000001",
            "input_descriptors": [
                {
                    "id": "descriptor-first",
                    "constraints": {"fields": [{"path": ["$.type"]}]},
                }
            ],
        }

        evaluator = PresentationExchangeEvaluator.compile(_DEF)

        submission = {
            "id": "4a5b6c7d-0001-4000-8000-000000000002",
            "definition_id": "4a5b6c7d-0001-4000-8000-000000000001",
            "descriptor_map": [
                {"id": "descriptor-first", "format": "jwt_vp", "path": "$"}
            ],
        }

        # A syntactically valid JWT string with an invalid (tampered) signature
        tampered_vp = "eyJhbGciOiJFUzI1NiJ9.eyJ2cCI6e319.INVALIDSIGNATURE"

        with patch(
            "oid4vc.pex.jwt_verify",
            AsyncMock(
                return_value=MagicMock(
                    verified=False,
                    payload={},
                )
            ),
        ):
            result = await evaluator.verify(profile, submission, tampered_vp)

        assert result.verified is False
        assert "JWT VP" in (result.details or "")

    @pytest.mark.asyncio
    async def test_jwt_vp_valid_outer_passes_to_inner_verification(self, profile):
        """A valid jwt_vp must have its decoded payload evaluated against the descriptor."""
        from unittest.mock import MagicMock, AsyncMock, patch
        from oid4vc.cred_processor import CredProcessors
        from oid4vc.pex import PresentationExchangeEvaluator

        _DEF = {
            "id": "4a5b6c7d-0001-4000-8000-000000000003",
            "input_descriptors": [
                {
                    "id": "descriptor-first",
                    "constraints": {"fields": [{"path": ["$.vp.type"]}]},
                }
            ],
        }

        evaluator = PresentationExchangeEvaluator.compile(_DEF)

        submission = {
            "id": "4a5b6c7d-0001-4000-8000-000000000004",
            "definition_id": "4a5b6c7d-0001-4000-8000-000000000003",
            "descriptor_map": [
                {"id": "descriptor-first", "format": "jwt_vp", "path": "$"}
            ],
        }

        vp_payload = {"vp": {"type": ["VerifiablePresentation"]}}

        mock_verifier = MagicMock()
        mock_verifier.verify_credential = AsyncMock(
            return_value=MagicMock(
                verified=True,
                payload=vp_payload,
            )
        )
        mock_processors = MagicMock(spec=CredProcessors)
        mock_processors.cred_verifier_for_format.return_value = mock_verifier
        profile.context.injector.bind_instance(CredProcessors, mock_processors)

        raw_vp_jwt = "eyJhbGciOiJFUzI1NiJ9.payload.sig"

        with patch(
            "oid4vc.pex.jwt_verify",
            AsyncMock(
                return_value=MagicMock(
                    verified=True,
                    payload=vp_payload,
                )
            ),
        ):
            result = await evaluator.verify(profile, submission, raw_vp_jwt)

        assert result.verified is True

    @pytest.mark.asyncio
    async def test_non_jwt_vp_format_skips_outer_jwt_decode(self, profile):
        """Non jwt_vp formats must NOT attempt JWT VP outer decoding."""
        from oid4vc.cred_processor import CredProcessors
        from oid4vc.pex import PresentationExchangeEvaluator

        _DEF = {
            "id": "4a5b6c7d-0001-4000-8000-000000000005",
            "input_descriptors": [
                {
                    "id": "descriptor-first",
                    "constraints": {"fields": [{"path": ["$.type"]}]},
                }
            ],
        }

        evaluator = PresentationExchangeEvaluator.compile(_DEF)
        submission = {
            "id": "4a5b6c7d-0001-4000-8000-000000000006",
            "definition_id": "4a5b6c7d-0001-4000-8000-000000000005",
            "descriptor_map": [
                {"id": "descriptor-first", "format": "ldp_vp", "path": "$"}
            ],
        }
        presentation = {"type": ["VerifiablePresentation"]}

        mock_verifier = MagicMock()
        mock_verifier.verify_credential = AsyncMock(
            return_value=MagicMock(
                verified=True,
                payload=presentation,
            )
        )
        mock_processors = MagicMock(spec=CredProcessors)
        mock_processors.cred_verifier_for_format.return_value = mock_verifier
        profile.context.injector.bind_instance(CredProcessors, mock_processors)

        with patch("oid4vc.pex.jwt_verify", AsyncMock()) as mock_jwt_verify:
            await evaluator.verify(profile, submission, presentation)

        mock_jwt_verify.assert_not_awaited()


# ---------------------------------------------------------------------------
# P2: SupportedCredential.query() pagination constant
# ---------------------------------------------------------------------------


class TestSupportedCredQueryLimit:
    """Tests for the SUPPORTED_CRED_QUERY_LIMIT cap in metadata endpoints."""

    def test_limit_constant_is_a_positive_int(self):
        """SUPPORTED_CRED_QUERY_LIMIT must be a positive integer."""
        assert isinstance(SUPPORTED_CRED_QUERY_LIMIT, int)
        assert SUPPORTED_CRED_QUERY_LIMIT > 0

    @pytest.mark.asyncio
    async def test_metadata_caps_credentials_at_limit(self, context):
        """credential_issuer_metadata must not return more than SUPPORTED_CRED_QUERY_LIMIT creds."""
        from oid4vc.models.supported_cred import SupportedCredential
        from oid4vc.public_routes.metadata import credential_issuer_metadata

        # Create LIMIT + 5 supported credentials
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
        assert len(cred_configs) <= SUPPORTED_CRED_QUERY_LIMIT, (
            f"Response contained {len(cred_configs)} credentials; "
            f"expected at most {SUPPORTED_CRED_QUERY_LIMIT}"
        )
