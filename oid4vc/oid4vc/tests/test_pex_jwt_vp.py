"""Tests for JWT VP outer wrapper verification in the PEX evaluator."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from oid4vc.cred_processor import CredProcessors


class TestJwtVpOuterWrapper:
    """Tests for the JWT VP outer wrapper signature check in PEX.verify()."""

    @pytest.mark.asyncio
    async def test_tampered_signature_returns_unverified(self, profile):
        """A jwt_vp with an invalid outer signature must produce verified=False."""
        from oid4vc.pex import PresentationExchangeEvaluator

        evaluator = PresentationExchangeEvaluator.compile(
            {
                "id": "4a5b6c7d-0001-4000-8000-000000000001",
                "input_descriptors": [
                    {
                        "id": "descriptor-first",
                        "constraints": {"fields": [{"path": ["$.type"]}]},
                    }
                ],
            }
        )
        submission = {
            "id": "4a5b6c7d-0001-4000-8000-000000000002",
            "definition_id": "4a5b6c7d-0001-4000-8000-000000000001",
            "descriptor_map": [
                {"id": "descriptor-first", "format": "jwt_vp", "path": "$"}
            ],
        }

        with patch(
            "oid4vc.pex.jwt_verify",
            AsyncMock(return_value=MagicMock(verified=False, payload={})),
        ):
            result = await evaluator.verify(
                profile,
                submission,
                "eyJhbGciOiJFUzI1NiJ9.eyJ2cCI6e319.INVALIDSIGNATURE",
            )

        assert result.verified is False
        assert "JWT VP" in (result.details or "")

    @pytest.mark.asyncio
    async def test_valid_outer_passes_to_descriptor_evaluation(self, profile):
        """A valid jwt_vp must have its decoded payload evaluated against the descriptor."""
        from oid4vc.pex import PresentationExchangeEvaluator

        vp_payload = {"vp": {"type": ["VerifiablePresentation"]}}
        evaluator = PresentationExchangeEvaluator.compile(
            {
                "id": "4a5b6c7d-0001-4000-8000-000000000003",
                "input_descriptors": [
                    {
                        "id": "descriptor-first",
                        "constraints": {"fields": [{"path": ["$.vp.type"]}]},
                    }
                ],
            }
        )
        submission = {
            "id": "4a5b6c7d-0001-4000-8000-000000000004",
            "definition_id": "4a5b6c7d-0001-4000-8000-000000000003",
            "descriptor_map": [
                {"id": "descriptor-first", "format": "jwt_vp", "path": "$"}
            ],
        }

        mock_verifier = MagicMock()
        mock_verifier.verify_credential = AsyncMock(
            return_value=MagicMock(verified=True, payload=vp_payload)
        )
        mock_processors = MagicMock(spec=CredProcessors)
        mock_processors.cred_verifier_for_format.return_value = mock_verifier
        profile.context.injector.bind_instance(CredProcessors, mock_processors)

        with patch(
            "oid4vc.pex.jwt_verify",
            AsyncMock(return_value=MagicMock(verified=True, payload=vp_payload)),
        ):
            result = await evaluator.verify(
                profile, submission, "eyJhbGciOiJFUzI1NiJ9.payload.sig"
            )

        assert result.verified is True

    @pytest.mark.asyncio
    async def test_non_jwt_vp_format_skips_outer_decode(self, profile):
        """Non jwt_vp formats must NOT attempt JWT VP outer decoding."""
        from oid4vc.pex import PresentationExchangeEvaluator

        presentation = {"type": ["VerifiablePresentation"]}
        evaluator = PresentationExchangeEvaluator.compile(
            {
                "id": "4a5b6c7d-0001-4000-8000-000000000005",
                "input_descriptors": [
                    {
                        "id": "descriptor-first",
                        "constraints": {"fields": [{"path": ["$.type"]}]},
                    }
                ],
            }
        )
        submission = {
            "id": "4a5b6c7d-0001-4000-8000-000000000006",
            "definition_id": "4a5b6c7d-0001-4000-8000-000000000005",
            "descriptor_map": [
                {"id": "descriptor-first", "format": "ldp_vp", "path": "$"}
            ],
        }

        mock_verifier = MagicMock()
        mock_verifier.verify_credential = AsyncMock(
            return_value=MagicMock(verified=True, payload=presentation)
        )
        mock_processors = MagicMock(spec=CredProcessors)
        mock_processors.cred_verifier_for_format.return_value = mock_verifier
        profile.context.injector.bind_instance(CredProcessors, mock_processors)

        with patch("oid4vc.pex.jwt_verify", AsyncMock()) as mock_jwt_verify:
            await evaluator.verify(profile, submission, presentation)

        mock_jwt_verify.assert_not_awaited()
