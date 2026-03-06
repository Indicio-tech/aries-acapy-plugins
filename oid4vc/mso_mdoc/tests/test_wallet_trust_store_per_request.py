"""Tests for per-request wallet-scoped trust store isolation.

Trust anchors are always stored in the Askar wallet; each call to
verify_credential / verify_presentation builds a fresh WalletTrustStore from
the *calling* profile so that sub-wallet tenants see only their own registry.
"""

import sys
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub the Rust native extension before any local imports.
# ---------------------------------------------------------------------------
_iso_stub = MagicMock()
sys.modules.setdefault("isomdl_uniffi", _iso_stub)

from ..cred_processor import MsoMdocCredProcessor  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(wallet_id: str = "sub-wallet-abc"):
    """Return a minimal mock profile."""
    profile = MagicMock()
    profile.settings = {"wallet.id": wallet_id}

    @asynccontextmanager
    async def _session():
        yield MagicMock()

    profile.session = _session
    return profile


def _make_processor() -> MsoMdocCredProcessor:
    """Return a fresh processor (trust store is always built per-request)."""
    return MsoMdocCredProcessor()


# ---------------------------------------------------------------------------
# verify_presentation — wallet-scoped per-request
# ---------------------------------------------------------------------------


class TestVerifyPresentationWalletTrustStorePerRequest:
    """verify_presentation must build a per-request WalletTrustStore from the
    calling profile on every call, keeping tenant registries isolated."""

    @pytest.mark.asyncio
    async def test_uses_calling_profile(self):
        """A fresh WalletTrustStore(profile) must be built from the calling
        profile on every verify_presentation call."""
        processor = _make_processor()
        sub_profile = _make_profile("tenant-123")
        pres_record = MagicMock()

        captured_profiles: list = []

        class FakeWalletTrustStore:
            def __init__(self, profile):
                captured_profiles.append(profile)

        mock_verifier_instance = MagicMock()
        mock_verifier_instance.verify_presentation = AsyncMock(
            return_value=MagicMock(verified=True)
        )

        with (
            patch(
                "mso_mdoc.cred_processor.WalletTrustStore",
                FakeWalletTrustStore,
            ),
            patch(
                "mso_mdoc.cred_processor.MsoMdocPresVerifier",
                return_value=mock_verifier_instance,
            ),
        ):
            await processor.verify_presentation(sub_profile, {}, pres_record)

        assert len(captured_profiles) == 1, (
            "WalletTrustStore must be constructed exactly once per request"
        )
        assert captured_profiles[0] is sub_profile, (
            "WalletTrustStore must be constructed with the calling (sub-wallet) "
            "profile.\n"
            f"Got: {captured_profiles[0]!r}\nExpected: {sub_profile!r}"
        )

    @pytest.mark.asyncio
    async def test_does_not_reuse_stale_trust_store(self):
        """self.trust_store (if set) must NOT be passed directly to the verifier;
        a fresh WalletTrustStore built from the calling profile is always used."""
        processor = _make_processor()
        # Simulate a stale/root trust store on the processor (legacy state)
        stale_trust_store = MagicMock(name="stale_root_trust_store")
        processor.trust_store = stale_trust_store

        sub_profile = _make_profile("tenant-456")
        pres_record = MagicMock()

        trust_stores_passed: list = []

        class CapturingPresVerifier:
            def __init__(self, trust_store=None):
                trust_stores_passed.append(trust_store)

            async def verify_presentation(self, *args, **kwargs):
                return MagicMock(verified=True)

        with (
            patch(
                "mso_mdoc.cred_processor.WalletTrustStore",
                lambda profile: f"ws({id(profile)})",
            ),
            patch(
                "mso_mdoc.cred_processor.MsoMdocPresVerifier",
                CapturingPresVerifier,
            ),
        ):
            await processor.verify_presentation(sub_profile, {}, pres_record)

        assert len(trust_stores_passed) == 1
        assert trust_stores_passed[0] is not stale_trust_store, (
            "A stale root trust store must NOT be forwarded to the verifier.  "
            "A fresh WalletTrustStore(calling_profile) must always be used."
        )


# ---------------------------------------------------------------------------
# Isolation: two concurrent sub-wallet calls get independent trust stores
# ---------------------------------------------------------------------------


class TestConcurrentSubWalletIsolation:
    """Each concurrent sub-wallet call must get its own WalletTrustStore so
    cache refreshes in one tenant do not affect another."""

    @pytest.mark.asyncio
    async def test_independent_trust_stores_per_call(self):
        """Two concurrent verify_presentation calls with different profiles
        must each receive a WalletTrustStore built from their own profile."""
        processor = _make_processor()

        profile_a = _make_profile("tenant-A")
        profile_b = _make_profile("tenant-B")
        pres_record = MagicMock()

        wts_calls: list = []

        def fake_wts(profile):
            wts_calls.append(profile)
            return MagicMock(name=f"wts-{profile.settings['wallet.id']}")

        with (
            patch("mso_mdoc.cred_processor.WalletTrustStore", fake_wts),
            patch("mso_mdoc.cred_processor.MsoMdocPresVerifier") as mock_cls,
        ):
            mock_cls.return_value.verify_presentation = AsyncMock(
                return_value=MagicMock(verified=True)
            )
            import asyncio

            await asyncio.gather(
                processor.verify_presentation(profile_a, {}, pres_record),
                processor.verify_presentation(profile_b, {}, pres_record),
            )

        assert len(wts_calls) == 2, "Each call must construct its own WalletTrustStore"
        profiles_seen = {id(p) for p in wts_calls}
        assert id(profile_a) in profiles_seen
        assert id(profile_b) in profiles_seen


# ---------------------------------------------------------------------------
# verify_credential — wallet-scoped per-request
# ---------------------------------------------------------------------------


class TestVerifyCredentialWalletTrustStorePerRequest:
    """verify_credential must build a per-request WalletTrustStore from the
    calling profile on every call."""

    @pytest.mark.asyncio
    async def test_uses_calling_profile(self):
        """A fresh WalletTrustStore(profile) must be built from the calling
        profile on every verify_credential call."""
        processor = _make_processor()
        sub_profile = _make_profile("cred-tenant-1")

        captured_wts_profiles: list = []

        def fake_wts(profile):
            captured_wts_profiles.append(profile)
            return f"wts({id(profile)})"

        trust_stores_passed: list = []

        class CapturingCredVerifier:
            def __init__(self, trust_store=None):
                trust_stores_passed.append(trust_store)

            async def verify_credential(self, *args, **kwargs):
                return MagicMock(verified=True)

        with (
            patch("mso_mdoc.cred_processor.WalletTrustStore", fake_wts),
            patch(
                "mso_mdoc.cred_processor.MsoMdocCredVerifier",
                CapturingCredVerifier,
            ),
        ):
            await processor.verify_credential(sub_profile, "raw-credential")

        assert len(captured_wts_profiles) == 1
        assert captured_wts_profiles[0] is sub_profile, (
            "verify_credential must construct WalletTrustStore with the calling profile."
        )
