"""Tests for the sub-wallet trust-store isolation fix.

BUG (fixed):
    ``_mso_mdoc_processor`` is a module-level singleton.  At startup a
    ``WalletTrustStore(root_profile)`` is attached to it.  When a sub-wallet
    request arrives, ``verify_presentation`` / ``verify_credential`` forward
    ``self.trust_store`` — which still holds the root profile — to the
    verifier.  ``refresh_cache()`` therefore queries the root wallet's Askar
    store, making any trust anchors registered via
    ``POST /mso_mdoc/trust-anchors`` with a sub-wallet Bearer invisible.

FIX:
    When ``OID4VC_MDOC_TRUST_STORE_TYPE=wallet``, both methods now construct a
    fresh ``WalletTrustStore(profile)`` from the *calling* profile rather than
    forwarding ``self.trust_store``.  For file- and None-based stores the
    singleton is still reused.

HOW TO RUN:
    pytest mso_mdoc/tests/test_wallet_trust_store_per_request.py -v
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


def _make_processor(root_trust_store: MagicMock) -> MsoMdocCredProcessor:
    """Return a processor with a singleton trust store simulating startup state."""
    processor = MsoMdocCredProcessor()
    processor.trust_store = root_trust_store
    return processor


# ---------------------------------------------------------------------------
# verify_presentation — wallet mode
# ---------------------------------------------------------------------------


class TestVerifyPresentationWalletTrustStorePerRequest:
    """verify_presentation must build a per-request WalletTrustStore when
    OID4VC_MDOC_TRUST_STORE_TYPE=wallet."""

    @pytest.mark.asyncio
    async def test_uses_calling_profile_not_singleton(self, monkeypatch):
        """A fresh WalletTrustStore(profile) must be constructed with the
        sub-wallet profile, not forwarded from self.trust_store."""
        root_trust_store = MagicMock(name="root_trust_store")
        processor = _make_processor(root_trust_store)
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

        monkeypatch.setenv("OID4VC_MDOC_TRUST_STORE_TYPE", "wallet")

        with (
            patch(
                "mso_mdoc.cred_processor.MsoMdocCredProcessor.verify_presentation.__wrapped__"
                if False
                else "mso_mdoc.mdoc.verifier.WalletTrustStore",
                FakeWalletTrustStore,
            ),
            patch(
                "mso_mdoc.mdoc.verifier.MsoMdocPresVerifier",
                return_value=mock_verifier_instance,
            ),
        ):
            await processor.verify_presentation(sub_profile, {}, pres_record)

        assert len(captured_profiles) == 1, (
            "WalletTrustStore must be constructed exactly once per request"
        )
        assert captured_profiles[0] is sub_profile, (
            "WalletTrustStore must be constructed with the calling (sub-wallet) "
            "profile, not the root profile from the singleton trust store.\n"
            f"Got: {captured_profiles[0]!r}\nExpected: {sub_profile!r}"
        )

    @pytest.mark.asyncio
    async def test_does_not_use_singleton_trust_store(self, monkeypatch):
        """self.trust_store (root profile) must NOT be passed to the verifier
        when OID4VC_MDOC_TRUST_STORE_TYPE=wallet."""
        root_trust_store = MagicMock(name="root_trust_store")
        processor = _make_processor(root_trust_store)
        sub_profile = _make_profile("tenant-456")
        pres_record = MagicMock()

        trust_stores_passed: list = []

        class CapturingPresVerifier:
            def __init__(self, trust_store=None):
                trust_stores_passed.append(trust_store)

            async def verify_presentation(self, *args, **kwargs):
                return MagicMock(verified=True)

        monkeypatch.setenv("OID4VC_MDOC_TRUST_STORE_TYPE", "wallet")

        with (
            patch(
                "mso_mdoc.mdoc.verifier.WalletTrustStore",
                lambda profile: f"ws({profile})",
            ),
            patch(
                "mso_mdoc.mdoc.verifier.MsoMdocPresVerifier",
                CapturingPresVerifier,
            ),
        ):
            await processor.verify_presentation(sub_profile, {}, pres_record)

        assert len(trust_stores_passed) == 1
        assert trust_stores_passed[0] is not root_trust_store, (
            "The singleton root trust store must NOT be forwarded to the verifier "
            "in wallet mode.  The verifier received self.trust_store instead of "
            "a fresh WalletTrustStore(calling_profile)."
        )

    @pytest.mark.asyncio
    async def test_file_mode_reuses_singleton(self, monkeypatch):
        """In file mode the singleton self.trust_store must be reused — no new
        WalletTrustStore is constructed."""
        root_trust_store = MagicMock(name="file_trust_store")
        processor = _make_processor(root_trust_store)
        sub_profile = _make_profile("tenant-789")
        pres_record = MagicMock()

        trust_stores_passed: list = []

        class CapturingPresVerifier:
            def __init__(self, trust_store=None):
                trust_stores_passed.append(trust_store)

            async def verify_presentation(self, *args, **kwargs):
                return MagicMock(verified=True)

        monkeypatch.setenv("OID4VC_MDOC_TRUST_STORE_TYPE", "file")

        with patch(
            "mso_mdoc.mdoc.verifier.MsoMdocPresVerifier",
            CapturingPresVerifier,
        ):
            await processor.verify_presentation(sub_profile, {}, pres_record)

        assert len(trust_stores_passed) == 1
        assert trust_stores_passed[0] is root_trust_store, (
            "In file mode, the singleton trust store must be reused."
        )

    @pytest.mark.asyncio
    async def test_default_env_reuses_singleton(self, monkeypatch):
        """Without OID4VC_MDOC_TRUST_STORE_TYPE set the default is 'file' and
        the singleton must be reused."""
        root_trust_store = MagicMock(name="default_trust_store")
        processor = _make_processor(root_trust_store)
        sub_profile = _make_profile()
        pres_record = MagicMock()

        trust_stores_passed: list = []

        class CapturingPresVerifier:
            def __init__(self, trust_store=None):
                trust_stores_passed.append(trust_store)

            async def verify_presentation(self, *args, **kwargs):
                return MagicMock(verified=True)

        monkeypatch.delenv("OID4VC_MDOC_TRUST_STORE_TYPE", raising=False)

        with patch(
            "mso_mdoc.mdoc.verifier.MsoMdocPresVerifier",
            CapturingPresVerifier,
        ):
            await processor.verify_presentation(sub_profile, {}, pres_record)

        assert trust_stores_passed[0] is root_trust_store, (
            "Default (file) mode must reuse the singleton trust store."
        )


# ---------------------------------------------------------------------------
# verify_credential — wallet mode
# ---------------------------------------------------------------------------


class TestVerifyCredentialWalletTrustStorePerRequest:
    """verify_credential must build a per-request WalletTrustStore when
    OID4VC_MDOC_TRUST_STORE_TYPE=wallet."""

    @pytest.mark.asyncio
    async def test_uses_calling_profile_not_singleton(self, monkeypatch):
        """A fresh WalletTrustStore(profile) must be constructed with the
        sub-wallet profile."""
        root_trust_store = MagicMock(name="root_trust_store")
        processor = _make_processor(root_trust_store)
        sub_profile = _make_profile("cred-tenant-1")

        trust_stores_passed: list = []

        class CapturingCredVerifier:
            def __init__(self, trust_store=None):
                trust_stores_passed.append(trust_store)

            async def verify_credential(self, *args, **kwargs):
                return MagicMock(verified=True)

        captured_wts_profiles: list = []

        def fake_wts(profile):
            captured_wts_profiles.append(profile)
            return f"wts({id(profile)})"

        monkeypatch.setenv("OID4VC_MDOC_TRUST_STORE_TYPE", "wallet")

        with (
            patch("mso_mdoc.mdoc.verifier.WalletTrustStore", fake_wts),
            patch(
                "mso_mdoc.mdoc.verifier.MsoMdocCredVerifier",
                CapturingCredVerifier,
            ),
        ):
            await processor.verify_credential(sub_profile, "raw-credential")

        assert len(captured_wts_profiles) == 1
        assert captured_wts_profiles[0] is sub_profile, (
            "verify_credential must construct WalletTrustStore with the calling "
            "profile, not the root profile singleton."
        )
        assert trust_stores_passed[0] is not root_trust_store, (
            "The singleton root trust store must NOT be forwarded in wallet mode."
        )

    @pytest.mark.asyncio
    async def test_file_mode_reuses_singleton(self, monkeypatch):
        """In file mode the singleton self.trust_store must be reused."""
        root_trust_store = MagicMock(name="file_trust_store")
        processor = _make_processor(root_trust_store)
        sub_profile = _make_profile("cred-tenant-2")

        trust_stores_passed: list = []

        class CapturingCredVerifier:
            def __init__(self, trust_store=None):
                trust_stores_passed.append(trust_store)

            async def verify_credential(self, *args, **kwargs):
                return MagicMock(verified=True)

        monkeypatch.setenv("OID4VC_MDOC_TRUST_STORE_TYPE", "file")

        with patch(
            "mso_mdoc.mdoc.verifier.MsoMdocCredVerifier",
            CapturingCredVerifier,
        ):
            await processor.verify_credential(sub_profile, "raw-credential")

        assert trust_stores_passed[0] is root_trust_store, (
            "In file mode, the singleton trust store must be reused."
        )


# ---------------------------------------------------------------------------
# Isolation: two concurrent sub-wallet calls get independent trust stores
# ---------------------------------------------------------------------------


class TestConcurrentSubWalletIsolation:
    """Each concurrent sub-wallet call must get its own WalletTrustStore so
    cache refreshes in one tenant don't affect another."""

    @pytest.mark.asyncio
    async def test_independent_trust_stores_per_call(self, monkeypatch):
        """Two concurrent verify_presentation calls with different profiles
        must each receive a WalletTrustStore built from their own profile."""
        root_trust_store = MagicMock(name="root_trust_store")
        processor = _make_processor(root_trust_store)

        profile_a = _make_profile("tenant-A")
        profile_b = _make_profile("tenant-B")
        pres_record = MagicMock()

        wts_calls: list = []

        def fake_wts(profile):
            wts_calls.append(profile)
            return MagicMock(name=f"wts-{profile.settings['wallet.id']}")

        async def fake_verify(*args, **kwargs):
            return MagicMock(verified=True)

        monkeypatch.setenv("OID4VC_MDOC_TRUST_STORE_TYPE", "wallet")

        with (
            patch("mso_mdoc.mdoc.verifier.WalletTrustStore", fake_wts),
            patch("mso_mdoc.mdoc.verifier.MsoMdocPresVerifier") as mock_verifier_cls,
        ):
            mock_verifier_cls.return_value.verify_presentation = AsyncMock(
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
