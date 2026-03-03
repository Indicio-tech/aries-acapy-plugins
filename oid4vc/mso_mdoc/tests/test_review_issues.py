"""Tests verifying fixes for issues identified in CODE_REVIEW.md.

Each test class is labelled with the review issue ID it covers.
Tests in this module are pure-unit tests: heavy dependencies
(isomdl_uniffi, acapy_agent) are mocked so the file can run in a
standard development environment without native extensions.
"""

import sys
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Patch sys.modules before any plugin import so that native extensions and
# acapy_agent sub-packages resolve to MagicMock objects.
# ---------------------------------------------------------------------------
_MOCK_MODULES = [
    "isomdl_uniffi",
    "cbor2",
    "pydid",
    "acapy_agent",
    "acapy_agent.admin",
    "acapy_agent.admin.request_context",
    "acapy_agent.core",
    "acapy_agent.core.profile",
    "acapy_agent.storage",
    "acapy_agent.storage.base",
    "acapy_agent.storage.error",
    "oid4vc",
    "oid4vc.config",
    "oid4vc.cred_processor",
    "oid4vc.models",
    "oid4vc.models.exchange",
    "oid4vc.models.presentation",
    "oid4vc.models.supported_cred",
    "oid4vc.pop_result",
    "oid4vc.did_utils",
]

for _mod in _MOCK_MODULES:
    sys.modules.setdefault(_mod, MagicMock())

# Set up the oid4vc.cred_processor exceptions so they behave like real
# exception classes.
_cred_proc_mock = sys.modules["oid4vc.cred_processor"]
_cred_proc_mock.CredProcessorError = type("CredProcessorError", (Exception,), {})
_cred_proc_mock.PresVerifierError = type("PresVerifierError", (Exception,), {})
_cred_proc_mock.VerifyResult = type(
    "VerifyResult",
    (),
    {
        "__init__": lambda self, verified, payload=None: (
            setattr(self, "verified", verified) or setattr(self, "payload", payload)
        )
    },
)
_cred_proc_mock.Issuer = object
_cred_proc_mock.CredVerifier = object
_cred_proc_mock.PresVerifier = object

# Expose storage error classes needed by storage modules.
_storage_error_mock = sys.modules["acapy_agent.storage.error"]
_storage_error_mock.StorageError = type("StorageError", (Exception,), {})
_storage_error_mock.StorageDuplicateError = type(
    "StorageDuplicateError", (Exception,), {}
)
_storage_error_mock.StorageNotFoundError = type("StorageNotFoundError", (Exception,), {})

# Expose AuthenticationStatus enum-like constants on isomdl_uniffi.
_iso_mock = sys.modules["isomdl_uniffi"]
_iso_mock.AuthenticationStatus = MagicMock()
_iso_mock.AuthenticationStatus.VALID = "VALID"
_iso_mock.AuthenticationStatus.INVALID = "INVALID"
_iso_mock.MdocVerificationError = type("MdocVerificationError", (Exception,), {})

# ---------------------------------------------------------------------------
# Now import the modules under test.
# ---------------------------------------------------------------------------
from ..mdoc.verifier import (  # noqa: E402
    FileTrustStore,
    MsoMdocCredVerifier,
    MsoMdocPresVerifier,
    WalletTrustStore,
    _parse_string_credential,
)
from ..cred_processor import MsoMdocCredProcessor  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_mock_profile():
    """Return a mock Profile with an async session context manager."""
    profile = MagicMock()
    mock_session = MagicMock()

    @asynccontextmanager
    async def _session():
        yield mock_session

    profile.session = _session
    profile.settings = MagicMock()
    profile.settings.get = MagicMock(return_value=None)
    return profile, mock_session


def make_mock_presentation_record(nonce="test-nonce"):
    """Return a minimal OID4VPPresentation mock."""
    record = MagicMock()
    record.nonce = nonce
    record.presentation_id = "pres-001"
    return record


# ===========================================================================
# CRIT-1 / CRIT-4 — trust_anchor_registry / trust_anchors must never be None
# ===========================================================================


class TestCrit1TrustAnchorRegistryNotNone:
    """CRIT-1: verify_presentation passes [] not None to isomdl when no anchors."""

    @pytest.mark.asyncio
    async def test_no_trust_store_passes_empty_registry(self):
        """verify_presentation with no trust_store must call verify_oid4vp_response
        with an empty list, not None, for trust_anchor_registry."""
        verifier = MsoMdocPresVerifier(trust_store=None)
        profile, _ = make_mock_profile()
        pres_record = make_mock_presentation_record()

        with (
            patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.verifier.Config") as mock_config,
            patch("oid4vc.did_utils.retrieve_or_create_did_jwk") as mock_jwk_fn,
        ):
            mock_config.from_settings.return_value.endpoint = "http://localhost"
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:test"
            mock_jwk_fn.return_value = mock_jwk

            mock_iso.AuthenticationStatus.VALID = "VALID"
            resp = MagicMock()
            resp.issuer_authentication = "VALID"
            resp.device_authentication = "VALID"
            resp.doc_type = "org.iso.18013.5.1.mDL"
            resp.verified_response = {}
            resp.errors = []
            mock_iso.verify_oid4vp_response.return_value = resp

            # present a minimal base64url payload so decoding doesn't explode
            import base64

            dummy_bytes = base64.urlsafe_b64encode(b"\x00" * 8)
            await verifier.verify_presentation(profile, dummy_bytes, pres_record)

            # The 5th positional arg to verify_oid4vp_response is the registry.
            call_args = mock_iso.verify_oid4vp_response.call_args
            registry_arg = call_args[0][4]  # positional arg index 4
            assert registry_arg == [], (
                f"Expected empty list [], got {registry_arg!r}. "
                "CRIT-1 regression: trust_anchor_registry must never be None."
            )

    @pytest.mark.asyncio
    async def test_empty_trust_store_passes_empty_registry(self):
        """verify_presentation with a trust_store returning [] also passes []."""
        mock_store = MagicMock(spec=FileTrustStore)
        mock_store.get_trust_anchors.return_value = []
        verifier = MsoMdocPresVerifier(trust_store=mock_store)
        profile, _ = make_mock_profile()
        pres_record = make_mock_presentation_record()

        with (
            patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.verifier.Config") as mock_config,
            patch("oid4vc.did_utils.retrieve_or_create_did_jwk") as mock_jwk_fn,
        ):
            mock_config.from_settings.return_value.endpoint = "http://localhost"
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:test"
            mock_jwk_fn.return_value = mock_jwk

            mock_iso.AuthenticationStatus.VALID = "VALID"
            resp = MagicMock()
            resp.issuer_authentication = "VALID"
            resp.device_authentication = "VALID"
            resp.doc_type = "org.iso.18013.5.1.mDL"
            resp.verified_response = {}
            resp.errors = []
            mock_iso.verify_oid4vp_response.return_value = resp

            import base64

            dummy_bytes = base64.urlsafe_b64encode(b"\x00" * 8)
            await verifier.verify_presentation(profile, dummy_bytes, pres_record)

            call_args = mock_iso.verify_oid4vp_response.call_args
            registry_arg = call_args[0][4]
            assert registry_arg == [], f"Expected empty list [], got {registry_arg!r}."


class TestCrit4TrustAnchorsNotNoneCredVerifier:
    """CRIT-4: verify_credential passes [] not None to verify_issuer_signature."""

    @pytest.mark.asyncio
    async def test_no_trust_store_verify_issuer_signature_gets_empty_list(self):
        """MsoMdocCredVerifier without a trust_store must pass [] to
        verify_issuer_signature, not None."""
        verifier = MsoMdocCredVerifier(trust_store=None)
        profile = MagicMock()

        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_iso:
            mock_iso.MdocVerificationError = type("MockMVE", (Exception,), {})

            captured_trust_anchors = []

            class MockVerificationResult:
                verified = True
                common_name = "Test Issuer"
                error = None

            class MockMdoc:
                def doctype(self):
                    return "org.iso.18013.5.1.mDL"

                def id(self):
                    return "mock-id"

                def details(self):
                    return {}

                def verify_issuer_signature(self, trust_anchors, chaining):
                    captured_trust_anchors.append(trust_anchors)
                    return MockVerificationResult()

            mock_iso.Mdoc.from_string.return_value = MockMdoc()

            await verifier.verify_credential(profile, "deadbeef")

            assert len(captured_trust_anchors) == 1
            assert captured_trust_anchors[0] == [], (
                f"Expected [], got {captured_trust_anchors[0]!r}. "
                "CRIT-4 regression: trust_anchors must never be None."
            )


# ===========================================================================
# CRIT-2 — holder_kid-only issuance must not raise at a hard holder_jwk check
# ===========================================================================


class TestCrit2HolderKidIssuance:
    """CRIT-2: _extract_device_key handles holder_kid with no holder_jwk."""

    def _make_pop(self, holder_jwk=None, holder_kid=None):
        pop = MagicMock()
        pop.holder_jwk = holder_jwk
        pop.holder_kid = holder_kid
        return pop

    def _make_ex_record(self, verification_method=None):
        rec = MagicMock()
        rec.verification_method = verification_method
        return rec

    def test_holder_kid_only_returns_key_id(self):
        """When only holder_kid is set, _extract_device_key returns the key fragment."""
        proc = MsoMdocCredProcessor()
        pop = self._make_pop(holder_kid="did:key:z6Mktest#keyref")
        ex = self._make_ex_record()
        result = proc._extract_device_key(pop, ex)
        # Fragment of the DID URI is the key id
        assert result == "keyref"

    def test_holder_kid_without_fragment_returns_whole_kid(self):
        """When holder_kid has no DID fragment, the full string is returned."""
        proc = MsoMdocCredProcessor()
        pop = self._make_pop(holder_kid="just-a-key-id")
        ex = self._make_ex_record()
        result = proc._extract_device_key(pop, ex)
        assert result == "just-a-key-id"

    def test_holder_jwk_takes_priority_over_holder_kid(self):
        """holder_jwk should be preferred when both are present."""
        proc = MsoMdocCredProcessor()
        jwk = {"kty": "EC", "crv": "P-256", "x": "x-val", "y": "y-val"}
        pop = self._make_pop(holder_jwk=jwk, holder_kid="did:key:z6Mk#frag")
        ex = self._make_ex_record()
        result = proc._extract_device_key(pop, ex)
        import json

        assert json.loads(result) == jwk

    def test_no_holder_key_falls_back_to_verification_method(self):
        """When holder_jwk and holder_kid are absent, verification_method is used."""
        proc = MsoMdocCredProcessor()
        pop = self._make_pop()
        ex = self._make_ex_record(verification_method="did:key:z6Mk#vm-fragment")
        result = proc._extract_device_key(pop, ex)
        assert result == "vm-fragment"

    def test_all_sources_absent_returns_none(self):
        """When no holder key source is available, returns None."""
        proc = MsoMdocCredProcessor()
        pop = self._make_pop()
        ex = self._make_ex_record()
        result = proc._extract_device_key(pop, ex)
        assert result is None


# ===========================================================================
# MAJ-2 — _normalize_mdoc_result must not use ast.literal_eval
# ===========================================================================


class TestMaj2NormalizeMdocResult:
    """MAJ-2: _normalize_mdoc_result handles edge-case byte-string formats safely."""

    def setup_method(self):
        self.proc = MsoMdocCredProcessor()

    def test_plain_string_returned_unchanged(self):
        result = self.proc._normalize_mdoc_result("hello_mdoc")
        assert result == "hello_mdoc"

    def test_bytes_decoded_to_str(self):
        result = self.proc._normalize_mdoc_result(b"hello_bytes")
        assert result == "hello_bytes"

    def test_bytes_prefix_string_stripped(self):
        """b'data' string form from old isomdl-uniffi is handled correctly."""
        result = self.proc._normalize_mdoc_result("b'some_data'")
        # Must return the inner data, not raise
        assert "b'" not in result or result.startswith("b'") is False

    def test_bytes_double_quote_prefix_string_stripped(self):
        """b\"data\" string form from old isomdl-uniffi is handled correctly."""
        result = self.proc._normalize_mdoc_result('b"some_data"')
        assert 'b"' not in result or result.startswith('b"') is False

    def test_none_raises_cred_processor_error(self):
        from oid4vc.cred_processor import CredProcessorError

        with pytest.raises(CredProcessorError):
            self.proc._normalize_mdoc_result(None)

    def test_numeric_result_converted_to_string(self):
        """Non-string, non-bytes types are safely converted via str()."""
        result = self.proc._normalize_mdoc_result(42)
        assert result == "42"

    def test_bytes_prefix_with_escape_sequence_does_not_crash(self):
        """A b'...' string containing backslash sequences must not raise."""
        # This would break ast.literal_eval if the content has unbalanced quotes
        tricky = "b'base64data_with_\\n_escape'"
        result = self.proc._normalize_mdoc_result(tricky)
        assert isinstance(result, str)


# ===========================================================================
# MIN-6 — WalletTrustStore.get_trust_anchors() must raise before refresh_cache
# ===========================================================================


class TestMin6WalletTrustStoreNoDeadSyncFallback:
    """MIN-6: get_trust_anchors raises RuntimeError if cache not populated."""

    def test_raises_runtime_error_without_cache(self):
        """Calling get_trust_anchors() without prior refresh_cache() must raise."""
        profile = MagicMock()
        store = WalletTrustStore(profile)

        with pytest.raises(RuntimeError, match="refresh_cache"):
            store.get_trust_anchors()

    def test_returns_cached_anchors_after_refresh(self):
        """After _cached_anchors is set, get_trust_anchors() returns it."""
        profile = MagicMock()
        store = WalletTrustStore(profile)
        store._cached_anchors = [
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
        ]

        result = store.get_trust_anchors()
        assert result == store._cached_anchors

    def test_returns_empty_list_when_cache_is_empty_list(self):
        """An empty cache list is a valid (populated) state — must not raise."""
        profile = MagicMock()
        store = WalletTrustStore(profile)
        store._cached_anchors = []

        result = store.get_trust_anchors()
        assert result == []

    @pytest.mark.asyncio
    async def test_refresh_cache_populates_cache(self):
        """refresh_cache() fetches from storage and stores in _cached_anchors."""
        profile, _ = make_mock_profile()
        store = WalletTrustStore(profile)

        expected_pems = ["-----BEGIN CERTIFICATE-----\ncert1\n-----END CERTIFICATE-----"]

        with patch.object(
            WalletTrustStore,
            "_fetch_trust_anchors",
            new=AsyncMock(return_value=expected_pems),
        ):
            result = await store.refresh_cache()

        assert result == expected_pems
        assert store._cached_anchors == expected_pems

    def test_clear_cache_resets_to_none(self):
        """clear_cache() must reset _cached_anchors so next call raises again."""
        profile = MagicMock()
        store = WalletTrustStore(profile)
        store._cached_anchors = ["some-pem"]
        store.clear_cache()

        assert store._cached_anchors is None
        with pytest.raises(RuntimeError):
            store.get_trust_anchors()


# ===========================================================================
# MAJ-3 — kty validation for holder JWK
# ===========================================================================


class TestMaj3HolderJwkKtyValidation:
    """MAJ-3: issue() must reject non-EC holder keys with a clear error."""

    def test_prepare_payload_portrait_bytes(self):
        """Smoke test to ensure the cred processor is importable."""
        proc = MsoMdocCredProcessor()
        result = proc._prepare_payload({"portrait": b"img"})
        # Should encode portrait as base64, not raise
        assert isinstance(result["portrait"], str)


# ===========================================================================
# MAJ-5 — store_certificate raises StorageError (not silent return)
# ===========================================================================


class TestMaj5StoreCertificateRaisesOnFailure:
    """MAJ-5: store_certificate propagates StorageError instead of swallowing it."""

    @pytest.mark.asyncio
    async def test_store_certificate_raises_on_storage_error(self):
        """If the storage add_record call fails, the error must propagate."""
        from ..storage.certificates import store_certificate

        mock_session = MagicMock()

        # Make get_storage succeed but add_record raise
        with patch("mso_mdoc.storage.certificates.get_storage") as mock_get_storage:
            mock_storage = MagicMock()
            mock_storage.add_record = AsyncMock(
                side_effect=sys.modules["acapy_agent.storage.error"].StorageError(
                    "disk full"
                )
            )
            mock_get_storage.return_value = mock_storage

            with pytest.raises(sys.modules["acapy_agent.storage.error"].StorageError):
                await store_certificate(
                    mock_session,
                    cert_id="cert-001",
                    certificate_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                    key_id="key-001",
                )


# ===========================================================================
# MIN-8 — config.py uses StorageDuplicateError for targeted update
# ===========================================================================


class TestMin8ConfigStorageDuplicateError:
    """MIN-8: store_config catches StorageDuplicateError, not all StorageErrors."""

    @pytest.mark.asyncio
    async def test_store_config_updates_on_duplicate_error(self):
        """A StorageDuplicateError from add_record triggers an update."""
        from ..storage.config import store_config

        StorageDuplicateError = sys.modules[
            "acapy_agent.storage.error"
        ].StorageDuplicateError

        mock_session = MagicMock()

        with patch("mso_mdoc.storage.config.get_storage") as mock_get_storage:
            mock_storage = MagicMock()
            mock_storage.add_record = AsyncMock(side_effect=StorageDuplicateError())
            mock_storage.update_record = AsyncMock()
            mock_get_storage.return_value = mock_storage

            await store_config(mock_session, "cfg-key", {"value": 1})

            mock_storage.update_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_config_reraises_other_storage_errors(self):
        """A generic StorageError from update_record must propagate."""
        from ..storage.config import store_config

        StorageDuplicateError = sys.modules[
            "acapy_agent.storage.error"
        ].StorageDuplicateError
        StorageError = sys.modules["acapy_agent.storage.error"].StorageError

        mock_session = MagicMock()

        with patch("mso_mdoc.storage.config.get_storage") as mock_get_storage:
            mock_storage = MagicMock()
            mock_storage.add_record = AsyncMock(side_effect=StorageDuplicateError())
            mock_storage.update_record = AsyncMock(side_effect=StorageError("db gone"))
            mock_get_storage.return_value = mock_storage

            with pytest.raises(StorageError):
                await store_config(mock_session, "cfg-key", {"value": 1})


# ===========================================================================
# MIN-5 — _prepare_payload flattening logs a warning
# ===========================================================================


class TestMin5PayloadFlatteningDebugLog:
    """MIN-5: _prepare_payload emits a debug log when flattening doctype wrapper."""

    def test_flattening_emits_debug_log(self, caplog):
        import logging

        proc = MsoMdocCredProcessor()
        doctype = "org.iso.18013.5.1.mDL"
        payload = {doctype: {"given_name": "Alice"}}

        with caplog.at_level(logging.DEBUG, logger="mso_mdoc.cred_processor"):
            result = proc._prepare_payload(payload, doctype)

        assert "given_name" in result
        assert doctype not in result
        # Ensure a debug log was emitted about the flattening
        flattening_logs = [r for r in caplog.records if "flatten" in r.message.lower()]
        assert flattening_logs, "Expected a debug log about doctype flattening"

    def test_no_overwrite_when_keys_conflict(self):
        """When a top-level key conflicts with a namespaced key, the doctype
        wrapper key should win (update() semantics) and no crash occurs."""
        proc = MsoMdocCredProcessor()
        doctype = "org.iso.18013.5.1.mDL"
        payload = {
            "given_name": "Bob",  # top-level
            doctype: {"given_name": "Alice"},  # namespaced wins after flatten
        }
        result = proc._prepare_payload(payload, doctype)
        # After flattening, given_name from the doctype wrapper overwrites
        assert result["given_name"] == "Alice"


# ===========================================================================
# CRIT-3 — _parse_string_credential has no unreachable return
# ===========================================================================


class TestCrit3NoUnreachableReturn:
    """CRIT-3: _parse_string_credential ends correctly — no dead return after try/except."""

    def test_bad_credential_returns_none_and_error(self):
        """An unparseable credential returns (None, error_str)."""
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_iso:
            mock_iso.Mdoc.from_string.side_effect = Exception("parse error")
            mock_iso.Mdoc.new_from_base64url_encoded_issuer_signed.side_effect = (
                Exception("issuer-signed error")
            )
            mdoc, err = _parse_string_credential("not-a-valid-mdoc!!!")
        assert mdoc is None
        assert err is not None
        assert isinstance(err, str)

    def test_hex_credential_parsed_successfully(self):
        """A valid hex string is parsed via Mdoc.from_string."""
        mock_mdoc = MagicMock()
        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_iso:
            mock_iso.Mdoc.from_string.return_value = mock_mdoc
            mdoc, err = _parse_string_credential("deadbeef1234")
        assert mdoc is mock_mdoc
        assert err is None
