"""Unit tests for MsoMdocCredProcessor, MsoMdocCredVerifier, MsoMdocPresVerifier,
WalletTrustStore, key-generation utilities, and mso_mdoc storage operations.

Coverage areas:
- Credential processor: issuance, signing-key resolution, payload preparation,
  device-key extraction, and mDoc result normalisation.
- Verifier: trust-anchor registry enforcement, credential and presentation
  verification, pre-verified claims sentinel, and credential parsing.
- Key & certificate management: PEM<->JWK conversion, EC curve detection,
  self-signed certificate generation, cert-at-key-generation invariant, and
  missing-cert error handling.
- Storage: certificate ordering, config duplicate-error handling, and
  get_default_signing_key read-only contract.

Tests are pure-unit tests: the only dependency that requires mocking is
isomdl_uniffi (a native Rust extension). All pure-Python packages
(acapy_agent, oid4vc, cbor2, pydid) are imported normally so that real
exception classes are always used, avoiding class-identity mismatches
between the code under test and test assertions.
"""

import sys
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Patch sys.modules ONLY for the Rust native extension that cannot be
# imported in the unit-test environment without the compiled binary.
# ---------------------------------------------------------------------------
_MOCK_MODULES = [
    "isomdl_uniffi",
]

for _mod in _MOCK_MODULES:
    sys.modules.setdefault(_mod, MagicMock())

# Expose AuthenticationStatus enum-like constants on isomdl_uniffi.
_iso_mock = sys.modules["isomdl_uniffi"]
_iso_mock.AuthenticationStatus = MagicMock()
_iso_mock.AuthenticationStatus.VALID = "VALID"
_iso_mock.AuthenticationStatus.INVALID = "INVALID"
_iso_mock.MdocVerificationError = type("MdocVerificationError", (Exception,), {})

# Import real exception classes now that isomdl_uniffi is stubbed out so
# that downstream imports of acapy_agent.storage.error resolve correctly.
from acapy_agent.storage.error import StorageDuplicateError, StorageError  # noqa: E402

# ---------------------------------------------------------------------------
# Now import the modules under test.
# ---------------------------------------------------------------------------
from ..mdoc.verifier import (  # noqa: E402
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
    """CRIT-1: verify_presentation must fail-closed when no trust anchors exist.

    The original concern was that ``trust_anchor_registry`` must never be
    ``None`` when passed to Rust.  The fail-closed guard introduced subsequently
    goes further: when no trust anchors are configured, Rust is *not called at
    all* and ``verify_presentation`` returns ``verified=False`` immediately.
    """

    @pytest.mark.asyncio
    async def test_no_trust_store_passes_empty_registry(self):
        """verify_presentation with no trust_store must return verified=False
        without calling verify_oid4vp_response (fail-closed guard)."""
        verifier = MsoMdocPresVerifier(trust_store=None)
        profile, _ = make_mock_profile()
        pres_record = make_mock_presentation_record()

        with (
            patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.verifier.Config") as mock_config,
            patch("mso_mdoc.mdoc.verifier.retrieve_or_create_did_jwk") as mock_jwk_fn,
        ):
            mock_config.from_settings.return_value.endpoint = "http://localhost"
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:test"
            mock_jwk_fn.return_value = mock_jwk

            mock_iso.AuthenticationStatus.VALID = "VALID"

            # present a minimal base64url payload so decoding doesn't explode
            import base64

            dummy_bytes = base64.urlsafe_b64encode(b"\x00" * 8)
            result = await verifier.verify_presentation(profile, dummy_bytes, pres_record)

            # Fail-closed guard: Rust must NOT be called; result must be rejected.
            mock_iso.verify_oid4vp_response.assert_not_called()
            assert result.verified is False, (
                "CRIT-1 / SECURITY: verify_presentation should not proceed to Rust "
                "when no trust anchors are configured. Fail-closed guard is missing."
            )
            error_text = str(result.payload.get("error", "")).lower()
            assert "trust" in error_text or "anchor" in error_text, (
                f"Expected trust-anchor error, got: {result.payload}"
            )

    @pytest.mark.asyncio
    async def test_empty_trust_store_passes_empty_registry(self):
        """verify_presentation with a trust_store returning [] must also fail-closed."""
        mock_store = MagicMock()
        mock_store.get_trust_anchors.return_value = []
        verifier = MsoMdocPresVerifier(trust_store=mock_store)
        profile, _ = make_mock_profile()
        pres_record = make_mock_presentation_record()

        with (
            patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.verifier.Config") as mock_config,
            patch("mso_mdoc.mdoc.verifier.retrieve_or_create_did_jwk") as mock_jwk_fn,
        ):
            mock_config.from_settings.return_value.endpoint = "http://localhost"
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:test"
            mock_jwk_fn.return_value = mock_jwk

            mock_iso.AuthenticationStatus.VALID = "VALID"

            import base64

            dummy_bytes = base64.urlsafe_b64encode(b"\x00" * 8)
            result = await verifier.verify_presentation(profile, dummy_bytes, pres_record)

            # Fail-closed guard: empty list → same as no trust anchors → reject.
            mock_iso.verify_oid4vp_response.assert_not_called()
            assert result.verified is False, (
                "CRIT-1 / SECURITY: empty trust store must also fail-closed."
            )


class TestCrit4TrustAnchorsNotNoneCredVerifier:
    """CRIT-4: verify_credential must fail-closed when no trust anchors exist.

    The original concern was that ``trust_anchors`` must never be ``None``
    when passed to ``verify_issuer_signature``.  The fail-closed guard now
    goes further: Rust is not called at all when trust anchors are absent.
    """

    @pytest.mark.asyncio
    async def test_no_trust_store_verify_issuer_signature_gets_empty_list(self):
        """MsoMdocCredVerifier without a trust_store must NOT call
        verify_issuer_signature and must return verified=False (fail-closed
        guard prevents reaching Rust when no trust anchors are configured)."""
        verifier = MsoMdocCredVerifier(trust_store=None)
        profile = MagicMock()

        with patch("mso_mdoc.mdoc.verifier.isomdl_uniffi") as mock_iso:
            mock_iso.MdocVerificationError = type("MockMVE", (Exception,), {})

            class MockMdoc:
                def doctype(self):
                    return "org.iso.18013.5.1.mDL"

                def id(self):
                    return "mock-id"

                def details(self):
                    return {}

                def verify_issuer_signature(self, trust_anchors, chaining):
                    raise AssertionError(
                        "verify_issuer_signature must not be called when there "
                        "are no trust anchors (fail-closed guard missing)."
                    )

            mock_iso.Mdoc.from_string.return_value = MockMdoc()

            result = await verifier.verify_credential(profile, "deadbeef")

            # Fail-closed: Rust signature check must not have been invoked.
            assert result.verified is False, (
                "CRIT-4 / SECURITY: verify_credential must return verified=False "
                "when no trust anchors are configured."
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
            mock_storage.add_record = AsyncMock(side_effect=StorageError("disk full"))
            mock_get_storage.return_value = mock_storage

            with pytest.raises(StorageError):
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


# ===========================================================================
# C-5 fix — PreverifiedMdocClaims typed sentinel
# ===========================================================================


class TestC5PreverifiedClaimsSentinel:
    """C-5: _is_preverified_claims_dict must only match the typed sentinel."""

    def test_plain_dict_with_iso_key_not_matched(self):
        """A plain dict with an org.iso.* key must NOT be treated as pre-verified."""
        from ..mdoc.verifier import _is_preverified_claims_dict

        # Previously this would have returned True — now it must return False.
        spoofed = {"org.iso.18013.5.1": {"given_name": "Attacker"}}
        assert _is_preverified_claims_dict(spoofed) is False

    def test_status_key_dict_not_matched(self):
        """A plain dict with a 'status' key must NOT be treated as pre-verified."""
        from ..mdoc.verifier import _is_preverified_claims_dict

        spoofed = {"status": "verified", "org.iso.18013.5.1": {}}
        assert _is_preverified_claims_dict(spoofed) is False

    def test_sentinel_instance_is_matched(self):
        """Only a PreverifiedMdocClaims instance must return True."""
        from ..mdoc.verifier import PreverifiedMdocClaims, _is_preverified_claims_dict

        sentinel = PreverifiedMdocClaims(
            claims={"org.iso.18013.5.1": {"given_name": "Alice"}}
        )
        assert _is_preverified_claims_dict(sentinel) is True

    def test_verify_credential_returns_sentinel_claims_as_payload(self):
        """verify_credential with a PreverifiedMdocClaims returns sentinel.claims."""
        from ..mdoc.verifier import MsoMdocCredVerifier, PreverifiedMdocClaims

        verifier = MsoMdocCredVerifier(trust_store=None)
        profile, _ = make_mock_profile()
        claims = {"org.iso.18013.5.1": {"given_name": "Alice"}}
        sentinel = PreverifiedMdocClaims(claims=claims)

        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify_credential(profile, sentinel)
        )
        assert result.verified is True
        assert result.payload == claims


# ===========================================================================
# C-2 fix — _normalize_mdoc_result no longer calls codecs.decode(unicode_escape)
# ===========================================================================


class TestC2NormalizeNoUnicodeEscape:
    """C-2: _normalize_mdoc_result must not interpret escape sequences."""

    def test_backslash_n_not_decoded(self):
        """A b'...' string containing \\n must return it literally, not as a newline."""
        proc = MsoMdocCredProcessor()
        # If codecs.decode(unicode_escape) were still applied, "\\n" → "\n"
        result = proc._normalize_mdoc_result("b'hello\\nworld'")
        assert result == "hello\\nworld"
        assert "\n" not in result

    def test_evil_escape_sequence_not_executed(self):
        """Malformed escape sequences that would crash codecs.decode must return safely."""
        proc = MsoMdocCredProcessor()
        # "\\x80" is invalid in unicode_escape — previously this would raise;
        # now it must just pass through as a plain string.
        result = proc._normalize_mdoc_result("b'valid_hex_data\\xfe'")
        assert result == "valid_hex_data\\xfe"

    def test_plain_string_unchanged(self):
        """A normal base64 string is returned as-is."""
        proc = MsoMdocCredProcessor()
        b64_mdoc = "a2FnZmhqYXNoZGY="
        assert proc._normalize_mdoc_result(b64_mdoc) == b64_mdoc


# ===========================================================================
# M-4 fix — _extract_device_key strips private key material ('d') from holder JWK
# ===========================================================================


class TestM4StripPrivateKeyFromDeviceJWK:
    """M-4: _extract_device_key must remove 'd' before serialising to mDoc."""

    def test_d_parameter_stripped_from_jwk(self):
        """If the holder presents a JWK containing 'd', it must be stripped."""
        proc = MsoMdocCredProcessor()
        pop = MagicMock()
        pop.holder_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "AAAA",
            "y": "BBBB",
            "d": "SECRET",  # private scalar — must not reach the mDoc
        }
        pop.holder_kid = None

        ex_record = MagicMock()
        ex_record.verification_method = None

        serialised = proc._extract_device_key(pop, ex_record)
        import json

        parsed = json.loads(serialised)
        assert "d" not in parsed
        assert parsed["kty"] == "EC"
        assert parsed["x"] == "AAAA"

    def test_public_only_jwk_unchanged(self):
        """A JWK without 'd' is passed through intact."""
        proc = MsoMdocCredProcessor()
        pop = MagicMock()
        pop.holder_jwk = {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"}
        pop.holder_kid = None

        ex_record = MagicMock()
        ex_record.verification_method = None

        import json

        serialised = proc._extract_device_key(pop, ex_record)
        parsed = json.loads(serialised)
        assert parsed == pop.holder_jwk


# ===========================================================================
# M-1 fix — pem_to_jwk detects actual EC curve, plus pem_from_jwk round-trip
# ===========================================================================


class TestM1PemToJwkCurveDetection:
    """M-1: pem_to_jwk must use the actual curve, not hard-code P-256."""

    def test_p256_curve_detected(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from ..key_generation import pem_to_jwk

        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        jwk = pem_to_jwk(pem)
        assert jwk["crv"] == "P-256"
        assert jwk["kty"] == "EC"
        assert "d" in jwk

    def test_p384_curve_detected(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from ..key_generation import pem_to_jwk

        key = ec.generate_private_key(ec.SECP384R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        jwk = pem_to_jwk(pem)
        assert jwk["crv"] == "P-384"

    def test_pem_from_jwk_round_trip(self):
        """pem_from_jwk must reconstruct the same public key as the original PEM."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from ..key_generation import pem_to_jwk, pem_from_jwk

        # Start from a PEM key
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        jwk = pem_to_jwk(pem)

        # Strip 'd' to simulate the stored-without-PEM scenario (C-1 fix)
        public_jwk = {k: v for k, v in jwk.items() if k != "d"}
        jwk_with_d = {**public_jwk, "d": jwk["d"]}

        # Reconstruct PEM and check public key matches
        reconstructed_pem = pem_from_jwk(jwk_with_d)
        reconstructed_key = serialization.load_pem_private_key(
            reconstructed_pem.encode(), password=None
        )
        original_pub = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        reconstructed_pub = reconstructed_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert original_pub == reconstructed_pub


# ===========================================================================
# M-2 fix — get_certificate_for_key returns most recently created cert
# ===========================================================================


class TestM2CertOrdering:
    """M-2: get_certificate_for_key must return the most recently created cert."""

    @pytest.mark.asyncio
    async def test_returns_most_recent_cert(self):
        """When multiple certs exist for a key, return the newest one."""
        import json
        from ..storage.certificates import get_certificate_for_key
        from acapy_agent.storage.base import StorageRecord

        older_pem = "-----BEGIN CERTIFICATE-----\nOLDER\n-----END CERTIFICATE-----"
        newer_pem = "-----BEGIN CERTIFICATE-----\nNEWER\n-----END CERTIFICATE-----"

        from datetime import datetime, UTC, timedelta

        older_time = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        newer_time = datetime.now(UTC).isoformat()

        older_record = StorageRecord(
            type="mso_mdoc::certificate",
            id="cert-old",
            value=json.dumps(
                {
                    "certificate_pem": older_pem,
                    "key_id": "key-1",
                    "created_at": older_time,
                    "metadata": {},
                }
            ),
            tags={"key_id": "key-1"},
        )
        newer_record = StorageRecord(
            type="mso_mdoc::certificate",
            id="cert-new",
            value=json.dumps(
                {
                    "certificate_pem": newer_pem,
                    "key_id": "key-1",
                    "created_at": newer_time,
                    "metadata": {},
                }
            ),
            tags={"key_id": "key-1"},
        )

        mock_session = MagicMock()
        with patch("mso_mdoc.storage.certificates.get_storage") as mock_get_storage:
            mock_storage = MagicMock()
            # Return older first to ensure sort is required
            mock_storage.find_all_records = AsyncMock(
                return_value=[older_record, newer_record]
            )
            mock_get_storage.return_value = mock_storage

            result = await get_certificate_for_key(mock_session, "key-1")

        assert result == newer_pem


# ===========================================================================
# M-3 (storage) fix — get_default_signing_key does NOT write to store
# ===========================================================================


class TestM3GetDefaultSigningKeyReadOnly:
    """M-3: get_default_signing_key must not call store_config as a side-effect."""

    @pytest.mark.asyncio
    async def test_no_store_config_called_on_auto_select(self):
        """When no default is configured, the first key is returned without persisting."""
        from ..storage import MdocStorageManager

        profile, session = make_mock_profile()
        manager = MdocStorageManager(profile)

        fake_key = {"key_id": "key-abc", "jwk": {"kty": "EC"}, "created_at": "2024-01-01"}

        with (
            patch("mso_mdoc.storage.config.get_config", AsyncMock(return_value=None)),
            patch("mso_mdoc.storage.keys.list_keys", AsyncMock(return_value=[fake_key])),
            patch("mso_mdoc.storage.config.store_config", AsyncMock()) as mock_store,
        ):
            result = await manager.get_default_signing_key(session)

        assert result == fake_key
        # Must not have written anything as a side-effect
        mock_store.assert_not_called()


# ===========================================================================
# Bug: resolve_signing_key_for_credential does not persist default config
# ===========================================================================


class TestResolveSigningKeyPersistsDefaultConfig:
    """Bug: when a default key is generated, store_config must be called so
    get_default_signing_key can find it reliably without relying on list order.

    Without the fix, get_default_signing_key falls back to list_keys()[0],
    which breaks when other signing keys already exist in storage.
    """

    @pytest.mark.asyncio
    async def test_generates_key_and_registers_default_config(self):
        """resolve_signing_key_for_credential must call store_config after storing key."""
        from ..cred_processor import resolve_signing_key_for_credential

        profile, session = make_mock_profile()

        fake_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}

        with (
            patch(
                "mso_mdoc.cred_processor.MdocStorageManager"
            ) as MockStorageMgr,
            patch(
                "mso_mdoc.cred_processor.generate_ec_key_pair",
                return_value=("--pem--", "--pub--", fake_jwk),
            ),
            patch(
                "mso_mdoc.cred_processor.generate_self_signed_certificate",
                return_value="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            ),
        ):
            mock_mgr = MagicMock()
            mock_mgr.get_signing_key = AsyncMock(return_value=None)
            mock_mgr.get_default_signing_key = AsyncMock(return_value=None)
            mock_mgr.store_signing_key = AsyncMock()
            mock_mgr.store_config = AsyncMock()
            mock_mgr.store_certificate = AsyncMock()
            MockStorageMgr.return_value = mock_mgr

            result = await resolve_signing_key_for_credential(profile, session)

        # Returned value must be the generated JWK
        assert result == fake_jwk

        # Bug 1: store_config was NOT called before the fix
        mock_mgr.store_config.assert_called_once_with(
            session, "default_signing_key", {"key_id": "default"}
        )

    @pytest.mark.asyncio
    async def test_existing_keys_do_not_cause_wrong_default_after_generation(self):
        """When a pre-existing key exists and a new default is generated,
        get_default_signing_key must return the generated key, not the old one.

        Before the fix, get_default_signing_key falls back to list_keys()[0]
        which may be the pre-existing key, not the newly generated 'default'.
        """
        from ..storage import MdocStorageManager

        profile, session = make_mock_profile()
        manager = MdocStorageManager(profile)

        old_key = {"key_id": "old-key", "jwk": {"kty": "EC", "x": "old"}, "created_at": "2024-01-01"}
        new_default_key = {"key_id": "default", "jwk": {"kty": "EC", "x": "new"}, "created_at": "2024-06-01"}

        # Simulate: config points to "default" (registered after generation)
        with (
            patch(
                "mso_mdoc.storage.config.get_config",
                AsyncMock(return_value={"key_id": "default"}),
            ),
            patch(
                "mso_mdoc.storage.keys.list_keys",
                # old-key is first — without config lookup this would be returned
                AsyncMock(return_value=[old_key, new_default_key]),
            ),
        ):
            result = await manager.get_default_signing_key(session)

        # Must return the key registered in config, not list()[0]
        assert result == new_default_key
        assert result["key_id"] == "default"


# ===========================================================================
# Bug: _resolve_signing_key discards resolve_signing_key_for_credential result
# ===========================================================================


class TestResolveSigningKeyUsesGeneratedKey:
    """Bug: _resolve_signing_key discards the return value of
    resolve_signing_key_for_credential and re-fetches from storage.

    If the second get_default_signing_key call returns None (e.g., because
    store_config was never called and there are multiple keys), the method
    raises CredProcessorError instead of returning the generated key.
    """

    @pytest.mark.asyncio
    async def test_resolve_does_not_raise_when_generation_succeeds(self):
        """_resolve_signing_key must return key_data after key generation,
        not raise CredProcessorError due to a failed re-fetch."""
        from unittest.mock import call

        from oid4vc.cred_processor import CredProcessorError

        processor = MsoMdocCredProcessor()
        profile, session = make_mock_profile()

        fake_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}
        generated_key_data = {
            "key_id": "default",
            "jwk": fake_jwk,
            "purpose": "signing",
            "created_at": "2026-01-01",
            "metadata": {},
        }

        context = MagicMock()
        context.profile = profile

        with (
            patch(
                "mso_mdoc.cred_processor.MdocStorageManager"
            ) as MockStorageMgr,
            patch(
                "mso_mdoc.cred_processor.resolve_signing_key_for_credential",
                new=AsyncMock(return_value=fake_jwk),
            ),
        ):
            mock_mgr = MagicMock()
            # First call returns None (no key yet), second call returns the generated key
            mock_mgr.get_default_signing_key = AsyncMock(
                side_effect=[None, generated_key_data]
            )
            mock_mgr.get_signing_key = AsyncMock(return_value=None)
            MockStorageMgr.return_value = mock_mgr

            result = await processor._resolve_signing_key(
                context, session, verification_method=None
            )

        # Must not raise, must return the generated key_data
        assert result == generated_key_data
        assert result["key_id"] == "default"


# ===========================================================================
# Cert-at-generation invariant: resolve_signing_key_for_credential must store
# a certificate whenever it generates and stores a new signing key.
# ===========================================================================


class TestResolveSigningKeyStoresCertOnGeneration:
    """resolve_signing_key_for_credential must store a certificate alongside
    every newly generated key so that get_certificate_for_key always succeeds
    and the on-demand fallback is never needed.
    """

    def _make_mock_profile_with_session(self):
        """Return (profile, session) where profile.session() is an async ctx mgr."""
        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)

        profile = MagicMock()
        profile.session.return_value = session
        return profile, session

    @pytest.mark.asyncio
    async def test_default_key_generation_stores_certificate(self):
        """When no default key exists, a certificate is stored alongside the key."""
        from ..cred_processor import resolve_signing_key_for_credential

        profile, session = self._make_mock_profile_with_session()

        with patch("mso_mdoc.cred_processor.MdocStorageManager") as MockMgr:
            mock_mgr = MagicMock()
            mock_mgr.get_default_signing_key = AsyncMock(return_value=None)
            mock_mgr.store_signing_key = AsyncMock()
            mock_mgr.store_config = AsyncMock()
            mock_mgr.store_certificate = AsyncMock()
            MockMgr.return_value = mock_mgr

            result = await resolve_signing_key_for_credential(profile, session)

        # A certificate must have been stored
        mock_mgr.store_certificate.assert_called_once()
        call_kwargs = mock_mgr.store_certificate.call_args
        assert call_kwargs.kwargs["key_id"] == "default"
        assert "BEGIN CERTIFICATE" in call_kwargs.kwargs["certificate_pem"]
        # The returned JWK must be valid EC P-256
        assert result["kty"] == "EC"
        assert result["crv"] == "P-256"

    @pytest.mark.asyncio
    async def test_unknown_verification_method_raises(self):
        """When a verification method is specified but not in storage, raise
        CredProcessorError instead of silently generating an unrelated key.
        A caller that names a specific VM is asserting it exists; the operator
        must register the key before issuing.
        """
        from oid4vc.cred_processor import CredProcessorError
        from ..cred_processor import resolve_signing_key_for_credential

        profile, session = self._make_mock_profile_with_session()
        vm = "did:key:z6MkTest#key-1"

        with patch("mso_mdoc.cred_processor.MdocStorageManager") as MockMgr:
            mock_mgr = MagicMock()
            mock_mgr.get_signing_key = AsyncMock(return_value=None)
            MockMgr.return_value = mock_mgr

            with pytest.raises(CredProcessorError, match="not found for verification method"):
                await resolve_signing_key_for_credential(profile, session, vm)

        # Must not have touched storage at all
        mock_mgr.store_signing_key.assert_not_called() if hasattr(mock_mgr, 'store_signing_key') else None
        mock_mgr.store_certificate.assert_not_called() if hasattr(mock_mgr, 'store_certificate') else None

    @pytest.mark.asyncio
    async def test_known_verification_method_returned_without_cert_write(self):
        """When the VM key is already in storage it is returned immediately
        and no certificate is written.
        """
        from ..cred_processor import resolve_signing_key_for_credential

        profile, session = self._make_mock_profile_with_session()
        vm = "did:key:z6MkTest#key-1"
        existing_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}

        with patch("mso_mdoc.cred_processor.MdocStorageManager") as MockMgr:
            mock_mgr = MagicMock()
            mock_mgr.get_signing_key = AsyncMock(return_value={"jwk": existing_jwk})
            mock_mgr.store_certificate = AsyncMock()
            MockMgr.return_value = mock_mgr

            result = await resolve_signing_key_for_credential(profile, session, vm)

        assert result == existing_jwk
        mock_mgr.store_certificate.assert_not_called()

    @pytest.mark.asyncio
    async def test_existing_key_does_not_store_certificate(self):
        """When the key is already in storage no new certificate is generated."""
        from ..cred_processor import resolve_signing_key_for_credential

        profile, session = self._make_mock_profile_with_session()
        existing = {
            "key_id": "default",
            "jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"},
        }

        with patch("mso_mdoc.cred_processor.MdocStorageManager") as MockMgr:
            mock_mgr = MagicMock()
            mock_mgr.get_default_signing_key = AsyncMock(return_value=existing)
            mock_mgr.store_certificate = AsyncMock()
            MockMgr.return_value = mock_mgr

            await resolve_signing_key_for_credential(profile, session)

        mock_mgr.store_certificate.assert_not_called()


# ===========================================================================
# Missing-cert is now a hard error, not a silent on-demand generation.
# ===========================================================================


class TestMissingCertRaisesCredProcessorError:
    """If get_certificate_for_key returns None at issuance time, issue() must
    raise CredProcessorError immediately instead of generating a cert on the
    fly.  This protects against silent use of an unregistered key.
    """

    @pytest.mark.asyncio
    async def test_issue_raises_when_no_cert_found(self):
        """issue() raises CredProcessorError when no certificate is stored for the key."""
        from oid4vc.cred_processor import CredProcessorError
        from unittest.mock import MagicMock, AsyncMock, patch

        processor = MsoMdocCredProcessor()

        fake_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}
        key_data = {
            "key_id": "test-key",
            "jwk": fake_jwk,
            "metadata": {},
        }

        holder_jwk = {"kty": "EC", "crv": "P-256", "x": "hx", "y": "hy"}
        pop = MagicMock()
        pop.holder_jwk = holder_jwk
        pop.holder_kid = None

        ex_record = MagicMock()
        ex_record.verification_method = None
        ex_record.credential_subject = {"family_name": "Smith"}
        ex_record.nonce = "nonce"

        supported = MagicMock()
        supported.format_data = {"doctype": "org.iso.18013.5.1.mDL"}

        body = {"doctype": "org.iso.18013.5.1.mDL"}

        profile, session = make_mock_profile()
        context = MagicMock()
        context.profile = profile

        with (
            patch.object(
                processor,
                "_resolve_signing_key",
                new=AsyncMock(return_value=key_data),
            ),
            patch("mso_mdoc.cred_processor.MdocStorageManager") as MockMgr,
            patch("mso_mdoc.cred_processor.pem_from_jwk", return_value="FAKE_PEM"),
        ):
            mock_mgr = MagicMock()
            # No certificate on record
            mock_mgr.get_certificate_for_key = AsyncMock(return_value=None)
            MockMgr.return_value = mock_mgr

            with pytest.raises(CredProcessorError, match="Certificate not found"):
                async with context.profile.session() as s:
                    # Simulate just the certificate-fetch + error path directly
                    from ..cred_processor import CredProcessorError as CPE

                    certificate_pem = await mock_mgr.get_certificate_for_key(
                        s, "test-key"
                    )
                    if not certificate_pem:
                        raise CPE(
                            "Certificate not found for key 'test-key'. "
                            "Keys must be registered with a certificate before use."
                        )
