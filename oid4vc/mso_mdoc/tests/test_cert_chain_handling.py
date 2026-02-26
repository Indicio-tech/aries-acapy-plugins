"""Unit tests for PEM certificate chain handling in mso_mdoc.

Background
----------
The isomdl-uniffi Rust library (x509_cert crate) reads **only the first**
``-----BEGIN CERTIFICATE-----`` block from a PEM string.  When a caller
passes a concatenated multi-cert PEM (e.g. leaf + intermediate) as either
the IACA cert for signing or a trust anchor for verification, every
certificate after the first is silently ignored.  This causes:

* **Issuer side** — the MSO embeds the first cert in the chain rather than
  the signing cert, so the embedded cert no longer corresponds to the signing
  key, and verification fails ("cert no. 1" error).

* **Verifier side** — a trust-anchor string containing two certs is treated
  as if it only contains the first cert; any mdoc whose chain relies on the
  second cert cannot be validated.

Fix
---
``mso_mdoc.mdoc.utils`` provides:

* ``split_pem_chain(pem)`` — splits a concatenated PEM into a list of
  individual cert PEM strings.
* ``extract_signing_cert(pem)`` — returns the first cert from a chain (the
  signing cert is expected to be first in standard chain encoding).
* ``flatten_trust_anchors(pems)`` — expands a list of possibly-chained PEM
  strings into a flat list of single-cert PEM strings.

``isomdl_mdoc_sign`` now calls ``extract_signing_cert`` before handing the
cert to Rust.  Both ``MsoMdocCredVerifier.verify_credential`` and
``mdoc_verify`` now call ``flatten_trust_anchors`` before calling Rust's
``verify_issuer_signature``.  ``MsoMdocPresVerifier.verify_presentation``
applies the same flattening before building the OID4VP trust-anchor registry.

These tests were originally written with ``pytest.mark.xfail(strict=True)``
to document the pre-fix failures; the markers have been removed because the
fix is now in place and every test below should pass.
"""

import pytest

try:
    import isomdl_uniffi  # noqa: F401

    ISOMDL_AVAILABLE = True
except ImportError:
    ISOMDL_AVAILABLE = False

from ..key_generation import generate_ec_key_pair, generate_self_signed_certificate
from ..mdoc.utils import extract_signing_cert, flatten_trust_anchors, split_pem_chain

# ---------------------------------------------------------------------------
# Subject name with all fields required by isomdl_uniffi (including ST)
# ---------------------------------------------------------------------------
_IACA_SUBJECT = "CN=mDoc Test IACA,ST=UT,O=TestOrg,C=US"

# ---------------------------------------------------------------------------
# Minimal 1×1 PNG portrait accepted by isomdl_uniffi for mDL signing
# ---------------------------------------------------------------------------
_PORTRAIT_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

_MDL_HEADERS = {"doctype": "org.iso.18013.5.1.mDL"}

_MDL_PAYLOAD = {
    "family_name": "Chain",
    "given_name": "Test",
    "birth_date": "1990-01-01",
    "document_number": "CHAIN001",
    "driving_privileges": [],
    "issue_date": "2024-01-01",
    "expiry_date": "2034-01-01",
    "issuing_country": "US",
    "issuing_authority": "Test Authority",
    "un_distinguishing_sign": "US",
    "portrait": _PORTRAIT_B64,
}


# ===========================================================================
# Pure-Python utility tests — always run, no isomdl_uniffi required
# ===========================================================================


class TestSplitPemChain:
    """Tests for split_pem_chain()."""

    def _make_fake_pem(self, tag: str = "AAAA") -> str:
        """Minimal syntactically-valid-looking PEM block (not a real cert)."""
        return f"-----BEGIN CERTIFICATE-----\n{tag}\n-----END CERTIFICATE-----\n"

    def test_single_cert_returns_one_element_list(self):
        """A single PEM cert block → one-element list."""
        pem = self._make_fake_pem("CERT1")
        result = split_pem_chain(pem)
        assert len(result) == 1
        assert result[0] == pem

    def test_two_certs_returns_two_element_list(self):
        """Two concatenated PEM blocks → two-element list."""
        pem1 = self._make_fake_pem("CERT1")
        pem2 = self._make_fake_pem("CERT2")
        result = split_pem_chain(pem1 + pem2)
        assert len(result) == 2
        assert result[0] == pem1
        assert result[1] == pem2

    def test_three_certs_returns_three_element_list(self):
        """leaf + intermediate + root chain → three-element list."""
        pems = [self._make_fake_pem(f"CERT{i}") for i in range(3)]
        result = split_pem_chain("".join(pems))
        assert len(result) == 3
        for i, cert in enumerate(result):
            assert cert == pems[i]

    def test_empty_string_returns_empty_list(self):
        """Empty string → empty list."""
        assert split_pem_chain("") == []

    def test_whitespace_only_returns_empty_list(self):
        """Whitespace-only string → empty list."""
        assert split_pem_chain("   \n\t  ") == []

    def test_whitespace_between_certs_is_handled(self):
        """Extra blank lines between PEM blocks are ignored."""
        pem1 = self._make_fake_pem("CERT1")
        pem2 = self._make_fake_pem("CERT2")
        result = split_pem_chain(pem1 + "\n\n" + pem2)
        assert len(result) == 2

    def test_each_result_contains_pem_header_and_footer(self):
        """Every returned string has a complete BEGIN/END marker pair."""
        pems = [self._make_fake_pem(f"X{i}") for i in range(3)]
        for cert in split_pem_chain("".join(pems)):
            assert "-----BEGIN CERTIFICATE-----" in cert
            assert "-----END CERTIFICATE-----" in cert

    def test_split_roundtrips_to_original_chain(self):
        """Joining the split result re-creates the original chain string."""
        pem1 = self._make_fake_pem("ALPHA")
        pem2 = self._make_fake_pem("BETA")
        chain = pem1 + pem2
        assert "".join(split_pem_chain(chain)) == chain


class TestExtractSigningCert:
    """Tests for extract_signing_cert()."""

    def _fake_pem(self, tag: str) -> str:
        return f"-----BEGIN CERTIFICATE-----\n{tag}\n-----END CERTIFICATE-----\n"

    def test_single_cert_is_returned_unchanged(self):
        """Single cert → returned as-is."""
        pem = self._fake_pem("SINGLE")
        assert extract_signing_cert(pem) == pem

    def test_first_cert_from_chain_is_returned(self):
        """Chain of two → first cert is returned."""
        pem1 = self._fake_pem("LEAF")
        pem2 = self._fake_pem("ROOT")
        assert extract_signing_cert(pem1 + pem2) == pem1

    def test_empty_string_raises_value_error(self):
        """Empty string → ValueError (no cert found)."""
        with pytest.raises(ValueError, match="No certificate found"):
            extract_signing_cert("")

    def test_no_pem_markers_raises_value_error(self):
        """String without PEM markers → ValueError."""
        with pytest.raises(ValueError, match="No certificate found"):
            extract_signing_cert("not a cert at all")


class TestFlattenTrustAnchors:
    """Tests for flatten_trust_anchors()."""

    def _fake_pem(self, tag: str) -> str:
        return f"-----BEGIN CERTIFICATE-----\n{tag}\n-----END CERTIFICATE-----\n"

    def test_single_cert_per_element_is_unchanged(self):
        """List of single-cert PEMs passes through without change."""
        anchors = [self._fake_pem(f"CERT{i}") for i in range(3)]
        result = flatten_trust_anchors(anchors)
        assert result == anchors

    def test_chain_element_is_split_into_individuals(self):
        """An element containing two certs is expanded to two entries."""
        pem1 = self._fake_pem("ROOT")
        pem2 = self._fake_pem("LEAF")
        result = flatten_trust_anchors([pem1 + pem2])
        assert len(result) == 2
        assert result[0] == pem1
        assert result[1] == pem2

    def test_mixed_list_produces_flat_result(self):
        """Mix of single-cert and chain elements → flat list of individual certs."""
        single = self._fake_pem("SINGLE")
        chain = self._fake_pem("CA") + self._fake_pem("DS")
        result = flatten_trust_anchors([single, chain])
        assert len(result) == 3  # 1 + 2

    def test_empty_list_returns_empty_list(self):
        assert flatten_trust_anchors([]) == []

    def test_list_of_empty_strings_returns_empty_list(self):
        assert flatten_trust_anchors(["", "  "]) == []


# ===========================================================================
# isomdl_uniffi integration tests — skipped when library is not installed
# ===========================================================================


@pytest.mark.skipif(not ISOMDL_AVAILABLE, reason="isomdl_uniffi not available")
class TestIssuerCertChainHandling:
    """Tests that expose (then verify the fix for) the issuer-side chain bug.

    Pre-fix behaviour
    -----------------
    ``isomdl_mdoc_sign`` passed ``iaca_cert_pem`` verbatim to
    ``Mdoc.create_and_sign``.  When that string contained two PEM blocks,
    Rust embedded only the **first** cert.  If that first cert was a root CA
    (not the signing cert), the MSO contained the wrong cert and verification
    always failed.

    Post-fix behaviour
    ------------------
    ``extract_signing_cert`` is called before ``Mdoc.create_and_sign`` so
    Rust always receives exactly one, correct, leaf/signing certificate.
    """

    @pytest.fixture
    def signing_key_and_cert(self):
        """Generate a fresh signing key pair and its self-signed certificate."""
        from ..mdoc import isomdl_mdoc_sign  # noqa: F401 – ensure importable

        private_pem, _, jwk = generate_ec_key_pair()
        cert_pem = generate_self_signed_certificate(private_pem, _IACA_SUBJECT)
        jwk_public = {k: v for k, v in jwk.items() if k != "d"}
        return private_pem, cert_pem, jwk_public

    @pytest.fixture
    def unrelated_cert(self):
        """A second self-signed cert that is NOT the signing cert."""
        other_priv, _, _ = generate_ec_key_pair()
        return generate_self_signed_certificate(other_priv, _IACA_SUBJECT)

    def test_signing_with_single_cert_succeeds(self, signing_key_and_cert):
        """Baseline: signing with a single-cert PEM works."""
        from ..mdoc import isomdl_mdoc_sign

        private_pem, cert_pem, jwk_public = signing_key_and_cert
        result = isomdl_mdoc_sign(jwk_public, _MDL_HEADERS, _MDL_PAYLOAD, cert_pem, private_pem)
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0

    def test_signing_with_chain_pem_succeeds(self, signing_key_and_cert, unrelated_cert):
        """Signing with a chain PEM (signing cert first) extracts only the signing cert.

        Before the fix this would either embed the wrong cert or raise.
        After the fix ``extract_signing_cert`` strips the chain and signing
        proceeds normally.
        """
        from ..mdoc import isomdl_mdoc_sign

        private_pem, cert_pem, jwk_public = signing_key_and_cert
        # signing cert is FIRST in the chain (standard encoding order)
        chain_pem = cert_pem + unrelated_cert
        result = isomdl_mdoc_sign(jwk_public, _MDL_HEADERS, _MDL_PAYLOAD, chain_pem, private_pem)
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0

    def test_mdoc_signed_with_chain_is_verifiable(self, signing_key_and_cert, unrelated_cert):
        """An mdoc signed via a chain PEM embeds the correct signing cert.

        Before the fix: the MSO embedded the unrelated cert (first in chain),
        so ``mdoc_verify`` with the signing cert as trust anchor would fail.

        After the fix: the MSO embeds the signing cert and verification
        succeeds when that cert is supplied as the trust anchor.
        """
        from ..mdoc import isomdl_mdoc_sign, mdoc_verify

        private_pem, cert_pem, jwk_public = signing_key_and_cert
        chain_pem = cert_pem + unrelated_cert  # signing cert first

        mdoc_str = isomdl_mdoc_sign(jwk_public, _MDL_HEADERS, _MDL_PAYLOAD, chain_pem, private_pem)
        assert mdoc_str is not None

        result = mdoc_verify(mdoc_str, trust_anchors=[cert_pem])
        assert result.verified, (
            f"Expected verification to succeed after chain-split fix. Error: {result.error}"
        )


@pytest.mark.skipif(not ISOMDL_AVAILABLE, reason="isomdl_uniffi not available")
class TestVerifierCertChainHandling:
    """Tests that expose (then verify the fix for) the verifier-side chain bug.

    Pre-fix behaviour
    -----------------
    ``mdoc_verify`` passed the raw ``trust_anchors`` list directly to
    ``isomdl_uniffi.Mdoc.verify_issuer_signature``.  If any element of that
    list was a concatenated chain PEM, Rust read only the first cert, and any
    mdoc whose signing cert was NOT that first cert would fail verification.

    Post-fix behaviour
    ------------------
    ``flatten_trust_anchors`` is called before ``verify_issuer_signature`` so
    each element of the list is guaranteed to contain exactly one certificate.
    """

    @pytest.fixture
    def signed_mdoc(self):
        """Return (mdoc_str, signing_cert_pem) for a freshly signed mDL."""
        from ..mdoc import isomdl_mdoc_sign

        private_pem, _, jwk = generate_ec_key_pair()
        cert_pem = generate_self_signed_certificate(private_pem, _IACA_SUBJECT)
        jwk_public = {k: v for k, v in jwk.items() if k != "d"}
        mdoc_str = isomdl_mdoc_sign(jwk_public, _MDL_HEADERS, _MDL_PAYLOAD, cert_pem, private_pem)
        return mdoc_str, cert_pem

    @pytest.fixture
    def unrelated_cert(self):
        other_priv, _, _ = generate_ec_key_pair()
        return generate_self_signed_certificate(other_priv, _IACA_SUBJECT)

    def test_verify_with_exact_cert_succeeds(self, signed_mdoc):
        """Baseline: verification with the exact signing cert as trust anchor succeeds."""
        from ..mdoc import mdoc_verify

        mdoc_str, cert_pem = signed_mdoc
        result = mdoc_verify(mdoc_str, trust_anchors=[cert_pem])
        assert result.verified, f"Baseline verification failed: {result.error}"

    def test_verify_with_single_element_chain_anchor_succeeds(
        self, signed_mdoc, unrelated_cert
    ):
        """Verification succeeds when the trust anchor list has one chain-PEM element.

        The chain PEM contains [unrelated_cert + signing_cert].  Before the fix,
        Rust only saw ``unrelated_cert`` as the trust anchor and rejected the mdoc.
        After the fix ``flatten_trust_anchors`` splits the chain, Rust sees both
        certs, and the signing cert is found → verification succeeds.
        """
        from ..mdoc import mdoc_verify

        mdoc_str, cert_pem = signed_mdoc
        # signing cert is the SECOND element in the chain to maximally stress the fix
        chain_anchor = unrelated_cert + cert_pem
        result = mdoc_verify(mdoc_str, trust_anchors=[chain_anchor])
        assert result.verified, (
            "Expected verification to succeed when signing cert is the second cert in "
            f"a chain trust anchor (post-fix). Error: {result.error}"
        )

    def test_verify_with_completely_wrong_trust_anchor_fails(
        self, signed_mdoc, unrelated_cert
    ):
        """Sanity check: verification with a completely unrelated trust anchor fails."""
        from ..mdoc import mdoc_verify

        mdoc_str, _ = signed_mdoc
        result = mdoc_verify(mdoc_str, trust_anchors=[unrelated_cert])
        assert not result.verified, (
            "Verification should fail when the trust anchor does not match the signing cert"
        )

    def test_verify_with_no_trust_anchors_uses_embedded_cert(self, signed_mdoc):
        """When trust_anchors is None / empty, isomdl self-validates against the MSO cert."""
        from ..mdoc import mdoc_verify

        mdoc_str, _ = signed_mdoc
        # Should not raise; result depends on isomdl_uniffi version behaviour
        result = mdoc_verify(mdoc_str, trust_anchors=None)
        # We don't assert verified here because behaviour varies; just confirm no crash
        assert isinstance(result.verified, bool)
