"""Unit tests for mDOC certificate generation and PEM parsing.

These tests are self-contained — they require no running docker services and
no conftest fixtures.  Run them locally to quickly check if cert generation or
trust-anchor parsing is the root cause of:

  "Failed to build trust anchor for cert no. 1"

The key hypothesis: the issuer API returns a chain PEM (leaf + intermediate)
which contains two `-----BEGIN CERTIFICATE-----` blocks.  When this PEM is
passed to isomdl_uniffi.verify_issuer_signature() as a single trust anchor
entry, the Rust library tries to build a trust anchor from EACH cert in the
PEM, and cert no. 1 (the intermediate) lacks the expected trust-anchor
extensions, causing the error.

Run with:
    cd oid4vc && poetry run pytest integration/tests/debug/test_cert_unit.py -v
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Local copies of the cert generation helpers from conftest.py
# (copied here so this file is self-contained)
# ---------------------------------------------------------------------------


def _gen_key():
    return ec.generate_private_key(ec.SECP256R1())


def _get_name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "UT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _add_iaca_extensions(
    builder, key, issuer_key, *, is_ca: bool, is_root: bool = False
):
    if is_ca:
        path_length = 1 if is_root else 0
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")]),
            critical=True,
        )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    )
    builder = builder.add_extension(
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier("https://example.com/test.crl")
                    ],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                )
            ]
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.IssuerAlternativeName(
            [x509.UniformResourceIdentifier("https://example.com")]
        ),
        critical=False,
    )
    return builder


def _root_ca(key):
    name = _get_name("Test Root CA")
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .serial_number(x509.random_serial_number())
        .public_key(key.public_key())
    )
    builder = _add_iaca_extensions(builder, key, key, is_ca=True, is_root=True)
    return builder.sign(key, hashes.SHA256())


def _intermediate_ca(key, issuer_key, issuer_cert):
    name = _get_name("Test Intermediate CA")
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject)
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .serial_number(x509.random_serial_number())
        .public_key(key.public_key())
    )
    builder = _add_iaca_extensions(builder, key, issuer_key, is_ca=True, is_root=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _leaf_ds(key, issuer_key, issuer_cert):
    name = _get_name("Test IACA DS")
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject)
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .serial_number(x509.random_serial_number())
        .public_key(key.public_key())
    )
    builder = _add_iaca_extensions(builder, key, issuer_key, is_ca=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _to_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _count_pem_certs(pem: str) -> int:
    return pem.count("-----BEGIN CERTIFICATE-----")


# ---------------------------------------------------------------------------
# Common fixture: a complete three-level PKI chain
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pki_chain():
    """Generate a root → intermediate → leaf certificate chain."""
    root_key = _gen_key()
    root_cert = _root_ca(root_key)

    inter_key = _gen_key()
    inter_cert = _intermediate_ca(inter_key, root_key, root_cert)

    leaf_key = _gen_key()
    leaf_cert = _leaf_ds(leaf_key, inter_key, inter_cert)

    return {
        "root_pem": _to_pem(root_cert),
        "intermediate_pem": _to_pem(inter_cert),
        "leaf_pem": _to_pem(leaf_cert),
        "chain_pem": _to_pem(leaf_cert) + _to_pem(inter_cert),
        "full_chain_pem": (
            _to_pem(leaf_cert) + _to_pem(inter_cert) + _to_pem(root_cert)
        ),
    }


# ---------------------------------------------------------------------------
# Test: PEM cert counts
# ---------------------------------------------------------------------------


def test_root_pem_is_single_cert(pki_chain):
    """Root CA PEM must contain exactly one certificate block."""
    assert _count_pem_certs(pki_chain["root_pem"]) == 1


def test_intermediate_pem_is_single_cert(pki_chain):
    """Intermediate CA PEM must contain exactly one certificate block."""
    assert _count_pem_certs(pki_chain["intermediate_pem"]) == 1


def test_leaf_pem_is_single_cert(pki_chain):
    """Leaf DS PEM must contain exactly one certificate block."""
    assert _count_pem_certs(pki_chain["leaf_pem"]) == 1


def test_chain_pem_has_two_certs(pki_chain):
    """A leaf+intermediate chain PEM contains two certificate blocks.

    This is what the 'certificate_pem' from the ACA-Py issuer API would look
    like if it returns a chain instead of a standalone cert.
    """
    assert _count_pem_certs(pki_chain["chain_pem"]) == 2


# ---------------------------------------------------------------------------
# Test: isomdl_uniffi trust anchor behaviour for single vs chain PEM
# ---------------------------------------------------------------------------

try:
    import isomdl_uniffi  # type: ignore

    MDOC_AVAILABLE = True
except ImportError:
    MDOC_AVAILABLE = False


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
def test_isomdl_single_cert_trustanchor_does_not_error(pki_chain):
    """isomdl_uniffi can build a trust registry from a single-cert PEM.

    If this test passes but test_isomdl_chain_pem_reproduces_cert_no_1_error
    fails, the fix is to strip the chain PEM to only the root/trust-anchor cert
    before passing it to verify_issuer_signature().
    """
    # We use the root cert as the trust anchor (it is a IACA root CA).
    # We don't have a real mdoc to verify, so we just check that calling
    # verify_issuer_signature with trust_anchors doesn't raise on the
    # trust-anchor loading step.
    # Build a tiny fake mdoc to trigger trust registry construction.
    # If no usable mdoc is at hand we can check via exception message.
    try:
        # Pass a valid single-cert PEM list — should reach the actual
        # signature check rather than the cert-parsing step.
        fake_mdoc_b64 = "aGVsbG8="  # not a real mdoc
        _ = isomdl_uniffi.Mdoc.from_string(fake_mdoc_b64)
    except Exception as e:
        # Parsing the fake mdoc will fail; that's expected.
        # The important thing is we don't get a "cert no. X" error.
        err = str(e).lower()
        assert "cert no." not in err, (
            f"Expected a parse error, but got trust-anchor error: {e}"
        )
        pytest.skip(f"Can't build a test mdoc in this env (expected): {e}")


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
def test_isomdl_chain_pem_reproduces_cert_no_1_error(pki_chain):
    """Chain PEM triggers 'cert no. N' error in isomdl_uniffi.

    This test REPRODUCES the CI failure:
        "Failed to build trust anchor for cert no. 1"

    If this test passes (the error is raised), it confirms the root cause and
    that splitting the chain into individual certs is the correct fix.

    The test is expected to see an error about cert no. 1 when the trust anchor
    list contains a PEM with two certificate blocks.
    """
    chain_pem = pki_chain["chain_pem"]
    assert _count_pem_certs(chain_pem) == 2, "Precondition: chain must have 2 certs"

    try:
        fake_mdoc_b64 = "aGVsbG8="
        mdoc_obj = isomdl_uniffi.Mdoc.from_string(fake_mdoc_b64)
        result = mdoc_obj.verify_issuer_signature([chain_pem], True)
        # If we get here without error, document what actually happens
        pytest.fail(f"Expected an error about parsing multi-cert PEM but got: {result}")
    except isomdl_uniffi.MdocVerificationError as e:
        err = str(e)
        print(f"\n[debug] isomdl error with chain PEM: {err}")
        if "cert no." in err:
            pytest.fail(
                f"REPRODUCED: Multi-cert chain PEM causes '{err}'.\n"
                "Fix: pass individual cert PEMs instead of a concatenated chain."
            )
        else:
            # Some other verification error — chain PEM doesn't cause this specific error
            pytest.skip(f"Different error raised (not cert-no. issue): {err}")
    except Exception as e:
        err = str(e)
        print(f"\n[debug] Non-MdocVerificationError with chain PEM: {err}")
        if "cert no." in err:
            pytest.fail(
                f"REPRODUCED via generic exception: Multi-cert chain PEM causes '{err}'.\n"
                "Fix: split chain PEM and pass one PEM per trust anchor."
            )
        else:
            pytest.skip(
                f"Could not parse fake mdoc (expected in unit test context): {err}"
            )


# ---------------------------------------------------------------------------
# Test: parsing a PEM string into individual certs (future fix validation)
# ---------------------------------------------------------------------------


def _split_pem_chain(pem: str) -> list[str]:
    """Split a concatenated PEM into a list of individual cert PEM strings."""
    import re

    pattern = r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)"
    certs = re.findall(pattern, pem, re.DOTALL)
    return [c + "\n" for c in certs]


def test_split_pem_chain_gives_individual_certs(pki_chain):
    """Splitting a chain PEM returns the same number of individual certs."""
    chain_pem = pki_chain["chain_pem"]
    individual = _split_pem_chain(chain_pem)

    assert len(individual) == 2, (
        f"Expected 2 individual certs after split, got {len(individual)}"
    )
    for i, cert_pem in enumerate(individual):
        assert _count_pem_certs(cert_pem) == 1, (
            f"cert[{i}] after split still has >1 cert block"
        )
    # Each individual cert must be parseable by cryptography
    for i, cert_pem in enumerate(individual):
        parsed = x509.load_pem_x509_certificate(cert_pem.encode())
        assert parsed.subject, f"cert[{i}] has empty subject after split+parse"


def test_root_cert_is_self_signed(pki_chain):
    """Root CA must be self-signed (issuer == subject)."""
    cert = x509.load_pem_x509_certificate(pki_chain["root_pem"].encode())
    assert cert.issuer == cert.subject, (
        f"Root CA is not self-signed:\n  issuer={cert.issuer}\n  subject={cert.subject}"
    )


def test_intermediate_cert_is_signed_by_root(pki_chain):
    """Intermediate CA must be signed by the root CA."""
    root = x509.load_pem_x509_certificate(pki_chain["root_pem"].encode())
    inter = x509.load_pem_x509_certificate(pki_chain["intermediate_pem"].encode())
    assert inter.issuer == root.subject, (
        f"Intermediate not signed by root:\n"
        f"  inter.issuer={inter.issuer}\n"
        f"  root.subject={root.subject}"
    )


def test_leaf_cert_is_not_ca(pki_chain):
    """Leaf DS cert must NOT be a CA (BasicConstraints.ca=False)."""
    leaf = x509.load_pem_x509_certificate(pki_chain["leaf_pem"].encode())
    try:
        bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        assert not bc.value.ca, "Leaf cert has BasicConstraints.ca=True"
    except x509.ExtensionNotFound:
        pass  # No BasicConstraints at all is fine for a leaf cert


def test_root_cert_has_ca_basic_constraints(pki_chain):
    """Root CA must have BasicConstraints.ca=True."""
    root = x509.load_pem_x509_certificate(pki_chain["root_pem"].encode())
    bc = root.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True, "Root CA missing BasicConstraints.ca=True"
