"""Utility functions for mso_mdoc credential operations."""

import re
from typing import List


# Matches a single complete PEM certificate block (including its trailing newline, if any)
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----\n?",
    re.DOTALL,
)


def split_pem_chain(pem_chain: str) -> List[str]:
    r"""Split a concatenated PEM chain into individual certificate PEM strings.

    The isomdl-uniffi Rust library (and the underlying x509_cert crate) reads
    only the **first** ``-----BEGIN CERTIFICATE-----`` block from a PEM string.
    When a caller stores or passes a multi-cert chain as one string, every cert
    after the first is silently dropped, causing either:

    * **Issuer side** – the wrong certificate is embedded in the MSO (the
      signing key no longer corresponds to the embedded cert → verification
      fails).
    * **Verifier side** – trust-anchor chains are truncated to one cert, so
      any mdoc whose embedded cert is not the single root in the chain cannot
      be verified.

    This function normalises any PEM input into a flat list of single-cert
    PEM strings so that each element can be safely handed to Rust.

    Args:
        pem_chain: Zero or more PEM certificate blocks, possibly concatenated
            with arbitrary whitespace between them.

    Returns:
        List of individual PEM certificate strings, one cert per element.
        Returns an empty list for blank / whitespace-only input.

    Examples::

        # Single cert → one-element list (no-op)
        split_pem_chain(single_cert_pem)  # ["-----BEGIN CERTIFICATE-----\n..."]

        # Root + leaf chain → two-element list
        split_pem_chain(root_pem + leaf_pem)  # [root_pem, leaf_pem]
    """
    if not pem_chain or not pem_chain.strip():
        return []

    matches = _PEM_CERT_RE.findall(pem_chain)
    return matches


def extract_signing_cert(pem_chain: str) -> str:
    """Return the first certificate from a PEM chain.

    For the issuer, the signing certificate (the one whose private key is
    used to sign the MSO) is expected to be the **first** cert in the chain.
    This helper extracts exactly that cert so that only one PEM block is
    forwarded to ``Mdoc.create_and_sign()``.

    Args:
        pem_chain: One or more concatenated PEM certificate blocks.

    Returns:
        PEM string containing only the first certificate in the chain.

    Raises:
        ValueError: If no certificate block is found in *pem_chain*.
    """
    certs = split_pem_chain(pem_chain)
    if not certs:
        raise ValueError(
            "No certificate found in provided PEM string. "
            "Expected at least one '-----BEGIN CERTIFICATE-----' block."
        )
    return certs[0]


def flatten_trust_anchors(trust_anchors: List[str]) -> List[str]:
    """Flatten a list of PEM trust-anchor strings into individual cert PEMs.

    Each element of *trust_anchors* may itself contain a concatenated PEM
    chain.  This function expands every element so that the returned list
    contains one entry per individual certificate, which is what the Rust
    ``verify_issuer_signature`` / ``verify_oid4vp_response`` APIs expect.

    Args:
        trust_anchors: List of PEM strings, each potentially containing
            multiple concatenated certificate blocks.

    Returns:
        Flat list of single-certificate PEM strings.
    """
    flat: List[str] = []
    for pem in trust_anchors:
        flat.extend(split_pem_chain(pem))
    return flat
