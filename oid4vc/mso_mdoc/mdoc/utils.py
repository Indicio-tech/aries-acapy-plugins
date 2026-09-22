"""Utility functions for mso_mdoc credential operations."""

import base64
import logging
import re
import time
import zlib
from typing import List, Optional

from acapy_agent.core.profile import Profile

from oid4vc.jwt import jwt_verify

LOGGER = logging.getLogger(__name__)

# Media type a status list token must declare (IETF Token Status List, sec. 5.1).
STATUS_LIST_TYP = "statuslist+jwt"

# Clock-skew allowance, in seconds, when checking `exp` and `nbf`.
CLOCK_SKEW_SECONDS = 60


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

    * **Issuer side** - the wrong certificate is embedded in the MSO (the
      signing key no longer corresponds to the embedded cert → verification
      fails).
    * **Verifier side** - trust-anchor chains are truncated to one cert, so
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


async def check_status_list_claim(
    profile: Profile, status_claim: Optional[dict]
) -> Optional[str]:
    """Check IETF Token Status List revocation status from an MSO status claim.

    *status_claim* is the credential's MSO-level status claim (e.g.
    ``{"status_list": {"idx": ..., "uri": ...}}``), read back via
    ``Mdoc.status()`` for direct credential verification or the reader-side
    ``status`` field for OID4VP presentation verification — not discovered
    by searching namespace claims; status isn't a namespace-embedded data
    element, it lives on the MSO itself. If present, fetches the published
    status list token, verifies its signature and claims, decodes the
    little-endian compressed bitstring, and checks the bit(s) at ``idx``.

    The fetched token is verified before any of its content is trusted:

    - its JWS signature must verify against the key identified by the
      token's ``kid``, ``jwk`` or ``x5c`` header (``alg: none`` and
      unsupported algorithms are rejected by ``jwt_verify``);
    - its ``typ`` header must be ``statuslist+jwt``, so a signed token of
      some other type cannot be substituted;
    - its ``sub`` claim must equal the URI the credential pointed at, so a
      validly signed status list for a *different* URI cannot be swapped in;
    - ``exp`` and ``nbf``, when present, must place it inside its validity
      window.

    Note that this does not bind the token's ``iss`` to the mdoc's issuer —
    an mdoc is issued under an X.509 signer rather than a DID, so there is
    no common identifier to compare. The ``sub``/URI binding plus signature
    verification is what ties the list to the credential.

    Per IETF Token Status List draft:
    - ``status_list.lst``: base64url-encoded, zlib-compressed little-endian bitstring
    - ``status_list.bits``: number of bits per credential entry (typically 1)
    - A non-zero value at position *idx* means the credential is revoked/suspended.

    Args:
        profile: Profile used to resolve the status list token's signing key.
        status_claim: The MSO's status claim dict, or ``None``/empty if the
            credential has no status claim at all.

    Returns:
        ``None`` if the credential is valid (or has no status claim).
        An error string if the credential is revoked/suspended, or if its
        status could not be determined (fetch failure, bad signature,
        unexpected token type or subject, expired or not-yet-valid token,
        decode failure, malformed claim, out-of-range index) — this fails
        closed rather than treating an inconclusive check as "valid".
    """
    if not isinstance(status_claim, dict) or "status_list" not in status_claim:
        return None  # No revocable status claim -> credential is valid

    status_entry = status_claim["status_list"]
    idx = status_entry.get("idx")
    uri = status_entry.get("uri")

    if idx is None or not uri:
        LOGGER.warning("Malformed status_list claim - missing idx or uri")
        return (
            "Could not verify credential status: malformed status_list claim "
            "(missing idx or uri)"
        )

    # Fetch the published status list token
    try:
        import aiohttp  # noqa: PLC0415 - imported lazily to keep utils lean

        async with aiohttp.ClientSession() as http:
            async with http.get(uri) as resp:
                resp.raise_for_status()
                jwt_text = await resp.text()
    except Exception as exc:
        LOGGER.warning("Could not fetch status list from %r: %s", uri, exc)
        return f"Could not verify credential status: {exc}"

    # Verify the token's signature before trusting anything inside it
    try:
        result = await jwt_verify(profile, jwt_text)
    except Exception as exc:
        LOGGER.warning("Could not verify status list token from %r: %s", uri, exc)
        return f"Could not verify credential status: invalid status list token: {exc}"

    if not result.verified:
        LOGGER.warning("Status list token from %r failed signature verification", uri)
        return (
            "Could not verify credential status: status list token signature "
            "verification failed"
        )

    claim_error = _check_status_list_token_claims(result.headers, result.payload, uri)
    if claim_error:
        return claim_error

    sl = result.payload.get("status_list")
    if not isinstance(sl, dict):
        LOGGER.warning("Token from %r has no 'status_list' claim", uri)
        return (
            "Could not verify credential status: status list token has no "
            "'status_list' claim"
        )

    bits: int = int(sl.get("bits", 1))
    lst: str = sl.get("lst", "")

    # Decode: base64url (no padding) -> zlib decompress -> little-endian bitstring bytes
    try:
        compressed = base64.urlsafe_b64decode(lst + "=" * (-len(lst) % 4))
        raw_bytes = zlib.decompress(compressed)
    except Exception as exc:
        LOGGER.warning("Failed to decode status list bitstring from %r: %s", uri, exc)
        return (
            "Could not verify credential status: failed to decode status list "
            f"bitstring: {exc}"
        )

    # Extract the status value for credential at position *idx*.
    # IETF Token Status List uses little-endian bit ordering within each byte:
    # bit 0 of the byte is the LSB, so right-shift by the bit position within
    # the byte and mask to *bits* wide.
    bit_pos = int(idx) * bits
    byte_idx = bit_pos // 8
    bit_in_byte = bit_pos % 8

    if byte_idx >= len(raw_bytes):
        LOGGER.warning(
            "Status list index %d is out of range (list byte length=%d)",
            idx,
            len(raw_bytes),
        )
        return (
            f"Could not verify credential status: index {idx} out of range "
            f"for status list of length {len(raw_bytes)} bytes"
        )

    mask = (1 << bits) - 1
    status_value = (raw_bytes[byte_idx] >> bit_in_byte) & mask

    if status_value != 0:
        return (
            f"Credential is revoked or suspended "
            f"(status_list idx={idx}, status={status_value})"
        )

    return None  # Bit is 0 -> credential is valid


# Validates a verified status list token's type header, subject and validity window.
def _check_status_list_token_claims(headers, payload, uri: str) -> Optional[str]:
    """Check the non-signature parts of a status list token.

    Returns an error string if the token is not a status list token for
    *uri*, or is outside its validity window; ``None`` when it is acceptable.
    """
    typ = headers.get("typ")
    if typ != STATUS_LIST_TYP:
        LOGGER.warning(
            "Status list token from %r has unexpected typ %r (expected %r)",
            uri,
            typ,
            STATUS_LIST_TYP,
        )
        return (
            f"Could not verify credential status: status list token has typ "
            f"{typ!r}, expected {STATUS_LIST_TYP!r}"
        )

    subject = payload.get("sub")
    if subject != uri:
        LOGGER.warning(
            "Status list token subject %r does not match requested URI %r",
            subject,
            uri,
        )
        return (
            "Could not verify credential status: status list token subject "
            f"{subject!r} does not match {uri!r}"
        )

    now = int(time.time())

    exp = payload.get("exp")
    if exp is not None and now > int(exp) + CLOCK_SKEW_SECONDS:
        LOGGER.warning("Status list token from %r expired at %s", uri, exp)
        return f"Could not verify credential status: status list token expired at {exp}"

    nbf = payload.get("nbf")
    if nbf is not None and now < int(nbf) - CLOCK_SKEW_SECONDS:
        LOGGER.warning("Status list token from %r is not valid until %s", uri, nbf)
        return (
            "Could not verify credential status: status list token is not valid "
            f"until {nbf}"
        )

    return None
