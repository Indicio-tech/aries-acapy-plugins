"""Tests for mdoc IETF Token Status List verification.

``check_status_list_claim`` reads the MSO-level status claim (not a
namespace-embedded data element), verifies the fetched status list token, and
fails closed: anything that leaves the credential's status undetermined
returns an error string rather than ``None``.

The aiohttp fetch and the JWS verification are both mocked, so these tests
need neither a status list server nor a wallet.
"""

import base64
import time
import zlib
from types import SimpleNamespace

import aiohttp
import pytest

from ..mdoc import utils
from ..mdoc.utils import STATUS_LIST_TYP, check_status_list_claim

URI = "https://issuer.example/status/1"
TOKEN = "header.payload.signature"


def _encoded_list(bits: int = 1, revoked_indices: list[int] | None = None) -> str:
    """Return the base64url zlib-compressed bitstring for a 1024-entry list."""
    revoked_indices = revoked_indices or []
    raw = bytearray((1024 * bits + 7) // 8)
    for idx in revoked_indices:
        bit_pos = idx * bits
        raw[bit_pos // 8] |= 1 << (bit_pos % 8)
    return base64.urlsafe_b64encode(zlib.compress(bytes(raw))).decode().rstrip("=")


def _payload(bits: int = 1, revoked_indices: list[int] | None = None, **overrides):
    """Return a status list token payload as the status_list plugin emits it."""
    now = int(time.time())
    payload = {
        "iss": "did:key:zIssuer",
        "sub": URI,
        "jti": "urn:uuid:1",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "status_list": {"bits": bits, "lst": _encoded_list(bits, revoked_indices)},
    }
    payload.update(overrides)
    return payload


class _Response:
    def __init__(self, token: str, error: Exception | None = None):
        self.token = token
        self.error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def raise_for_status(self):
        """Model an HTTP response, raising *error* when the fetch failed."""
        if self.error:
            raise self.error

    async def text(self):
        return self.token


class _Session:
    def __init__(self, token: str, requested_urls: list[str], error=None):
        self.token = token
        self.requested_urls = requested_urls
        self.error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def get(self, url: str):
        self.requested_urls.append(url)
        return _Response(self.token, self.error)


def _patch_fetch(monkeypatch, token: str = TOKEN, error=None) -> list[str]:
    """Patch aiohttp.ClientSession to serve *token*; return the requested URLs."""
    requested_urls: list[str] = []
    monkeypatch.setattr(
        aiohttp, "ClientSession", lambda: _Session(token, requested_urls, error)
    )
    return requested_urls


def _patch_verify(
    monkeypatch, payload=None, headers=None, verified: bool = True, raises=None
):
    """Patch jwt_verify to model the outcome of verifying the fetched token."""

    async def _fake_verify(profile, jwt):
        if raises:
            raise raises
        return SimpleNamespace(
            headers={"typ": STATUS_LIST_TYP, "alg": "EdDSA", **(headers or {})},
            payload=_payload() if payload is None else payload,
            verified=verified,
        )

    monkeypatch.setattr(utils, "jwt_verify", _fake_verify)


@pytest.fixture
def profile():
    """The profile is only passed through to jwt_verify, which is mocked."""
    return SimpleNamespace()


# ---------------------------------------------------------------------------
# No status claim
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_list_claim_absent_is_valid(profile):
    assert await check_status_list_claim(profile, None) is None
    assert await check_status_list_claim(profile, {}) is None


@pytest.mark.asyncio
async def test_status_claim_without_status_list_key_is_valid(profile):
    assert await check_status_list_claim(profile, {"other": "value"}) is None


# ---------------------------------------------------------------------------
# Bitstring evaluation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_list_claim_active(monkeypatch, profile):
    requested_urls = _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch)

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 3, "uri": URI}}
    )

    assert result is None
    assert requested_urls == [URI]


@pytest.mark.asyncio
async def test_status_list_claim_revoked(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(revoked_indices=[3]))

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 3, "uri": URI}}
    )

    assert result == "Credential is revoked or suspended (status_list idx=3, status=1)"


@pytest.mark.asyncio
async def test_other_index_revoked_leaves_credential_valid(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(revoked_indices=[10]))

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 42, "uri": URI}}
    )

    assert result is None


@pytest.mark.asyncio
async def test_index_zero_valid(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch)

    assert (
        await check_status_list_claim(profile, {"status_list": {"idx": 0, "uri": URI}})
        is None
    )


@pytest.mark.asyncio
async def test_index_zero_revoked(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(revoked_indices=[0]))

    assert (
        await check_status_list_claim(profile, {"status_list": {"idx": 0, "uri": URI}})
        is not None
    )


@pytest.mark.asyncio
async def test_two_bit_entries_valid(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(bits=2))

    assert (
        await check_status_list_claim(profile, {"status_list": {"idx": 5, "uri": URI}})
        is None
    )


@pytest.mark.asyncio
async def test_two_bit_entries_revoked(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(bits=2, revoked_indices=[5]))

    assert (
        await check_status_list_claim(profile, {"status_list": {"idx": 5, "uri": URI}})
        is not None
    )


@pytest.mark.asyncio
async def test_index_out_of_range_fails_closed(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch)

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 99999, "uri": URI}}
    )

    assert result is not None
    assert "out of range" in result


# ---------------------------------------------------------------------------
# Malformed claims and fetch failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_list_claim_malformed_fails_closed(profile):
    result = await check_status_list_claim(profile, {"status_list": {"idx": 3}})

    assert result is not None
    assert "malformed status_list claim" in result


@pytest.mark.asyncio
async def test_missing_idx_fails_closed(profile):
    result = await check_status_list_claim(profile, {"status_list": {"uri": URI}})

    assert result is not None
    assert "malformed status_list claim" in result


@pytest.mark.asyncio
async def test_fetch_failure_fails_closed(monkeypatch, profile):
    _patch_fetch(monkeypatch, error=Exception("Connection refused"))

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is not None
    assert "Could not verify credential status" in result


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unverifiable_token_fails_closed(monkeypatch, profile):
    """jwt_verify raising (bad alg, unresolvable kid, ...) rejects the credential."""
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, raises=ValueError("unsupported alg 'none'"))

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is not None
    assert "invalid status list token" in result


@pytest.mark.asyncio
async def test_bad_signature_fails_closed(monkeypatch, profile):
    """A token whose signature does not verify rejects the credential."""
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, verified=False)

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is not None
    assert "signature verification failed" in result


@pytest.mark.asyncio
async def test_wrong_typ_fails_closed(monkeypatch, profile):
    """A validly signed token of some other type cannot be substituted."""
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, headers={"typ": "JWT"})

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is not None
    assert "expected 'statuslist+jwt'" in result


@pytest.mark.asyncio
async def test_subject_mismatch_fails_closed(monkeypatch, profile):
    """A validly signed status list for a different URI cannot be swapped in."""
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(sub="https://issuer.example/status/9"))

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is not None
    assert "does not match" in result


@pytest.mark.asyncio
async def test_expired_token_fails_closed(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(exp=int(time.time()) - 3600))

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is not None
    assert "expired" in result


@pytest.mark.asyncio
async def test_expiry_within_clock_skew_is_accepted(monkeypatch, profile):
    """A token that expired seconds ago is still accepted (clock skew)."""
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(exp=int(time.time()) - 5))

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is None


@pytest.mark.asyncio
async def test_not_yet_valid_token_fails_closed(monkeypatch, profile):
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=_payload(nbf=int(time.time()) + 3600))

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is not None
    assert "not valid until" in result


@pytest.mark.asyncio
async def test_token_without_status_list_claim_fails_closed(monkeypatch, profile):
    payload = _payload()
    del payload["status_list"]
    _patch_fetch(monkeypatch)
    _patch_verify(monkeypatch, payload=payload)

    result = await check_status_list_claim(
        profile, {"status_list": {"idx": 0, "uri": URI}}
    )

    assert result is not None
    assert "no 'status_list' claim" in result
