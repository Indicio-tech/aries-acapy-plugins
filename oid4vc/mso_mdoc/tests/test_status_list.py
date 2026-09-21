"""Tests for mdoc IETF Token Status List verification.

``check_status_list_claim`` reads the MSO-level status claim (not a
namespace-embedded data element) and fails closed: anything that leaves the
credential's status undetermined returns an error string rather than ``None``.
The aiohttp fetch is mocked so these tests need no status list server.
"""

import base64
import json
import zlib

import aiohttp
import pytest

from ..mdoc.utils import check_status_list_claim


def _status_list_token(bits: int = 1, revoked_indices: list[int] | None = None) -> str:
    """Return an unsigned IETF Token Status List JWT over a 1024-entry list."""
    revoked_indices = revoked_indices or []
    raw = bytearray((1024 * bits + 7) // 8)
    for idx in revoked_indices:
        bit_pos = idx * bits
        raw[bit_pos // 8] |= 1 << (bit_pos % 8)

    encoded_list = (
        base64.urlsafe_b64encode(zlib.compress(bytes(raw))).decode().rstrip("=")
    )
    payload = {
        "iss": "did:key:testissuer",
        "status_list": {"bits": bits, "lst": encoded_list},
    }
    encoded_payload = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    )
    return f"header.{encoded_payload}.signature"


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


def _patch_session(monkeypatch, token: str, error=None) -> list[str]:
    """Patch aiohttp.ClientSession to serve *token*; return the requested URLs."""
    requested_urls: list[str] = []
    monkeypatch.setattr(
        aiohttp, "ClientSession", lambda: _Session(token, requested_urls, error)
    )
    return requested_urls


def _claim(idx: int, uri: str = "https://issuer.example/status/1") -> dict:
    return {"status_list": {"idx": idx, "uri": uri}}


@pytest.mark.asyncio
async def test_status_list_claim_absent_is_valid():
    assert await check_status_list_claim(None) is None
    assert await check_status_list_claim({}) is None


@pytest.mark.asyncio
async def test_status_claim_without_status_list_key_is_valid():
    assert await check_status_list_claim({"other": "value"}) is None


@pytest.mark.asyncio
async def test_status_list_claim_active(monkeypatch):
    requested_urls = _patch_session(monkeypatch, _status_list_token())

    result = await check_status_list_claim(_claim(3))

    assert result is None
    assert requested_urls == ["https://issuer.example/status/1"]


@pytest.mark.asyncio
async def test_status_list_claim_revoked(monkeypatch):
    _patch_session(monkeypatch, _status_list_token(revoked_indices=[3]))

    result = await check_status_list_claim(_claim(3))

    assert result == "Credential is revoked or suspended (status_list idx=3, status=1)"


@pytest.mark.asyncio
async def test_other_index_revoked_leaves_credential_valid(monkeypatch):
    _patch_session(monkeypatch, _status_list_token(revoked_indices=[10]))

    assert await check_status_list_claim(_claim(42)) is None


@pytest.mark.asyncio
async def test_index_zero_valid(monkeypatch):
    _patch_session(monkeypatch, _status_list_token())

    assert await check_status_list_claim(_claim(0)) is None


@pytest.mark.asyncio
async def test_index_zero_revoked(monkeypatch):
    _patch_session(monkeypatch, _status_list_token(revoked_indices=[0]))

    assert await check_status_list_claim(_claim(0)) is not None


@pytest.mark.asyncio
async def test_two_bit_entries_valid(monkeypatch):
    _patch_session(monkeypatch, _status_list_token(bits=2))

    assert await check_status_list_claim(_claim(5)) is None


@pytest.mark.asyncio
async def test_two_bit_entries_revoked(monkeypatch):
    _patch_session(monkeypatch, _status_list_token(bits=2, revoked_indices=[5]))

    assert await check_status_list_claim(_claim(5)) is not None


@pytest.mark.asyncio
async def test_status_list_claim_malformed_fails_closed():
    result = await check_status_list_claim({"status_list": {"idx": 3}})

    assert result is not None
    assert "malformed status_list claim" in result


@pytest.mark.asyncio
async def test_missing_idx_fails_closed():
    result = await check_status_list_claim(
        {"status_list": {"uri": "https://issuer.example/status/1"}}
    )

    assert result is not None
    assert "malformed status_list claim" in result


@pytest.mark.asyncio
async def test_fetch_failure_fails_closed(monkeypatch):
    _patch_session(monkeypatch, "", error=Exception("Connection refused"))

    result = await check_status_list_claim(_claim(0))

    assert result is not None
    assert "Could not verify credential status" in result


@pytest.mark.asyncio
async def test_malformed_jwt_fails_closed(monkeypatch):
    _patch_session(monkeypatch, "not.a.valid.jwt.at.all.blah")

    result = await check_status_list_claim(_claim(0))

    assert result is not None
    assert "failed to decode status list JWT" in result


@pytest.mark.asyncio
async def test_jwt_without_status_list_claim_fails_closed(monkeypatch):
    payload = base64.urlsafe_b64encode(json.dumps({"iss": "x"}).encode()).decode()
    _patch_session(monkeypatch, f"header.{payload.rstrip('=')}.signature")

    result = await check_status_list_claim(_claim(0))

    assert result is not None
    assert "no 'status_list' claim" in result


@pytest.mark.asyncio
async def test_index_out_of_range_fails_closed(monkeypatch):
    _patch_session(monkeypatch, _status_list_token())

    result = await check_status_list_claim(_claim(99999))

    assert result is not None
    assert "out of range" in result
