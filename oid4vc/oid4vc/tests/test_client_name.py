"""Tests for the optional OID4VP client_name (RFC 7591).

One validator (normalize_client_name) is used by the request schema (422 on
create) and again when the request object is built.
"""

import json
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.storage.error import StorageNotFoundError
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from aiohttp_apispec import setup_aiohttp_apispec, validation_middleware

from oid4vc.client_name import is_refused_character, normalize_client_name
from oid4vc.models.request import OID4VPRequest
from oid4vc.routes.vp_request import create_oid4vp_request

VP_FORMATS = {"jwt_vp_json": {"alg": ["ES256"]}}

# (value sent, value stored)
ACCEPTED = [
    ("Example Clinic", "Example Clinic"),
    ("  Example Clinic  ", "Example Clinic"),
    # NBSP and the ideographic space are whitespace and are trimmed.
    ("\u00a0Example Clinic\u3000", "Example Clinic"),
    ("x" * 80, "x" * 80),
    # The length is counted after trimming.
    ("x" * 80 + " ", "x" * 80),
    ("\u00e9" * 80, "\u00e9" * 80),
    # 80 code points (160 UTF-16 code units): the limit counts code points.
    ("\U0001f600" * 80, "\U0001f600" * 80),
    # A valid surrogate pair in the JSON text is one code point.
    (json.loads('"Example \\ud83d\\ude00"'), "Example \U0001f600"),
    # 40 letters, each with a combining mark: 80 code points.
    ("e\u0301" * 40, "e\u0301" * 40),
    ("Cl\u00ednica Ejemplo", "Cl\u00ednica Ejemplo"),
    ("\u0639\u064a\u0627\u062f\u0629", "\u0639\u064a\u0627\u062f\u0629"),
    # Neighbours of refused characters and ranges are accepted.
    ("Example\u00a1", "Example\u00a1"),
    ("Example\u2801", "Example\u2801"),
    ("Example\u3163", "Example\u3163"),
    ("Example\u115e\u1161", "Example\u115e\u1161"),
    ("Example\ufe10", "Example\ufe10"),
    ("Example\uff9f", "Example\uff9f"),
    ("e\u034e", "e\u034e"),
]

REFUSED_TYPE = [None, 123, 1.5, True, [], {}, ["Example Clinic"]]

REFUSED_LENGTH = [
    "",
    "   ",
    "\u00a0\u3000",
    "x" * 81,
    "\U0001f600" * 81,
    # 80 letters and one combining mark: 81 code points.
    "x" * 80 + "\u0301",
    "e\u0301" * 40 + "x",
]

# One sample of each refused kind, placed inside the name.
REFUSED_CHARACTERS = [
    "\x00",  # Cc
    "\t",
    "\n",
    "\x1f",
    "\x7f",
    "\x85",
    "\x9f",
    "\u00ad",  # Cf: soft hyphen
    "\u061c",  # Cf: Arabic letter mark
    "\u180e",  # Cf: Mongolian vowel separator
    "\u200b",  # Cf: zero-width space
    "\u200c",  # Cf: ZWNJ
    "\u200d",  # Cf: ZWJ
    "\u200e",
    "\u202a",
    "\u202e",
    "\u2060",  # Cf: word joiner
    "\u2064",
    "\u2065",  # Cn in the Unicode version of the runtime
    "\u2066",
    "\u2069",
    "\u206a",
    "\u206f",
    "\ufeff",  # Cf: byte order mark
    "\ufff9",
    "\ufffb",
    "\U000e0001",  # Cf: language tag
    "\U000e0020",  # Cf: tag space
    "\U000e007f",  # Cf: cancel tag
    "\u2028",  # Zl
    "\u2029",  # Zp
    "\ue000",  # Co
    "\U000f0000",  # Co
    "\U0010fffd",  # Co
    "\u0378",  # Cn
    "\ud800",  # Cs: lone surrogate
    "\udfff",
    "\ufe00",  # variation selectors
    "\ufe0f",
    "\U000e0100",
    "\U000e01ef",
    "\u034f",  # combining grapheme joiner
    "\u115f",  # Hangul fillers
    "\u1160",
    "\u3164",
    "\uffa0",
    "\u2800",  # blank braille pattern
]


@pytest.mark.parametrize(("value", "expected"), ACCEPTED)
def test_accepted(value, expected):
    assert normalize_client_name(value) == expected


@pytest.mark.parametrize("value", REFUSED_TYPE)
def test_refused_type(value):
    with pytest.raises(ValueError, match="must be a string"):
        normalize_client_name(value)


@pytest.mark.parametrize("value", REFUSED_LENGTH)
def test_refused_length(value):
    with pytest.raises(ValueError, match="1 to 80 characters"):
        normalize_client_name(value)


@pytest.mark.parametrize("char", REFUSED_CHARACTERS)
@pytest.mark.parametrize("template", ["Example{}Clinic", "{}Example", "Example{}"])
def test_refused_character_anywhere(char, template):
    """Refused inside the name, and at either end (checked before trimming)."""
    with pytest.raises(ValueError, match="must not contain"):
        normalize_client_name(template.format(char))


def test_refused_lone_surrogate_from_json():
    with pytest.raises(ValueError, match="must not contain"):
        normalize_client_name(json.loads('"Example\\udc00Clinic"'))


def test_refused_emoji_zwj_sequence():
    """ZWJ is refused, so an emoji ZWJ sequence is refused too."""
    with pytest.raises(ValueError, match="must not contain"):
        normalize_client_name("Example \U0001f469\u200d\u2695\ufe0f")


@pytest.mark.parametrize(
    ("low", "high"),
    [
        (0x0000, 0x001F),
        (0x007F, 0x009F),
        (0x200B, 0x200F),
        (0x2060, 0x206F),
        (0xFE00, 0xFE0F),
        (0xFFF9, 0xFFFB),
        (0xD800, 0xDFFF),
        (0xE000, 0xF8FF),
        (0xE0000, 0xE007F),
        (0xE0100, 0xE01EF),
    ],
)
def test_whole_ranges_refused(low, high):
    assert all(is_refused_character(chr(cp)) for cp in range(low, high + 1))


class TestRecordRoundTrip:
    """A stored request keeps client_name, and older records load without it."""

    def test_with_client_name(self):
        record = OID4VPRequest(
            dcql_query_id="dcql-001",
            vp_formats=VP_FORMATS,
            client_name="Example Clinic",
        )
        stored = record.record_value
        assert stored["client_name"] == "Example Clinic"

        loaded = OID4VPRequest.from_storage("req-001", stored)

        assert loaded.client_name == "Example Clinic"
        assert loaded.dcql_query_id == "dcql-001"

    def test_without_client_name(self):
        record = OID4VPRequest(dcql_query_id="dcql-001", vp_formats=VP_FORMATS)
        stored = record.record_value
        assert "client_name" not in stored

        loaded = OID4VPRequest.from_storage("req-001", stored)

        assert loaded.client_name is None


def _patch_create_route(context, monkeypatch):
    """Patch the create route's collaborators; return the OID4VPRequest mock."""
    jwk = MagicMock(did="did:jwk:abc123")
    req_record = MagicMock(_id="req-id-003")
    req_record.serialize = MagicMock(return_value={"request_id": "req-id-003"})
    req_record.save = AsyncMock()
    pres_record = MagicMock()
    pres_record.serialize = MagicMock(return_value={"pres_id": "pres-id-003"})
    pres_record.save = AsyncMock()
    request_cls = MagicMock(return_value=req_record)

    module = "oid4vc.routes.vp_request"
    monkeypatch.setattr(
        f"{module}.retrieve_or_create_did_jwk", AsyncMock(return_value=jwk)
    )
    monkeypatch.setattr(f"{module}.OID4VPRequest", request_cls)
    monkeypatch.setattr(
        f"{module}.OID4VPPresentation", MagicMock(return_value=pres_record)
    )
    monkeypatch.setattr(
        f"{module}.Config.from_settings",
        MagicMock(
            return_value=MagicMock(endpoint="http://localhost:8020", oid4vp_endpoint=None)
        ),
    )

    storage = MagicMock()
    storage.get_record = AsyncMock(side_effect=StorageNotFoundError("no x509 record"))
    session = MagicMock()
    session.inject = MagicMock(return_value=storage)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(context, "session", MagicMock(return_value=session))
    return request_cls


@pytest.fixture
def admin_app(context):
    """The create route behind the admin server's request validation."""

    @web.middleware
    async def add_context(request, handler):
        request["context"] = context
        return await handler(request)

    app = web.Application(middlewares=[add_context, validation_middleware])
    app.router.add_post("/oid4vp/request", create_oid4vp_request)
    setup_aiohttp_apispec(app)
    return app


class TestCreateRoute:
    """client_name through the admin route, with its request validation."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("id_field", ["pres_def_id", "dcql_query_id"])
    async def test_stored_trimmed(self, admin_app, context, monkeypatch, id_field):
        request_cls = _patch_create_route(context, monkeypatch)
        body = {
            id_field: "id-001",
            "vp_formats": VP_FORMATS,
            "client_name": "\u00a0 Example Clinic \u3000",
        }

        async with TestClient(TestServer(admin_app)) as client:
            response = await client.post("/oid4vp/request", json=body)

        assert response.status == 200
        request_cls.assert_called_once_with(
            **{id_field: "id-001"},
            vp_formats=VP_FORMATS,
            client_name="Example Clinic",
        )

    @pytest.mark.asyncio
    async def test_without_client_name(self, admin_app, context, monkeypatch):
        request_cls = _patch_create_route(context, monkeypatch)
        body = {"dcql_query_id": "id-001", "vp_formats": VP_FORMATS}

        async with TestClient(TestServer(admin_app)) as client:
            response = await client.post("/oid4vp/request", json=body)

        assert response.status == 200
        request_cls.assert_called_once_with(
            dcql_query_id="id-001", vp_formats=VP_FORMATS, client_name=None
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "client_name",
        [None, 123, "", "   ", "x" * 81, "Example\u200bClinic", "Example\u2800"],
    )
    async def test_refused_with_422(self, admin_app, context, monkeypatch, client_name):
        request_cls = _patch_create_route(context, monkeypatch)
        body = {
            "dcql_query_id": "id-001",
            "vp_formats": VP_FORMATS,
            "client_name": client_name,
        }

        async with TestClient(TestServer(admin_app)) as client:
            response = await client.post("/oid4vp/request", json=body)

        assert response.status == 422
        request_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_logs_self_asserted_name(self, admin_app, context, monkeypatch, caplog):
        _patch_create_route(context, monkeypatch)
        context.profile.settings["wallet.id"] = "wallet-001"
        body = {
            "dcql_query_id": "id-001",
            "vp_formats": VP_FORMATS,
            "client_name": "Example Clinic",
        }

        with caplog.at_level(logging.INFO, logger="oid4vc.routes.vp_request"):
            async with TestClient(TestServer(admin_app)) as client:
                response = await client.post("/oid4vp/request", json=body)

        assert response.status == 200
        messages = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
        assert any(
            "wallet-001" in m and "'Example Clinic'" in m and "self-asserted" in m
            for m in messages
        )

    @pytest.mark.asyncio
    async def test_no_log_without_name(self, admin_app, context, monkeypatch, caplog):
        _patch_create_route(context, monkeypatch)
        body = {"dcql_query_id": "id-001", "vp_formats": VP_FORMATS}

        with caplog.at_level(logging.INFO, logger="oid4vc.routes.vp_request"):
            async with TestClient(TestServer(admin_app)) as client:
                response = await client.post("/oid4vp/request", json=body)

        assert response.status == 200
        assert not any("client_name" in r.getMessage() for r in caplog.records)
