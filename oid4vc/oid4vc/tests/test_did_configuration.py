"""Tests for the DIF Well-Known DID Configuration endpoint."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web


class TestDidConfiguration:
    """Tests for the /.well-known/did-configuration.json endpoint."""

    @pytest.mark.asyncio
    async def test_returns_valid_document(self, context):
        """Endpoint must return a JSON document with @context and linked_dids."""
        from oid4vc.public_routes.did_configuration import did_configuration

        mock_did_info = MagicMock()
        mock_did_info.did = "did:jwk:test123"

        request = MagicMock()
        request.__getitem__ = (
            lambda _, k: context if k == "context" else (_ for _ in ()).throw(KeyError(k))
        )
        request.match_info = {}

        with (
            patch(
                "oid4vc.public_routes.did_configuration.retrieve_or_create_did_jwk",
                AsyncMock(return_value=mock_did_info),
            ),
            patch(
                "oid4vc.public_routes.did_configuration.jwt_sign",
                AsyncMock(return_value="signed.jwt.token"),
            ),
        ):
            response = await did_configuration(request)

        assert response.status == 200
        body = json.loads(response.body)
        assert "@context" in body
        assert (
            body["@context"]
            == "https://identity.foundation/.well-known/did-configuration/v1"
        )
        assert "linked_dids" in body
        assert isinstance(body["linked_dids"], list)
        assert len(body["linked_dids"]) == 1
        assert body["linked_dids"][0] == "signed.jwt.token"

    @pytest.mark.asyncio
    async def test_cache_control_header(self, context):
        """Response must carry Cache-Control: no-store."""
        from oid4vc.public_routes.did_configuration import did_configuration

        mock_did_info = MagicMock()
        mock_did_info.did = "did:jwk:test123"

        request = MagicMock()
        request.__getitem__ = (
            lambda _, k: context if k == "context" else (_ for _ in ()).throw(KeyError(k))
        )
        request.match_info = {}

        with (
            patch(
                "oid4vc.public_routes.did_configuration.retrieve_or_create_did_jwk",
                AsyncMock(return_value=mock_did_info),
            ),
            patch(
                "oid4vc.public_routes.did_configuration.jwt_sign",
                AsyncMock(return_value="signed.jwt.token"),
            ),
        ):
            response = await did_configuration(request)

        assert response.headers.get("Cache-Control") == "no-store"

    @pytest.mark.asyncio
    async def test_route_is_registered(self):
        """The /.well-known/did-configuration.json route must be registered."""
        from oid4vc.public_routes.registration import register

        app = web.Application()
        app.router.freeze = lambda: None

        context_mock = MagicMock()
        await register(app, multitenant=False, context=context_mock)

        routes = [resource.canonical for resource in app.router.resources()]
        assert "/.well-known/did-configuration.json" in routes
