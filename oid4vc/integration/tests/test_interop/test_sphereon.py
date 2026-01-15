from typing import Any

import pytest

from sphereon_wrapper import SphereaonWrapper


@pytest.mark.interop
@pytest.mark.asyncio
async def test_api(sphereon: SphereaonWrapper):
    """Test that we can hit the sphereon rpc api."""

    result = await sphereon.test()
    assert result
    # Sphereon health endpoint returns {'status': 'ok'}
    assert result.get("status") == "ok"


@pytest.mark.interop
@pytest.mark.asyncio
async def test_sphereon_pre_auth(sphereon: SphereaonWrapper, offer: dict[str, Any]):
    """Test receive offer for pre auth code flow."""
    await sphereon.accept_credential_offer(offer["credential_offer"])


@pytest.mark.interop
@pytest.mark.asyncio
async def test_sphereon_pre_auth_by_ref(
    sphereon: SphereaonWrapper, offer_by_ref: dict[str, Any]
):
    """Test receive offer for pre auth code flow, where offer is passed by reference from the
    credential-offer-by-ref endpoint and then dereferenced."""
    await sphereon.accept_credential_offer(offer_by_ref["credential_offer"])
