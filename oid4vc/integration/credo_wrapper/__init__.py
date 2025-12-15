"""Credo Wrapper."""

import httpx


class CredoWrapper:
    """Credo Wrapper using HTTP."""

    def __init__(self, base_url: str):
        """Initialize the wrapper."""
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient()

    async def start(self):
        """Start the wrapper."""
        # Check Credo agent health
        response = await self.client.get(f"{self.base_url}/health")
        response.raise_for_status()

    async def stop(self):
        """Stop the wrapper."""
        await self.client.aclose()

    async def __aenter__(self):
        """Start the wrapper when entering the context manager."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Stop the wrapper when exiting the context manager."""
        await self.stop()

    # Credo API

    async def test(self):
        """Test basic connectivity to Credo agent."""
        response = await self.client.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()

    async def openid4vci_accept_offer(self, offer: str, holder_did_method: str = "key"):
        """Accept OpenID4VCI credential offer."""
        response = await self.client.post(
            f"{self.base_url}/oid4vci/accept-offer",
            json={"credential_offer": offer, "holder_did_method": holder_did_method}
        )
        response.raise_for_status()
        return response.json()

    async def openid4vp_accept_request(
        self, request: str, credentials: list = None
    ):
        """Accept OpenID4VP presentation (authorization) request.
        
        Args:
            request: The presentation request URI
            credentials: List of credentials to present (can be strings for mso_mdoc or dicts)
        """
        payload = {"request_uri": request}
        if credentials:
            payload["credentials"] = credentials

        response = await self.client.post(
            f"{self.base_url}/oid4vp/present",
            json=payload,
        )
        response.raise_for_status()
        return response.json()
