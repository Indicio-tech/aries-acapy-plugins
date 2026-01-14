"""HTTP wrapper for the Sphereon demo service."""

from __future__ import annotations

from typing import Any

import httpx


class SphereaonWrapper:
    """Minimal async HTTP client for the Sphereon wrapper."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        """Verify the service is reachable."""
        self.client = httpx.AsyncClient()
        response = await self.client.get(f"{self.base_url}/health", timeout=30.0)
        response.raise_for_status()

    async def stop(self) -> None:
        """Close the underlying HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None

    def _client(self) -> httpx.AsyncClient:
        if not self.client:
            raise RuntimeError(
                "SphereaonWrapper not started; use within an async context manager"
            )
        return self.client

    async def __aenter__(self) -> "SphereaonWrapper":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def test(self) -> dict[str, Any]:
        """Return the health payload from the service."""
        response = await self._client().get(f"{self.base_url}/health", timeout=30.0)
        response.raise_for_status()
        return response.json()

    async def accept_credential_offer(
        self, offer: str, *, format: str | None = None, invalid_proof: bool = False
    ) -> dict[str, Any]:
        """Accept an OID4VCI credential offer via the Sphereon wrapper."""

        payload: dict[str, Any] = {"offer": offer}
        if format:
            payload["format"] = format
        if invalid_proof:
            payload["invalid_proof"] = True

        response = await self._client().post(
            f"{self.base_url}/oid4vci/accept-offer",
            json=payload,
            timeout=60.0,
        )
        response.raise_for_status()
        return response.json()
