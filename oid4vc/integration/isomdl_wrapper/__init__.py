"""AFJ Wrapper."""

from jrpc_client import BaseSocketTransport, JsonRpcClient
from . import isomdl_uniffi


class ISOMDLWrapper:
    """Sphereon Wrapper."""

    def __init__(self, transport: BaseSocketTransport, client: JsonRpcClient):
        """Initialize the wrapper."""
        self.transport = transport
        self.client = client

    async def start(self):
        """Start the wrapper."""
        # await self.transport.connect()
        # await self.client.start()

    async def stop(self):
        """Stop the wrapper."""
        # await self.client.stop()
        # await self.transport.close()

    async def __aenter__(self):
        """Start the wrapper when entering the context manager."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Stop the wrapper when exiting the context manager."""
        await self.stop()

    async def test(self) -> dict:
        """Hit test method."""
        return await self.client.request("test")

    async def accept_mdl_credential_offer(self, trust_anchor: str, offer: str):
        """Accpet offer."""
        key = isomdl_uniffi.P256KeyPair()
        if not key:
            print("Key is None")
            return False
        else:
            print(f"Key: {key}")

        session = isomdl_uniffi.establish_session(
            offer,
            {
                "org.iso.18013.5.1": {
                    "given_name": True,
                    "family_name": True,
                }
            },
            [trust_anchor]
        )
        if not session:
            print("Session is None")
            return False
        else:
            print(f"Session: {session}")
        if not session.acceptCredentialOffer(offer):
            print("Session acceptCredentialOffer failed")
            return False
        else:
            print(f"Session acceptCredentialOffer: {session}")
        return False
        return await self.client.request("acceptMDLCredentialOffer", offer=offer)
