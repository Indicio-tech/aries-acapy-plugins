"""AFJ Wrapper."""

from base64 import b64encode, urlsafe_b64encode
from . import isomdl_uniffi
from aries_askar import Key as AskarKey

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oid4vci_client.client import OpenID4VCIClient
    from jrpc_client import BaseSocketTransport, JsonRpcClient


class ISOMDLWrapper:
    """Sphereon Wrapper."""

    def __init__(self, transport: "BaseSocketTransport", client: "JsonRpcClient"):
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

    async def accept_mdl_credential_offer(
        self, test_client: "OpenID4VCIClient", trust_anchor: str, offer: str
    ):
        """Accpet offer."""
        # print(f"Offer: {offer}")
        from urllib.parse import urlparse, parse_qs

        parsed_url = urlparse(offer["credential_offer_uri"])
        query_string = parse_qs(parsed_url.query)
        print(query_string)
        offer2 = query_string.get("credential_offer", [None])[0]
        print(f"Parsed Offer: {offer2}")
        assert offer2, "Offer is None or empty"
        import json

        offer2 = json.loads(offer2)
        for key in offer2:
            print(f"Offer key: {key}, value: {offer2[key]}")
        print(f"Step 1: Offer: {offer2["credential_issuer"]}")
        key = isomdl_uniffi.P256KeyPair()
        if not key:
            print("Key is None")
            return False
        else:
            print(f"Key: {key}")

        did = f"did:jwk:{urlsafe_b64encode(key.public_jwk().encode('utf-8')).rstrip(b"=").decode('utf-8')}"
        print(f"Step 2: DID: {did}")
        key = AskarKey.from_jwk(key.private_jwk())
        test_client.did_to_key[did] = key

        response = await test_client.receive_offer(offer, did)
        print(f"Step 3: Response: {response}")
        assert False

        session = isomdl_uniffi.establish_session(
            offer,
            {
                "org.iso.18013.5.1": {
                    "given_name": True,
                    "family_name": True,
                }
            },
            [trust_anchor],
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
