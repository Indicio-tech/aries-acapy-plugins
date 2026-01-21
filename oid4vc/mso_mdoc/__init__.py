"""MSO_MDOC Credential Handler Plugin."""

import logging
import os
from typing import Optional, Union

from acapy_agent.admin.base_server import BaseAdminServer
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.event_bus import EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import STARTUP_EVENT_PATTERN

from mso_mdoc.cred_processor import MsoMdocCredProcessor
from mso_mdoc.key_generation import generate_default_keys_and_certs
from mso_mdoc.mdoc.verifier import FileTrustStore, WalletTrustStore
from mso_mdoc.storage import MdocStorageManager
from oid4vc.cred_processor import CredProcessors
from . import routes

LOGGER = logging.getLogger(__name__)

# Trust store type configuration
TRUST_STORE_TYPE_FILE = "file"
TRUST_STORE_TYPE_WALLET = "wallet"

# Store reference to processor for startup initialization
_mso_mdoc_processor: Optional[MsoMdocCredProcessor] = None


def create_trust_store(
    profile: Optional[Profile] = None,
) -> Optional[Union[FileTrustStore, WalletTrustStore]]:
    """Create a trust store based on configuration.

    Environment variables:
    - OID4VC_MDOC_TRUST_STORE_TYPE: "file" or "wallet" (default: "file")
    - OID4VC_MDOC_TRUST_ANCHORS_PATH: Path for file-based trust store

    Args:
        profile: ACA-Py profile for wallet-based trust store (optional, required for wallet type)

    Returns:
        Configured trust store instance or None if disabled
    """
    trust_store_type = os.getenv(
        "OID4VC_MDOC_TRUST_STORE_TYPE", TRUST_STORE_TYPE_FILE
    ).lower()

    if trust_store_type == TRUST_STORE_TYPE_WALLET:
        if profile is None:
            LOGGER.warning(
                "Wallet trust store requires a profile, deferring initialization"
            )
            return None
        LOGGER.info("Using wallet-based trust store")
        return WalletTrustStore(profile)
    elif trust_store_type == TRUST_STORE_TYPE_FILE:
        trust_store_path = os.getenv(
            "OID4VC_MDOC_TRUST_ANCHORS_PATH", "/etc/acapy/mdoc/trust-anchors/"
        )
        LOGGER.info("Using file-based trust store at: %s", trust_store_path)
        return FileTrustStore(trust_store_path)
    elif trust_store_type == "none" or trust_store_type == "disabled":
        LOGGER.info("Trust store disabled")
        return None
    else:
        LOGGER.warning(
            "Unknown trust store type '%s', falling back to file-based",
            trust_store_type,
        )
        trust_store_path = os.getenv(
            "OID4VC_MDOC_TRUST_ANCHORS_PATH", "/etc/acapy/mdoc/trust-anchors/"
        )
        return FileTrustStore(trust_store_path)


async def on_startup(profile: Profile, event: object):
    """Handle startup event to initialize profile-dependent resources."""
    global _mso_mdoc_processor

    LOGGER.info("MSO_MDOC plugin startup - initializing profile-dependent resources")

    trust_store_type = os.getenv(
        "OID4VC_MDOC_TRUST_STORE_TYPE", TRUST_STORE_TYPE_FILE
    ).lower()

    # If using wallet trust store, initialize it now that we have a profile
    if trust_store_type == TRUST_STORE_TYPE_WALLET and _mso_mdoc_processor is not None:
        trust_store = WalletTrustStore(profile)
        try:
            await trust_store.refresh_cache()
            LOGGER.info("Loaded trust anchors from wallet")
        except Exception as e:
            LOGGER.warning("Failed to load trust anchors from wallet: %s", e)

        # Update the processor with the trust store
        _mso_mdoc_processor.trust_store = trust_store

    # Initialize storage and generate default keys/certs if needed
    try:
        storage_manager = MdocStorageManager(profile)

        # Use a session for storage operations
        async with profile.session() as session:
            # Check if default keys exist
            default_key = await storage_manager.get_default_signing_key(session)
            if not default_key:
                LOGGER.info("No default mDoc keys found, generating new ones...")
                generated = await generate_default_keys_and_certs(
                    storage_manager, session
                )
                LOGGER.info("Generated default mDoc key: %s", generated["key_id"])
            else:
                LOGGER.info(
                    "Using existing default mDoc key: %s",
                    default_key["key_id"],
                )

    except Exception as e:
        LOGGER.error("Failed to initialize mDoc storage: %s", e)
        # Don't fail plugin startup, but log the error


async def setup(context: InjectionContext):
    """Setup the plugin."""
    global _mso_mdoc_processor

    LOGGER.info("Setting up MSO_MDOC plugin")

    # For wallet trust store, we'll initialize the trust store in on_startup
    # For file-based trust store, we can initialize now
    trust_store_type = os.getenv(
        "OID4VC_MDOC_TRUST_STORE_TYPE", TRUST_STORE_TYPE_FILE
    ).lower()

    if trust_store_type == TRUST_STORE_TYPE_WALLET:
        # Defer trust store initialization until startup
        trust_store = None
        LOGGER.info("Wallet-based trust store will be initialized at startup")
    else:
        # File-based trust store can be initialized immediately
        trust_store = create_trust_store()

    # Register credential processor
    processors = context.inject(CredProcessors)
    _mso_mdoc_processor = MsoMdocCredProcessor(trust_store=trust_store)
    processors.register_issuer("mso_mdoc", _mso_mdoc_processor)
    processors.register_cred_verifier("mso_mdoc", _mso_mdoc_processor)
    processors.register_pres_verifier("mso_mdoc", _mso_mdoc_processor)

    # Register startup event handler for profile-dependent initialization
    event_bus = context.inject(EventBus)
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup)
    LOGGER.info("MSO_MDOC plugin registered startup handler")
