"""MSO_MDOC Credential Handler Plugin."""

import logging

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.event_bus import EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import STARTUP_EVENT_PATTERN

from mso_mdoc.cred_processor import MsoMdocCredProcessor
from mso_mdoc.key_generation import generate_default_keys_and_certs
from mso_mdoc.storage import MdocStorageManager
from oid4vc.cred_processor import CredProcessors
from . import routes as routes

LOGGER = logging.getLogger(__name__)


async def on_startup(profile: Profile, event: object):
    """Handle startup event to initialize profile-dependent resources.

    Trust anchors are always wallet-scoped; a fresh WalletTrustStore is
    constructed per-request in verify_credential / verify_presentation so
    each tenant's Askar partition is queried automatically.
    """
    LOGGER.info("MSO_MDOC plugin startup - initializing profile-dependent resources")

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
    LOGGER.info("Setting up MSO_MDOC plugin")

    # Trust anchors are always wallet-scoped.  A fresh WalletTrustStore is
    # constructed per-request inside verify_credential / verify_presentation
    # so each tenant's Askar partition is used automatically.
    # Register credential processor
    processors = context.inject(CredProcessors)
    _mso_mdoc_processor = MsoMdocCredProcessor()
    processors.register_issuer("mso_mdoc", _mso_mdoc_processor)
    processors.register_cred_verifier("mso_mdoc", _mso_mdoc_processor)
    processors.register_pres_verifier("mso_mdoc", _mso_mdoc_processor)

    # Register startup event handler for storage initialization
    event_bus = context.inject(EventBus)
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup)
    LOGGER.info("MSO_MDOC plugin registered startup handler")
