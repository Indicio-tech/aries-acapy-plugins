"""MSO_MDOC Credential Handler Plugin."""

import logging
import os

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from mso_mdoc.cred_processor import MsoMdocCredProcessor
from mso_mdoc.key_generation import generate_default_keys_and_certs
from mso_mdoc.mdoc.verifier import FileTrustStore
from mso_mdoc.storage import MdocStorageManager

from oid4vc.cred_processor import CredProcessors

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.info("Setting up MSO_MDOC plugin")

    # Configure trust store
    trust_store_path = os.getenv(
        "OID4VC_MDOC_TRUST_ANCHORS_PATH", "/etc/acapy/mdoc/trust-anchors/"
    )
    trust_store = FileTrustStore(trust_store_path)

    # Register credential processor
    processors = context.inject(CredProcessors)
    mso_mdoc = MsoMdocCredProcessor(trust_store=trust_store)
    processors.register_issuer("mso_mdoc", mso_mdoc)
    processors.register_cred_verifier("mso_mdoc", mso_mdoc)
    processors.register_pres_verifier("mso_mdoc", mso_mdoc)

    # Initialize storage and generate default keys/certs if needed
    try:
        # Get profile from context
        profile = context.inject(Profile)
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
        # Don't fail plugin setup, but log the error
        pass
