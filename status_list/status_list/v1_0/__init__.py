"""Status List Plugin v1.0."""

import logging

from acapy_agent.admin.base_server import BaseAdminServer
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import STARTUP_EVENT_PATTERN

from . import routes

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.info("> status_list plugin setup...")

    admin_server = context.inject_or(BaseAdminServer)
    if admin_server:
        await routes.register(admin_server.app)

    LOGGER.info("< status_list plugin setup.")


# async def on_startup(profile: Profile, event: Event):
#     """Handle startup event."""
#     LOGGER.info("> status_list on_startup")

#     admin_server = profile.context.inject(BaseAdminServer)
#     if admin_server:
#         await routes.register(admin_server.app)

#     LOGGER.info("< status_list on_startup")
