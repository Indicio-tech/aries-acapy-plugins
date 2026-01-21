"""Route registration for OID4VC public routes."""

from acapy_agent.config.injection_context import InjectionContext
from aiohttp import web

from ..status_handler import StatusHandler
from .credential import dereference_cred_offer, issue_cred
from .metadata import credential_issuer_metadata
from .notification import receive_notification
from .status_list import get_status_list
from .token import token
from .verification import get_request, post_response


async def register(app: web.Application, multitenant: bool, context: InjectionContext):
    """Register routes with support for multitenant mode.

    Adds the subpath with Wallet ID as a path parameter if multitenant is True.
    """
    subpath = "/tenant/{wallet_id}" if multitenant else ""
    routes = [
        web.get(
            f"{subpath}/oid4vci/dereference-credential-offer",
            dereference_cred_offer,
            allow_head=False,
        ),
        web.get(
            f"{subpath}/.well-known/openid-credential-issuer",
            credential_issuer_metadata,
            allow_head=False,
        ),
        # TODO Add .well-known/did-configuration.json
        # Spec: https://identity.foundation/.well-known/resources/did-configuration/
        web.post(f"{subpath}/token", token),
        web.post(f"{subpath}/notification", receive_notification),
        web.post(f"{subpath}/credential", issue_cred),
        web.get(f"{subpath}/oid4vp/request/{{request_id}}", get_request),
        web.post(f"{subpath}/oid4vp/response/{{presentation_id}}", post_response),
    ]
    # Conditionally add status route
    if context.inject_or(StatusHandler):
        routes.append(
            web.get(
                f"{subpath}/status/{{list_number}}", get_status_list, allow_head=False
            )
        )
    # Add the routes to the application
    app.add_routes(routes)
