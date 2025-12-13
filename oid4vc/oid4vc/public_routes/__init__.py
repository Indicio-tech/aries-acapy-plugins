"""Public routes for OID4VC.

This package contains the public-facing HTTP routes for OID4VCI (credential issuance)
and OID4VP (verifiable presentations).
"""

from acapy_agent.config.injection_context import InjectionContext
from aiohttp import web

from ..did_utils import retrieve_or_create_did_jwk
from ..models.supported_cred import SupportedCredential
from ..pop_result import PopResult
from ..status_handler import StatusHandler
from .constants import (
    EXPIRES_IN,
    LOGGER,
    NONCE_BYTES,
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
)
from .credential import (
    IssueCredentialRequestSchema,
    NotificationSchema,
    create_nonce,
    dereference_cred_offer,
    get_nonce,
    issue_cred,
    receive_notification,
    types_are_subset,
)
from .metadata import (
    BatchCredentialIssuanceSchema,
    CredentialIssuerMetadataSchema,
    OpenIDConfigurationSchema,
    credential_issuer_metadata,
    credential_issuer_metadata_deprecated,
    deprecated_credential_issuer_metadata,
    openid_configuration,
)
from .presentation import (
    OID4VPPresentationIDMatchSchema,
    OID4VPRequestIDMatchSchema,
    PostOID4VPResponseSchema,
    get_request,
    post_response,
    verify_dcql_presentation,
    verify_pres_def_presentation,
)
from .proof import (
    handle_proof_of_posession,
)
from .status import (
    StatusListMatchSchema,
    get_status_list,
)
from .token import (
    GetTokenSchema,
    check_token,
    token,
)

# Re-export for backward compatibility
__all__ = [
    # Constants
    "EXPIRES_IN",
    "LOGGER",
    "NONCE_BYTES",
    "PRE_AUTHORIZED_CODE_GRANT_TYPE",
    # Token
    "GetTokenSchema",
    "check_token",
    "token",
    # Metadata
    "BatchCredentialIssuanceSchema",
    "CredentialIssuerMetadataSchema",
    "OpenIDConfigurationSchema",
    "credential_issuer_metadata",
    "credential_issuer_metadata_deprecated",
    "deprecated_credential_issuer_metadata",
    "openid_configuration",
    # Credential
    "NotificationSchema",
    "IssueCredentialRequestSchema",
    "create_nonce",
    "dereference_cred_offer",
    "get_nonce",
    "issue_cred",
    "receive_notification",
    "types_are_subset",
    # Proof
    "handle_proof_of_posession",
    # Presentation
    "OID4VPPresentationIDMatchSchema",
    "OID4VPRequestIDMatchSchema",
    "PostOID4VPResponseSchema",
    "get_request",
    "post_response",
    "verify_dcql_presentation",
    "verify_pres_def_presentation",
    # Status
    "StatusListMatchSchema",
    "get_status_list",
    # Registration
    "register",
    # Backward compatibility re-exports
    "PopResult",
    "retrieve_or_create_did_jwk",
    "SupportedCredential",
]


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
        web.get(
            f"{subpath}/.well-known/openid_credential_issuer",
            deprecated_credential_issuer_metadata,
            allow_head=False,
        ),
        web.get(
            f"{subpath}/.well-known/openid-configuration",
            openid_configuration,
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

    # Add v1 routes
    v1_subpath = f"{subpath}/v1"
    routes.extend(
        [
            web.get(
                f"{v1_subpath}/oid4vci/dereference-credential-offer",
                dereference_cred_offer,
                allow_head=False,
            ),
            web.get(
                f"{v1_subpath}/.well-known/openid-credential-issuer",
                credential_issuer_metadata,
                allow_head=False,
            ),
            web.get(
                f"{v1_subpath}/.well-known/openid-configuration",
                openid_configuration,
                allow_head=False,
            ),
            web.post(f"{v1_subpath}/token", token),
            web.post(f"{v1_subpath}/notification", receive_notification),
            web.post(f"{v1_subpath}/credential", issue_cred),
            web.get(f"{v1_subpath}/oid4vp/request/{{request_id}}", get_request),
            web.post(
                f"{v1_subpath}/oid4vp/response/{{presentation_id}}", post_response
            ),
        ]
    )

    # Conditionally add status route
    if context.inject_or(StatusHandler):
        routes.append(
            web.get(
                f"{subpath}/status/{{list_number}}", get_status_list, allow_head=False
            )
        )
        routes.append(
            web.get(
                f"{v1_subpath}/status/{{list_number}}",
                get_status_list,
                allow_head=False,
            )
        )
    # Add the routes to the application
    app.add_routes(routes)
