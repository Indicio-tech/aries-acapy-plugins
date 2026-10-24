"""Retrieve configuration values."""

import re
from dataclasses import dataclass
from os import getenv

from acapy_agent.config.base import BaseSettings
from acapy_agent.config.settings import Settings


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            f"Invalid {var} specified for OID4VCI server; use either "
            f"oid4vci.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for OID4VCI Plugin."""

    host: str
    port: int
    endpoint: str
    # OID4VP public endpoint (may differ from OID4VCI endpoint).
    # Reads OID4VP_ENDPOINT env var; falls back to OID4VCI endpoint if not set.
    oid4vp_endpoint: str | None = None
    status_handler: str | None = None
    auth_server_url: str | None = None
    auth_server_client: str | None = None
    # PEM bundle of roots a registered verifier certificate chain must end at.
    verifier_trust_roots: str | None = None

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""
        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("oid4vci")
        host = plugin_settings.get("host") or getenv("OID4VCI_HOST")
        port = int(plugin_settings.get("port") or getenv("OID4VCI_PORT", "0"))
        # Prefer environment variable for endpoint to allow tests and deployments
        # to override any static plugin configuration. This ensures the
        # credential_issuer matches the intended OID4VCI base URL.
        endpoint = getenv("OID4VCI_ENDPOINT") or plugin_settings.get("endpoint")
        # OID4VP endpoint may differ (e.g., behind a separate TLS proxy).
        oid4vp_endpoint = getenv("OID4VP_ENDPOINT") or None
        status_handler = plugin_settings.get("status_handler") or getenv(
            "OID4VCI_STATUS_HANDLER"
        )
        auth_server_url = plugin_settings.get("auth_server_url") or getenv(
            "OID4VCI_AUTH_SERVER_URL"
        )
        auth_server_client = plugin_settings.get("auth_server_client") or getenv(
            "OID4VCI_AUTH_SERVER_CLIENT"
        )
        verifier_trust_roots = plugin_settings.get("verifier_trust_roots") or getenv(
            "OID4VP_VERIFIER_TRUST_ROOTS"
        )
        if not host:
            raise ConfigError("host", "OID4VCI_HOST")
        if not port:
            raise ConfigError("port", "OID4VCI_PORT")
        if not endpoint:
            raise ConfigError("endpoint", "OID4VCI_ENDPOINT")

        # Expand environment variables in endpoint if needed
        # Handle ${VAR:-default} format
        def expand_vars(text):
            def replacer(match):
                var_expr = match.group(1)
                if ":-" in var_expr:
                    var_name, default_value = var_expr.split(":-", 1)
                    return getenv(var_name.strip(), default_value.strip())
                else:
                    return getenv(var_expr.strip(), match.group(0))

            return re.sub(r"\$\{([^}]+)\}", replacer, text)

        endpoint = expand_vars(endpoint)

        return cls(
            host,
            port,
            endpoint,
            oid4vp_endpoint=oid4vp_endpoint,
            status_handler=status_handler,
            auth_server_url=auth_server_url,
            auth_server_client=auth_server_client,
            verifier_trust_roots=verifier_trust_roots,
        )


def oid4vp_response_uri(settings: BaseSettings, presentation_id: str) -> str:
    """Return the response_uri that a request object for this presentation carries.

    The request object and the verification of the response (for example the
    mdoc session transcript) must use the same value, so both build it here.
    """
    config = Config.from_settings(settings)
    wallet_id = settings.get("wallet.id") if settings.get("multitenant.enabled") else None
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    # OID4VP_ENDPOINT may differ from the OID4VCI endpoint (e.g. a separate proxy).
    oid4vp_base = config.oid4vp_endpoint or config.endpoint
    return f"{oid4vp_base}{subpath}/oid4vp/response/{presentation_id}"
