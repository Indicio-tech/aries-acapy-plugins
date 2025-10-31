"""Retrieve configuration values."""

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

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""
        import re

        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("oid4vci")
        host = plugin_settings.get("host") or getenv("OID4VCI_HOST")
        port = int(plugin_settings.get("port") or getenv("OID4VCI_PORT", "0"))
        # Prefer environment variable for endpoint to allow tests and deployments
        # to override any static plugin configuration. This ensures the
        # credential_issuer matches the intended OID4VCI base URL.
        endpoint = getenv("OID4VCI_ENDPOINT") or plugin_settings.get("endpoint")

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

        return cls(host, port, endpoint)
