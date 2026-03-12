"""Constants for public routes (OID4VCI token endpoint)."""

import logging

LOGGER = logging.getLogger(__name__)

# OAuth 2.0 grant type for pre-authorized code flow
# https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow
PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

# Number of random bytes for nonce generation
NONCE_BYTES = 16

# Token expiration time in seconds (24 hours)
EXPIRES_IN = 86400

# Maximum age (seconds) allowed for a DPoP proof iat claim relative to server clock.
# RFC 9449 §4.3 requires servers to check that the DPoP proof was created recently to
# prevent replay outside the accepted time window.  60 seconds is a common choice.
DPOP_PROOF_MAX_AGE_SECONDS = 60
