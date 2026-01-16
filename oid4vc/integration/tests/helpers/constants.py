"""Constants used across OID4VC integration tests."""

import os
from enum import Enum
from typing import Final


# MDOC availability check
try:
    import isomdl_uniffi as mdl

    MDOC_AVAILABLE = True
except ImportError:
    if os.getenv("REQUIRE_MDOC", "false").lower() == "true":
        raise ImportError("isomdl_uniffi is required but not installed")
    MDOC_AVAILABLE = False
    mdl = None


# Test configuration
TEST_CONFIG = {
    "oid4vci_endpoint": os.getenv("OID4VCI_ENDPOINT", "http://issuer:3000"),
    "admin_endpoint": os.getenv("ADMIN_ENDPOINT", "http://issuer:3001"),
    "test_timeout": int(os.getenv("TEST_TIMEOUT", "30")),
    "test_data_dir": os.getenv("TEST_DATA_DIR", "test_data"),
    "results_dir": os.getenv("RESULTS_DIR", "test_results"),
}


class CredentialFormat(str, Enum):
    """Credential format identifiers."""

    SD_JWT = "vc+sd-jwt"
    JWT_VC = "jwt_vc_json"
    MDOC = "mso_mdoc"


class Doctype:
    """ISO mDOC doctype constants."""

    MDL: Final[str] = "org.iso.18013.5.1.mDL"
    MDL_NAMESPACE: Final[str] = "org.iso.18013.5.1"


class VCT:
    """Verifiable Credential Type (vct) URIs."""

    IDENTITY: Final[str] = "https://credentials.example.com/identity_credential"
    ADDRESS: Final[str] = "https://credentials.example.com/address_credential"
    EDUCATION: Final[str] = "https://credentials.example.com/education_credential"
    EMPLOYMENT: Final[str] = "https://credentials.example.com/employment_credential"
    
    # DCQL test VCTs
    DCQL_TEST: Final[str] = "https://credentials.example.com/dcql_test_credential"
    DCQL_IDENTITY: Final[str] = "https://credentials.example.com/dcql_identity"
    DCQL_ADDRESS: Final[str] = "https://credentials.example.com/dcql_address"


class ALGORITHMS:
    """Cryptographic algorithm constants."""

    # Signature algorithms
    ED25519: Final[str] = "EdDSA"
    ES256: Final[str] = "ES256"
    ES384: Final[str] = "ES384"
    
    # Common algorithm lists
    SD_JWT_ALGS: Final[list[str]] = ["EdDSA", "ES256"]
    JWT_VC_ALGS: Final[list[str]] = ["ES256"]
    MDOC_ALGS: Final[list[str]] = ["ES256"]


class CLAIM_PATHS:
    """Common claim path patterns for presentation definitions."""

    # Identity claims
    GIVEN_NAME: Final[list[str]] = ["$.given_name", "$.credentialSubject.given_name"]
    FAMILY_NAME: Final[list[str]] = ["$.family_name", "$.credentialSubject.family_name"]
    BIRTH_DATE: Final[list[str]] = ["$.birth_date", "$.credentialSubject.birth_date"]
    EMAIL: Final[list[str]] = ["$.email", "$.credentialSubject.email"]
    
    # Address claims
    STREET_ADDRESS: Final[list[str]] = ["$.street_address", "$.credentialSubject.street_address"]
    LOCALITY: Final[list[str]] = ["$.locality", "$.credentialSubject.locality"]
    POSTAL_CODE: Final[list[str]] = ["$.postal_code", "$.credentialSubject.postal_code"]
    COUNTRY: Final[list[str]] = ["$.country", "$.credentialSubject.country"]
    
    # Type/VCT paths
    VCT_PATH: Final[list[str]] = ["$.vct", "$.type"]
    TYPE_PATH: Final[list[str]] = ["$.type", "$.vc.type"]


# Endpoint configuration (from environment)
class ENDPOINTS:
    """Service endpoint URLs - typically loaded from environment."""
    # These are defaults; tests should use fixtures that read from environment
    pass


# Timeouts
DEFAULT_TIMEOUT: Final[int] = 30
VALIDATION_POLL_INTERVAL: Final[float] = 0.5
VALIDATION_MAX_ATTEMPTS: Final[int] = 20
