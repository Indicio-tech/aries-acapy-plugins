"""Test configuration and shared data for OID4VCI 1.0 compliance tests."""

import os
from pathlib import Path

# Base test configuration
TEST_CONFIG = {
    "oid4vci_endpoint": os.getenv("ACAPY_ISSUER_OID4VCI_URL", "http://localhost:8022"),
    "admin_endpoint": os.getenv("ACAPY_ISSUER_ADMIN_URL", "http://localhost:8021"),
    "test_timeout": 60,
    "test_data_dir": Path(__file__).parent / "data",
    "results_dir": Path(__file__).parent.parent / "test-results",
}

# OID4VCI 1.0 test data
OID4VCI_TEST_DATA = {
    "supported_credential": {
        "id": "UniversityDegree-1.0",
        "format": "jwt_vc_json",
        "identifier": "UniversityDegreeCredential",
        "cryptographic_binding_methods_supported": ["did:key", "did:jwk"],
        "cryptographic_suites_supported": ["ES256", "ES384", "ES512"],
        "display": [
            {
                "name": "University Degree",
                "locale": "en-US",
                "background_color": "#1e3a8a",
                "text_color": "#ffffff"
            }
        ],
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ]
    },
    "credential_subject": {
        "given_name": "John",
        "family_name": "Doe",
        "birth_date": "1990-01-01",
        "issue_date": "2023-01-01",
        "expiry_date": "2033-01-01",
        "issuing_country": "US",
        "issuing_authority": "DMV",
        "document_number": "12345678"
    },
    "test_jwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
    }
}

# Test data for OID4VCI 1.0 compliance
SUPPORTED_CREDENTIAL_CONFIG = {
    "id": "UniversityDegree-1.0",
    "format": "jwt_vc_json",
    "identifier": "UniversityDegreeCredential",
    "cryptographic_binding_methods_supported": ["did:key", "did:jwk"],
    "cryptographic_suites_supported": ["ES256", "ES384", "ES512"],
    "display": [
        {
            "name": "University Degree",
            "locale": "en-US",
            "logo": {
                "url": "https://example.com/logo.png",
                "alt_text": "University Logo"
            },
            "background_color": "#1e3a8a",
            "text_color": "#ffffff"
        }
    ],
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
    ]
}

CREDENTIAL_SUBJECT_DATA = {
    "given_name": "John",
    "family_name": "Doe",
    "birth_date": "1990-01-01",
    "issue_date": "2023-01-01",
    "expiry_date": "2033-01-01",
    "issuing_country": "US",
    "issuing_authority": "DMV",
    "document_number": "12345678",
    "driving_privileges": [
        {
            "vehicle_category_code": "A",
            "issue_date": "2023-01-01",
            "expiry_date": "2033-01-01"
        }
    ]
}

# mso_mdoc credential configuration for ISO 18013-5 Mobile Driver's License
MSO_MDOC_CREDENTIAL_CONFIG = {
    "id": "mDL-1.0",
    "format": "mso_mdoc",
    "identifier": "org.iso.18013.5.1.mDL",
    "doctype": "org.iso.18013.5.1.mDL",
    "cryptographic_binding_methods_supported": ["cose_key"],
    "cryptographic_suites_supported": ["ES256", "ES384", "ES512"],
    "display": [
        {
            "name": "Mobile Driver's License",
            "locale": "en-US",
            "logo": {
                "url": "https://example.com/mdl-logo.png",
                "alt_text": "mDL Logo"
            },
            "background_color": "#003f7f",
            "text_color": "#ffffff"
        }
    ],
    "claims": {
        "org.iso.18013.5.1": {
            "given_name": {
                "mandatory": True,
                "display": [{"name": "Given Name", "locale": "en-US"}]
            },
            "family_name": {
                "mandatory": True,
                "display": [{"name": "Family Name", "locale": "en-US"}]
            },
            "birth_date": {
                "mandatory": True,
                "display": [{"name": "Date of Birth", "locale": "en-US"}]
            },
            "issue_date": {
                "mandatory": True,
                "display": [{"name": "Issue Date", "locale": "en-US"}]
            },
            "expiry_date": {
                "mandatory": True,
                "display": [{"name": "Expiry Date", "locale": "en-US"}]
            },
            "issuing_country": {
                "mandatory": True,
                "display": [{"name": "Issuing Country", "locale": "en-US"}]
            },
            "document_number": {
                "mandatory": True,
                "display": [{"name": "Document Number", "locale": "en-US"}]
            }
        }
    }
}

# Import mdoc capabilities
try:
    import isomdl_uniffi as mdl
    MDOC_AVAILABLE = True
except ImportError:
    MDOC_AVAILABLE = False
    mdl = None

# Expected OID4VCI 1.0 compliance requirements
COMPLIANCE_REQUIREMENTS = {
    "metadata_endpoint": {
        "required_fields": [
            "credential_issuer",
            "credential_endpoint",
            "credential_configurations_supported"
        ],
        "format_requirements": {
            # Must be object in OID4VCI 1.0
            "credential_configurations_supported": "object"
        }
    },
    "credential_request": {
        "mutual_exclusion": ["credential_identifier", "format"],
        "required_proof_type": "openid4vci-proof+jwt"
    },
    "mso_mdoc": {
        "required_parameters": ["doctype"],
        "format": "mso_mdoc"
    }
}
