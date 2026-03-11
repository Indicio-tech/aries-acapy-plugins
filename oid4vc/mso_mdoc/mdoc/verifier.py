"""Mdoc Verifier — re-exports from focused sub-modules for backward compatibility."""

from oid4vc.cred_processor import VerifyResult  # noqa: F401

from .cred_verifier import (  # noqa: F401
    MsoMdocCredVerifier,
    PreverifiedMdocClaims,
    _extract_mdoc_claims,
    _is_preverified_claims_dict,
    _parse_string_credential,
)
from .pres_verifier import (  # noqa: F401
    MdocVerifyResult,
    MsoMdocPresVerifier,
    extract_mdoc_item_value,
    extract_verified_claims,
    mdoc_verify,
)
from .trust_store import TrustStore, WalletTrustStore  # noqa: F401

__all__ = [
    "MdocVerifyResult",
    "MsoMdocCredVerifier",
    "MsoMdocPresVerifier",
    "PreverifiedMdocClaims",
    "TrustStore",
    "VerifyResult",
    "WalletTrustStore",
    "_extract_mdoc_claims",
    "_is_preverified_claims_dict",
    "_parse_string_credential",
    "extract_mdoc_item_value",
    "extract_verified_claims",
    "mdoc_verify",
]

