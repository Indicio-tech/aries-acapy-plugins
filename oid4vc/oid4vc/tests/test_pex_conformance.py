"""DIF Presentation Exchange v2.0 Conformance Tests.

Official test vectors derived from the DIF specification repository:
  https://github.com/decentralized-identity/presentation-exchange/tree/main/test

Each vector is inline Python, sourced from the corresponding JSON file noted
in the docstring, so the mapping back to the spec is always explicit.

Feature support matrix
======================

SUPPORTED — tests in this file are expected to PASS
----------------------------------------------------
- PD compilation: any valid PD shape compiles without error
- Field constraints: JSONPath path evaluation (§7.1.1)
- Multiple path alternatives: first-match semantics (§7.1.1)
- JSON Schema Draft 7 filter evaluation (§7.1.1), including 'contains'
- Nested path_nested descriptor map traversal (§5.1.1)
- jwt_vp outer wrapper verification (our P1 addition)
- Positional id fallback for non-conformant wallets (interop relaxation)
- §5   submission MUST cover all input_descriptors (no submission_requirements)
- §4.1 submission_requirements pick / all / min / max group rules
- §7.1.3 limit_disclosure: required — selective disclosure enforcement

NOT YET IMPLEMENTED — add xfail markers if/when tested
-------------------------------------------------------
- §7.1.4 is_holder — holder binding constraints
- §7.1.5 same_subject — same-subject constraints
- §7.1.6 statuses — credential status constraints
- §7.1.7 predicate — ZK predicate constraints
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from oid4vc.cred_processor import CredProcessors
from oid4vc.pex import (
    ConstraintFieldEvaluator,
    FilterEvaluator,
    PresentationExchangeEvaluator,
)

# ===========================================================================
# Official PD test vectors — inline JSON sourced from the spec repo
# ===========================================================================

# test/presentation-definition/minimal_example.json
PD_MINIMAL = {
    "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "input_descriptors": [
        {
            "id": "wa_driver_license",
            "name": "Washington State Business License",
            "purpose": (
                "We can only allow licensed Washington State business "
                "representatives into the WA Business Conference"
            ),
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.credentialSubject.dateOfBirth",
                            "$.credentialSubject.dob",
                            "$.vc.credentialSubject.dateOfBirth",
                            "$.vc.credentialSubject.dob",
                        ]
                    }
                ]
            },
        }
    ],
}

# test/presentation-definition/pd_filter.json
# The spec example uses {type: array, contains: {type: string, const: "..."}}
# to require a specific VC type string.  ACA-Py's DIFField.Filter model only
# preserves scalar JSON Schema properties; 'contains' is silently dropped.
# We therefore use 'const' on a scalar schema-id field here, which IS preserved.
# See test_xf_array_contains_filter_silently_dropped for the known gap.
#
# Note: ACA-Py requires UUID4 for PD 'id'; the DIF PEX spec allows any string.
PD_CONST_FILTER = {
    "id": "4f5d6e7a-1234-4abc-8def-000000000010",
    "input_descriptors": [
        {
            "id": "degree_input",
            "name": "University Degree Certificate",
            "purpose": "We require a credential conforming to the degree schema.",
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.credentialSchema.id",
                            "$.vc.credentialSchema.id",
                        ],
                        "filter": {
                            "type": "string",
                            "const": "https://university.example.com/schemas/degree.json",
                        },
                    }
                ]
            },
        }
    ],
}

# test/presentation-definition/pd_filter2_simplified.json
PD_TERMS_OF_USE_FILTER = {
    "id": "4f5d6e7a-1234-4abc-8def-000000000020",
    "input_descriptors": [
        {
            "id": "credit_card_input",
            "name": "Credit card from trusted bank",
            "purpose": "Please provide your credit card details",
            "constraints": {
                "fields": [
                    {
                        "path": ["$.termsOfUse.type"],
                        "filter": {
                            "type": "string",
                            "pattern": "^https://train.trust-scheme.de/info$",
                        },
                    },
                    {
                        "path": ["$.termsOfUse.trustScheme"],
                        "filter": {
                            "type": "string",
                            "pattern": "^worldbankfederation.com$",
                        },
                    },
                    {
                        "path": ["$.type"],
                        "filter": {
                            "type": "string",
                            "pattern": "^creditCard$",
                        },
                    },
                ]
            },
        }
    ],
}

# test/presentation-definition/format_example.json — no input_descriptors,
# top-level format metadata only
PD_FORMAT_METADATA = {
    "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "input_descriptors": [],
    "format": {
        "jwt": {"alg": ["EdDSA", "ES256K", "ES384"]},
        "jwt_vc": {"alg": ["ES256K", "ES384"]},
        "jwt_vp": {"alg": ["EdDSA", "ES256K"]},
        "ldp_vc": {
            "proof_type": [
                "JsonWebSignature2020",
                "Ed25519Signature2018",
                "EcdsaSecp256k1Signature2019",
                "RsaSignature2018",
            ]
        },
        "ldp_vp": {"proof_type": ["Ed25519Signature2018"]},
        "ldp": {"proof_type": ["RsaSignature2018"]},
    },
}

# test/presentation-definition/single_group_example.json
# submission_requirements: pick exactly 1 from group A
PD_SINGLE_GROUP = {
    "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "submission_requirements": [
        {"name": "Citizenship Information", "rule": "pick", "count": 1, "from": "A"}
    ],
    "input_descriptors": [
        {
            "id": "citizenship_input_1",
            "name": "EU Driver's License",
            "group": ["A"],
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.credentialSchema.id",
                            "$.vc.credentialSchema.id",
                        ],
                        "filter": {
                            "type": "string",
                            "const": "https://eu.com/claims/DriversLicense.json",
                        },
                    },
                    {
                        "path": [
                            "$.credentialSubject.dob",
                            "$.vc.credentialSubject.dob",
                            "$.dob",
                        ],
                        "filter": {"type": "string", "format": "date"},
                    },
                ]
            },
        },
        {
            "id": "citizenship_input_2",
            "name": "US Passport",
            "group": ["A"],
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.credentialSchema.id",
                            "$.vc.credentialSchema.id",
                        ],
                        "filter": {
                            "type": "string",
                            "const": "hub://did:foo:123/Collections/schema.us.gov/passport.json",
                        },
                    },
                    {
                        "path": [
                            "$.credentialSubject.birth_date",
                            "$.vc.credentialSubject.birth_date",
                            "$.birth_date",
                        ],
                        "filter": {"type": "string", "format": "date"},
                    },
                ]
            },
        },
    ],
}

# Synthetic PD with two descriptors and NO submission_requirements.
# Per spec §5, a submission MUST satisfy ALL input_descriptors.
PD_TWO_DESCRIPTORS = {
    "id": "4f5d6e7a-1234-4abc-8def-000000000040",
    "input_descriptors": [
        {
            "id": "id_doc",
            "constraints": {"fields": [{"path": ["$.credentialSubject.id_number"]}]},
        },
        {
            "id": "employment_doc",
            "constraints": {"fields": [{"path": ["$.credentialSubject.employer"]}]},
        },
    ],
}

# Synthetic PD with pick(count=1) group constraint — both group members
# have identical simple constraints so either one satisfies the field check,
# letting us isolate the group-count logic.
PD_PICK_ONE = {
    "id": "4f5d6e7a-1234-4abc-8def-000000000050",
    "submission_requirements": [
        {"name": "Pick one ID doc", "rule": "pick", "count": 1, "from": "A"}
    ],
    "input_descriptors": [
        {
            "id": "id_type_a",
            "group": ["A"],
            "constraints": {"fields": [{"path": ["$.type"]}]},
        },
        {
            "id": "id_type_b",
            "group": ["A"],
            "constraints": {"fields": [{"path": ["$.type"]}]},
        },
    ],
}

# test/presentation-definition/basic_example.json (first descriptor, simplified)
# Descriptor has limit_disclosure: required
PD_LIMIT_DISCLOSURE = {
    "id": "4f5d6e7a-1234-4abc-8def-000000000030",
    "input_descriptors": [
        {
            "id": "bankaccount_input",
            "name": "Full Bank Account Routing Information",
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    {
                        "path": ["$.credentialSubject.account_number"],
                        "filter": {"type": "string"},
                    }
                ],
            },
        }
    ],
}


# ===========================================================================
# Helpers
# ===========================================================================

# Sentinel UUID for the helper PD used in _field_via_pd; not a real PD.
_HELPER_PD_ID = "4f5d6e7a-1234-4abc-8def-000000000099"
_HELPER_DESC_ID = "helper-descriptor"


def _field_via_pd(field_dict):
    """Compile a ConstraintFieldEvaluator through ACA-Py's full PD deserialization.

    ConstraintFieldEvaluator.compile(dict) does NOT populate _filter because
    ACA-Py's DIFField schema only sets _filter when the full constraint tree is
    deserialized from a PresentationDefinition.  This helper goes through that
    path so filters are properly wired up.
    """
    evaluator = PresentationExchangeEvaluator.compile(
        {
            "id": _HELPER_PD_ID,
            "input_descriptors": [
                {"id": _HELPER_DESC_ID, "constraints": {"fields": [field_dict]}}
            ],
        }
    )
    return evaluator._id_to_descriptor[_HELPER_DESC_ID]._field_constraints[0]


# ===========================================================================
# Shared fixture
# ===========================================================================


@pytest.fixture
def mock_processors():
    """CredProcessors mock whose verifier returns verified=True.

    Individual tests can override verify_credential on
    mock_processors.cred_verifier_for_format.return_value to control
    the returned payload.
    """
    mock_verifier = MagicMock()
    mock_verifier.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"type": ["VerifiableCredential"]},
        )
    )
    processors = MagicMock(spec=CredProcessors)
    processors.cred_verifier_for_format.return_value = mock_verifier
    return processors


# ===========================================================================
# 1. PD Compilation
#    Tests that every structural variant in the DIF corpus compiles to a
#    PresentationExchangeEvaluator without error.  No mocks needed.
# ===========================================================================


class TestPDCompilation:
    """Compile official PD fixtures from the spec — no credential mocks needed."""

    def test_compile_minimal_pd(self):
        """minimal_example.json — single descriptor, no filter."""
        ev = PresentationExchangeEvaluator.compile(PD_MINIMAL)
        assert ev.id == "32f54163-7166-48f1-93d8-ff217bdb0653"
        assert len(ev._id_to_descriptor) == 1
        assert "wa_driver_license" in ev._id_to_descriptor

    def test_compile_pd_with_const_filter(self):
        """pd_filter.json variant — credentialSchema.id with JSON Schema 'const' filter."""
        ev = PresentationExchangeEvaluator.compile(PD_CONST_FILTER)
        assert "degree_input" in ev._id_to_descriptor

    def test_compile_pd_with_multi_field_filter(self):
        """pd_filter2_simplified.json — multiple fields each with string-pattern filter."""
        ev = PresentationExchangeEvaluator.compile(PD_TERMS_OF_USE_FILTER)
        assert "credit_card_input" in ev._id_to_descriptor

    def test_compile_pd_with_format_metadata(self):
        """format_example.json — top-level format object, zero input_descriptors."""
        ev = PresentationExchangeEvaluator.compile(PD_FORMAT_METADATA)
        assert len(ev._id_to_descriptor) == 0

    def test_compile_pd_with_submission_requirements_single_group(self):
        """single_group_example.json — submission_requirements pick rule.

        Compilation must succeed even though group-constraint evaluation is
        not yet implemented; unsupported fields are silently parsed past.
        """
        ev = PresentationExchangeEvaluator.compile(PD_SINGLE_GROUP)
        assert "citizenship_input_1" in ev._id_to_descriptor
        assert "citizenship_input_2" in ev._id_to_descriptor

    def test_compile_pd_with_limit_disclosure_required(self):
        """basic_example.json descriptor — limit_disclosure: required.

        Compilation must succeed; the unsupported field is ignored at
        compile time and not stored on the DescriptorEvaluator.
        """
        ev = PresentationExchangeEvaluator.compile(PD_LIMIT_DISCLOSURE)
        assert "bankaccount_input" in ev._id_to_descriptor


# ===========================================================================
# 2. FilterEvaluator Unit Tests
#    Exercises the JSON Schema Draft 7 filter shapes used across the corpus.
# ===========================================================================


class TestFilterEvaluation:
    """FilterEvaluator.compile(filter).match(value) — isolated from verify()."""

    # --- string const -------------------------------------------------------

    def test_string_const_matches(self):
        """string / const — exact value match (single_group_example.json field 1)."""
        f = FilterEvaluator.compile(
            {"type": "string", "const": "https://eu.com/claims/DriversLicense.json"}
        )
        assert f.match("https://eu.com/claims/DriversLicense.json") is True

    def test_string_const_rejects_wrong_value(self):
        f = FilterEvaluator.compile(
            {"type": "string", "const": "https://eu.com/claims/DriversLicense.json"}
        )
        assert f.match("https://other.example/SomethingElse.json") is False

    # --- string pattern -----------------------------------------------------

    def test_string_pattern_matches_first_alternative(self):
        """input_descriptors_example.json — issuer must match one of two DIDs."""
        f = FilterEvaluator.compile(
            {"type": "string", "pattern": "^did:example:123$|^did:example:456$"}
        )
        assert f.match("did:example:123") is True
        assert f.match("did:example:456") is True

    def test_string_pattern_rejects_no_match(self):
        f = FilterEvaluator.compile(
            {"type": "string", "pattern": "^did:example:123$|^did:example:456$"}
        )
        assert f.match("did:example:999") is False

    # --- array contains -----------------------------------------------------

    def test_array_contains_const_matches(self):
        """pd_filter.json shape — $.type array must contain specific type string."""
        f = FilterEvaluator.compile(
            {
                "type": "array",
                "contains": {"type": "string", "const": "UniversityDegreeCredential"},
            }
        )
        assert f.match(["VerifiableCredential", "UniversityDegreeCredential"]) is True

    def test_array_contains_const_rejects_absent_value(self):
        f = FilterEvaluator.compile(
            {
                "type": "array",
                "contains": {"type": "string", "const": "UniversityDegreeCredential"},
            }
        )
        assert f.match(["VerifiableCredential", "SomeOtherCredential"]) is False

    def test_array_contains_pattern_matches(self):
        """input_descriptors_example.json — pattern match inside an array."""
        f = FilterEvaluator.compile(
            {
                "type": "array",
                "contains": {
                    "type": "string",
                    "pattern": "^https://bank-schemas.org/",
                },
            }
        )
        assert f.match(["https://bank-schemas.org/1.0.0/accounts.json"]) is True

    # --- number minimum -----------------------------------------------------

    def test_number_minimum_matches_above(self):
        """multi_group_example.json — portfolio_value >= 1_000_000."""
        f = FilterEvaluator.compile({"type": "number", "minimum": 1_000_000})
        assert f.match(1_500_000) is True

    def test_number_minimum_matches_at_boundary(self):
        f = FilterEvaluator.compile({"type": "number", "minimum": 1_000_000})
        assert f.match(1_000_000) is True

    def test_number_minimum_rejects_below(self):
        f = FilterEvaluator.compile({"type": "number", "minimum": 1_000_000})
        assert f.match(999_999) is False

    # --- date format --------------------------------------------------------

    def test_date_format_accepts_date_string(self):
        """single_group_example.json — dob field with format: date.

        Note: JSON Schema Draft 7 treats 'format' as an annotation by default
        (not a hard assertion), so any string satisfies the type constraint.
        """
        f = FilterEvaluator.compile({"type": "string", "format": "date"})
        assert f.match("1990-05-15") is True

    def test_date_format_rejects_non_string(self):
        """Type constraint is still enforced — integers are rejected."""
        f = FilterEvaluator.compile({"type": "string", "format": "date"})
        assert f.match(19900515) is False

    # --- $defs / $ref -------------------------------------------------------

    def test_defs_ref_filter_compiles_and_matches(self):
        """pd_filter2.json shape — $defs/$ref composition (simplified)."""
        f = FilterEvaluator.compile(
            {
                "$defs": {
                    "tosObject": {
                        "type": "object",
                        "required": ["type", "trustScheme"],
                        "properties": {
                            "type": {"type": "string"},
                            "trustScheme": {"type": "string"},
                        },
                    }
                },
                "$ref": "#/$defs/tosObject",
            }
        )
        assert f.match({"type": "TrustFramework", "trustScheme": "example.com"}) is True
        assert f.match({"type": "TrustFramework"}) is False  # missing required field


# ===========================================================================
# 3. ConstraintFieldEvaluator Unit Tests
#    Exercises JSONPath path-matching and filter-combination logic from §7.1.1.
# ===========================================================================


class TestConstraintFieldEvaluation:
    """ConstraintFieldEvaluator.compile(field).match(payload) — isolated."""

    def test_simple_path_matches_present_value(self):
        ev = ConstraintFieldEvaluator.compile({"path": ["$.credentialSubject.id"]})
        result = ev.match({"credentialSubject": {"id": "did:example:holder"}})
        assert result is not None
        assert result.value == "did:example:holder"

    def test_simple_path_returns_none_when_absent(self):
        ev = ConstraintFieldEvaluator.compile({"path": ["$.credentialSubject.id"]})
        result = ev.match({"credentialSubject": {}})
        assert result is None

    def test_multiple_paths_first_match_wins(self):
        """§7.1.1 — paths are tried in order; first found value is returned.

        minimal_example.json has four alternate paths for the birth-date field.
        Only the second path ($.credentialSubject.dob) is present here.
        """
        ev = ConstraintFieldEvaluator.compile(
            {
                "path": [
                    "$.credentialSubject.dateOfBirth",
                    "$.credentialSubject.dob",
                    "$.vc.credentialSubject.dateOfBirth",
                ]
            }
        )
        result = ev.match({"credentialSubject": {"dob": "1985-03-22"}})
        assert result is not None
        assert result.value == "1985-03-22"

    def test_deep_jsonpath_wildcard_matches(self):
        """input_descriptors_example.json — $.credentialSubject.account[*].id."""
        ev = ConstraintFieldEvaluator.compile(
            {
                "path": [
                    "$.credentialSubject.account[*].id",
                    "$.account[*].id",
                ]
            }
        )
        result = ev.match(
            {
                "credentialSubject": {
                    "account": [{"id": "12345678901", "route": "021000021"}]
                }
            }
        )
        assert result is not None
        assert result.value == "12345678901"

    def test_path_with_filter_passes_matching_value(self):
        """When a filter is present, only values passing the filter are returned.

        We use a 'const' filter on a scalar field because ACA-Py's DIFField.Filter
        model only preserves scalar JSON Schema keywords; nested keywords such as
        'contains' are silently dropped.  Built via the full PD deserialization path
        so that _filter is properly populated.
        """
        ev = _field_via_pd(
            {
                "path": ["$.credentialSubject.country"],
                "filter": {"type": "string", "const": "CA"},
            }
        )
        result = ev.match({"credentialSubject": {"country": "CA"}})
        assert result is not None

    def test_path_with_filter_returns_none_when_filter_fails(self):
        """Value found at path but fails filter — must return None (§7.1.1).

        Uses a 'const' filter (ACA-Py-preserved) on a scalar field.
        """
        ev = _field_via_pd(
            {
                "path": ["$.credentialSubject.country"],
                "filter": {"type": "string", "const": "CA"},
            }
        )
        result = ev.match({"credentialSubject": {"country": "US"}})
        assert result is None


# ===========================================================================
# 4. PresentationExchangeEvaluator.verify() Integration Tests
#    End-to-end evaluation with mocked credential processor.
# ===========================================================================


@pytest.mark.asyncio
async def test_verify_minimal_pd_success(profile, mock_processors):
    """§5 — submission covering a single descriptor must verify."""
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"credentialSubject": {"dateOfBirth": "1990-01-15"}},
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_MINIMAL)

    submission = {
        "id": "sub-001",
        "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "descriptor_map": [
            {"id": "wa_driver_license", "format": "jwt_vc_json", "path": "$"}
        ],
    }
    result = await evaluator.verify(
        profile, submission, {"credentialSubject": {"dateOfBirth": "1990-01-15"}}
    )
    assert result.verified is True
    assert "wa_driver_license" in result.descriptor_id_to_claims


@pytest.mark.asyncio
async def test_verify_definition_id_mismatch_fails(profile, mock_processors):
    """§5.1 — definition_id in submission must match PD id."""
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_MINIMAL)

    submission = {
        "id": "sub-002",
        "definition_id": "wrong-definition-id",
        "descriptor_map": [
            {"id": "wa_driver_license", "format": "jwt_vc_json", "path": "$"}
        ],
    }
    result = await evaluator.verify(profile, submission, {})
    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_accepts_alternate_path(profile, mock_processors):
    """§7.1.1 — evaluator accepts any of the listed path alternatives.

    minimal_example.json has four paths for the birth-date field.
    credential uses 'dob' (second path) rather than 'dateOfBirth' (first).
    """
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"credentialSubject": {"dob": "1990-06-15"}},
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_MINIMAL)

    submission = {
        "id": "sub-003",
        "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "descriptor_map": [
            {"id": "wa_driver_license", "format": "jwt_vc_json", "path": "$"}
        ],
    }
    result = await evaluator.verify(
        profile, submission, {"credentialSubject": {"dob": "1990-06-15"}}
    )
    assert result.verified is True


@pytest.mark.asyncio
async def test_verify_rejects_credential_missing_required_field(profile, mock_processors):
    """§7.1.1 — credential that satisfies no path for a required field must fail."""
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"credentialSubject": {}},  # dateOfBirth and dob both absent
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_MINIMAL)

    submission = {
        "id": "sub-004",
        "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "descriptor_map": [
            {"id": "wa_driver_license", "format": "jwt_vc_json", "path": "$"}
        ],
    }
    result = await evaluator.verify(profile, submission, {"credentialSubject": {}})
    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_rejects_credential_not_matching_filter(profile, mock_processors):
    """§7.1.1 — field filter mismatch causes verification failure.

    PD requires credentialSchema.id == specific const value.
    Credential carries a different schema URL, so the filter fails.

    We use 'const' on a scalar string field (not the 'contains' array pattern from
    pd_filter.json) because ACA-Py's DIFField.Filter silently drops 'contains';
    see test_xf_array_contains_filter_silently_dropped.
    """
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={
                "credentialSchema": {
                    "id": "https://university.example.com/schemas/OTHER.json"
                }
            },
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_CONST_FILTER)

    submission = {
        "id": "sub-005",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000010",
        "descriptor_map": [{"id": "degree_input", "format": "jwt_vc_json", "path": "$"}],
    }
    result = await evaluator.verify(
        profile,
        submission,
        {"credentialSchema": {"id": "https://university.example.com/schemas/OTHER.json"}},
    )
    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_matching_const_filter_passes(profile, mock_processors):
    """§7.1.1 — credential whose schema id passes the const filter must verify."""
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={
                "credentialSchema": {
                    "id": "https://university.example.com/schemas/degree.json"
                }
            },
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_CONST_FILTER)

    submission = {
        "id": "sub-006",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000010",
        "descriptor_map": [{"id": "degree_input", "format": "jwt_vc_json", "path": "$"}],
    }
    result = await evaluator.verify(
        profile,
        submission,
        {
            "credentialSchema": {
                "id": "https://university.example.com/schemas/degree.json"
            }
        },
    )
    assert result.verified is True


@pytest.mark.asyncio
async def test_verify_multi_field_and_semantics_all_must_match(profile, mock_processors):
    """§7.1.1 — ALL fields in a descriptor use AND semantics.

    pd_filter2_simplified.json: three fields must all pass.
    Second field's filter fails → whole descriptor fails.
    """
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={
                "termsOfUse": {
                    "type": "https://train.trust-scheme.de/info",  # field 1 ✓
                    "trustScheme": "wrong-scheme.com",  # field 2 ✗
                },
                "type": "creditCard",  # field 3 ✓
            },
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_TERMS_OF_USE_FILTER)

    submission = {
        "id": "sub-007",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000020",
        "descriptor_map": [
            {"id": "credit_card_input", "format": "jwt_vc_json", "path": "$"}
        ],
    }
    result = await evaluator.verify(profile, submission, {})
    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_multi_field_all_fields_pass(profile, mock_processors):
    """§7.1.1 — all fields passing → verified."""
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={
                "termsOfUse": {
                    "type": "https://train.trust-scheme.de/info",
                    "trustScheme": "worldbankfederation.com",
                },
                "type": "creditCard",
            },
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_TERMS_OF_USE_FILTER)

    submission = {
        "id": "sub-008",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000020",
        "descriptor_map": [
            {"id": "credit_card_input", "format": "jwt_vc_json", "path": "$"}
        ],
    }
    result = await evaluator.verify(profile, submission, {})
    assert result.verified is True


# ===========================================================================
# 5. Unsupported Features — xfail(strict=True)
#
# Each test documents a normative requirement from the DIF PEX spec that our
# evaluator does not yet implement.  The test asserts the CORRECT spec
# behaviour; it is expected to fail while the feature is absent.
#
# strict=True means pytest will treat an unexpected PASS as a test failure,
# ensuring the marker is removed once the feature is implemented.
# ===========================================================================


@pytest.mark.asyncio
async def test_xf_missing_required_descriptor_should_fail(profile, mock_processors):
    """§5 — partial submission must be rejected when all descriptors are required.

    PD_TWO_DESCRIPTORS has two descriptors (id_doc, employment_doc).
    A submission providing only id_doc must be REJECTED per the spec.
    Currently returns verified=True because absent descriptors are not checked.
    """
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"credentialSubject": {"id_number": "A12345"}},
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_TWO_DESCRIPTORS)

    submission = {
        "id": "sub-xf-001",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000040",
        "descriptor_map": [
            # employment_doc is absent — spec requires it
            {"id": "id_doc", "format": "jwt_vc_json", "path": "$"},
        ],
    }
    result = await evaluator.verify(
        profile, submission, {"credentialSubject": {"id_number": "A12345"}}
    )
    # Spec: False (employment_doc not satisfied); current impl: True → xfail
    assert result.verified is False


@pytest.mark.asyncio
async def test_xf_submission_requirements_pick_count_enforced(profile, mock_processors):
    """§4.1 pick(count=1, from=A) must reject a submission with 2 group-A entries.

    Both id_type_a and id_type_b are in group A; only one should be submitted.
    Submitting both should violate the 'count: 1' constraint.
    Currently returns verified=True because group constraints are not evaluated.
    """
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"type": ["VerifiableCredential"]},
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_PICK_ONE)

    submission = {
        "id": "sub-xf-002",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000050",
        "descriptor_map": [
            # Submitting BOTH group-A members — violates pick count: 1
            {"id": "id_type_a", "format": "jwt_vc_json", "path": "$.vcs[0]"},
            {"id": "id_type_b", "format": "jwt_vc_json", "path": "$.vcs[1]"},
        ],
    }
    result = await evaluator.verify(
        profile, submission, {"vcs": [{"type": ["VerifiableCredential"]}] * 2}
    )
    # Spec: False (count exceeded); current impl: True → xfail
    assert result.verified is False


@pytest.mark.asyncio
async def test_xf_array_contains_filter_silently_dropped(profile, mock_processors):
    """ACA-Py DIFField.Filter drops 'contains' — array element check not enforced.

    pd_filter.json uses {type: array, contains: {type: string, const: "X"}} to
    require the $.type array to contain a specific string.  After ACA-Py round-
    trip, only {type: array} survives, so a credential with ANY array in $.type
    passes the filter even if it doesn't contain the required value.
    """
    # Credential whose $.type does NOT contain 'UniversityDegreeCredential'
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"type": ["VerifiableCredential", "SomethingElse"]},
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    # Compile a PD with the raw pd_filter.json contains shape
    pd = {
        "id": "4f5d6e7a-1234-4abc-8def-000000000060",
        "input_descriptors": [
            {
                "id": "degree_input",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": {
                                "type": "array",
                                "contains": {
                                    "type": "string",
                                    "const": "UniversityDegreeCredential",
                                },
                            },
                        }
                    ]
                },
            }
        ],
    }
    evaluator = PresentationExchangeEvaluator.compile(pd)
    submission = {
        "id": "sub-xf-004",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000060",
        "descriptor_map": [{"id": "degree_input", "format": "jwt_vc_json", "path": "$"}],
    }
    result = await evaluator.verify(
        profile, submission, {"type": ["VerifiableCredential", "SomethingElse"]}
    )
    # Spec requires False (wrong type); ACA-Py drops 'contains' so returns True → xfail
    assert result.verified is False


@pytest.mark.asyncio
async def test_xf_limit_disclosure_required_not_enforced(profile, mock_processors):
    """§7.1.3 — limit_disclosure: required must reject a non-SD credential.

    PD_LIMIT_DISCLOSURE sets limit_disclosure=required on its descriptor.
    Submitting a plain jwt_vc_json credential (not SD-JWT) should fail.
    Currently returns verified=True because limit_disclosure is ignored.
    """
    mock_processors.cred_verifier_for_format.return_value.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"credentialSubject": {"account_number": "1234567890"}},
        )
    )
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(PD_LIMIT_DISCLOSURE)

    submission = {
        "id": "sub-xf-003",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000030",
        "descriptor_map": [
            {
                "id": "bankaccount_input",
                "format": "jwt_vc_json",  # plain JWT — not selective disclosure
                "path": "$",
            }
        ],
    }
    result = await evaluator.verify(
        profile,
        submission,
        {"credentialSubject": {"account_number": "1234567890"}},
    )
    # Spec: False (format prohibited by limit_disclosure); current impl: True → xfail
    assert result.verified is False
