from unittest import mock

import pytest
from acapy_agent.core.profile import Profile

from oid4vc.cred_processor import CredProcessors, VerifyResult
from oid4vc.dcql import DCQLQueryEvaluator
from oid4vc.models.dcql_query import CredentialQuery, DCQLQuery

raw_query = {
    "credentials": [
        {
            "id": "pid",
            "format": "vc+sd-jwt",
            "meta": {
                "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [
                {"path": ["given_name"]},
                {"path": ["family_name"]},
                {"path": ["address", "street_address"]},
            ],
        }
    ]
}

failure_query = {
    "credentials": [
        {
            "id": "mdoc_cred",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "org.example.doc.1"},
            "claims": [{"path": ["org.example.doc.1", "given_name"]}],
        }
    ]
}

# The exact wording a credential found revoked produces (mso_mdoc status list).
STATUS_ERROR = "Credential is revoked or suspended (status_list idx=44444, status=1)"


@pytest.mark.asyncio
async def test_dcql_query_deser_roundtrip():
    des_query = DCQLQuery.deserialize(raw_query)
    ser_query = des_query.serialize()

    assert raw_query == ser_query


@pytest.mark.asyncio
async def test_dcql_query_saving(profile: Profile):
    des_query = DCQLQuery.deserialize(raw_query)
    async with profile.session() as session:
        await des_query.save(session=session)

        retrieved_query = await DCQLQuery.retrieve_by_id(session, des_query.dcql_query_id)

    assert len(retrieved_query.credentials) == 1
    assert isinstance(retrieved_query.credentials[0], CredentialQuery)


@pytest.mark.asyncio
async def test_dcql_verify(profile: Profile):
    pres_result_payload = {
        "given_name": "Sally",
        "family_name": "Sparrow",
        "address": {
            "street_address": "123 Main Street",
        },
        "vct": "https://credentials.example.com/identity_credential",
    }
    vp_token = {"pid": "blah"}

    pres_rec = mock.MagicMock()
    mock_cred_processors = mock.MagicMock(CredProcessors)

    mock_pres_verifier = mock.MagicMock()
    mock_pres_verifier.verify_presentation = mock.AsyncMock(
        return_value=VerifyResult(True, pres_result_payload)
    )
    mock_cred_processors.pres_verifier_for_format = mock.MagicMock(
        return_value=mock_pres_verifier
    )

    mock_cred_verifier = mock.MagicMock()
    mock_cred_verifier.verify_credential = mock.AsyncMock(
        return_value=VerifyResult(True, pres_result_payload)
    )
    mock_cred_processors.cred_verifier_for_format = mock.MagicMock(
        return_value=mock_cred_verifier
    )

    profile.context.injector.bind_instance(CredProcessors, mock_cred_processors)

    async with profile.session() as session:
        eval = DCQLQueryEvaluator.compile(raw_query)

        verified = await eval.verify(
            profile=profile, vp_token=vp_token, presentation_record=pres_rec
        )

        assert verified.verified


async def _verify_with_results(
    profile: Profile,
    pres_results,
    cred_results,
    query: dict = failure_query,
    vp_token: dict | None = None,
):
    """Run the evaluator with mocked verifiers.

    pres_results and cred_results are a VerifyResult, or a dict from the
    presented value (for presentations) or the presentation payload's "id"
    (for credentials) to a VerifyResult. Returns the result and the
    credential verifier mock.
    """
    mock_cred_processors = mock.MagicMock(CredProcessors)

    def pick(results, key):
        return results[key] if isinstance(results, dict) else results

    mock_pres_verifier = mock.MagicMock()
    mock_pres_verifier.verify_presentation = mock.AsyncMock(
        side_effect=lambda profile, presentation, presentation_record: pick(
            pres_results, presentation
        )
    )
    mock_cred_processors.pres_verifier_for_format = mock.MagicMock(
        return_value=mock_pres_verifier
    )

    mock_cred_verifier = mock.MagicMock()
    mock_cred_verifier.verify_credential = mock.AsyncMock(
        side_effect=lambda profile, credential: pick(
            cred_results,
            credential.get("id") if isinstance(credential, dict) else None,
        )
    )
    mock_cred_processors.cred_verifier_for_format = mock.MagicMock(
        return_value=mock_cred_verifier
    )

    profile.context.injector.bind_instance(CredProcessors, mock_cred_processors)

    evaluator = DCQLQueryEvaluator.compile(query)
    result = await evaluator.verify(
        profile=profile,
        vp_token=vp_token or {"mdoc_cred": "blah"},
        presentation_record=mock.MagicMock(),
    )
    return result, mock_cred_verifier


PRESENTED = {"docType": "org.example.doc.1"}

# (error value in the failure payload, expected suffix after the line)
ERROR_CASES = [
    (STATUS_ERROR, f": {STATUS_ERROR}"),
    (None, ""),
    ("", ""),
    ("   ", ""),
    (123, ": 123"),
    ({}, ""),
    ([], ""),
    (
        ["IssuerAuthentication: invalid", "DeviceAuthentication: invalid"],
        ": IssuerAuthentication: invalid; DeviceAuthentication: invalid",
    ),
    ({"issuer": "invalid"}, ": {'issuer': 'invalid'}"),
    ("line one\nline two\ttab\x00nul\x85", ": line one line two tab nul"),
    ("x" * 1000, ": " + "x" * 297 + "..."),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("error", "suffix"), ERROR_CASES)
@pytest.mark.parametrize("stage", ["Presentation", "Credential"])
async def test_failure_line_keeps_verifier_error(profile: Profile, stage, error, suffix):
    failed = VerifyResult(False, {"error": error, "docType": "org.example.doc.1"})
    if stage == "Presentation":
        result, _ = await _verify_with_results(profile, failed, VerifyResult(True, {}))
    else:
        result, _ = await _verify_with_results(
            profile, VerifyResult(True, PRESENTED), failed
        )

    assert not result.verified
    assert result.details == f"{stage} for mdoc_cred failed verification{suffix}"


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{"docType": "org.example.doc.1"}, "not a dict"])
@pytest.mark.parametrize("stage", ["Presentation", "Credential"])
async def test_failure_line_without_error_is_bare(profile: Profile, stage, payload):
    failed = VerifyResult(False, payload)
    if stage == "Presentation":
        result, _ = await _verify_with_results(profile, failed, VerifyResult(True, {}))
    else:
        result, _ = await _verify_with_results(
            profile, VerifyResult(True, PRESENTED), failed
        )

    assert result.details == f"{stage} for mdoc_cred failed verification"


@pytest.mark.asyncio
async def test_revoked_wording_reaches_details_unchanged(profile: Profile):
    """Consumers match "Credential is revoked or suspended"; keep it intact."""
    result, _ = await _verify_with_results(
        profile,
        VerifyResult(False, {"error": STATUS_ERROR, "docType": "org.example.doc.1"}),
        VerifyResult(True, {}),
    )

    assert result.details == (
        "Presentation for mdoc_cred failed verification: Credential is revoked "
        "or suspended (status_list idx=44444, status=1)"
    )


@pytest.mark.asyncio
async def test_only_the_error_value_is_forwarded(profile: Profile):
    """A realistic mdoc failure payload: issuer_auth, device_auth and claims
    stay out of the line."""
    failed = VerifyResult(
        False,
        {
            "error": '{"issuer_authentication":"Invalid signature"}',
            "issuer_auth": "Invalid",
            "device_auth": "Valid",
            "claims": {"org.example.doc.1": {"given_name": "Example"}},
        },
    )

    result, _ = await _verify_with_results(profile, failed, VerifyResult(True, {}))

    assert result.details == (
        "Presentation for mdoc_cred failed verification: "
        '{"issuer_authentication":"Invalid signature"}'
    )
    assert "given_name" not in result.details


@pytest.mark.asyncio
async def test_credential_not_verified_after_presentation_failure(profile: Profile):
    result, cred_verifier = await _verify_with_results(
        profile,
        VerifyResult(False, {"error": "Presentation could not be verified"}),
        VerifyResult(True, {}),
    )

    assert not result.verified
    cred_verifier.verify_credential.assert_not_called()


two_credential_query = {
    "credentials": [
        {"id": "first", "format": "mso_mdoc"},
        {"id": "second", "format": "mso_mdoc"},
    ]
}


@pytest.mark.asyncio
async def test_two_credentials_second_fails(profile: Profile):
    result, _ = await _verify_with_results(
        profile,
        {
            "pres-first": VerifyResult(True, {"id": "first"}),
            "pres-second": VerifyResult(True, {"id": "second"}),
        },
        {
            "first": VerifyResult(True, {"id": "first"}),
            "second": VerifyResult(False, {"error": STATUS_ERROR}),
        },
        query=two_credential_query,
        vp_token={"first": "pres-first", "second": "pres-second"},
    )

    assert not result.verified
    assert result.details == (
        f"Credential for second failed verification: {STATUS_ERROR}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("required", [True, False])
async def test_credential_sets_keep_the_verifier_reason(profile: Profile, required):
    """A failed credential under credential_sets: a required set that is not
    met names the reason; an optional set does not fail the query."""
    query = {
        **two_credential_query,
        "credential_sets": [
            {"options": [["first"]], "required": True},
            {"options": [["second"]], "required": required},
        ],
    }

    result, _ = await _verify_with_results(
        profile,
        {
            "pres-first": VerifyResult(True, {"id": "first"}),
            "pres-second": VerifyResult(True, {"id": "second"}),
        },
        {
            "first": VerifyResult(True, {"id": "first"}),
            "second": VerifyResult(False, {"error": STATUS_ERROR}),
        },
        query=query,
        vp_token={"first": "pres-first", "second": "pres-second"},
    )

    if required:
        assert not result.verified
        assert result.details.startswith("Required credential set 1 not satisfied.")
        assert result.details.endswith(
            f". Failed: Credential for second failed verification: {STATUS_ERROR}"
        )
    else:
        assert result.verified
        assert result.satisfied_credential_sets == [0]
