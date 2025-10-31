import pytest
from acapy_agent.core.profile import Profile

from oid4vc.models.supported_cred import SupportedCredential


@pytest.fixture
def record():
    yield SupportedCredential(
        format="jwt_vc_json",
        identifier="MyCredential",
        cryptographic_suites_supported=["EdDSA"],
        format_data={
            "credentialSubject": {"name": "alice"},
        },
    )


def test_serde(record: SupportedCredential):
    record._id = "123"
    serialized = record.serialize()
    deserialized = SupportedCredential.deserialize(serialized)
    assert record == deserialized


@pytest.mark.asyncio
async def test_save(profile: Profile, record: SupportedCredential):
    async with profile.session() as session:
        await record.save(session)
        loaded = await SupportedCredential.retrieve_by_id(
            session, record.supported_cred_id
        )
        assert loaded == record


def test_to_issuer_metadata(record: SupportedCredential):
    """Test conversion to issuer metadata per OID4VCI 1.0 § 11.2.3."""
    assert record.to_issuer_metadata() == {
        "format": "jwt_vc_json",
        "cryptographic_suites_supported": ["EdDSA"],
        "credentialSubject": {"name": "alice"},
    }
