"""Fixtures for sd-jwt vc tests."""

from acapy_agent.resolver.did_resolver import DIDResolver
import pytest
from acapy_agent.core.in_memory import InMemoryProfile

from oid4vc.cred_processor import CredProcessors
from oid4vc.jwk_resolver import JwkResolver
from sd_jwt_vc.cred_processor import SdJwtCredIssueProcessor


@pytest.fixture
async def profile():
    profile = InMemoryProfile.test_profile()
    processors = CredProcessors()
    sd_jwt = SdJwtCredIssueProcessor()
    processors.register_issuer("vc+sd-jwt", sd_jwt)
    processors.register_cred_verifier("vc+sd-jwt", sd_jwt)
    processors.register_pres_verifier("vc+sd-jwt", sd_jwt)
    profile.context.injector.bind_instance(CredProcessors, processors)

    resolver = DIDResolver([JwkResolver()])

    profile.context.injector.bind_instance(DIDResolver, resolver)
    yield profile
