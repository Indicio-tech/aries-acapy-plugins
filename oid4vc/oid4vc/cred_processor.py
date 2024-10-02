"""CredProcessor interface and exception."""

from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Protocol, Type

from aries_cloudagent.core.error import BaseError
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.core.profile import Profile

from .models.exchange import OID4VCIExchangeRecord
from .models.supported_cred import SupportedCredential
from .pop_result import PopResult

import json
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.core.profile import ProfileSession


@dataclass
class VerifyResult:
    """Result of verification."""

    verified: bool
    payload: Any


class Issuer(Protocol):
    """Issuer protocol."""

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ) -> Any:
        """Issue a credential."""
        ...

    def validate_credential_subject(
        self, supported: SupportedCredential, subject: dict
    ):
        """Validate the credential subject."""
        ...

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate the credential."""
        ...


class CredVerifier(Protocol):
    """Credential verifier protocol."""

    async def verify_credential(
        self, profile: Profile, credential: Any
    ) -> VerifyResult:
        """Verify credential."""
        ...


class PresVerifier(Protocol):
    """Presentation verifier protocol."""

    async def verify_presentation(
        self, profile: Profile, presentation: Any
    ) -> VerifyResult:
        """Verify presentation."""
        ...


class CredProcessorError(BaseError):
    """Base class for CredProcessor errors."""


class IssuerError(CredProcessorError):
    """Raised on issuer errors."""


class CredVerifeirError(CredProcessorError):
    """Raised on credential verifier errors."""


class PresVerifeirError(CredProcessorError):
    """Raised on presentation verifier errors."""


class CredProcessors:
    """Registry for credential format processors."""

    def __init__(
        self,
        issuers: Optional[Mapping[str, Issuer]] = None,
        cred_verifiers: Optional[Mapping[str, CredVerifier]] = None,
        pres_verifiers: Optional[Mapping[str, PresVerifier]] = None,
        supported_creds: Optional[Mapping[str, Type[SupportedCredential]]] = None,
    ):
        """Initialize the processor registry."""
        self.issuers = dict(issuers) if issuers else {}
        self.cred_verifiers = dict(cred_verifiers) if cred_verifiers else {}
        self.pres_verifiers = dict(pres_verifiers) if pres_verifiers else {}
        self.supported_creds = dict(supported_creds) if supported_creds else {}

    def issuer_for_format(self, format: str) -> Issuer:
        """Return the processor to handle the given format."""
        processor = self.issuers.get(format)
        if not processor:
            raise CredProcessorError(f"No loaded issuer for format {format}")
        return processor

    def cred_verifier_for_format(self, format: str) -> CredVerifier:
        """Return the processor to handle the given format."""
        processor = self.cred_verifiers.get(format)
        if not processor:
            raise CredProcessorError(
                f"No loaded credential verifier for format {format}"
            )
        return processor

    def pres_verifier_for_format(self, format: str) -> PresVerifier:
        """Return the processor to handle the given format."""
        processor = self.pres_verifiers.get(format)
        if not processor:
            raise CredProcessorError(
                f"No loaded presentation verifier for format {format}"
            )
        return processor

    def supported_cred_for_format(self, format: str) -> Type[SupportedCredential]:
        """Return the supported credential of a given format."""
        supported_cred = self.supported_creds.get(format)
        if not supported_cred:
            raise CredProcessorError(f"No supported credential for format {format}")
        return supported_cred

    def register_issuer(self, format: str, processor: Issuer):
        """Register a new processor for a format."""
        self.issuers[format] = processor

    def register_cred_verifier(self, format: str, processor: CredVerifier):
        """Register a new processor for a format."""
        self.cred_verifiers[format] = processor

    def register_pres_verifier(self, format: str, processor: PresVerifier):
        """Register a new processor for a format."""
        self.pres_verifiers[format] = processor

    def register_supported_cred(self, format: str, cred: Type[SupportedCredential]):
        """Register a new credential for a format."""
        self.supported_creds[format] = cred

    async def retrieve_all_types(
        self, session: ProfileSession
    ) -> List[SupportedCredential]:
        """Retrieve all the supported credential formats."""
        storage = session.inject(BaseStorage)

        # TODO: Worry about pagination later
        rows = await storage.find_all_records(
            type_filter=SupportedCredential.RECORD_TYPE
        )
        result = []
        for record in rows:
            vals = json.loads(record.value)
            SupportedCredCls = self.supported_cred_for_format(vals["format"])

            result.append(SupportedCredCls.from_storage(record.id, vals))

        return result
