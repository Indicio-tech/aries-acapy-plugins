"""CredProcessor interface and exception."""

from abc import ABC, abstractmethod
from typing import Any, Mapping

from aries_cloudagent.core.error import BaseError
from aries_cloudagent.admin.request_context import AdminRequestContext

from .models.exchange import OID4VCIExchangeRecord
from .models.supported_cred import SupportedCredential
from .pop_result import PopResult


class ICredProcessor(ABC):
    """Returns singed credential payload."""

    @abstractmethod
    def issue_cred(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ) -> Any:
        """Method signature.

        Args:
            body: any
            supported: SupportedCredential
            ex_record: OID4VCIExchangeRecord
            pop: PopResult
            context: AdminRequestContext
        Returns:
            encoded: signed credential payload.
        """


class CredIssueError(BaseError):
    """Base class for CredProcessor errors."""


class CredProcessors:
    """Registry for credential format processors."""

    def __init__(self, processors: Mapping[str, ICredProcessor]):
        """Initialize the processor registry."""
        self.processors = dict(processors)

    def for_format(self, format: str):
        """Return the processor to handle the given format."""
        processor = self.processors.get(format)
        if not processor:
            raise CredIssueError(f"No loaded processor for format {format}")
        return processor

    def register(self, format: str, processor: ICredProcessor):
        """Register a new processor for a format."""
        self.processors[format] = processor