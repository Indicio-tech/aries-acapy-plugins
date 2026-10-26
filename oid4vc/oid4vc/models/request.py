"""Request model for OID4VP."""

from typing import Any, Dict, Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class OID4VPRequest(BaseRecord):
    """Class for OpenID4VP Requests."""

    class Meta:
        """OID4VPRequest Metadata."""

        schema_class = "OID4VPRequestSchema"

    RECORD_ID_NAME = "request_id"
    RECORD_TYPE = "oid4vp"
    RECORD_TOPIC = "oid4vp"
    TAG_NAMES = {"pres_def_id", "dcql_query_id"}

    def __init__(
        self,
        *,
        request_id: Optional[str] = None,
        pres_def_id: Optional[str] = None,
        dcql_query_id: Optional[str] = None,
        vp_formats: Dict[str, Any],
        client_name: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize a OID4VPRequest instance."""

        super().__init__(request_id, **kwargs)

        self.pres_def_id = pres_def_id
        self.dcql_query_id = dcql_query_id
        self.vp_formats = vp_formats
        self.client_name = client_name

    @property
    def request_id(self) -> str:
        """Accessor for the ID associated with this request record."""

        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the exchange record for storage."""
        result: dict = {"vp_formats": self.vp_formats}
        if self.pres_def_id is not None:
            result["pres_def_id"] = self.pres_def_id
        if self.dcql_query_id is not None:
            result["dcql_query_id"] = self.dcql_query_id
        if self.client_name is not None:
            result["client_name"] = self.client_name
        return result


class OID4VPRequestSchema(BaseRecordSchema):
    """OID4VP Request Schema."""

    class Meta:
        """OID4VP Request Schema Metadata."""

        model_class = "OID4VPRequest"

    request_id = fields.Str(
        required=False,
        metadata={
            "description": "Request identifier",
        },
    )

    pres_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify presentation definition",
        },
    )

    dcql_query_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify DCQL Query",
        },
    )

    vp_formats = fields.Dict(
        required=True,
        metadata={
            "description": "Expected presentation formats from the holder",
        },
    )

    client_name = fields.Str(
        required=False,
        metadata={
            "description": (
                "Verifier name shown to the holder; self-asserted by the"
                " verifier, not bound to client_id or to any certificate"
            ),
            "example": "Example Clinic",
        },
    )
