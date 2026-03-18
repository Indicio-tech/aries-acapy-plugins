"""mso_mdoc signing key record.

A ``MdocSigningKeyRecord`` persists the EC private key and X.509 certificate
used by the issuer to sign mDoc credentials.  Records are scoped to the
current wallet session, giving multi-tenant isolation automatically.

Replaces the previous pattern of storing signing material in
``SupportedCredential.vc_additional_data``.
"""

from typing import Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class MdocSigningKeyRecord(BaseRecord):
    """Persisted signing key and certificate for mDoc credential issuance."""

    RECORD_TOPIC = "mso_mdoc"
    RECORD_TYPE = "signing_key"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"doctype", "label"}

    class Meta:
        """MdocSigningKeyRecord metadata."""

        schema_class = "MdocSigningKeyRecordSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        doctype: Optional[str] = None,
        label: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        certificate_pem: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize a new MdocSigningKeyRecord."""
        super().__init__(id, **kwargs)
        self.doctype = doctype
        self.label = label
        self.private_key_pem = private_key_pem
        self.certificate_pem = certificate_pem

    @property
    def id(self) -> str:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage.

        ``private_key_pem`` is included here so it is persisted, but it is
        marked ``load_only`` in the schema so it is never returned via the API.
        """
        return {
            prop: getattr(self, prop)
            for prop in ("doctype", "label", "private_key_pem", "certificate_pem")
        }


class MdocSigningKeyRecordSchema(BaseRecordSchema):
    """Schema for MdocSigningKeyRecord serialisation."""

    class Meta:
        """MdocSigningKeyRecordSchema metadata."""

        model_class = "MdocSigningKeyRecord"

    id = fields.Str(
        required=False,
        metadata={"description": "Signing key record identifier"},
    )
    doctype = fields.Str(
        required=False,
        metadata={
            "description": (
                "ISO 18013-5 doctype this signing key handles. "
                "Omit to use for all doctypes."
            ),
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    label = fields.Str(
        required=False,
        metadata={"description": "Human-readable label for this signing key."},
    )
    private_key_pem = fields.Str(
        required=False,
        load_only=True,
        metadata={
            "description": (
                "PEM-encoded EC private key (write-only). "
                "Never returned in GET responses."
            )
        },
    )
    certificate_pem = fields.Str(
        required=False,
        metadata={
            "description": (
                "PEM-encoded X.509 certificate (or chain) for this signing key."
            )
        },
    )
