"""Supported Credential Record."""

from typing import Dict, List, Optional

from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class SupportedCredential(BaseRecord):
    """Supported Credential Record."""

    class Meta:
        """SupportedCredential metadata."""

        schema_class = "SupportedCredentialSchema"

    # EVENT_NAMESPACE = "oid4vci"
    RECORD_TOPIC = "oid4vci"
    RECORD_ID_NAME = "supported_cred_id"
    RECORD_TYPE = "supported_cred"
    TAG_NAMES = {"identifier", "format"}

    def __init__(
        self,
        *,
        supported_cred_id: Optional[str] = None,
        format: Optional[str] = None,
        identifier: Optional[str] = None,
        cryptographic_binding_methods_supported: Optional[List[str]] = None,
        cryptographic_suites_supported: Optional[List[str]] = None,
        display: Optional[List[Dict]] = None,
        **kwargs,
    ):
        """Initialize a new SupportedCredential Record.

        Args:
            supported_cred_id (Optional[str]): Record identifier. This is
                purely a record identifier; it does NOT correspond to anything in
                the spec.
            format (Optional[str]): Format identifier of the credential. e.g. jwt_vc_json
            identifier (Optional[str]): Identifier of the supported credential
                metadata. This is the `id` from the spec (NOT a record identifier).
            cryptographic_binding_methods_supported (Optional[List[str]]): A
                list of supported cryptographic binding methods.
            cryptographic_suites_supported (Optional[List[str]]): A list of
                supported cryptographic suites.
            display (Optional[List[Dict]]): Display characteristics of the credential.
            kwargs: Keyword arguments to allow generic initialization of the record.
        """
        super().__init__(supported_cred_id, **kwargs)
        self.format = format
        self.identifier = identifier
        self.cryptographic_binding_methods_supported = (
            cryptographic_binding_methods_supported
        )
        self.cryptographic_suites_supported = cryptographic_suites_supported
        self.display = display

    @property
    def supported_cred_id(self):
        """Accessor for the ID associated with this record."""
        return self._id

    def to_issuer_metadata(self) -> dict:
        """Return a representation of this record as issuer metadata."""
        raise NotImplementedError()


class SupportedCredentialSchema(BaseRecordSchema):
    """Schema for SupportedCredential."""

    class Meta:
        """SupportedCredentialSchema metadata."""

        model_class = SupportedCredential

    supported_cred_id = fields.Str(
        required=False,
        description="supported credential identifier",
    )
    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    identifier = fields.Str(
        data_key="id", required=True, metadata={"example": "UniversityDegreeCredential"}
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": []}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256K"]}
    )
    display = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university",
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF",
                }
            ]
        },
    )
