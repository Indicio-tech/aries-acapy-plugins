"""Supported Credential Record."""

from typing import Dict, List, Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
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
        format_data: Optional[Dict] = None,
        vc_additional_data: Optional[Dict] = None,
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
            format_data (Optional[Dict]): Format sepcific attributes; e.g.
                credentialSubject for jwt_vc_json
            vc_additional_data (Optional[Dict]): Additional data to include in the
                Verifiable Credential.
            kwargs: Keyword arguments to allow generic initialization of the record.
        """
        # Filter kwargs to only include parameters that BaseRecord accepts
        base_record_kwargs = {
            k: v
            for k, v in kwargs.items()
            if k in ("state", "created_at", "updated_at", "new_with_id")
        }
        super().__init__(supported_cred_id, **base_record_kwargs)
        self.format = format
        self.identifier = identifier
        self.cryptographic_binding_methods_supported = (
            cryptographic_binding_methods_supported
        )
        self.cryptographic_suites_supported = cryptographic_suites_supported
        self.display = display
        self.format_data = format_data
        self.vc_additional_data = vc_additional_data

    @property
    def supported_cred_id(self):
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the exchange record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "format",
                "identifier",
                "cryptographic_binding_methods_supported",
                "cryptographic_suites_supported",
                "display",
                "format_data",
                "vc_additional_data",
            )
        }

    def to_issuer_metadata(self) -> dict:
        """Return a representation of this record as issuer metadata.

        OpenID4VCI 1.0 § 11.2.3: Credential Configuration Identifier
        https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2.3

        Returns credential configuration object as per OID4VCI 1.0 specification.
        """
        # Base credential configuration per OID4VCI 1.0 § 11.2.3
        issuer_metadata = {
            "format": self.format,  # REQUIRED: Credential format identifier
        }

        # Add optional cryptographic binding methods (OID4VCI 1.0 § 11.2.3.2)
        if self.cryptographic_binding_methods_supported:
            issuer_metadata["cryptographic_binding_methods_supported"] = (
                self.cryptographic_binding_methods_supported
            )

        # Add optional cryptographic suites (OID4VCI 1.0 § 11.2.3.3)
        if self.cryptographic_suites_supported:
            issuer_metadata["cryptographic_suites_supported"] = (
                self.cryptographic_suites_supported
            )

        # Add optional display properties (OID4VCI 1.0 § 11.2.3.1)
        if self.display:
            issuer_metadata["display"] = self.display

        # OID4VCI 1.0 § E: Format-specific parameters
        # Flatten the format specific metadata into the configuration object
        if self.format_data:
            issuer_metadata.update(self.format_data)

        return issuer_metadata


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
        required=True, metadata={"example": "UniversityDegreeCredential"}
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
    format_data = fields.Dict(
        required=False,
        metadata={
            "example": {
                "credentialSubject": {
                    "given_name": {
                        "display": [{"name": "Given Name", "locale": "en-US"}]
                    },
                    "last_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
                    "degree": {},
                    "gpa": {"display": [{"name": "GPA"}]},
                }
            }
        },
    )
    vc_additional_data = fields.Dict(
        required=False,
        metadata={
            "example": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            }
        },
    )
