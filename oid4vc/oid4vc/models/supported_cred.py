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
        proof_types_supported: Optional[Dict] = None,
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
            proof_types_supported (Optional[Dict]): A dict of supported proof types.
            display (Optional[List[Dict]]): Display characteristics of the credential.
            format_data (Optional[Dict]): Format specific attributes; e.g.
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
        self.proof_types_supported = proof_types_supported
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
                "proof_types_supported",
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
            prop: value
            for prop in (
                "format",
                "cryptographic_binding_methods_supported",
                "cryptographic_suites_supported",
                "proof_types_supported",
                "display",
            )
            if (value := getattr(self, prop)) is not None
        }

        # Rename cryptographic_suites_supported to credential_signing_alg_values_supported
        alg_supported = issuer_metadata.pop("cryptographic_suites_supported", None)
        if alg_supported:
            issuer_metadata["credential_signing_alg_values_supported"] = alg_supported

        issuer_metadata["id"] = self.identifier

        # Handle format_data
        if self.format_data:
            if self.format in ("jwt_vc_json", "jwt_vc"):
                # For jwt_vc_json, wrap in credential_definition
                cred_def = self.format_data.copy()
                context = cred_def.pop("context", None)
                if context:
                    cred_def["@context"] = context

                # Filter None values
                cred_def = {k: v for k, v in cred_def.items() if v is not None}

                issuer_metadata["credential_definition"] = cred_def
            else:
                # For other formats (e.g. mso_mdoc), flatten
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
    proof_types_supported = fields.Dict(
        required=False,
        metadata={"example": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}},
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
