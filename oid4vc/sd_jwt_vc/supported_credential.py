"""Supported Credential Record."""

from typing import Any, Dict, List, Optional


from marshmallow import fields

from oid4vc.models.supported_cred import SupportedCredential, SupportedCredentialSchema


class SdJwtSupportedCredential(SupportedCredential):
    """SD-JWT Supported Credential Record."""

    class Meta:
        """SdJwtSupportedCredential metadata."""

        schema_class = "SdJwtSupportedCredentialSchema"

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
        claims: Optional[Dict[str, Any]] = None,
        order: Optional[List[str]] = None,
        sd_list: Optional[List[str]] = None,
        vct: str,
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
            vct: String designating the type of a Credential.
            order: The order in which claims should be displayed.
            claims: Dictionary of selectively disclosable claims.
            sd_list: List of JSON pointers to selectively disclosable claims.
            kwargs: Keyword arguments to allow generic initialization of the record.
        """
        super().__init__(
            supported_cred_id=supported_cred_id,
            format=format,
            identifier=identifier,
            cryptographic_binding_methods_supported=cryptographic_binding_methods_supported,
            cryptographic_suites_supported=cryptographic_suites_supported,
            display=display,
            **kwargs,
        )
        self.vct = vct
        self.claims = claims
        self.order = order
        self.sd_list = sd_list

    @property
    def supported_cred_id(self):
        """Accessor for the ID associated with this record."""
        return self._id

    def to_issuer_metadata(self) -> dict:
        """Return a representation of this record as issuer metadata.

        To arrive at the structure defined by the specification, it must be
        derived from this record (the record itself is not exactly aligned with
        the spec).
        """
        issuer_metadata = {
            prop: value
            for prop in (
                "format",
                "cryptographic_binding_methods_supported",
                "cryptographic_suites_supported",
                "display",
                "vct",
                "order",
                "claims",
            )
            if (value := getattr(self, prop)) is not None
        }

        issuer_metadata["id"] = self.identifier

        return issuer_metadata


class SdJwtSupportedCredentialSchema(SupportedCredentialSchema):
    """Schema for SdJwtSupportedCredential."""

    class Meta:
        """SdJwtSupportedCredentialSchema metadata."""

        model_class = SdJwtSupportedCredential

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

    vct = fields.Str(
        required=True,
        metadata={"description": "String designating the type of a Credential."},
    )

    order = fields.List(
        fields.Str,
        required=False,
        metadata={"description": "The order in which claims should be displayed."},
    )

    claims = fields.Dict(
        keys=fields.Str,
        required=False,
        metadata={"description": "Selectively disclosable claims."},
    )

    sd_list = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": "List of JSON pointers to selectively disclosable attributes."
        },
    )
