"""Supported Credential Record."""

from typing import Any, Dict, List, Optional

from marshmallow import fields, validate
from aries_cloudagent.messaging.models.base import BaseModelSchema

from oid4vc.models.supported_cred import SupportedCredential, SupportedCredentialSchema


class JwtSupportedCredential(SupportedCredential):
    """JWT Supported Credential Record."""

    class Meta:
        """JwtSupportedCredential metadata."""

        schema_class = "JwtSupportedCredentialSchema"

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
        credential_subject: Optional[Dict[str, Any]] = None,
        order: Optional[List[str]] = None,
        type: List[str],
        context: List[Any],
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
            credential_subject: Metadata about the Credential Subject.
            type: List of credential types supported.
            order: The order in which claims should be displayed.
            context: A list of JSON-LD contexts.
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
        self.credential_subject = credential_subject
        self.type = type
        self.order = order
        self.context = context

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
                "order",
            )
            if (value := getattr(self, prop)) is not None
        }

        issuer_metadata["id"] = self.identifier
        issuer_metadata["credentialSubject"] = self.credential_subject
        issuer_metadata["types"] = self.type

        return issuer_metadata


class CredentialSubjectValueSchema(BaseModelSchema):
    """Schema for a nested credential subject."""

    mandatory = fields.Bool(
        required=False,
        metadata={
            "description": "Boolean which when set to true indicates the claim "
            "MUST be present in the issued Credential. If the mandatory property is "
            "omitted its default should be assumed to be false."
        },
    )

    value_type = fields.Str(
        required=False,
        metadata={
            "description": "String value determining type of value of the claim. A "
            "non-exhaustive list of valid values defined by this specification are "
            "string, number, and image media types such as image/jpeg as defined in "
            "IANA media type registry for images"
        },
    )

    display = fields.List(
        fields.Dict,
        required=False,
        metadata={
            "description": "An array of objects, where each object contains display "
            "properties of a certain claim in the Credential for a certain language. "
        },
    )


class JwtSupportedCredentialSchema(SupportedCredentialSchema):
    """Schema for JwtSupportedCredential."""

    class Meta:
        """JwtSupportedCredentialSchema metadata."""

        model_class = JwtSupportedCredential

    format = fields.Str(
        required=True,
        metadata={"example": "jwt_vc_json"},
        validate=validate.OneOf(["jwt_vc_json"]),
    )

    type = fields.List(
        fields.Str,
        required=True,
        metadata={"description": "List of credential types supported."},
    )

    credential_subject = fields.Dict(
        keys=fields.Str,
        data_key="credentialSubject",
        required=False,
        metadata={
            "description": "Metadata about the Credential Subject.",
            "example": {
                "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
                "last_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
                "degree": {},
                "gpa": {"display": [{"name": "GPA"}]},
            },
        },
    )

    order = fields.List(
        fields.Str,
        required=False,
        metadata={"description": "The order in which claims should be displayed."},
    )

    context = fields.List(
        fields.Raw,
        data_key="@context",
        required=True,
        metadata={
            "example": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
        },
    )
