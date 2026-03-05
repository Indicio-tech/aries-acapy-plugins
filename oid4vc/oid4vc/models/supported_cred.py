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
        # Handle type and @context if they are passed in kwargs (top level in JSON)
        # by moving them to vc_additional_data
        if "type" in kwargs:
            type_val = kwargs.pop("type")
            if vc_additional_data is None:
                vc_additional_data = {}
            if "type" not in vc_additional_data:
                vc_additional_data["type"] = type_val

        if "@context" in kwargs:
            context_val = kwargs.pop("@context")
            if vc_additional_data is None:
                vc_additional_data = {}
            if "@context" not in vc_additional_data:
                vc_additional_data["@context"] = context_val

        super().__init__(supported_cred_id, **kwargs)
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

    def to_issuer_metadata(self, issuer=None) -> dict:
        """Return a representation of this record as issuer metadata.

        To arrive at the structure defined by the specification, it must be
        derived from this record (the record itself is not exactly aligned with
        the spec).

        Args:
            issuer: Optional credential issuer processor. If the processor
                implements ``format_data_is_top_level()`` (returns True) the
                format_data fields are emitted at the top level of the
                credential configuration object rather than being wrapped in
                ``credential_definition``.  If the processor additionally
                implements ``transform_issuer_metadata(metadata)`` that method
                is called with the partially-built metadata dict for any
                format-specific post-processing (e.g. converting algorithm
                names, reshaping claims arrays).
        """
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
        alg_supported = issuer_metadata.pop("cryptographic_suites_supported", None)
        if alg_supported:
            issuer_metadata["credential_signing_alg_values_supported"] = alg_supported

        # NOTE: Per OID4VCI spec §11.2.3, the credential configuration identifier
        # is ONLY the map key in credential_configurations_supported, never a
        # field inside the object.  Do NOT add "id" here.

        format_data = self.format_data or {}

        # Extension point: processors can opt in to top-level format_data layout
        # (used by SD-JWT and mDOC formats per OID4VCI spec) by implementing
        # format_data_is_top_level().  Falls back to the legacy
        # credential_definition wrapping used by jwt_vc_json / ldp_vc.
        use_top_level = hasattr(issuer, "format_data_is_top_level") and bool(
            issuer.format_data_is_top_level()
        )

        if use_top_level:
            # SD-JWT and mDOC formats: format_data fields (e.g. vct, claims,
            # doctype) belong at the top level of the credential configuration.
            for key, value in format_data.items():
                if value is None:
                    continue
                if key == "cryptographic_suites_supported":
                    # Deprecated field — promote to OID4VCI 1.0 name if not
                    # already set by the model-level attribute above.
                    if "credential_signing_alg_values_supported" not in issuer_metadata:
                        issuer_metadata["credential_signing_alg_values_supported"] = value
                    continue
                issuer_metadata[key] = value
        else:
            # JWT VC JSON, JSON-LD, and other formats: format_data is wrapped in
            # credential_definition per OID4VCI spec.
            credential_definition = dict(format_data)
            context = credential_definition.pop("context", None)
            if context:
                credential_definition["@context"] = context
            issuer_metadata["credential_definition"] = {
                k: v for k, v in credential_definition.items() if v is not None
            }

        # Extension point: processors can implement transform_issuer_metadata()
        # to perform format-specific post-processing (e.g. COSE algorithm name
        # → integer conversion for mDOC, claims dict → array for SD-JWT).
        # The method receives the metadata dict and may mutate it in place.
        if hasattr(issuer, "transform_issuer_metadata"):
            issuer.transform_issuer_metadata(issuer_metadata)

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
