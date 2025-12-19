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
        import logging

        LOGGER = logging.getLogger(__name__)
        LOGGER.info(
            f"to_issuer_metadata: format={self.format}, binding_methods={self.cryptographic_binding_methods_supported}"
        )

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
                # OID4VCI 1.0 §11.2.3.1: credential_definition ONLY contains:
                # - @context (optional)
                # - type (required)
                # - credentialSubject (optional)
                cred_def = {}
                format_data = self.format_data.copy()

                # Handle @context
                context = format_data.pop("context", None) or format_data.pop(
                    "@context", None
                )
                if context:
                    cred_def["@context"] = context

                # Handle type/types
                types_value = format_data.pop("types", None) or format_data.pop(
                    "type", None
                )
                if types_value:
                    cred_def["type"] = types_value
                    # Also add at top level for backward compatibility with walt.id
                    # and other wallets still using older OID4VCI drafts
                    issuer_metadata["types"] = types_value

                # Handle credentialSubject - can come from "credentialSubject" or "claims"
                # OID4VCI 1.0 uses "credentialSubject" for jwt_vc_json format (flat map)
                # Some implementations incorrectly put "claims" here
                cred_subject = format_data.pop("credentialSubject", None)
                if not cred_subject:
                    # If claims is a flat map (not namespaced), treat it as credentialSubject
                    claims = format_data.pop("claims", None)
                    if claims:
                        cred_subject = claims
                if cred_subject:
                    cred_def["credentialSubject"] = cred_subject

                # Handle display - MUST be at top level, not inside credential_definition
                display_from_format_data = format_data.pop("display", None)
                if display_from_format_data and "display" not in issuer_metadata:
                    issuer_metadata["display"] = display_from_format_data

                # Handle fields that belong at top level of credential config, not in cred_def
                # These may have been incorrectly placed in format_data
                top_level_fields = [
                    "cryptographic_binding_methods_supported",
                    "cryptographic_suites_supported",
                    "proof_types_supported",
                    "scope",
                ]
                for field in top_level_fields:
                    if field in format_data and field not in issuer_metadata:
                        value = format_data.pop(field)
                        if field == "cryptographic_suites_supported":
                            # Rename to spec-compliant name
                            issuer_metadata[
                                "credential_signing_alg_values_supported"
                            ] = value
                        else:
                            issuer_metadata[field] = value

                if cred_def:
                    issuer_metadata["credential_definition"] = cred_def
            else:
                # For other formats (e.g. mso_mdoc, vc+sd-jwt), flatten
                # But first handle display which must be at top level
                format_data = self.format_data.copy()
                display_from_format_data = format_data.pop("display", None)
                if display_from_format_data and "display" not in issuer_metadata:
                    issuer_metadata["display"] = display_from_format_data

                # For vc+sd-jwt format, walt.id expects "credentialSubject" not "claims"
                # The claims field is used internally for validation, but the output
                # should use credentialSubject for wallet compatibility
                if self.format == "vc+sd-jwt" and "claims" in format_data:
                    claims = format_data.pop("claims")
                    format_data["credentialSubject"] = claims

                issuer_metadata.update(format_data)
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
        metadata={
            "example": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}
        },
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
