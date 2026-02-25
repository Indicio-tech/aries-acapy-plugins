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

    # Formats where format_data fields go directly at the top level of the
    # credential configuration (per OID4VCI spec), NOT inside credential_definition.
    # - vc+sd-jwt / dc+sd-jwt: top-level fields include vct, claims, display, etc.
    # - mso_mdoc: top-level fields include doctype, claims, display, etc.
    TOP_LEVEL_FORMAT_DATA_FORMATS = {"vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"}

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
                "proof_types_supported",
                "display",
            )
            if (value := getattr(self, prop)) is not None
        }
        alg_supported = issuer_metadata.pop("cryptographic_suites_supported", None)
        if alg_supported:
            issuer_metadata["credential_signing_alg_values_supported"] = alg_supported
        # NOTE: Do NOT add "id" here — per OID4VCI spec §11.2.3, the credential
        # configuration identifier is ONLY the map key in
        # credential_configurations_supported, never a field inside the object.

        format_data = self.format_data or {}
        if self.format in self.TOP_LEVEL_FORMAT_DATA_FORMATS:
            # For SD-JWT (vc+sd-jwt, dc+sd-jwt) and mDOC formats, format_data
            # fields (e.g. vct, claims, doctype) belong at the top level of the
            # credential configuration object per OID4VCI spec.
            for key, value in format_data.items():
                if value is None:
                    continue
                if key == "cryptographic_suites_supported":
                    # Deprecated field — convert to the OID4VCI 1.0 name if not
                    # already set by the model-level attribute above.
                    if "credential_signing_alg_values_supported" not in issuer_metadata:
                        issuer_metadata["credential_signing_alg_values_supported"] = value
                    # Don't add the deprecated name to the output.
                    continue
                issuer_metadata[key] = value
        else:
            # For JWT VC JSON, JSON-LD, and other formats, format_data is
            # wrapped in credential_definition per OID4VCI spec.
            credential_definition = dict(format_data)
            context = credential_definition.pop("context", None)
            if context:
                credential_definition["@context"] = context
            issuer_metadata["credential_definition"] = {
                k: v for k, v in credential_definition.items() if v is not None
            }

        # ── Format-specific post-processing ────────────────────────────────────

        # SD-JWT VC (dc+sd-jwt / vc+sd-jwt): the OIDF conformance test requires
        # `claims` to be an array of per-claim objects (not a dict) per the
        # latest OID4VCI spec.  Stored format_data uses the legacy dict form
        # {claim_name: {display: ...}}, so convert it here.
        if self.format in ("dc+sd-jwt", "vc+sd-jwt"):
            claims = issuer_metadata.get("claims")
            if isinstance(claims, dict):
                claims_arr = []
                for claim_name, claim_meta in claims.items():
                    entry: dict = {"path": [claim_name]}
                    if isinstance(claim_meta, dict):
                        if "display" in claim_meta:
                            entry["display"] = claim_meta["display"]
                        if "mandatory" in claim_meta:
                            entry["mandatory"] = claim_meta["mandatory"]
                    claims_arr.append(entry)
                issuer_metadata["claims"] = claims_arr

        # mso_mdoc: `credential_signing_alg_values_supported` must contain COSE
        # algorithm integer identifiers (e.g. -7 for ES256), NOT string names.
        # Convert any string entries (from old configs) to COSE integers.
        if self.format == "mso_mdoc":
            _COSE_ALG = {"ES256": -7, "ES384": -35, "ES512": -36, "ES256K": -47}
            algs = issuer_metadata.get("credential_signing_alg_values_supported")
            if algs:
                issuer_metadata["credential_signing_alg_values_supported"] = [
                    _COSE_ALG.get(a, a) if isinstance(a, str) else a for a in algs
                ]

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
