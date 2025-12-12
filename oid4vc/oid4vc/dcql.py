"""Digital Credentials Query Language evaluator."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from acapy_agent.core.profile import Profile

from oid4vc.cred_processor import CredProcessors
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation

ClaimsPath = List[str | int | None]
Absent = object()


class ClaimsPathPointer:
    """A pointer into a JSON structure, identifying one or more claims in a VC.

    Example:
    {
        "name": "Arthur Dent",
        "address": {
            "street_address": "42 Market Street",
            "locality": "Milliways",
            "postal_code": "12345"
        },
        "degrees": [
            {
                "type": "Bachelor of Science",
                "university": "University of Betelgeuse"
            },
            {
                "type": "Master of Science",
                "university": "University of Betelgeuse"
            }
        ],
        "nationalities": ["British", "Betelgeusian"]
    }

    The following shows examples of claims path pointers and the respective selected
    claims:
    - ["name"]: The claim name with the value `Arthur Dent` is selected.
    - ["address"]: The claim address with its sub-claims as the value is selected.
    - ["address", "street_address"]: The claim street_address with the value
      `"42 Market Street"` is selected.
    - ["degrees", null, "type"]: All type claims in the degrees array are selected.
    - ["nationalities", 1]: The second nationality is selected.
    """

    def __init__(self, path: ClaimsPath):
        """Init the path pointer."""
        self.path = path

    @staticmethod
    def _str_component(component: str, selected: List[Any], next: List[Any]):
        """Handle a str component."""
        for element in selected:
            if not isinstance(element, dict):
                raise ValueError(
                    "Attempted to step into value by key when value is not an object"
                )
            if component in element:
                next.append(element[component])

    @staticmethod
    def _null_component(selected: List[Any], next: List[Any]):
        """Handle a null component."""
        for element in selected:
            if not isinstance(element, list):
                raise ValueError(
                    "Attempted to select all elements of list but got "
                    "value that is not a list"
                )
            next.extend(element)

    @staticmethod
    def _int_component(component: int, selected: List[Any], next: List[Any]):
        """Handle an int component."""
        for element in selected:
            if not isinstance(element, list):
                raise ValueError(
                    "Attempted to step into value by index when value is not a list"
                )
            if 0 <= component < len(element):
                next.append(element[component])

    def resolve(self, source: Any):
        """Resolve a value from a source object using this path pointer."""
        selected = [source]
        for component in self.path:
            next = []
            if isinstance(component, str):
                self._str_component(component, selected, next)
            elif component is None:
                self._null_component(selected, next)
            elif isinstance(component, int) and component > -1:
                self._int_component(component, selected, next)
            else:
                raise ValueError(
                    f"Invalid type {type(component).__name__} component in path pointer"
                )
            selected = next
        return selected


@dataclass
class DCQLVerifyResult:
    """Result of verification."""

    verified: bool = False
    cred_query_id_to_claims: Dict[str, dict] = field(default_factory=dict)
    details: Optional[str] = None


class DCQLQueryEvaluator:
    """Evaluate a query against a submission to ensure it matches."""

    def __init__(self, query: DCQLQuery):
        """Init the evaluator."""
        self.query: DCQLQuery = query

    @classmethod
    def compile(cls, query: dict | DCQLQuery) -> "DCQLQueryEvaluator":
        """Compile an evaluator."""
        if isinstance(query, dict):
            query = DCQLQuery.deserialize(query)

        return cls(query)

    async def verify(
        self,
        profile: Profile,
        vp_token: Dict[str, Any],
        presentation_record: OID4VPPresentation,
    ):
        """Verify a submission against the query."""
        # TODO: we're ignoring CredentialSets for now, and assuming that all Credentials
        # in the CredentialList are required, to simplify the initial implementation
        # We're also ignoring ClaimSets for now ~ mepeltier

        processors = profile.inject(CredProcessors)
        id_to_claim = {}

        for cred in self.query.credentials:
            pres_list = vp_token.get(cred.credential_query_id)
            if not pres_list:
                return DCQLVerifyResult(
                    details=f"Missing presentation for {cred.credential_query_id}"
                )

            # DCQL vp_token format: {credential_query_id: [presentations...]}
            # The value is always an array of presentations per the spec
            # For now, we verify the first presentation in the array
            if isinstance(pres_list, list):
                if len(pres_list) == 0:
                    return DCQLVerifyResult(
                        details=f"Empty presentation array for {cred.credential_query_id}"
                    )
                pres = pres_list[0]
            else:
                # Handle case where it's already a single presentation (backwards compat)
                pres = pres_list

            pres_verifier = processors.pres_verifier_for_format(cred.format)

            vp_result = await pres_verifier.verify_presentation(
                profile=profile,
                presentation=pres,
                presentation_record=presentation_record,
            )
            if not vp_result.verified:
                return DCQLVerifyResult(
                    details=f"Presentation for {cred.credential_query_id} "
                    "failed verification"
                )

            cred_verifier = processors.cred_verifier_for_format(cred.format)

            vc_result = await cred_verifier.verify_credential(
                profile=profile,
                credential=vp_result.payload,
            )
            if not vc_result.verified:
                return DCQLVerifyResult(
                    details=f"Credential for {cred.credential_query_id} "
                    "failed verification"
                )

            # Doctype validation for mDOC credentials
            if cred.meta:
                # Get expected doctype(s) from the query
                expected_doctypes = []
                if cred.meta.doctype_value:
                    expected_doctypes = [cred.meta.doctype_value]
                elif cred.meta.doctype_values:
                    expected_doctypes = cred.meta.doctype_values

                if expected_doctypes:
                    # mDOC credentials include doctype in payload
                    presented_doctype = vc_result.payload.get("docType")
                    if presented_doctype is None:
                        return DCQLVerifyResult(
                            details=f"Credential for {cred.credential_query_id} "
                            "is missing doctype"
                        )
                    if presented_doctype not in expected_doctypes:
                        return DCQLVerifyResult(
                            details=f"Presented doctype '{presented_doctype}' does not "
                            f"match requested doctype(s): {expected_doctypes}"
                        )

            if cred.meta and cred.meta.vct_values:
                presented_vct = vc_result.payload.get("vct")
                vct = cred.meta.vct_values

                if presented_vct not in vct:
                    return DCQLVerifyResult(
                        details="Presented vct does not match requested vct(s)."
                    )

            # Handle claims verification for both JSON-based (path) and mDOC (namespace/claim_name) formats
            for claim in cred.claims or []:
                if claim.path is not None:
                    # JSON-based claims structure (SD-JWT, etc.) - use path pointer
                    path = claim.path
                    pointer = ClaimsPathPointer(path)
                    try:
                        value = pointer.resolve(vc_result.payload)
                        if claim.values and value not in claim.values:
                            return DCQLVerifyResult(
                                details="Credential presented did not "
                                "match the values required by the query"
                            )
                    except ValueError:
                        return DCQLVerifyResult(details=f"Path {path} does not exist")
                elif claim.namespace is not None and claim.claim_name is not None:
                    # mDOC format - use namespace/claim_name syntax
                    # mDOC payload structure is typically: {"namespace": {"claim_name": value}}
                    namespace_data = vc_result.payload.get(claim.namespace)
                    if namespace_data is None:
                        return DCQLVerifyResult(
                            details=f"Namespace {claim.namespace} does not exist in credential"
                        )
                    if claim.claim_name not in namespace_data:
                        return DCQLVerifyResult(
                            details=f"Claim {claim.claim_name} does not exist in namespace {claim.namespace}"
                        )
                    value = namespace_data[claim.claim_name]
                    if claim.values and value not in claim.values:
                        return DCQLVerifyResult(
                            details="Credential presented did not "
                            "match the values required by the query"
                        )
                # If neither path nor namespace/claim_name is set, skip the claim check

            id_to_claim[cred.credential_query_id] = vc_result.payload

        return DCQLVerifyResult(verified=True, cred_query_id_to_claims=id_to_claim)
