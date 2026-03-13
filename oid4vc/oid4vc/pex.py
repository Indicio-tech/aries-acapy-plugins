"""Presentation Exchange evaluation."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

import jsonpath_ng as jsonpath
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModel, BaseModelSchema
from acapy_agent.messaging.valid import UUID4_EXAMPLE
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    DIFField,
    InputDescriptors,
    PresentationDefinition,
    SubmissionRequirements,
)
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    InputDescriptorMapping as InnerInDescMapping,
)
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    InputDescriptorMappingSchema as InnerInDescMappingSchema,
)
from jsonpath_ng import DatumInContext as Matched
from jsonpath_ng import JSONPath
from jsonschema import Draft7Validator, ValidationError
from marshmallow import EXCLUDE, fields

from oid4vc.cred_processor import CredProcessors
from oid4vc.jwt import jwt_verify

# Credential formats that support selective disclosure (PEX §7.1.3 limit_disclosure)
_SELECTIVE_DISCLOSURE_FORMATS = frozenset({"vc+sd-jwt", "mso_mdoc"})


# TODO Update ACA-Py's InputDescriptorMapping model to match this
class InputDescriptorMapping(BaseModel):
    """Single InputDescriptorMapping object."""

    class Meta:
        """InputDescriptorMapping metadata."""

        schema_class = "InputDescriptorMappingSchema"

    def __init__(
        self,
        *,
        id: str,
        fmt: str,
        path: str,
        path_nested: Optional[InnerInDescMapping] = None,
    ):
        """Initialize InputDescriptorMapping."""
        self.id = id
        self.fmt = fmt
        self.path = path
        self.path_nested = path_nested


class InputDescriptorMappingSchema(BaseModelSchema):
    """Single InputDescriptorMapping Schema."""

    class Meta:
        """InputDescriptorMappingSchema metadata."""

        model_class = InputDescriptorMapping
        unknown = EXCLUDE

    # PEX 2.0 §5.1.1 technically requires `id` in every descriptor_map entry.
    # However, some wallets (e.g. waltid) omit it in practice.  Making the
    # field optional here is a deliberate interoperability relaxation for
    # non-conformant wallets; the evaluator compensates with positional
    # matching as a fallback (see PresentationExchangeEvaluator.verify).
    id = fields.Str(required=False, load_default=None, metadata={"description": "ID"})
    fmt = fields.Str(
        required=True,
        dump_default="ldp_vc",
        data_key="format",
        metadata={"description": "Format"},
    )
    path = fields.Str(required=True, metadata={"description": "Path"})
    path_nested = fields.Nested(
        InnerInDescMappingSchema(),
        required=False,
        metadata={"description": "Path nested"},
    )


# TODO Update ACA-Py's Pres Submission model to match this
class PresentationSubmission(BaseModel):
    """Single PresentationSubmission object."""

    class Meta:
        """PresentationSubmission metadata."""

        schema_class = "PresentationSubmissionSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        definition_id: Optional[str] = None,
        descriptor_maps: Optional[Sequence[InputDescriptorMapping]] = None,
    ):
        """Initialize InputDescriptorMapping."""
        self.id = id
        self.definition_id = definition_id
        self.descriptor_maps = descriptor_maps


class PresentationSubmissionSchema(BaseModelSchema):
    """Single PresentationSubmission Schema."""

    class Meta:
        """PresentationSubmissionSchema metadata."""

        model_class = PresentationSubmission
        unknown = EXCLUDE

    id = fields.Str(
        required=False,
        metadata={"description": "ID", "example": UUID4_EXAMPLE},
    )
    definition_id = fields.Str(
        required=False,
        metadata={"description": "DefinitionID", "example": UUID4_EXAMPLE},
    )
    descriptor_maps = fields.List(
        fields.Nested(InputDescriptorMappingSchema),
        required=False,
        data_key="descriptor_map",
    )


class FilterEvaluator:
    """Evaluate a filter."""

    def __init__(self, validator: Draft7Validator):
        """Initliaze."""
        self.validator = validator

    @classmethod
    def compile(cls, filter: dict) -> "FilterEvaluator":
        """Compile an input descriptor."""
        Draft7Validator.check_schema(filter)
        validator = Draft7Validator(filter)
        return cls(validator)

    def match(self, value: Any) -> bool:
        """Check value."""
        try:
            self.validator.validate(value)
            return True
        except ValidationError:
            return False


class ConstraintFieldEvaluator:
    """Evaluate a constraint."""

    def __init__(
        self,
        paths: Sequence[JSONPath],
        filter: Optional[FilterEvaluator] = None,
        # TODO Add `name`
    ):
        """Initialize the constraint field evaluator."""
        self.paths = paths
        self.filter = filter

    @classmethod
    def compile(
        cls,
        constraint: Union[dict, DIFField],
        raw_filter: Optional[dict] = None,
    ):
        """Compile an input descriptor.

        raw_filter, if supplied, is the original JSON Schema dict for the field's
        filter as it appeared in the PD before ACA-Py deserialization.  ACA-Py's
        DIFField.Filter model silently drops nested keywords such as 'contains',
        'anyOf', and '$ref', so we use the raw dict when available to ensure the
        full JSON Schema filter is evaluated (PEX §7.1.1).
        """
        if isinstance(constraint, dict):
            if raw_filter is None:
                raw_filter = constraint.get("filter")
            constraint = DIFField.deserialize(constraint)
        elif isinstance(constraint, DIFField):
            pass
        else:
            raise TypeError("constraint must be dict or DIFField")

        paths = [jsonpath.parse(path) for path in constraint.paths]

        filter_ev = None
        if raw_filter is not None:
            filter_ev = FilterEvaluator.compile(raw_filter)
        elif constraint._filter:
            filter_ev = FilterEvaluator.compile(constraint._filter.serialize())

        return cls(paths, filter_ev)

    def match(self, value: Any) -> Optional[Matched]:
        """Check if value matches and return path of first matching."""
        matched: Sequence[Matched] = [
            found for path in self.paths for found in path.find(value)
        ]
        if matched and self.filter is not None:
            for match in matched:
                if self.filter.match(match.value):
                    return match
            return None

        if matched:
            return matched[0]

        return None


class DescriptorMatchFailed(Exception):
    """Raised when a Descriptor fails to match."""


class DescriptorEvaluator:
    """Evaluate input descriptors."""

    def __init__(
        self,
        id: str,
        field_constraints: List[ConstraintFieldEvaluator],
        limit_disclosure: Optional[str] = None,
        groups: Optional[List[str]] = None,
    ):
        """Initialize descriptor evaluator."""
        self.id = id
        self._field_constraints = field_constraints
        self.limit_disclosure = limit_disclosure
        self.groups = groups or []

    @classmethod
    def compile(
        cls,
        descriptor: Union[dict, InputDescriptors],
        raw_descriptor: Optional[dict] = None,
    ) -> "DescriptorEvaluator":
        """Compile an input descriptor.

        raw_descriptor, if supplied, is the original descriptor dict before ACA-Py
        deserialization so that raw filter dicts (including keywords dropped by
        ACA-Py's Filter model) are preserved for each field.
        """
        if isinstance(descriptor, dict):
            raw_descriptor = descriptor
            descriptor = InputDescriptors.deserialize(descriptor)
        elif isinstance(descriptor, InputDescriptors):
            pass
        else:
            raise TypeError("descriptor must be dict or InputDescriptor")

        # Extract raw filter dicts from the original descriptor dict so that
        # keywords silently dropped by ACA-Py's Filter model (e.g. 'contains')
        # are preserved for JSONSchema evaluation (PEX §7.1.1).
        raw_fields: List[Optional[dict]] = []
        if raw_descriptor:
            for rf in (raw_descriptor.get("constraints") or {}).get("fields") or []:
                raw_fields.append(rf.get("filter") if isinstance(rf, dict) else None)

        acapy_fields = descriptor.constraint._fields if descriptor.constraint else []
        field_constraints = [
            ConstraintFieldEvaluator.compile(
                constraint,
                raw_filter=raw_fields[i] if i < len(raw_fields) else None,
            )
            for i, constraint in enumerate(acapy_fields)
        ]

        limit_disclosure = (
            descriptor.constraint.limit_disclosure if descriptor.constraint else None
        )
        groups = list(descriptor.groups or [])
        return cls(
            descriptor.id,
            field_constraints,
            limit_disclosure=limit_disclosure,
            groups=groups,
        )

    def match(self, value: Any) -> Dict[str, Any]:
        """Check value."""
        matched_fields = {}
        for constraint in self._field_constraints:
            matched = constraint.match(value)
            if matched is None:
                raise DescriptorMatchFailed("Failed to match descriptor to submission")
            matched_fields[str(matched.full_path)] = matched.value
        return matched_fields


@dataclass
class PexVerifyResult:
    """Result of verification."""

    verified: bool = False
    descriptor_id_to_claims: Dict[str, dict] = field(default_factory=dict)
    descriptor_id_to_fields: Dict[str, Any] = field(default_factory=dict)
    details: Optional[str] = None


class PresentationExchangeEvaluator:
    """Evaluate presentation submissions against presentation definitions."""

    def __init__(
        self,
        id: str,
        descriptors: List[DescriptorEvaluator],
        submission_requirements: Optional[List[SubmissionRequirements]] = None,
    ):
        """Initialize the evaluator."""
        self.id = id
        self._id_to_descriptor: Dict[str, DescriptorEvaluator] = {
            desc.id: desc for desc in descriptors
        }
        self._submission_requirements: List[SubmissionRequirements] = (
            submission_requirements or []
        )

    @classmethod
    def compile(cls, definition: Union[dict, PresentationDefinition]):
        """Compile a presentation definition object into evaluatable state."""
        # Keep raw descriptor dicts (keyed by id) so that filter keywords dropped
        # by ACA-Py's model (e.g. 'contains') can be recovered during compilation.
        raw_by_id: Dict[str, dict] = {}
        if isinstance(definition, dict):
            for rd in definition.get("input_descriptors") or []:
                if isinstance(rd, dict) and "id" in rd:
                    raw_by_id[rd["id"]] = rd
            definition = PresentationDefinition.deserialize(definition)
        elif isinstance(definition, PresentationDefinition):
            pass
        else:
            raise TypeError("definition must be dict or PresentationDefinition")

        descriptors = [
            DescriptorEvaluator.compile(desc, raw_descriptor=raw_by_id.get(desc.id))
            for desc in definition.input_descriptors
        ]
        return cls(
            definition.id,
            descriptors,
            submission_requirements=definition.submission_requirements or [],
        )

    async def verify(
        self,
        profile: Profile,
        submission: Union[dict, PresentationSubmission],
        presentation: Mapping[str, Any],
    ) -> PexVerifyResult:
        """Check if a submission matches the definition."""
        if isinstance(submission, dict):
            submission = PresentationSubmission.deserialize(submission)
        elif isinstance(submission, PresentationSubmission):
            pass
        else:
            raise TypeError("submission must be dict or PresentationSubmission")

        if submission.definition_id != self.id:
            return PexVerifyResult(details="Submission id doesn't match definition")

        descriptor_id_to_claims = {}
        descriptor_id_to_fields = {}
        descriptors_list = list(self._id_to_descriptor.values())
        for idx, item in enumerate(submission.descriptor_maps or []):
            # JWT VP outer wrapper: when the submission descriptor format is
            # jwt_vp, the presentation is a raw JWT string that wraps VCs inside
            # a "vp" claim.  Decode and verify the outer envelope first, then
            # use the decoded VP payload dict for JSONPath evaluation below.
            vp_payload = presentation
            if item.fmt == "jwt_vp" and isinstance(vp_payload, str):
                vp_result = await jwt_verify(profile, vp_payload)
                if not vp_result.verified:
                    return PexVerifyResult(
                        details="JWT VP outer wrapper signature verification failed"
                    )
                vp_payload = vp_result.payload

            evaluator = self._id_to_descriptor.get(item.id) if item.id else None
            if not evaluator and item.id is None and idx < len(descriptors_list):
                # Deliberate interoperability relaxation: PEX 2.0 §5.1.1
                # requires descriptor_map entries to carry an `id` that
                # matches an input descriptor id, but some wallets (e.g.
                # waltid) omit the field entirely.  When id is absent we
                # fall back to positional matching — the Nth submission entry
                # is evaluated against the Nth input descriptor.  Named
                # lookup (above) always takes priority when id IS present.
                evaluator = descriptors_list[idx]
            if not evaluator:
                return PexVerifyResult(
                    details=f"Could not find input descriptor corresponding to {item.id}"
                )

            # PEX §7.1.3 — limit_disclosure: required means the credential MUST
            # use a format that supports selective disclosure (SD-JWT or mDOC).
            if evaluator.limit_disclosure == "required":
                fmt = item.path_nested.fmt if item.path_nested else item.fmt
                if fmt not in _SELECTIVE_DISCLOSURE_FORMATS:
                    return PexVerifyResult(
                        details=(
                            f"Descriptor '{evaluator.id}' requires"
                            " limit_disclosure=required but submitted"
                            f" format '{fmt}' does not support"
                            " selective disclosure"
                        )
                    )

            processors = profile.inject(CredProcessors)
            if item.path_nested:
                assert item.path_nested.path
                path = jsonpath.parse(item.path_nested.path)
                values = path.find(vp_payload)
                if len(values) != 1:
                    return PexVerifyResult(
                        details="More than one value found for path "
                        f"{item.path_nested.path}"
                    )

                vc = values[0].value
                processor = processors.cred_verifier_for_format(item.path_nested.fmt)
            else:
                vc = vp_payload
                processor = processors.cred_verifier_for_format(item.fmt)

            result = await processor.verify_credential(profile, vc)
            if not result.verified:
                return PexVerifyResult(details="Credential signature verification failed")

            try:
                fields = evaluator.match(result.payload)
            except DescriptorMatchFailed:
                return PexVerifyResult(
                    details="Credential did not match expected descriptor constraints"
                )

            # Use evaluator.id (the real descriptor ID) rather than item.id,
            # which may be None for positional-fallback submissions.
            descriptor_id_to_claims[evaluator.id] = result.payload
            descriptor_id_to_fields[evaluator.id] = fields

        satisfied_ids = set(descriptor_id_to_claims.keys())

        if self._submission_requirements:
            # PEX §4.1 — enforce group rules declared in submission_requirements.
            for sr in self._submission_requirements:
                if not sr._from:
                    # from_nested groups not yet supported; skip
                    continue
                group_desc_ids = {
                    did
                    for did, desc in self._id_to_descriptor.items()
                    if sr._from in (desc.groups or [])
                }
                n = sum(1 for did in satisfied_ids if did in group_desc_ids)
                if sr.rule == "pick":
                    if sr.count is not None and n != sr.count:
                        return PexVerifyResult(
                            details=(
                                f"Group '{sr._from}': pick rule requires exactly "
                                f"{sr.count} descriptor(s), got {n}"
                            )
                        )
                    if sr.minimum is not None and n < sr.minimum:
                        return PexVerifyResult(
                            details=(
                                f"Group '{sr._from}': pick rule requires at least "
                                f"{sr.minimum} descriptor(s), got {n}"
                            )
                        )
                    if sr.maximum is not None and n > sr.maximum:
                        return PexVerifyResult(
                            details=(
                                f"Group '{sr._from}': pick rule requires at most "
                                f"{sr.maximum} descriptor(s), got {n}"
                            )
                        )
                elif sr.rule == "all":
                    if n != len(group_desc_ids):
                        return PexVerifyResult(
                            details=(
                                f"Group '{sr._from}': 'all' rule requires all "
                                f"{len(group_desc_ids)} descriptor(s), got {n}"
                            )
                        )
        else:
            # PEX §5 — when no submission_requirements are declared, the submission
            # MUST include an entry for every input_descriptor.
            missing = set(self._id_to_descriptor.keys()) - satisfied_ids
            if missing:
                return PexVerifyResult(
                    details=f"Submission missing required descriptors: {missing}"
                )

        return PexVerifyResult(
            verified=True,
            descriptor_id_to_claims=descriptor_id_to_claims,
            descriptor_id_to_fields=descriptor_id_to_fields,
        )
