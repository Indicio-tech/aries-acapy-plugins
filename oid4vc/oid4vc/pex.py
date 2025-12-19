"""Presentation Exchange evaluation."""

import json
import logging
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

LOGGER = logging.getLogger(__name__)


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

    id = fields.Str(required=True, metadata={"description": "ID"})
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
    def compile(cls, constraint: Union[dict, DIFField]):
        """Compile an input descriptor."""
        if isinstance(constraint, dict):
            constraint = DIFField.deserialize(constraint)
        elif isinstance(constraint, DIFField):
            pass
        else:
            raise TypeError("constraint must be dict or DIFField")

        paths = [jsonpath.parse(path) for path in constraint.paths]

        filter = None
        if constraint._filter:
            filter = FilterEvaluator.compile(constraint._filter.serialize())

        return cls(paths, filter)

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
        formats: Optional[List[str]] = None,
    ):
        """Initialize descriptor evaluator."""
        self.id = id
        self._field_constraints = field_constraints
        self.formats = formats or []

    @classmethod
    def compile(
        cls, descriptor: Union[dict, InputDescriptors], raw_dict: Optional[dict] = None
    ) -> "DescriptorEvaluator":
        """Compile an input descriptor.

        Args:
            descriptor: The input descriptor object or dict
            raw_dict: Optional raw dictionary with format information (for ACA-Py < 1.5)
        """
        formats = []

        if isinstance(descriptor, dict):
            # Extract format from the dict before deserializing
            format_dict = descriptor.get("format", {})
            if format_dict:
                formats = list(format_dict.keys())
            LOGGER.info(f"PEX: Extracted formats from dict: {formats}")
            descriptor = InputDescriptors.deserialize(descriptor)
        elif isinstance(descriptor, InputDescriptors):
            # Try to get fmt attribute if it exists (ACA-Py >= 1.5)
            descriptor_fmt = getattr(descriptor, "fmt", None)
            if descriptor_fmt:
                # Get format names from the attributes
                for attr_name in vars(descriptor_fmt):
                    if not attr_name.startswith("_"):
                        value = getattr(descriptor_fmt, attr_name, None)
                        if value is not None:
                            formats.append(attr_name)
            # If fmt not available and raw_dict provided, use that
            elif raw_dict and "format" in raw_dict:
                formats = list(raw_dict.get("format", {}).keys())
            LOGGER.info(f"PEX: Extracted formats from object: {formats}")
        else:
            raise TypeError("descriptor must be dict or InputDescriptor")

        field_constraints = []
        if descriptor.constraint:
            field_constraints = [
                ConstraintFieldEvaluator.compile(constraint)
                for constraint in descriptor.constraint._fields
            ]

        return cls(descriptor.id, field_constraints, formats)

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

    def __init__(self, id: str, descriptors: List[DescriptorEvaluator]):
        """Initialize the evaluator."""
        self.id = id
        self._id_to_descriptor: Dict[str, DescriptorEvaluator] = {
            desc.id: desc for desc in descriptors
        }

    @classmethod
    def compile(
        cls,
        definition: Union[dict, PresentationDefinition],
        raw_definition: Optional[dict] = None,
    ):
        """Compile a presentation definition object into evaluatable state.

        Args:
            definition: The presentation definition object or dict
            raw_definition: Optional raw dictionary for format extraction (for ACA-Py < 1.5)
        """
        raw_descriptors = {}
        if isinstance(definition, dict):
            # Store the raw input_descriptors for format extraction
            for desc in definition.get("input_descriptors", []):
                raw_descriptors[desc.get("id")] = desc
            definition = PresentationDefinition.deserialize(definition)
        elif isinstance(definition, PresentationDefinition):
            # If raw_definition provided, extract raw descriptors from it
            if raw_definition:
                for desc in raw_definition.get("input_descriptors", []):
                    raw_descriptors[desc.get("id")] = desc
        else:
            raise TypeError("definition must be dict or PresentationDefinition")

        descriptors = [
            DescriptorEvaluator.compile(desc, raw_descriptors.get(desc.id))
            for desc in definition.input_descriptors
        ]
        return cls(definition.id, descriptors)

    def _extract_vc_from_presentation(
        self,
        item: DescriptorMap,
        presentation: Mapping[str, Any],
    ) -> tuple[Any, str]:
        """Extract the verifiable credential from the presentation.

        Args:
            item: The descriptor map item
            presentation: The presentation mapping

        Returns:
            Tuple of (vc, format) where vc is the extracted credential
        """
        if item.path_nested:
            assert item.path_nested.path
            path = jsonpath.parse(item.path_nested.path)
            values = path.find(presentation)
            if len(values) != 1:
                raise ValueError(
                    f"More than one value found for path {item.path_nested.path}"
                )
            return values[0].value, item.path_nested.fmt

        if item.path:
            try:
                path = jsonpath.parse(item.path)
                values = path.find(presentation)
                if len(values) == 1:
                    return values[0].value, item.fmt
            except Exception:
                pass

        return presentation, item.fmt

    async def _try_extract_mdoc_from_vp(
        self,
        profile: Profile,
        result: CredVerifyResult,
        evaluator: DescriptorEvaluator,
    ) -> CredVerifyResult:
        """Try to extract and verify mso_mdoc from a VP payload.

        Args:
            profile: The profile for credential processing
            result: The initial verification result
            evaluator: The descriptor evaluator

        Returns:
            Updated verification result if mso_mdoc found, original otherwise
        """
        if "mso_mdoc" not in evaluator.formats:
            return result

        vp_payload = result.payload
        LOGGER.info(f"PEX: Checking VP payload for mso_mdoc: {type(vp_payload)}")

        if not vp_payload or not isinstance(vp_payload, dict):
            return result

        vcs = vp_payload.get("vp", {}).get(
            "verifiableCredential"
        ) or vp_payload.get("verifiableCredential")

        LOGGER.info(
            f"PEX: Extracted vcs from VP: {type(vcs)}, "
            f"value preview: {str(vcs)[:200] if vcs else 'None'}"
        )

        if not vcs:
            return result

        if not isinstance(vcs, list):
            vcs = [vcs]

        processors = profile.inject(CredProcessors)
        mdoc_processor = processors.cred_verifier_for_format("mso_mdoc")
        LOGGER.info(f"PEX: mdoc_processor: {mdoc_processor}")

        if not mdoc_processor:
            return result

        LOGGER.info("PEX: Attempting to extract and verify mso_mdoc from VP")
        for inner_vc in vcs:
            LOGGER.info(
                f"PEX: Processing inner vc: {type(inner_vc)}, "
                f"preview: {str(inner_vc)[:100]}"
            )
            try:
                inner_result = await mdoc_processor.verify_credential(profile, inner_vc)
                LOGGER.info(
                    f"PEX: Inner verification result: verified={inner_result.verified}"
                )
                if inner_result.verified:
                    LOGGER.info(
                        f"PEX: Successfully verified inner mso_mdoc, "
                        f"payload keys: {inner_result.payload.keys() if inner_result.payload else 'None'}"
                    )
                    return inner_result
            except Exception as e:
                LOGGER.warning(f"PEX: Failed to verify inner credential: {e}")
                import traceback
                LOGGER.warning(f"PEX: Traceback: {traceback.format_exc()}")

        return result

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

        for item in submission.descriptor_maps or []:
            # TODO Check JWT VP generally, if format is jwt_vp
            evaluator = self._id_to_descriptor.get(item.id)
            if not evaluator:
                return PexVerifyResult(
                    details=f"Could not find input descriptor corresponding to {item.id}"
                )

            LOGGER.info(
                f"PEX: Processing descriptor map item: "
                f"id={item.id}, fmt={item.fmt}, path={item.path}"
            )

            # Extract VC from presentation
            try:
                vc, fmt = self._extract_vc_from_presentation(item, presentation)
            except ValueError as e:
                return PexVerifyResult(details=str(e))

            # Verify the credential
            processors = profile.inject(CredProcessors)
            processor = processors.cred_verifier_for_format(fmt)
            LOGGER.info(
                f"PEX: Verifying credential type {type(vc)} with processor {processor}"
            )
            result = await processor.verify_credential(profile, vc)
            LOGGER.info(f"PEX: Verification result: {result.verified}")

            if result.verified:
                LOGGER.info(
                    f"PEX: Payload keys: "
                    f"{result.payload.keys() if result.payload else 'None'}"
                )
                LOGGER.debug(
                    f"PEX Payload: "
                    f"{json.dumps(result.payload) if result.payload else 'None'}"
                )

            # Try to extract mso_mdoc from VP if applicable
            if result.verified and not item.path_nested:
                result = await self._try_extract_mdoc_from_vp(
                    profile, result, evaluator
                )

            if not result.verified:
                LOGGER.debug(f"Credential verification failed: {result.payload}")
                return PexVerifyResult(
                    details="Credential signature verification failed"
                )

            try:
                fields = evaluator.match(result.payload)
            except DescriptorMatchFailed as e:
                LOGGER.debug(f"Descriptor match failed: {e}")
                return PexVerifyResult(
                    details="Credential did not match expected descriptor constraints"
                )

            descriptor_id_to_claims[item.id] = result.payload
            descriptor_id_to_fields[item.id] = fields

        return PexVerifyResult(
            verified=True,
            descriptor_id_to_claims=descriptor_id_to_claims,
            descriptor_id_to_fields=descriptor_id_to_fields,
        )
