"""Typed element values for generic (non-mDL) mso_mdoc doctypes.

JSON has no byte string and no tagged date, so a generic doctype element sent
as JSON text is written to the mdoc as CBOR text. A credential configuration
can name the ISO 18013-5 data type of an element in its claims descriptor:

    "claims": {"<namespace>": {"<element>": {"value_type": "bstr", ...}}}

Supported ``value_type`` values and the input each expects:

| value_type  | input                                       | CBOR written    |
|-------------|---------------------------------------------|-----------------|
| ``bstr``    | base64 or base64url text, padded or not     | byte string     |
| ``full-date`` | ``YYYY-MM-DD``                            | tag 1004, text  |
| ``tdate``   | ``YYYY-MM-DDTHH:MM:SSZ`` (UTC, no fraction) | tag 0, text     |

The issuer wraps a typed element as ``{"$isomdl": "<type>", "value": "<text>"}``
before JSON-encoding it; isomdl-uniffi writes the CBOR type. Elements without a
``value_type`` are unchanged. Error messages name the element and the type,
never the value.
"""

import base64
import binascii
import re
from datetime import date, datetime
from typing import Any, Mapping, Optional

TYPED_ELEMENT_KEY = "$isomdl"
VALUE_TYPES = ("bstr", "full-date", "tdate")

_B64_STANDARD = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_B64_URLSAFE = re.compile(r"[A-Za-z0-9_-]*={0,2}")
_FULL_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_TDATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class TypedValueError(ValueError):
    """A typed element value or configuration is invalid."""


def value_types_for(
    format_data: Optional[Mapping[str, Any]], namespace: Optional[str]
) -> dict:
    """Return ``{element: value_type}`` for one namespace of a configuration.

    Reads the namespace-keyed ``claims`` dict stored with the credential
    configuration, or the OID4VCI 1.0 list form (``[{"path": [ns, el], ...}]``).
    Elements without a ``value_type`` are left out.

    Raises:
        TypedValueError: If a ``value_type`` is not one of ``VALUE_TYPES``.
    """
    if not format_data or not namespace:
        return {}
    claims = format_data.get("claims")
    descriptors: dict = {}
    if isinstance(claims, Mapping):
        ns_claims = claims.get(namespace)
        if isinstance(ns_claims, Mapping):
            descriptors = dict(ns_claims)
    elif isinstance(claims, list):
        for entry in claims:
            if not isinstance(entry, Mapping):
                continue
            path = entry.get("path")
            if (
                isinstance(path, list)
                and len(path) == 2
                and path[0] == namespace
                and isinstance(path[1], str)
            ):
                descriptors[path[1]] = entry

    value_types = {}
    for element, descriptor in descriptors.items():
        if not isinstance(descriptor, Mapping) or "value_type" not in descriptor:
            continue
        value_type = descriptor["value_type"]
        if value_type not in VALUE_TYPES:
            raise TypedValueError(
                f"claim '{element}': unknown value_type; expected one of "
                f"{', '.join(VALUE_TYPES)}"
            )
        value_types[element] = value_type
    return value_types


def validate_value_types(format_data: Optional[Mapping[str, Any]]) -> None:
    """Check every ``value_type`` in a configuration's claims, all namespaces.

    Raises:
        TypedValueError: On an unknown ``value_type``.
    """
    claims = (format_data or {}).get("claims")
    if isinstance(claims, Mapping):
        namespaces = list(claims.keys())
    elif isinstance(claims, list):
        namespaces = {
            entry["path"][0]
            for entry in claims
            if isinstance(entry, Mapping)
            and isinstance(entry.get("path"), list)
            and entry["path"]
        }
    else:
        return
    for namespace in namespaces:
        value_types_for(format_data, namespace)


def _is_base64(text: str) -> bool:
    if len(text) % 4 == 1:
        return False
    if "=" in text and len(text) % 4 != 0:
        return False
    for pattern, decode in (
        (_B64_STANDARD, base64.b64decode),
        (_B64_URLSAFE, base64.urlsafe_b64decode),
    ):
        if pattern.fullmatch(text):
            try:
                decode(text + "=" * (-len(text) % 4))
                return True
            except (binascii.Error, ValueError):
                return False
    return False


def check_typed_value(element: str, value_type: str, value: Any) -> str:
    """Check one typed element input and return it unchanged.

    Raises:
        TypedValueError: Naming the element and type, never the value.
    """
    if not isinstance(value, str):
        raise TypedValueError(f"claim '{element}': {value_type} value must be text")
    if value_type == "bstr":
        if not _is_base64(value):
            raise TypedValueError(
                f"claim '{element}': bstr value is not valid base64 or base64url"
            )
    elif value_type == "full-date":
        try:
            ok = bool(_FULL_DATE.fullmatch(value)) and bool(date.fromisoformat(value))
        except ValueError:
            ok = False
        if not ok:
            raise TypedValueError(
                f"claim '{element}': full-date value is not a valid YYYY-MM-DD date"
            )
    elif value_type == "tdate":
        try:
            ok = bool(_TDATE.fullmatch(value)) and bool(
                datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            )
        except ValueError:
            ok = False
        if not ok:
            raise TypedValueError(
                f"claim '{element}': tdate value is not a valid "
                "YYYY-MM-DDTHH:MM:SSZ date-time"
            )
    else:
        raise TypedValueError(f"claim '{element}': unknown value_type")
    return value


def check_typed_payload(payload: Mapping[str, Any], value_types: Mapping[str, str]):
    """Check every typed element present in a flat payload."""
    for element, value_type in value_types.items():
        if element in payload:
            check_typed_value(element, value_type, payload[element])


def wrap_typed_value(element: str, value_type: str, value: Any) -> dict:
    """Return the typed element envelope isomdl-uniffi converts to CBOR."""
    return {
        TYPED_ELEMENT_KEY: value_type,
        "value": check_typed_value(element, value_type, value),
    }
