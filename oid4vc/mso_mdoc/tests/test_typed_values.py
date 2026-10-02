"""Tests for typed element values (value_type) on generic mso_mdoc doctypes."""

import base64
import json
from datetime import date, datetime, timedelta, timezone

import pytest

from oid4vc.cred_processor import CredProcessorError
from oid4vc.models.supported_cred import SupportedCredential

from ..cred_processor import MsoMdocCredProcessor
from ..mdoc.issuer import _prepare_generic_namespaces
from ..mdoc.typed_values import (
    TypedValueError,
    check_typed_value,
    value_types_for,
    wrap_typed_value,
)

try:
    import cbor2

    CBOR_AVAILABLE = True
except ImportError:
    CBOR_AVAILABLE = False

try:
    import isomdl_uniffi  # noqa: F401

    ISOMDL_AVAILABLE = True
except ImportError:
    ISOMDL_AVAILABLE = False

DOCTYPE = "org.example.typed.1"
IMAGE = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46])
IMAGE_B64 = base64.b64encode(IMAGE).decode()

CLAIMS = {
    DOCTYPE: {
        "given_name": {"display": [{"name": "Given name"}]},
        "portrait": {"value_type": "bstr", "mandatory": True},
        "issue_date": {"value_type": "full-date"},
        "signed_at": {"value_type": "tdate"},
    }
}
FORMAT_DATA = {"doctype": DOCTYPE, "claims": CLAIMS}
VALUE_TYPES = {"portrait": "bstr", "issue_date": "full-date", "signed_at": "tdate"}
SUBJECT = {
    "given_name": "Sample",
    "portrait": IMAGE_B64,
    "issue_date": "2026-10-02",
    "signed_at": "2026-10-02T21:15:00Z",
    "categories": ["A", "B"],
}


class TestValueTypesFor:
    def test_namespace_keyed_claims(self):
        assert value_types_for(FORMAT_DATA, DOCTYPE) == VALUE_TYPES

    def test_list_form_claims(self):
        claims = [
            {"path": [DOCTYPE, "portrait"], "value_type": "bstr"},
            {"path": [DOCTYPE, "given_name"]},
            {"path": ["other.ns", "issue_date"], "value_type": "full-date"},
        ]
        assert value_types_for({"claims": claims}, DOCTYPE) == {"portrait": "bstr"}

    def test_no_claims_or_no_types(self):
        assert value_types_for({"doctype": DOCTYPE}, DOCTYPE) == {}
        assert value_types_for(None, DOCTYPE) == {}
        assert value_types_for({"claims": {DOCTYPE: {"a": {}}}}, DOCTYPE) == {}
        assert value_types_for(FORMAT_DATA, "other.ns") == {}

    def test_unknown_value_type_is_refused(self):
        bad = {"claims": {DOCTYPE: {"portrait": {"value_type": "jpeg"}}}}
        with pytest.raises(TypedValueError, match="'portrait'"):
            value_types_for(bad, DOCTYPE)


class TestCheckTypedValue:
    @pytest.mark.parametrize(
        "value_type,value",
        [
            ("bstr", IMAGE_B64),
            ("bstr", IMAGE_B64.rstrip("=")),
            ("bstr", base64.urlsafe_b64encode(bytes(range(256))).decode()),
            ("bstr", base64.urlsafe_b64encode(bytes(range(256))).decode().rstrip("=")),
            ("full-date", "2024-02-29"),
            ("tdate", "2026-10-02T21:15:00Z"),
        ],
    )
    def test_accepts(self, value_type, value):
        assert check_typed_value("e", value_type, value) == value

    @pytest.mark.parametrize(
        "value_type,value",
        [
            ("bstr", "SECRET*"),
            ("bstr", "SECRET+/mixed-_"),
            ("bstr", "SECRETA=="),
            ("bstr", b"SECRET"),
            ("bstr", 12),
            ("full-date", "2026-02-30"),
            ("full-date", "2026-2-03"),
            ("full-date", "20261002"),
            ("full-date", "2026-10-02T00:00:00Z"),
            ("full-date", "٢٠٢٦-١٠-٠٢"),
            ("tdate", "2026-10-02T21:15:00.5Z"),
            ("tdate", "2026-10-02T21:15:00+10:00"),
            ("tdate", "2026-10-02T25:15:00Z"),
            ("tdate", "2026-10-02"),
            ("uuid", "SECRET"),
        ],
    )
    def test_refuses_without_printing_the_value(self, value_type, value):
        with pytest.raises(TypedValueError) as info:
            check_typed_value("portrait", value_type, value)
        message = str(info.value)
        assert "'portrait'" in message
        assert "SECRET" not in message
        assert "2026-" not in message

    def test_wrap(self):
        assert wrap_typed_value("portrait", "bstr", IMAGE_B64) == {
            "$isomdl": "bstr",
            "value": IMAGE_B64,
        }


class TestPrepareGenericNamespaces:
    def test_untyped_is_unchanged(self):
        expected = {DOCTYPE: {k: json.dumps(v) for k, v in SUBJECT.items()}}
        assert _prepare_generic_namespaces(DOCTYPE, SUBJECT) == expected
        assert _prepare_generic_namespaces(DOCTYPE, SUBJECT, {}) == expected

    def test_typed_elements_are_wrapped(self):
        result = _prepare_generic_namespaces(DOCTYPE, SUBJECT, VALUE_TYPES)[DOCTYPE]
        assert json.loads(result["portrait"]) == {"$isomdl": "bstr", "value": IMAGE_B64}
        assert json.loads(result["issue_date"]) == {
            "$isomdl": "full-date",
            "value": "2026-10-02",
        }
        assert json.loads(result["signed_at"]) == {
            "$isomdl": "tdate",
            "value": "2026-10-02T21:15:00Z",
        }
        assert json.loads(result["given_name"]) == "Sample"
        assert json.loads(result["categories"]) == ["A", "B"]

    def test_typed_element_absent_from_payload_is_skipped(self):
        payload = {"given_name": "Sample"}
        result = _prepare_generic_namespaces(DOCTYPE, payload, VALUE_TYPES)
        assert result == {DOCTYPE: {"given_name": json.dumps("Sample")}}

    def test_bad_typed_input_fails(self):
        payload = dict(SUBJECT, issue_date="02/10/2026")
        with pytest.raises(TypedValueError, match="'issue_date'"):
            _prepare_generic_namespaces(DOCTYPE, payload, VALUE_TYPES)


class TestProcessorHooks:
    def test_registration_refuses_unknown_value_type(self):
        processor = MsoMdocCredProcessor()
        bad = SupportedCredential(
            format_data={
                "doctype": DOCTYPE,
                "claims": {DOCTYPE: {"portrait": {"value_type": "png"}}},
            }
        )
        with pytest.raises(CredProcessorError, match="'portrait'"):
            processor.validate_supported_credential(bad)

    def test_registration_accepts_known_value_types(self):
        processor = MsoMdocCredProcessor()
        assert processor.validate_supported_credential(
            SupportedCredential(format_data=FORMAT_DATA)
        )

    def test_exchange_refuses_bad_typed_input(self):
        processor = MsoMdocCredProcessor()
        supported = SupportedCredential(format_data=FORMAT_DATA)
        subject = dict(SUBJECT, portrait="data:image/jpeg;base64," + IMAGE_B64)
        with pytest.raises(CredProcessorError, match="'portrait'") as info:
            processor.validate_credential_subject(supported, subject)
        assert IMAGE_B64 not in str(info.value)

    def test_exchange_accepts_namespace_wrapped_subject(self):
        processor = MsoMdocCredProcessor()
        supported = SupportedCredential(format_data=FORMAT_DATA)
        assert processor.validate_credential_subject(supported, {DOCTYPE: SUBJECT})

    def test_value_type_stays_out_of_issuer_metadata(self):
        processor = MsoMdocCredProcessor()
        metadata = {"claims": json.loads(json.dumps(CLAIMS))}
        processor.transform_issuer_metadata(metadata)
        for entry in metadata["credential_metadata"]["claims"]:
            assert "value_type" not in entry


def _iaca_pems():
    """Self-signed P-256 IACA certificate and key, PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Typed Test IACA"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _holder_jwk():
    from cryptography.hazmat.primitives.asymmetric import ec

    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()

    def b64(n):
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).decode().rstrip("=")

    return {"kty": "EC", "crv": "P-256", "x": b64(numbers.x), "y": b64(numbers.y)}


def _element_values(issuer_signed_b64: str) -> tuple[dict, dict]:
    """Decoded element values and raw IssuerSignedItem bytes, by identifier."""
    padded = issuer_signed_b64 + "=" * (-len(issuer_signed_b64) % 4)
    issuer_signed = cbor2.loads(base64.urlsafe_b64decode(padded))
    values, raw = {}, {}
    for item in issuer_signed["nameSpaces"][DOCTYPE]:
        decoded = cbor2.loads(item.value)  # IssuerSignedItemBytes: tag 24
        values[decoded["elementIdentifier"]] = decoded["elementValue"]
        raw[decoded["elementIdentifier"]] = item.value
    return values, raw


@pytest.mark.skipif(
    not (CBOR_AVAILABLE and ISOMDL_AVAILABLE), reason="needs cbor2 and isomdl_uniffi"
)
class TestRealSigning:
    """Sign with the installed isomdl_uniffi and decode the IssuerSigned CBOR."""

    def _sign(self, value_types):
        from ..mdoc.issuer import isomdl_mdoc_sign

        cert_pem, key_pem = _iaca_pems()
        return isomdl_mdoc_sign(
            _holder_jwk(),
            {"doctype": DOCTYPE},
            dict(SUBJECT),
            cert_pem,
            key_pem,
            value_types=value_types,
        )

    def test_typed_elements_are_written_as_iso_types(self):
        try:
            signed = self._sign(VALUE_TYPES)
        except ValueError as ex:
            if "does not support typed elements" in str(ex):
                pytest.skip("installed isomdl_uniffi has no typed-element support")
            raise
        values, raw = _element_values(signed)
        assert values["portrait"] == IMAGE  # CBOR byte string
        # cbor2 decodes tag 1004 to a date and tag 0 to a datetime; the raw
        # bytes pin the exact tags: d9 03ec (1004) and c0 (0) before the text.
        assert values["issue_date"] == date(2026, 10, 2)
        assert bytes.fromhex("d903ec6a") + b"2026-10-02" in raw["issue_date"]
        assert values["signed_at"] == datetime(2026, 10, 2, 21, 15, tzinfo=timezone.utc)
        assert bytes.fromhex("c074") + b"2026-10-02T21:15:00Z" in raw["signed_at"]
        assert values["given_name"] == "Sample"
        assert values["categories"] == ["A", "B"]

    def test_untyped_configuration_writes_text_as_before(self):
        values, _ = _element_values(self._sign(None))
        assert values["portrait"] == IMAGE_B64
        assert values["issue_date"] == "2026-10-02"
        assert values["signed_at"] == "2026-10-02T21:15:00Z"


class TestTypedSupportGuard:
    """A library without typed-element support must not issue silently."""

    def test_envelope_written_as_map_fails_the_issue(self, monkeypatch):
        from types import SimpleNamespace

        from ..mdoc import issuer

        envelope_json = json.dumps({"$isomdl": "bstr", "value": IMAGE_B64}, indent=2)

        class OldLibraryMdoc:
            def details(self):
                return {
                    DOCTYPE: [
                        SimpleNamespace(identifier="portrait", value=envelope_json),
                        SimpleNamespace(identifier="given_name", value='"Sample"'),
                    ]
                }

            def doctype(self):
                return DOCTYPE

            def issuer_signed_b64(self):
                return "unused"

        monkeypatch.setattr(
            issuer.Mdoc, "create_and_sign", staticmethod(lambda *a: OldLibraryMdoc())
        )
        cert_pem, key_pem = _iaca_pems()
        with pytest.raises(ValueError, match="does not support typed elements") as info:
            issuer.isomdl_mdoc_sign(
                _holder_jwk(),
                {"doctype": DOCTYPE},
                dict(SUBJECT),
                cert_pem,
                key_pem,
                value_types=VALUE_TYPES,
            )
        assert IMAGE_B64 not in str(info.value)
