"""Issue a mso_mdoc credential."""

import json
import logging
import re
from typing import Any

from acapy_agent.admin.request_context import AdminRequestContext

from oid4vc.cred_processor import CredProcessorError, Issuer
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult

from .mdoc import mso_mdoc_sign
from mso_mdoc.uniffi_scratch.isomdl_uniffi import Mdoc

LOGGER = logging.getLogger(__name__)


class MsoMdocCredProcessor(Issuer):
    """Credential processor class for mso_mdoc credential format."""

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Return signed credential in COBR format."""
        assert supported.format_data
        if body.get("doctype") != supported.format_data.get("doctype"):
            raise CredProcessorError("Requested doctype does not match offer.")

        try:
            headers = {
                "doctype": supported.format_data.get("doctype"),
                "deviceKey": re.sub(
                    "did:(.+?):(.+?)#(.*)",
                    "\\2",
                    json.dumps(pop.holder_jwk or pop.holder_kid),
                ),
            }
            did = None
            verification_method = ex_record.verification_method
            payload = ex_record.credential_subject
            mso_mdoc = await mso_mdoc_sign(
                context.profile, headers, payload, did, verification_method
            )
            mso_mdoc = mso_mdoc[2:-1] if mso_mdoc.startswith("b'") else None
        except Exception as ex:
            raise CredProcessorError("Failed to issue credential") from ex

        return mso_mdoc

    def validate_credential_subject(
        self, supported: SupportedCredential, subject: dict
    ):
        """Validate the credential subject."""
        pass

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported MSO MDOC Credential."""
        pass


utrechtCert = "-----BEGIN CERTIFICATE-----"
"MIICWTCCAf+gAwIBAgIULZgAnZswdEysOLq+G0uNW0svhYIwCgYIKoZIzj0EAwIw"
"VjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQKDAhTcHJ1Y2VJRDEn"
"MCUGA1UEAwweU3BydWNlSUQgVGVzdCBDZXJ0aWZpY2F0ZSBSb290MB4XDTI1MDIx"
"MjEwMjU0MFoXDTI2MDIxMjEwMjU0MFowVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgM"
"Ak5ZMREwDwYDVQQKDAhTcHJ1Y2VJRDEnMCUGA1UEAwweU3BydWNlSUQgVGVzdCBD"
"ZXJ0aWZpY2F0ZSBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwWfpUAMW"
"HkOzSctR8szsMNLeOCMyjk9HAkAYZ0HiHsBMNyrOcTxScBhEiHj+trE5d5fVq36o"
"cvrVkt2X0yy/N6OBqjCBpzAdBgNVHQ4EFgQU+TKkY3MApIowvNzakcIr6P4ZQDQw"
"EgYDVR0TAQH/BAgwBgEB/wIBADA+BgNVHR8ENzA1MDOgMaAvhi1odHRwczovL2lu"
"dGVyb3BldmVudC5zcHJ1Y2VpZC5jb20vaW50ZXJvcC5jcmwwDgYDVR0PAQH/BAQD"
"AgEGMCIGA1UdEgQbMBmBF2lzb2ludGVyb3BAc3BydWNlaWQuY29tMAoGCCqGSM49"
"BAMCA0gAMEUCIAJrzCSS/VIjf7uTq+Kt6+97VUNSvaAAwdP6fscIvp4RAiEA0dOP"
"Ld7ivuH83lLHDuNpb4NShfdBG57jNEIPNUs9OEg="
"-----END CERTIFICATE-----"

utrechtKey = "-----BEGIN PRIVATE KEY-----"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMIAu+2XfU/9Cwv3H"
"oI5nExdS8cA9Js/kzoXmMueGYJuhRANCAATBZ+lQAxYeQ7NJy1HyzOww0t44IzKO"
"T0cCQBhnQeIewEw3Ks5xPFJwGESIeP62sTl3l9Wrfqhy+tWS3ZfTLL83"
"-----END PRIVATE KEY-----"


class UniffiMsoMdocCredProcessor(Issuer):
    """Credential processor class for mso_mdoc using the Python-rust bindings."""

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Return signed credential in COBR format."""
        assert supported.format_data
        if body.get("doctype") != supported.format_data.get("doctype"):
            raise CredProcessorError("Requested doctype does not match offer.")

        fmt_data = supported.format_data

        mdoc = Mdoc.create_and_sign(
            doc_type=fmt_data["doctype"],
            namespaces=ex_record.credential_subject,
            holder_jwk=pop.holder_jwk,
            iaca_cert_perm=utrechtCert,
            iaca_key_perm=utrechtKey,
        )

    def validate_credential_subject(
        self, supported: SupportedCredential, subject: dict
    ):
        """Validate the credential subject."""
        pass

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported MSO MDOC Credential."""
        pass
