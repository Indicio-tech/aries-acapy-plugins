"""Issue a jwt_vc_json credential."""

import datetime
import json
import logging
import uuid
from typing import Any

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.util import bytes_to_b64
from pydid import DIDUrl  # noqa: F401  (kept for backward compatibility if needed)

from oid4vc.cred_processor import (
    CredProcessorError,
    CredVerifier,
    Issuer,
    PresVerifier,
    VerifyResult,
)
from oid4vc.jwt import jwt_sign, jwt_verify
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from oid4vc.public_routes import retrieve_or_create_did_jwk, types_are_subset
from oid4vc.status_handler import StatusHandler

LOGGER = logging.getLogger(__name__)


class JwtVcJsonCredProcessor(Issuer, CredVerifier, PresVerifier):
    """Credential processor class for jwt_vc_json format."""

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ) -> Any:
        """Return signed credential in JWT format."""
        try:
            assert supported.format_data
            if body.get("types") and not types_are_subset(
                body.get("types"), supported.format_data.get("types")
            ):
                raise CredProcessorError("Requested types does not match offer.")

            current_time = datetime.datetime.now(datetime.timezone.utc)
            current_time_unix_timestamp = int(current_time.timestamp())
            formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            cred_id = str(uuid.uuid4())

            # note: Some wallets require that the "jti" and "id" are a uri
            if pop.holder_kid and pop.holder_kid.startswith("did:"):
                # Extract DID by stripping any fragment from verification method
                subject = pop.holder_kid.split("#", 1)[0]
            elif pop.holder_jwk:
                # Derive a did:jwk subject from the holder's JWK per did:jwk method
                try:
                    jwk_json = json.dumps(pop.holder_jwk, separators=(",", ":"))
                except Exception:
                    jwk_json = json.dumps(pop.holder_jwk)
                did_jwk = "did:jwk:" + bytes_to_b64(
                    jwk_json.encode(), urlsafe=True, pad=False
                )
                # pydid may not recognize did:jwk scheme; use the DID string as-is
                subject = did_jwk
            else:
                raise CredProcessorError("Unsupported pop holder value")

            payload = {
                "vc": {
                    **(supported.vc_additional_data or {}),
                    "id": f"urn:uuid:{cred_id}",
                    "issuer": ex_record.issuer_id,
                    "issuanceDate": formatted_time,
                    "credentialSubject": {
                        **(ex_record.credential_subject or {}),
                        "id": subject,
                    },
                },
                "iss": ex_record.issuer_id,
                "nbf": current_time_unix_timestamp,
                "jti": f"urn:uuid:{cred_id}",
                "sub": subject,
            }

            status_handler = context.inject_or(StatusHandler)
            if status_handler and (
                credential_status := await status_handler.assign_status_entries(
                    context, supported.supported_cred_id, ex_record.exchange_id
                )
            ):
                payload["vc"]["credentialStatus"] = credential_status
                LOGGER.debug("credential with status: %s", payload)

            try:
                jws = await jwt_sign(
                    context.profile,
                    {},
                    payload,
                    verification_method=ex_record.verification_method,
                )
            except Exception:
                # Fallback: use default did:jwk under this wallet for signing
                async with context.profile.session() as session:
                    jwk_info = await retrieve_or_create_did_jwk(session)
                # Update issuer in payload to match the did:jwk we're signing with
                payload["vc"]["issuer"] = jwk_info.did
                payload["iss"] = jwk_info.did
                jws = await jwt_sign(
                    context.profile,
                    {},
                    payload,
                    verification_method=f"{jwk_info.did}#0",
                )

            return jws
        except CredProcessorError:
            raise
        except Exception as exc:
            LOGGER.exception("JWT VC issuance failed")
            debug_msg = (
                f"{exc.__class__.__name__}: {exc}; "
                f"kid={pop.holder_kid}, has_jwk={bool(pop.holder_jwk)}, "
                f"vm={ex_record.verification_method}, issuer={ex_record.issuer_id}"
            )
            raise CredProcessorError(debug_msg)

    def validate_credential_subject(
        self, supported: SupportedCredential, subject: dict
    ):
        """Validate the credential subject."""
        if not isinstance(subject, dict):
            raise ValueError("Credential subject must be a dictionary")

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported JWT VC JSON Credential."""
        if not supported.format_data:
            raise ValueError("format_data is required for jwt_vc_json")

        if not supported.format_data.get("types"):
            raise ValueError("types is required in format_data for jwt_vc_json")

    async def verify(self, profile: Profile, jwt: str) -> VerifyResult:
        """Verify a credential or presentation."""
        res = await jwt_verify(profile, jwt)
        return VerifyResult(
            verified=res.verified,
            payload=res.payload,
        )

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ) -> VerifyResult:
        """Verify a credential in JWT VC format."""
        return await self.verify(profile, credential)

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: OID4VPPresentation,
    ) -> VerifyResult:
        """Verify a presentation in JWT VP format."""
        return await self.verify(profile, presentation)
