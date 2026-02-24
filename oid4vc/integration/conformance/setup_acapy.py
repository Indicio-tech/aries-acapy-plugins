"""
ACA-Py Setup Script for OpenID Conformance Tests.

Configures ACA-Py issuer and verifier services with the necessary DIDs,
credential configurations, trust anchors, and credential offers before
the conformance suite begins testing.

Outputs a JSON file with dynamic configuration values (DID identifiers,
offer URIs, request URIs) that the conformance test runner consumes
to build the final conformance suite configuration.
"""

import asyncio
import json
import logging
import os
import sys
import uuid
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

ISSUER_ADMIN_URL = os.environ.get("ACAPY_ISSUER_ADMIN_URL", "http://acapy-issuer:8021")
ISSUER_OID4VCI_URL = os.environ.get(
    "ACAPY_ISSUER_OID4VCI_URL", "http://acapy-issuer:8022"
)
VERIFIER_ADMIN_URL = os.environ.get(
    "ACAPY_VERIFIER_ADMIN_URL", "http://acapy-verifier:8031"
)
VERIFIER_OID4VP_URL = os.environ.get(
    "ACAPY_VERIFIER_OID4VP_URL", "http://acapy-verifier:8032"
)
OUTPUT_FILE = os.environ.get("CONFORMANCE_SETUP_OUTPUT", "/tmp/conformance-setup.json")

POLL_INTERVAL = 2.0
POLL_MAX_ATTEMPTS = 60


async def wait_for_service(url: str, name: str) -> None:
    """Poll a service health endpoint until it responds."""
    health_url = f"{url}/status/live"
    logger.info(f"Waiting for {name} at {health_url} ...")
    async with httpx.AsyncClient() as client:
        for attempt in range(1, POLL_MAX_ATTEMPTS + 1):
            try:
                resp = await client.get(health_url, timeout=5.0)
                if resp.status_code < 500:
                    logger.info(f"{name} is healthy after {attempt} attempt(s)")
                    return
            except httpx.RequestError:
                pass
            if attempt < POLL_MAX_ATTEMPTS:
                await asyncio.sleep(POLL_INTERVAL)
    raise RuntimeError(f"{name} did not become healthy at {url}")


async def admin_get(client: httpx.AsyncClient, base: str, path: str) -> Any:
    """GET from ACA-Py admin API."""
    resp = await client.get(f"{base}{path}", timeout=30.0)
    resp.raise_for_status()
    return resp.json()


async def admin_post(
    client: httpx.AsyncClient, base: str, path: str, body: dict | None = None
) -> Any:
    """POST to ACA-Py admin API."""
    resp = await client.post(
        f"{base}{path}", json=body or {}, timeout=30.0
    )
    resp.raise_for_status()
    return resp.json()


async def create_did_jwk(client: httpx.AsyncClient, base: str, key_type: str) -> str:
    """Create a did:jwk and return the DID string."""
    result = await admin_post(client, base, "/did/jwk/create", {"key_type": key_type})
    did = result.get("did") or result.get("result", {}).get("did")
    if not did:
        raise RuntimeError(f"No DID in response: {result}")
    logger.info(f"Created did:jwk ({key_type}): {did}")
    return did


async def create_sd_jwt_credential_config(
    client: httpx.AsyncClient, base: str, issuer_did: str
) -> dict:
    """Register an SD-JWT VC credential configuration in ACA-Py."""
    config_id = f"conformance-sdjwt-{uuid.uuid4().hex[:8]}"
    payload = {
        "id": config_id,
        "format": "dc+sd-jwt",
        "scope": config_id,
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": ["EdDSA", "ES256"]
            }
        },
        "display": [{"name": "Identity Credential", "locale": "en"}],
        "format_data": {
            "vct": "https://credentials.example.com/identity_credential",
            "cryptographic_binding_methods_supported": ["did:key", "jwk"],
            # credential_signing_alg_values_supported belongs at the credential
            # config level (not inside format_data), and is handled by the model.
            # Do NOT add cryptographic_suites_supported here — it is deprecated
            # in OID4VCI 1.0 and causes "invalid entries" in conformance tests.
            "claims": {
                "given_name": {"display": [{"name": "Given Name", "locale": "en"}]},
                "family_name": {"display": [{"name": "Family Name", "locale": "en"}]},
                "email": {"display": [{"name": "Email", "locale": "en"}]},
                "birthdate": {"display": [{"name": "Date of Birth", "locale": "en"}]},
            },
        },
        "vc_additional_data": {
            "sd_list": [
                "/given_name",
                "/family_name",
                "/email",
                "/birthdate",
            ]
        },
    }
    result = await admin_post(
        client, base, "/oid4vci/credential-supported/create", payload
    )
    supported_cred_id = result.get("supported_cred_id")
    if not supported_cred_id:
        raise RuntimeError(f"No supported_cred_id in response: {result}")
    logger.info(f"Created SD-JWT credential config: {config_id} → {supported_cred_id}")
    return {
        "config_id": config_id,
        "supported_cred_id": supported_cred_id,
        "issuer_did": issuer_did,
    }


async def create_mdoc_credential_config(
    client: httpx.AsyncClient, base: str, issuer_did: str
) -> dict:
    """Register an mDOC/mDL credential configuration in ACA-Py."""
    config_id = f"conformance-mdoc-{uuid.uuid4().hex[:8]}"
    payload = {
        "id": config_id,
        "format": "mso_mdoc",
        "display": [{"name": "Mobile Driver's License", "locale": "en"}],
        "cryptographic_binding_methods_supported": ["cose_key"],
        # Store as JOSE string — to_issuer_metadata() converts it to the COSE
        # integer identifier (-7) required by the OID4VCI metadata spec for mso_mdoc.
        "cryptographic_suites_supported": ["ES256"],
        "format_data": {
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {
                        "display": [{"name": "Given Name", "locale": "en"}],
                        "mandatory": True,
                    },
                    "family_name": {
                        "display": [{"name": "Family Name", "locale": "en"}],
                        "mandatory": True,
                    },
                    "birth_date": {
                        "display": [{"name": "Date of Birth", "locale": "en"}],
                        "mandatory": True,
                    },
                    "document_number": {
                        "display": [{"name": "Document Number", "locale": "en"}],
                        "mandatory": False,
                    },
                }
            },
        },
    }
    result = await admin_post(
        client, base, "/oid4vci/credential-supported/create", payload
    )
    supported_cred_id = result.get("supported_cred_id")
    if not supported_cred_id:
        raise RuntimeError(f"No supported_cred_id in response: {result}")
    logger.info(f"Created mDOC credential config: {config_id} → {supported_cred_id}")
    return {
        "config_id": config_id,
        "supported_cred_id": supported_cred_id,
        "issuer_did": issuer_did,
    }


async def create_credential_offer(
    client: httpx.AsyncClient,
    base: str,
    credential_config_id: str,
    issuer_did: str,
    pin: str | None = None,
) -> dict:
    """Create a pre-authorized credential offer and return offer details."""
    exchange_body: dict[str, Any] = {
        "supported_cred_id": credential_config_id,
        "credential_subject": {
            "given_name": "Alice",
            "family_name": "Smith",
            "email": "alice@example.com",
            "birthdate": "1990-01-15",
        },
        # verification_method format: {did}#0  (selects the first key on the DID)
        "verification_method": f"{issuer_did}#0",
    }
    if pin is not None:
        exchange_body["pin"] = pin
    exchange_result = await admin_post(
        client,
        base,
        "/oid4vci/exchange/create",
        exchange_body,
    )
    exchange_id = exchange_result.get("exchange_id") or exchange_result.get("id")
    if not exchange_id:
        raise RuntimeError(f"No exchange_id in response: {exchange_result}")

    offer_result = await admin_get(
        client, base, f"/oid4vci/credential-offer?exchange_id={exchange_id}"
    )
    offer_uri = offer_result.get("offer_uri") or offer_result.get("credential_offer")
    if not offer_uri:
        raise RuntimeError(f"No offer_uri in response: {offer_result}")

    logger.info(f"Created credential offer for {credential_config_id}: {offer_uri}")
    return {
        "exchange_id": exchange_id,
        "offer_uri": offer_uri,
        "credential_config_id": credential_config_id,
    }


def _generate_test_pki() -> tuple[bytes, bytes, bytes]:
    """Generate a minimal PKI chain (root CA → DS cert) for mDOC trust testing.

    Returns (root_cert_pem, ds_cert_pem, ds_key_pem).
    """
    now = datetime.datetime.utcnow()

    # Root CA key + cert
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Conformance Test Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Conformance"),
        ]
    )
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )

    # DS (Document Signer) key + cert
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Conformance Test DS"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Conformance"),
        ]
    )
    ds_cert = (
        x509.CertificateBuilder()
        .subject_name(ds_name)
        .issuer_name(root_name)
        .public_key(ds_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(root_key, hashes.SHA256())
    )

    return (
        root_cert.public_bytes(serialization.Encoding.PEM),
        ds_cert.public_bytes(serialization.Encoding.PEM),
        ds_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


async def upload_trust_anchor(
    client: httpx.AsyncClient, base: str, cert_pem: bytes, *, anchor_type: str = "mso_mdoc"
) -> None:
    """Upload a trust anchor certificate to an ACA-Py instance."""
    cert_str = cert_pem.decode()
    await admin_post(
        client,
        base,
        f"/{anchor_type}/trust-anchors",
        {"certificate_pem": cert_str},
    )
    logger.info(f"Uploaded trust anchor to {base} ({anchor_type})")


async def create_vp_presentation_definition(
    client: httpx.AsyncClient, base: str, credential_type: str
) -> dict:
    """Create a presentation definition for OID4VP conformance testing."""
    pres_def_id = f"conformance-pd-{uuid.uuid4().hex[:8]}"
    if credential_type == "sdjwt":
        payload = {
            "pres_def": {
                "id": pres_def_id,
                "input_descriptors": [
                    {
                        "id": "identity-credential",
                        "name": "Identity Credential",
                        "purpose": "To verify your identity",
                        "format": {"vc+sd-jwt": {"alg": ["EdDSA", "ES256"]}},
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$.vct"],
                                    "filter": {
                                        "type": "string",
                                        "const": "https://credentials.example.com/identity_credential",
                                    },
                                }
                            ]
                        },
                    }
                ],
            }
        }
    else:  # mdl
        payload = {
            "pres_def": {
                "id": pres_def_id,
                "input_descriptors": [
                    {
                        "id": "mdl-credential",
                        "name": "Mobile Driver's License",
                        "purpose": "To verify your identity",
                        "format": {"mso_mdoc": {"alg": ["ES256"]}},
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$['org.iso.18013.5.1']['given_name']",
                                        "$['org.iso.18013.5.1']['family_name']",
                                    ]
                                }
                            ]
                        },
                    }
                ],
            }
        }
    result = await admin_post(
        client, base, "/oid4vp/presentation-definition", payload
    )
    pres_def_record_id = result.get("id") or result.get("pres_def_id")
    logger.info(f"Created presentation definition ({credential_type}): {pres_def_record_id}")
    return {"pres_def_id": pres_def_record_id, "definition_id": pres_def_id}


async def create_vp_request(
    client: httpx.AsyncClient,
    base: str,
    pres_def_id: str,
    *,
    vp_url: str,
) -> dict:
    """Create an OID4VP authorization request and return the request URI."""
    payload = {
        "pres_def_id": pres_def_id,
        "vp_formats": {
            "vc+sd-jwt": {"alg": ["EdDSA", "ES256"]},
            "mso_mdoc": {"alg": ["ES256"]},
        },
    }
    result = await admin_post(client, base, "/oid4vp/request", payload)
    request_uri = result.get("request_uri", "")
    request_id = (
        (result.get("request") or {}).get("request_id")
        or (result.get("presentation") or {}).get("request_id")
    )
    presentation_id = (result.get("presentation") or {}).get("presentation_id")
    logger.info(f"Created VP request: {request_uri}")
    return {
        "request_id": request_id,
        "presentation_id": presentation_id,
        "request_uri": request_uri,
    }


async def main() -> None:
    """Main setup flow."""
    logger.info("=== ACA-Py Conformance Test Setup ===")

    # Wait for services
    await wait_for_service(ISSUER_ADMIN_URL, "ACA-Py Issuer")
    await wait_for_service(VERIFIER_ADMIN_URL, "ACA-Py Verifier")

    setup_output: dict[str, Any] = {
        "issuer": {},
        "verifier": {},
    }

    async with httpx.AsyncClient() as client:
        # ── Issuer setup ────────────────────────────────────────────────────
        logger.info("--- Configuring Issuer ---")

        # Create DIDs
        ed25519_did = await create_did_jwk(client, ISSUER_ADMIN_URL, "ed25519")
        p256_did = await create_did_jwk(client, ISSUER_ADMIN_URL, "p256")

        # Register credential configs
        sdjwt_config = await create_sd_jwt_credential_config(
            client, ISSUER_ADMIN_URL, ed25519_did
        )
        mdoc_config = await create_mdoc_credential_config(
            client, ISSUER_ADMIN_URL, p256_did
        )

        # Generate PKI for mDOC trust
        root_cert_pem, ds_cert_pem, _ds_key_pem = _generate_test_pki()

        # Upload issuer signing cert
        await upload_trust_anchor(
            client, ISSUER_ADMIN_URL, root_cert_pem, anchor_type="mso_mdoc"
        )

        # Create credential offers (pre-auth code)
        # A fixed tx_code (pin) is used so the conformance suite can use
        # "static_tx_code" in its config, bypassing the interactive tx_code
        # delivery step that would require polling.
        SDJWT_TX_CODE = "123456"
        sdjwt_offer = await create_credential_offer(
            client,
            ISSUER_ADMIN_URL,
            sdjwt_config["supported_cred_id"],
            ed25519_did,
            pin=SDJWT_TX_CODE,
        )
        mdoc_offer = await create_credential_offer(
            client,
            ISSUER_ADMIN_URL,
            mdoc_config["supported_cred_id"],
            p256_did,
        )

        setup_output["issuer"] = {
            "url": ISSUER_OID4VCI_URL,
            "admin_url": ISSUER_ADMIN_URL,
            "ed25519_did": ed25519_did,
            "p256_did": p256_did,
            "sdjwt_credential_config_id": sdjwt_config["supported_cred_id"],
            "sdjwt_identifier": sdjwt_config["config_id"],
            "sdjwt_tx_code": SDJWT_TX_CODE,
            "mdoc_credential_config_id": mdoc_config["supported_cred_id"],
            "mdoc_identifier": mdoc_config["config_id"],
            "sdjwt_offer": sdjwt_offer,
            "mdoc_offer": mdoc_offer,
        }

        # ── Verifier setup ──────────────────────────────────────────────────
        logger.info("--- Configuring Verifier ---")

        # Upload trust anchor to verifier
        await upload_trust_anchor(
            client, VERIFIER_ADMIN_URL, root_cert_pem, anchor_type="mso_mdoc"
        )

        # Create presentation definitions
        sdjwt_pd = await create_vp_presentation_definition(
            client, VERIFIER_ADMIN_URL, "sdjwt"
        )
        mdoc_pd = await create_vp_presentation_definition(
            client, VERIFIER_ADMIN_URL, "mdl"
        )

        # Create initial VP requests (the conformance suite will make more)
        sdjwt_vp_request = await create_vp_request(
            client,
            VERIFIER_ADMIN_URL,
            sdjwt_pd["pres_def_id"],
            vp_url=VERIFIER_OID4VP_URL,
        )
        mdoc_vp_request = await create_vp_request(
            client,
            VERIFIER_ADMIN_URL,
            mdoc_pd["pres_def_id"],
            vp_url=VERIFIER_OID4VP_URL,
        )

        setup_output["verifier"] = {
            "url": VERIFIER_OID4VP_URL,
            "admin_url": VERIFIER_ADMIN_URL,
            "sdjwt_pres_def": sdjwt_pd,
            "mdoc_pres_def": mdoc_pd,
            "sdjwt_vp_request": sdjwt_vp_request,
            "mdoc_vp_request": mdoc_vp_request,
        }

    # Write output file
    with open(OUTPUT_FILE, "w") as f:
        json.dump(setup_output, f, indent=2)

    logger.info(f"Setup complete — output written to {OUTPUT_FILE}")
    logger.info(json.dumps(setup_output, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
