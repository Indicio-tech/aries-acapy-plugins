"""Verifier X.509 identity for signed OID4VP request objects.

A tenant can hold one checked X.509 identity. Its P-256 key is created in the
agent wallet and never leaves it: the certificate signing request (CSR) is
built here and signed through the wallet. A certificate chain issued for that
key is registered only after the checks in ``check_chain`` pass. Requests then
use ``client_id = "x509_hash:" + base64url(SHA-256(leaf DER))`` and carry the
chain in the ``x5c`` header.

Records (all in the tenant's own storage):

- active: the identity requests are signed with;
- pending: an open CSR, until its chain is registered;
- previous: the identity the active one replaced, kept for rollback.
"""

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from acapy_agent.config.base import BaseSettings
from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from acapy_agent.wallet.key_type import P256
from acapy_agent.wallet.util import bytes_to_b64
from aiohttp import web
from aries_askar import Key, KeyAlg
from asn1crypto import csr as asn1_csr
from asn1crypto import keys as asn1_keys
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, ObjectIdentifier

from .config import Config
from .jwk import DID_JWK

LOGGER = logging.getLogger(__name__)

RECORD_TYPE = "OID4VP.x509_identity"
ACTIVE_ID = "OID4VP.x509_identity"
PENDING_ID = "OID4VP.x509_identity.pending"
PREVIOUS_ID = "OID4VP.x509_identity.previous"

SCHEME_X509_HASH = "x509_hash"
SCHEME_X509_SAN_DNS = "x509_san_dns"
SCHEMES = (SCHEME_X509_HASH, SCHEME_X509_SAN_DNS)

MAX_CHAIN_LENGTH = 4
EXPIRY_WARNING_DAYS = 30
# ISO 18013-5 mdoc reader authentication
READER_EKU = ObjectIdentifier("1.0.18013.5.1.6")

SUBJECT_FIELDS = {
    "common_name": "common_name",
    "organization": "organization_name",
    "organizational_unit": "organizational_unit_name",
    "country": "country_name",
    "locality": "locality_name",
    "state": "state_or_province_name",
}

# RFC 5280 upper bounds (country is an ISO 3166 two-letter code).
SUBJECT_MAX_LENGTHS = {
    "common_name": 64,
    "organization": 64,
    "organizational_unit": 64,
    "locality": 128,
    "state": 128,
}
SAN_MAX_LENGTHS = {"dns": 253, "uri": 2048}

# Last day an expiry warning was logged, per tenant, so the log stays quiet.
_warned_on: dict = {}


class X509IdentityError(Exception):
    """A request to change the identity is refused (HTTP 400)."""


class X509IdentityUnusable(Exception):
    """The active identity cannot sign requests (HTTP 409)."""


def conflict_response(reason: str) -> web.Response:
    """Return a 409 answer and log it as one warning line.

    Returned rather than raised: ACA-Py's ready_middleware logs a full
    traceback for an HTTPConflict raised from a handler. The body matches
    aiohttp's own ("409: <reason>").
    """
    LOGGER.warning("Verifier identity request refused: %s", reason)
    return web.Response(status=409, reason=reason, text=f"409: {reason}")


@dataclass
class ClientIdentity:
    """What a request object is signed and identified with."""

    client_id: str
    x5c: List[str]
    verification_method: str


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


async def get_record(session: ProfileSession, record_id: str) -> Optional[dict]:
    """Return an identity record's value, or None."""
    storage = session.inject(BaseStorage)
    try:
        record = await storage.get_record(RECORD_TYPE, record_id)
    except StorageNotFoundError:
        return None
    return json.loads(record.value)


async def put_record(session: ProfileSession, record_id: str, value: dict) -> None:
    """Create or replace an identity record."""
    storage = session.inject(BaseStorage)
    try:
        existing = await storage.get_record(RECORD_TYPE, record_id)
        await storage.update_record(existing, json.dumps(value), {})
    except StorageNotFoundError:
        await storage.add_record(
            StorageRecord(type=RECORD_TYPE, value=json.dumps(value), id=record_id)
        )


async def delete_record(session: ProfileSession, record_id: str) -> bool:
    """Delete an identity record; return False if there was none."""
    storage = session.inject(BaseStorage)
    try:
        record = await storage.get_record(RECORD_TYPE, record_id)
    except StorageNotFoundError:
        return False
    await storage.delete_record(record)
    return True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _did_of(verification_method: str) -> str:
    return verification_method.split("#", 1)[0]


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def public_jwk_of(verification_method: str) -> dict:
    """Return the public JWK of a did:jwk verification method."""
    did = _did_of(verification_method)
    if not did.startswith("did:jwk:"):
        raise X509IdentityError("verification_method must be a did:jwk")
    jwk = json.loads(_b64url_decode(did[len("did:jwk:") :]))
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise X509IdentityError("verification_method must hold a P-256 key")
    return jwk


async def create_p256_did_jwk(session: ProfileSession) -> DIDInfo:
    """Create a P-256 key in the wallet and store it as a did:jwk.

    Stored the same way as the /did/jwk/create admin route stores keys, so
    jwt_sign and wallet.sign_message find it by its JWK thumbprint.
    """
    handle = getattr(session, "handle", None)
    if handle is None:
        raise WalletError("did:jwk creation requires an Askar-backed profile session")
    key = Key.generate(KeyAlg.P256)
    await handle.insert_key(key.get_jwk_thumbprint(), key)
    jwk = json.loads(key.get_jwk_public())
    jwk["use"] = "sig"
    did = "did:jwk:" + bytes_to_b64(json.dumps(jwk).encode(), urlsafe=True, pad=False)
    did_info = DIDInfo(
        did=did,
        verkey=key.get_jwk_thumbprint(),
        metadata={},
        method=DID_JWK,
        key_type=P256,
    )
    await session.inject(BaseWallet).store_did(did_info)
    return did_info


async def delete_did_jwk_key(session: ProfileSession, verification_method: str) -> None:
    """Delete a verifier key and its stored did:jwk, if they still exist."""
    did = _did_of(verification_method)
    wallet = session.inject(BaseWallet)
    try:
        did_info = await wallet.get_local_did(did)
    except WalletNotFoundError:
        return
    handle = session.handle
    try:
        await handle.remove_key(did_info.verkey)
    except Exception:  # the key may already be gone
        LOGGER.warning("Verifier key for %s was already removed", did)
    try:
        await handle.remove("did", did)
    except Exception:
        LOGGER.warning("Stored DID %s was already removed", did)


# ---------------------------------------------------------------------------
# CSR
# ---------------------------------------------------------------------------


def _ec_public_key_info(jwk: dict) -> asn1_keys.PublicKeyInfo:
    point = b"\x04" + _b64url_decode(jwk["x"]) + _b64url_decode(jwk["y"])
    return asn1_keys.PublicKeyInfo(
        {
            "algorithm": asn1_keys.PublicKeyAlgorithm(
                {
                    "algorithm": "ec",
                    "parameters": asn1_keys.ECDomainParameters(
                        name="named", value="secp256r1"
                    ),
                }
            ),
            "public_key": point,
        }
    )


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def validate_csr_input(subject, san) -> None:
    """Check the subject and SAN of a CSR request; raise X509IdentityError.

    Run before a key is made, so a refused request leaves nothing behind.
    """
    if not isinstance(subject, dict):
        raise X509IdentityError("subject must be an object")
    unknown = set(subject) - set(SUBJECT_FIELDS)
    if unknown:
        raise X509IdentityError("Unknown subject fields: " + ", ".join(sorted(unknown)))
    if (
        not isinstance(subject.get("common_name"), str)
        or not subject["common_name"].strip()
    ):
        raise X509IdentityError("subject.common_name is required")
    for name, value in subject.items():
        if not isinstance(value, str) or _has_control_characters(value):
            raise X509IdentityError(f"subject.{name} must be a string")
        if name == "country":
            if len(value) != 2 or not value.isascii() or not value.isupper():
                raise X509IdentityError(
                    "subject.country must be a two-letter ISO 3166 code, e.g. US"
                )
        elif not 1 <= len(value) <= SUBJECT_MAX_LENGTHS[name]:
            raise X509IdentityError(
                f"subject.{name} must be 1 to {SUBJECT_MAX_LENGTHS[name]} characters"
            )

    if san is None:
        return
    if not isinstance(san, dict):
        raise X509IdentityError("san must be an object")
    unknown = set(san) - set(SAN_MAX_LENGTHS)
    if unknown:
        raise X509IdentityError("Unknown san fields: " + ", ".join(sorted(unknown)))
    for name, limit in SAN_MAX_LENGTHS.items():
        values = san.get(name) or []
        if not isinstance(values, list) or any(
            not isinstance(value, str)
            or not 1 <= len(value) <= limit
            or _has_control_characters(value)
            for value in values
        ):
            raise X509IdentityError(
                f"san.{name} must be a list of strings of 1 to {limit} characters"
            )


def _subject_name(subject: dict) -> asn1_x509.Name:
    return asn1_x509.Name.build(
        {SUBJECT_FIELDS[name]: value for name, value in subject.items() if value}
    )


def _extension_request(san: Optional[dict]) -> asn1_csr.CRIAttributes:
    extensions = [
        {
            "extn_id": "key_usage",
            "critical": True,
            "extn_value": asn1_x509.KeyUsage({"digital_signature"}),
        }
    ]
    names = []
    for dns_name in (san or {}).get("dns") or []:
        names.append(asn1_x509.GeneralName(name="dns_name", value=dns_name))
    for uri in (san or {}).get("uri") or []:
        names.append(asn1_x509.GeneralName(name="uniform_resource_identifier", value=uri))
    if names:
        extensions.append(
            {"extn_id": "subject_alt_name", "critical": False, "extn_value": names}
        )
    return asn1_csr.CRIAttributes(
        [
            {
                "type": "extension_request",
                "values": [asn1_x509.Extensions(extensions)],
            }
        ]
    )


async def build_csr(
    session: ProfileSession,
    did_info: DIDInfo,
    subject: dict,
    san: Optional[dict] = None,
) -> str:
    """Build a PKCS#10 CSR for a wallet key, signed through the wallet.

    The signature comes from wallet.sign_message (ES256, raw r||s), the same
    call jwt_sign uses, so the private key never leaves the wallet.
    """
    validate_csr_input(subject, san)
    jwk = public_jwk_of(did_info.did)
    info = asn1_csr.CertificationRequestInfo(
        {
            "version": "v1",
            "subject": _subject_name(subject),
            "subject_pk_info": _ec_public_key_info(jwk),
            "attributes": _extension_request(san),
        }
    )
    tbs = info.dump()
    raw = await session.inject(BaseWallet).sign_message(tbs, did_info.verkey)
    if len(raw) != 64:
        raise WalletError("Unexpected ES256 signature length from the wallet")
    signature = encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    request = asn1_csr.CertificationRequest(
        {
            "certification_request_info": info,
            "signature_algorithm": {"algorithm": "sha256_ecdsa"},
            "signature": signature,
        }
    )
    csr_pem = asn1_pem.armor("CERTIFICATE REQUEST", request.dump()).decode()

    # Self-check: the CSR must verify under its own public key.
    if not x509.load_pem_x509_csr(csr_pem.encode()).is_signature_valid:
        raise WalletError("The CSR signature did not verify")
    return csr_pem


# ---------------------------------------------------------------------------
# Chain checks
# ---------------------------------------------------------------------------


@dataclass
class CheckedChain:
    """A chain that passed every check, with what the record stores."""

    cert_chain: List[str]
    client_id: str
    leaf_not_before: datetime
    leaf_not_after: datetime
    subject: str
    issuer: str
    reader_eku: bool
    # The window in which every certificate of the submitted chain is valid
    valid_from: datetime
    valid_until: datetime


def parse_chain(cert_chain_pem: str) -> List[x509.Certificate]:
    """Read a PEM chain (leaf first) of 1 to MAX_CHAIN_LENGTH certificates."""
    try:
        chain = x509.load_pem_x509_certificates(cert_chain_pem.encode())
    except ValueError as err:
        raise X509IdentityError(f"cert_chain_pem could not be read: {err}") from err
    if not 1 <= len(chain) <= MAX_CHAIN_LENGTH:
        raise X509IdentityError(
            f"cert_chain_pem must hold 1 to {MAX_CHAIN_LENGTH} certificates"
        )
    return chain


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _is_self_signed(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject and _issued_by(cert, cert)


def without_trust_anchor(chain: List[x509.Certificate]) -> List[x509.Certificate]:
    """Return the chain without a self-signed last certificate (the trust anchor).

    HAIP 1.0 clause 5: the trust anchor's certificate MUST NOT be in the x5c
    header of a signed request. The leaf itself is never dropped.
    """
    if len(chain) > 1 and _is_self_signed(chain[-1]):
        LOGGER.info(
            "Trust anchor %s left out of the verifier chain (not sent in x5c)",
            chain[-1].subject.rfc4514_string(),
        )
        return chain[:-1]
    return chain


def _extension(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def x509_hash(leaf: x509.Certificate) -> str:
    """Return the x509_hash value: base64url (no padding) SHA-256 of the DER."""
    digest = hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def load_trust_roots(settings: BaseSettings) -> List[x509.Certificate]:
    """Return the configured trust roots, or an empty list."""
    path = Config.from_settings(settings).verifier_trust_roots
    if not path:
        return []
    with open(path, "rb") as roots_file:
        return x509.load_pem_x509_certificates(roots_file.read())


def check_chain(
    chain: List[x509.Certificate],
    public_jwk: dict,
    scheme: str = SCHEME_X509_HASH,
    dns_name: Optional[str] = None,
    roots: Optional[List[x509.Certificate]] = None,
    now: Optional[datetime] = None,
) -> CheckedChain:
    """Check a verifier certificate chain (leaf first) for a wallet key.

    Raises X509IdentityError naming the first check that fails.
    """
    now = now or datetime.now(timezone.utc)
    leaf = chain[0]

    # The leaf certifies the wallet key.
    leaf_key = leaf.public_key()
    if not isinstance(leaf_key, ec.EllipticCurvePublicKey) or not isinstance(
        leaf_key.curve, ec.SECP256R1
    ):
        raise X509IdentityError("The leaf certificate does not hold a P-256 key")
    numbers = leaf_key.public_numbers()
    if numbers.x.to_bytes(32, "big") != _b64url_decode(
        public_jwk["x"]
    ) or numbers.y.to_bytes(32, "big") != _b64url_decode(public_jwk["y"]):
        raise X509IdentityError(
            "The leaf certificate's key does not match the wallet key"
        )

    # Not self-signed (HAIP).
    if leaf.issuer == leaf.subject or _issued_by(leaf, leaf):
        raise X509IdentityError("The leaf certificate must not be self-signed")

    # Each certificate is issued by the next.
    for position in range(len(chain) - 1):
        if not _issued_by(chain[position], chain[position + 1]):
            raise X509IdentityError(
                f"Certificate {position + 1} is not issued by certificate "
                f"{position + 2}; give the chain leaf first"
            )

    # Every certificate is in date.
    for position, cert in enumerate(chain):
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise X509IdentityError(
                f"Certificate {position + 1} is not valid now "
                f"({cert.not_valid_before_utc.isoformat()} to "
                f"{cert.not_valid_after_utc.isoformat()})"
            )

    # Key usage.
    key_usage = _extension(leaf, ExtensionOID.KEY_USAGE)
    if key_usage is None or not key_usage.digital_signature:
        raise X509IdentityError("The leaf certificate must allow digitalSignature")
    for position, cert in enumerate(chain[1:], start=2):
        constraints = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
        usage = _extension(cert, ExtensionOID.KEY_USAGE)
        if not constraints or not constraints.ca or not usage or not usage.key_cert_sign:
            raise X509IdentityError(
                f"Certificate {position} is not a CA certificate (CA and keyCertSign)"
            )

    # Optional configured roots: the chain must end at one of them.
    if roots:
        last = chain[-1]
        if not any(last == root or _issued_by(last, root) for root in roots):
            raise X509IdentityError(
                "The chain does not end at a configured verifier trust root"
            )

    # x509_san_dns only: the leaf names the client_id as a DNS SAN.
    if scheme == SCHEME_X509_SAN_DNS:
        san = _extension(leaf, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san.get_values_for_type(x509.DNSName) if san else []
        if not dns_name or dns_name not in dns_names:
            raise X509IdentityError(
                "For x509_san_dns the leaf certificate must have a dNSName SAN "
                "equal to client_id"
            )

    # The ISO 18013-5 reader EKU is logged, not required.
    eku = _extension(leaf, ExtensionOID.EXTENDED_KEY_USAGE)
    reader_eku = bool(eku) and READER_EKU in eku
    if not reader_eku:
        LOGGER.warning(
            "Verifier certificate has no ISO 18013-5 reader EKU (%s); accepted",
            READER_EKU.dotted_string,
        )
    if eku and ExtendedKeyUsageOID.SERVER_AUTH in eku:
        LOGGER.warning("Verifier certificate also allows serverAuth")

    if scheme == SCHEME_X509_HASH:
        client_id = f"{SCHEME_X509_HASH}:{x509_hash(leaf)}"
    else:
        client_id = f"{SCHEME_X509_SAN_DNS}:{dns_name}"

    # Every check ran on the chain as submitted; the trust anchor is not stored.
    return CheckedChain(
        cert_chain=[
            base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
            for cert in without_trust_anchor(chain)
        ],
        client_id=client_id,
        leaf_not_before=leaf.not_valid_before_utc,
        leaf_not_after=leaf.not_valid_after_utc,
        subject=leaf.subject.rfc4514_string(),
        issuer=leaf.issuer.rfc4514_string(),
        reader_eku=reader_eku,
        valid_from=max(cert.not_valid_before_utc for cert in chain),
        valid_until=min(cert.not_valid_after_utc for cert in chain),
    )


def active_record(checked: CheckedChain, scheme: str, verification_method: str) -> dict:
    """Return the stored form of a checked identity."""
    return {
        "state": "active",
        "client_id_scheme": scheme,
        "client_id": checked.client_id,
        "cert_chain": checked.cert_chain,
        "verification_method": verification_method,
        "leaf_not_before": checked.leaf_not_before.isoformat(),
        "leaf_not_after": checked.leaf_not_after.isoformat(),
        "valid_from": checked.valid_from.isoformat(),
        "valid_until": checked.valid_until.isoformat(),
        "subject": checked.subject,
        "issuer": checked.issuer,
        "reader_eku": checked.reader_eku,
        "checked": True,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def chain_from_record(record: dict) -> List[x509.Certificate]:
    """Return the certificates of a stored record."""
    return [
        x509.load_der_x509_certificate(base64.b64decode(entry))
        for entry in record["cert_chain"]
    ]


async def recheck_record(
    session: ProfileSession, record: dict, settings: BaseSettings
) -> dict:
    """Run every check on a stored record and return it in checked form.

    Used for records stored before checks existed (no ``checked`` flag) and
    before a rollback. Raises X509IdentityError if a check fails.
    """
    verification_method = record["verification_method"]
    jwk = public_jwk_of(verification_method)
    try:
        await session.inject(BaseWallet).get_local_did(_did_of(verification_method))
    except WalletNotFoundError as err:
        raise X509IdentityError("The identity's key is not in this wallet") from err
    scheme = record.get("client_id_scheme")
    dns_name = None
    if scheme is None:
        # Before checks existed every record was x509_san_dns with a bare name.
        scheme = SCHEME_X509_SAN_DNS
        dns_name = record["client_id"]
    elif scheme == SCHEME_X509_SAN_DNS:
        dns_name = record["client_id"].split(":", 1)[1]
    checked = check_chain(
        chain_from_record(record),
        jwk,
        scheme=scheme,
        dns_name=dns_name,
        roots=load_trust_roots(settings),
    )
    return active_record(checked, scheme, verification_method)


# ---------------------------------------------------------------------------
# Use in requests
# ---------------------------------------------------------------------------


def expiry_status(record: dict, now: Optional[datetime] = None) -> dict:
    """Return the expiry fields shown by the read route."""
    now = now or datetime.now(timezone.utc)
    # The earliest expiry in the chain counts, not only the leaf's.
    not_before = datetime.fromisoformat(
        record.get("valid_from") or record["leaf_not_before"]
    )
    not_after = datetime.fromisoformat(
        record.get("valid_until") or record["leaf_not_after"]
    )
    expired = not not_before <= now < not_after
    expires_in_days = max((not_after - now).days, 0)
    return {
        "expired": expired,
        "expires_in_days": expires_in_days,
        "expiry_warning": not expired
        and not_after - now <= timedelta(days=EXPIRY_WARNING_DAYS),
    }


async def resolve_client_identity(
    session: ProfileSession, settings: BaseSettings
) -> Optional[ClientIdentity]:
    """Return the identity a request is signed with, or None for did:jwk.

    Raises X509IdentityUnusable if an identity exists but cannot sign: it
    fails its checks, or its certificate is expired or not yet valid. There
    is no fallback to did:jwk in that case.
    """
    record = await get_record(session, ACTIVE_ID)
    if record is None:
        return None

    if not record.get("checked"):
        try:
            record = await recheck_record(session, record, settings)
        except X509IdentityError as err:
            raise X509IdentityUnusable(
                f"The registered verifier certificate failed its checks: {err}"
            ) from err
        await put_record(session, ACTIVE_ID, record)

    status = expiry_status(record)
    if status["expired"]:
        raise X509IdentityUnusable(
            "The verifier certificate chain is not valid now (valid until "
            f"{record.get('valid_until') or record['leaf_not_after']}); "
            "register a renewed certificate"
        )
    if status["expiry_warning"]:
        tenant = settings.get("wallet.id") or "base"
        today = datetime.now(timezone.utc).date()
        if _warned_on.get(tenant) != today:
            _warned_on[tenant] = today
            LOGGER.warning(
                "Verifier certificate for tenant %s expires in %s days (%s)",
                tenant,
                status["expires_in_days"],
                record.get("valid_until") or record["leaf_not_after"],
            )

    # A record stored before the trust anchor was left out may still hold it.
    chain = chain_from_record(record)
    x5c = record["cert_chain"][: len(without_trust_anchor(chain))]

    return ClientIdentity(
        client_id=record["client_id"],
        x5c=x5c,
        verification_method=record["verification_method"],
    )
