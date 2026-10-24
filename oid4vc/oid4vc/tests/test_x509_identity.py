"""Tests for the verifier X.509 identity (x509_hash) module."""

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.key_type import KeyTypes
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from aiohttp import web
from cryptography.x509.oid import NameOID

from oid4vc import x509_identity as xid
from oid4vc.jwk import DID_JWK
from oid4vc.public_routes import verification
from oid4vc.routes import vp_request

NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Test PKI
# ---------------------------------------------------------------------------


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_root(common_name: str = "Example Verifier Root"):
    """Return (key, certificate) for a self-signed CA root."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(
    public_key,
    issuer_key,
    issuer_cert,
    *,
    not_before=None,
    not_after=None,
    digital_signature=True,
    reader_eku=True,
    dns_name=None,
    common_name="Example Clinic",
):
    """Return a leaf certificate for public_key issued by issuer."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(hours=1))
        .not_valid_after(not_after or NOW + timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=not digital_signature,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if reader_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([xid.READER_EKU]), critical=True
        )
    if dns_name:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def public_key_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    def b64(value):
        return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))

    return ec.EllipticCurvePublicNumbers(
        b64(jwk["x"]), b64(jwk["y"]), ec.SECP256R1()
    ).public_key()


def pem(*certs) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


@pytest.fixture
async def wallet_key(profile: Profile):
    """A P-256 did:jwk made in the test wallet."""
    # As the plugin's setup does in a running agent.
    methods = DIDMethods()
    methods.register(DID_JWK)
    profile.context.injector.bind_instance(DIDMethods, methods)
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    async with profile.session() as session:
        did_info = await xid.create_p256_did_jwk(session)
    return did_info


# ---------------------------------------------------------------------------
# Key and CSR
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csr_is_signed_by_the_wallet_key(profile: Profile, wallet_key):
    async with profile.session() as session:
        csr_pem = await xid.build_csr(
            session,
            wallet_key,
            {
                "common_name": "Example Clinic",
                "organization": "Example Org",
                "country": "US",
            },
            {"dns": ["verifier.example.org"]},
        )

    csr = x509.load_pem_x509_csr(csr_pem.encode())
    assert csr.is_signature_valid
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "Example Clinic"
    )
    jwk = xid.public_jwk_of(wallet_key.did)
    assert csr.public_key().public_numbers() == public_key_from_jwk(jwk).public_numbers()
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["verifier.example.org"]
    key_usage = csr.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature


@pytest.mark.asyncio
async def test_csr_needs_a_common_name(profile: Profile, wallet_key):
    async with profile.session() as session:
        with pytest.raises(xid.X509IdentityError):
            await xid.build_csr(session, wallet_key, {"organization": "Example Org"})
        with pytest.raises(xid.X509IdentityError):
            await xid.build_csr(
                session, wallet_key, {"common_name": "Example", "email": "x"}
            )


@pytest.mark.asyncio
async def test_key_is_a_p256_did_jwk_in_the_wallet(profile: Profile, wallet_key):
    jwk = xid.public_jwk_of(wallet_key.did + "#0")
    assert jwk["crv"] == "P-256"
    async with profile.session() as session:
        stored = await session.inject(BaseWallet).get_local_did(wallet_key.did)
    assert stored.verkey == wallet_key.verkey


@pytest.mark.asyncio
async def test_delete_did_jwk_key(profile: Profile, wallet_key):
    async with profile.session() as session:
        await xid.delete_did_jwk_key(session, wallet_key.did + "#0")
        with pytest.raises(WalletNotFoundError):
            await session.inject(BaseWallet).get_local_did(wallet_key.did)
        assert await session.handle.fetch_key(wallet_key.verkey) is None
        # A second delete is harmless.
        await xid.delete_did_jwk_key(session, wallet_key.did + "#0")


# ---------------------------------------------------------------------------
# Chain checks
# ---------------------------------------------------------------------------


@pytest.fixture
def pki(wallet_key):
    root_key, root = make_root()
    wallet_public = public_key_from_jwk(xid.public_jwk_of(wallet_key.did))
    leaf = make_leaf(wallet_public, root_key, root)
    return {
        "root_key": root_key,
        "root": root,
        "leaf": leaf,
        "wallet_public": wallet_public,
        "jwk": xid.public_jwk_of(wallet_key.did),
    }


def test_good_chain_gives_x509_hash(pki):
    checked = xid.check_chain([pki["leaf"]], pki["jwk"], roots=[pki["root"]])

    digest = hashlib.sha256(pki["leaf"].public_bytes(serialization.Encoding.DER)).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert checked.client_id == f"x509_hash:{expected}"
    assert "=" not in checked.client_id
    assert checked.reader_eku is True
    assert len(checked.cert_chain) == 1


def _der_b64(cert) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def make_intermediate(root_key, root_cert):
    """Return (key, certificate) for a CA certificate issued by the root."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Example Verifier Issuing CA"))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    return key, cert


def test_trust_anchor_is_left_out(pki, caplog):
    # HAIP 1.0 clause 5: the trust anchor is not sent in x5c.
    caplog.set_level(logging.INFO, logger="oid4vc.x509_identity")
    checked = xid.check_chain([pki["leaf"], pki["root"]], pki["jwk"], roots=[pki["root"]])
    assert checked.cert_chain == [_der_b64(pki["leaf"])]
    assert checked.client_id == f"x509_hash:{xid.x509_hash(pki['leaf'])}"
    assert "Trust anchor" in caplog.text


def test_intermediates_are_kept(pki):
    mid_key, mid = make_intermediate(pki["root_key"], pki["root"])
    leaf = make_leaf(pki["wallet_public"], mid_key, mid)
    checked = xid.check_chain([leaf, mid, pki["root"]], pki["jwk"], roots=[pki["root"]])
    assert checked.cert_chain == [_der_b64(leaf), _der_b64(mid)]
    # Without the root submitted, the configured root still completes the chain.
    assert xid.check_chain([leaf, mid], pki["jwk"], roots=[pki["root"]]).cert_chain == [
        _der_b64(leaf),
        _der_b64(mid),
    ]


def test_refuses_leaf_for_another_key(pki):
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    leaf = make_leaf(other, pki["root_key"], pki["root"])
    with pytest.raises(xid.X509IdentityError, match="does not match the wallet key"):
        xid.check_chain([leaf], pki["jwk"])


def test_refuses_self_signed_leaf(pki, wallet_key):
    # A certificate for the wallet key, signed by its own issuer name and key.
    key = ec.generate_private_key(ec.SECP256R1())
    jwk_numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(jwk_numbers.x.to_bytes(32, "big"))
        .rstrip(b"=")
        .decode(),
        "y": base64.urlsafe_b64encode(jwk_numbers.y.to_bytes(32, "big"))
        .rstrip(b"=")
        .decode(),
    }
    self_signed = (
        x509.CertificateBuilder()
        .subject_name(_name("Example Clinic"))
        .issuer_name(_name("Example Clinic"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(hours=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(xid.X509IdentityError, match="self-signed"):
        xid.check_chain([self_signed], jwk)


def test_refuses_reversed_chain(pki):
    with pytest.raises(xid.X509IdentityError):
        xid.check_chain([pki["root"], pki["leaf"]], pki["jwk"])


def test_refuses_chain_out_of_order(pki):
    other_key, other_root = make_root("Example Other Root")
    with pytest.raises(xid.X509IdentityError, match="is not issued by"):
        xid.check_chain([pki["leaf"], other_root], pki["jwk"])


def test_refuses_expired_and_not_yet_valid_leaf(pki):
    expired = make_leaf(
        pki["wallet_public"],
        pki["root_key"],
        pki["root"],
        not_before=NOW - timedelta(days=400),
        not_after=NOW - timedelta(days=1),
    )
    with pytest.raises(xid.X509IdentityError, match="not valid now"):
        xid.check_chain([expired], pki["jwk"])
    future = make_leaf(
        pki["wallet_public"],
        pki["root_key"],
        pki["root"],
        not_before=NOW + timedelta(days=1),
        not_after=NOW + timedelta(days=30),
    )
    with pytest.raises(xid.X509IdentityError, match="not valid now"):
        xid.check_chain([future], pki["jwk"])


def test_refuses_leaf_without_digital_signature(pki):
    leaf = make_leaf(
        pki["wallet_public"], pki["root_key"], pki["root"], digital_signature=False
    )
    with pytest.raises(xid.X509IdentityError, match="digitalSignature"):
        xid.check_chain([leaf], pki["jwk"])


def test_refuses_foreign_root_when_roots_configured(pki):
    _, other_root = make_root("Example Other Root")
    with pytest.raises(xid.X509IdentityError, match="configured verifier trust root"):
        xid.check_chain([pki["leaf"]], pki["jwk"], roots=[other_root])
    # Without configured roots the chain is accepted.
    assert xid.check_chain([pki["leaf"]], pki["jwk"]).client_id.startswith("x509_hash:")


def test_missing_reader_eku_is_logged_not_refused(pki, caplog):
    leaf = make_leaf(pki["wallet_public"], pki["root_key"], pki["root"], reader_eku=False)
    checked = xid.check_chain([leaf], pki["jwk"])
    assert checked.reader_eku is False
    assert "reader EKU" in caplog.text


def test_x509_san_dns_needs_matching_san(pki):
    leaf = make_leaf(
        pki["wallet_public"],
        pki["root_key"],
        pki["root"],
        dns_name="verifier.example.org",
    )
    checked = xid.check_chain(
        [leaf], pki["jwk"], scheme="x509_san_dns", dns_name="verifier.example.org"
    )
    assert checked.client_id == "x509_san_dns:verifier.example.org"
    with pytest.raises(xid.X509IdentityError, match="dNSName"):
        xid.check_chain(
            [leaf], pki["jwk"], scheme="x509_san_dns", dns_name="other.example.org"
        )


def test_refuses_too_many_certificates(pki):
    with pytest.raises(xid.X509IdentityError, match="1 to 4"):
        xid.parse_chain(pem(*([pki["root"]] * 5)))


def test_expiry_status():
    record = {
        "leaf_not_before": (NOW - timedelta(days=300)).isoformat(),
        "leaf_not_after": (NOW + timedelta(days=20)).isoformat(),
    }
    status = xid.expiry_status(record)
    assert status["expired"] is False
    assert status["expiry_warning"] is True
    assert status["expires_in_days"] in (19, 20)
    record["leaf_not_after"] = (NOW + timedelta(days=60)).isoformat()
    assert xid.expiry_status(record)["expiry_warning"] is False
    record["leaf_not_after"] = (NOW - timedelta(minutes=1)).isoformat()
    assert xid.expiry_status(record)["expired"] is True


# ---------------------------------------------------------------------------
# Admin routes and request signing
# ---------------------------------------------------------------------------


class FakeRequest:
    def __init__(self, context, body=None, query=None, match_info=None):
        self._context = context
        self._body = body or {}
        self.query = query or {}
        self.match_info = match_info or {}

    async def json(self):
        return self._body

    def __getitem__(self, key):
        if key == "context":
            return self._context
        raise KeyError(key)


def call(handler, context, **kwargs):
    return handler(cast(web.Request, FakeRequest(context, **kwargs)))


def body_of(response) -> dict:
    return json.loads(response.body)


@pytest.fixture
def admin(profile: Profile, wallet_key):
    """An admin request context on the test profile (DIDMethods bound)."""
    return AdminRequestContext.test_context({}, profile)


@pytest.fixture
def root():
    return make_root()


async def csr_and_leaf(admin, root, **leaf_kwargs):
    """Make a CSR through the route and a leaf for it signed by root."""
    response = await call(
        vp_request.create_x509_identity_csr,
        admin,
        body={"subject": {"common_name": "Example Clinic"}},
    )
    created = body_of(response)
    csr = x509.load_pem_x509_csr(created["csr_pem"].encode())
    root_key, root_cert = root
    leaf = make_leaf(csr.public_key(), root_key, root_cert, **leaf_kwargs)
    return created, leaf


@pytest.mark.asyncio
async def test_csr_route_stores_pending_and_returns_no_private_key(admin):
    response = await call(
        vp_request.create_x509_identity_csr,
        admin,
        body={"subject": {"common_name": "Example Clinic"}},
    )
    created = body_of(response)
    assert set(created) == {"csr_pem", "verification_method", "public_jwk"}
    assert "d" not in created["public_jwk"]

    shown = body_of(await call(vp_request.get_x509_identity, admin))
    assert shown["pending"]["state"] == "csr_created"
    assert shown["pending"]["verification_method"] == created["verification_method"]


@pytest.mark.asyncio
async def test_csr_route_refuses_bad_subject(admin):
    with pytest.raises(web.HTTPBadRequest):
        await call(vp_request.create_x509_identity_csr, admin, body={"subject": "x"})
    with pytest.raises(web.HTTPBadRequest):
        await call(
            vp_request.create_x509_identity_csr,
            admin,
            body={"subject": {"country": "US"}},
        )


@pytest.mark.asyncio
async def test_register_good_chain(admin, root):
    created, leaf = await csr_and_leaf(admin, root)
    response = await call(
        vp_request.register_x509_identity, admin, body={"cert_chain_pem": pem(leaf)}
    )
    shown = body_of(response)

    assert shown["state"] == "active"
    assert shown["client_id"] == f"x509_hash:{xid.x509_hash(leaf)}"
    assert shown["client_id_scheme"] == "x509_hash"
    assert shown["verification_method"] == created["verification_method"]
    assert shown["checked"] is True
    assert shown["managed_key"] is True
    assert shown["expired"] is False
    assert shown["reader_eku"] is True
    assert "pending" not in shown


@pytest.mark.asyncio
async def test_register_leaf_and_root_stores_leaf_only(admin, root):
    _, leaf = await csr_and_leaf(admin, root)
    shown = body_of(
        await call(
            vp_request.register_x509_identity,
            admin,
            body={"cert_chain_pem": pem(leaf, root[1])},
        )
    )
    assert shown["cert_chain"] == [_der_b64(leaf)]


@pytest.mark.asyncio
async def test_register_refuses_unchecked_chain_on_old_route(admin, root):
    created, _ = await csr_and_leaf(admin, root)
    root_key, root_cert = root
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    wrong_leaf = make_leaf(other, root_key, root_cert)

    with pytest.raises(web.HTTPBadRequest, match="does not match the wallet key"):
        await call(
            vp_request.register_x509_identity,
            admin,
            body={
                "cert_chain_pem": pem(wrong_leaf),
                "verification_method": created["verification_method"],
            },
        )
    # Nothing was registered; the open CSR stays.
    shown = body_of(await call(vp_request.get_x509_identity, admin))
    assert "state" not in shown
    assert shown["pending"]["verification_method"] == created["verification_method"]


@pytest.mark.asyncio
async def test_register_needs_a_key(admin, root):
    _, leaf = await csr_and_leaf(admin, root)
    await call(vp_request.delete_x509_identity, admin, query={"pending": "true"})
    with pytest.raises(web.HTTPBadRequest, match="no open CSR"):
        await call(
            vp_request.register_x509_identity, admin, body={"cert_chain_pem": pem(leaf)}
        )


@pytest.mark.asyncio
async def test_renewal_keeps_one_previous_and_deletes_older(admin, root, profile):
    first, leaf1 = await csr_and_leaf(admin, root)
    await call(
        vp_request.register_x509_identity, admin, body={"cert_chain_pem": pem(leaf1)}
    )
    second, leaf2 = await csr_and_leaf(admin, root)
    shown = body_of(
        await call(
            vp_request.register_x509_identity, admin, body={"cert_chain_pem": pem(leaf2)}
        )
    )
    assert shown["previous"]["client_id"] == f"x509_hash:{xid.x509_hash(leaf1)}"

    third, leaf3 = await csr_and_leaf(admin, root)
    await call(
        vp_request.register_x509_identity, admin, body={"cert_chain_pem": pem(leaf3)}
    )

    first_did = first["verification_method"].split("#")[0]
    second_did = second["verification_method"].split("#")[0]
    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        with pytest.raises(WalletNotFoundError):
            await wallet.get_local_did(first_did)
        assert (await wallet.get_local_did(second_did)).did == second_did


@pytest.mark.asyncio
async def test_rollback_restores_previous(admin, root):
    _, leaf1 = await csr_and_leaf(admin, root)
    await call(
        vp_request.register_x509_identity, admin, body={"cert_chain_pem": pem(leaf1)}
    )
    _, leaf2 = await csr_and_leaf(admin, root)
    await call(
        vp_request.register_x509_identity, admin, body={"cert_chain_pem": pem(leaf2)}
    )

    shown = body_of(await call(vp_request.rollback_x509_identity, admin))
    assert shown["client_id"] == f"x509_hash:{xid.x509_hash(leaf1)}"
    assert shown["previous"]["client_id"] == f"x509_hash:{xid.x509_hash(leaf2)}"


@pytest.mark.asyncio
async def test_rollback_refused_without_previous(admin, root):
    response = await call(vp_request.rollback_x509_identity, admin)
    assert response.status == 409
    assert "No previous X.509 identity" in response.text


@pytest.mark.asyncio
async def test_delete_removes_managed_key_only(admin, root, profile, wallet_key):
    created, leaf = await csr_and_leaf(admin, root)
    await call(
        vp_request.register_x509_identity, admin, body={"cert_chain_pem": pem(leaf)}
    )
    await call(vp_request.delete_x509_identity, admin)
    async with profile.session() as session:
        with pytest.raises(WalletNotFoundError):
            await session.inject(BaseWallet).get_local_did(
                created["verification_method"].split("#")[0]
            )

    # A key registered by hand (not made by the CSR route) is never deleted.
    root_key, root_cert = root
    own_leaf = make_leaf(
        public_key_from_jwk(xid.public_jwk_of(wallet_key.did)), root_key, root_cert
    )
    await call(
        vp_request.register_x509_identity,
        admin,
        body={
            "cert_chain_pem": pem(own_leaf),
            "verification_method": wallet_key.did + "#0",
        },
    )
    await call(vp_request.delete_x509_identity, admin)
    async with profile.session() as session:
        assert (await session.inject(BaseWallet).get_local_did(wallet_key.did)).did


async def store_active(profile, root, wallet_key, **leaf_kwargs):
    root_key, root_cert = root
    leaf = make_leaf(
        public_key_from_jwk(xid.public_jwk_of(wallet_key.did)),
        root_key,
        root_cert,
        **leaf_kwargs,
    )
    vm = wallet_key.did + "#0"
    record = xid.active_record(
        xid.check_chain([leaf], xid.public_jwk_of(vm), now=NOW), "x509_hash", vm
    )
    async with profile.session() as session:
        await xid.put_record(session, xid.ACTIVE_ID, record)
    return leaf


@pytest.mark.asyncio
async def test_expired_identity_stops_signing(
    profile, admin, root, wallet_key, monkeypatch
):
    await store_active(profile, root, wallet_key)
    async with profile.session() as session:
        record = await xid.get_record(session, xid.ACTIVE_ID)
        record["valid_until"] = (NOW - timedelta(minutes=1)).isoformat()
        await xid.put_record(session, xid.ACTIVE_ID, record)

    response = await call(
        vp_request.create_oid4vp_request,
        admin,
        body={
            "dcql_query_id": "query-1",
            "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
        },
    )
    assert response.status == 409
    assert "register a renewed certificate" in response.text

    request_record = MagicMock(pres_def_id=None, dcql_query_id="query-1")
    request_record.delete_record = AsyncMock()
    monkeypatch.setattr(
        verification.OID4VPRequest,
        "retrieve_by_id",
        AsyncMock(return_value=request_record),
    )
    response = await call(
        verification.get_request, admin, match_info={"request_id": "r-1"}
    )
    assert response.status == 409
    # The request is not used up by a refused fetch.
    request_record.delete_record.assert_not_called()


@pytest.mark.asyncio
async def test_expiry_warning_shown_and_logged_once(
    profile, admin, root, wallet_key, caplog
):
    xid._warned_on.clear()
    await store_active(profile, root, wallet_key, not_after=NOW + timedelta(days=20))

    shown = body_of(await call(vp_request.get_x509_identity, admin))
    assert shown["expiry_warning"] is True

    async with profile.session() as session:
        await xid.resolve_client_identity(session, profile.settings)
        await xid.resolve_client_identity(session, profile.settings)
    assert caplog.text.count("expires in") == 1


@pytest.mark.asyncio
async def test_legacy_record_checked_on_first_use(profile, root, wallet_key):
    root_key, root_cert = root
    leaf = make_leaf(
        public_key_from_jwk(xid.public_jwk_of(wallet_key.did)),
        root_key,
        root_cert,
        dns_name="verifier.example.org",
    )
    legacy = {
        "cert_chain": [
            base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()
        ],
        "verification_method": wallet_key.did + "#0",
        "client_id": "verifier.example.org",
    }
    async with profile.session() as session:
        await xid.put_record(session, xid.ACTIVE_ID, legacy)
        identity = await xid.resolve_client_identity(session, profile.settings)
        stored = await xid.get_record(session, xid.ACTIVE_ID)
    assert identity.client_id == "x509_san_dns:verifier.example.org"
    assert stored["checked"] is True

    # A legacy record whose leaf has no matching SAN is refused.
    legacy["client_id"] = "other.example.org"
    async with profile.session() as session:
        await xid.put_record(session, xid.ACTIVE_ID, legacy)
        with pytest.raises(xid.X509IdentityUnusable, match="failed its checks"):
            await xid.resolve_client_identity(session, profile.settings)


@pytest.mark.asyncio
async def test_old_record_with_trust_anchor_signs_without_it(profile, root, wallet_key):
    leaf = await store_active(profile, root, wallet_key)
    async with profile.session() as session:
        record = await xid.get_record(session, xid.ACTIVE_ID)
        record["cert_chain"] = [_der_b64(leaf), _der_b64(root[1])]
        await xid.put_record(session, xid.ACTIVE_ID, record)
        identity = await xid.resolve_client_identity(session, profile.settings)
    assert identity.x5c == [_der_b64(leaf)]


@pytest.mark.asyncio
async def test_no_identity_means_did_jwk(profile):
    async with profile.session() as session:
        assert await xid.resolve_client_identity(session, profile.settings) is None


@pytest.mark.asyncio
async def test_request_object_uses_x509_hash(
    profile, admin, root, wallet_key, monkeypatch
):
    leaf = await store_active(profile, root, wallet_key)
    request_record = MagicMock(
        pres_def_id=None,
        dcql_query_id="query-1",
        vp_formats={"mso_mdoc": {"alg": ["ES256"]}},
    )
    request_record.delete_record = AsyncMock()
    expected = f"x509_hash:{xid.x509_hash(leaf)}"
    # As stored by the create route
    pres = MagicMock(presentation_id="pres-1", client_id=expected)
    pres.save = AsyncMock()
    jwt_sign = AsyncMock(return_value="signed-token")
    monkeypatch.setattr(
        verification.OID4VPRequest,
        "retrieve_by_id",
        AsyncMock(return_value=request_record),
    )
    monkeypatch.setattr(
        verification.OID4VPPresentation,
        "retrieve_by_request_id",
        AsyncMock(return_value=pres),
    )
    monkeypatch.setattr(
        verification.DCQLQuery,
        "retrieve_by_id",
        AsyncMock(return_value=MagicMock(record_value={"credentials": []})),
    )
    monkeypatch.setattr(verification, "jwt_sign", jwt_sign)

    response = await call(
        verification.get_request, admin, match_info={"request_id": "r-1"}
    )

    assert response.text == "signed-token"
    kwargs = jwt_sign.call_args.kwargs
    assert kwargs["payload"]["client_id"] == expected
    assert kwargs["payload"]["iss"] == expected
    assert pres.client_id == expected
    assert kwargs["headers"]["alg"] == "ES256"
    assert kwargs["headers"]["x5c"] == [
        base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()
    ]
    assert "kid" not in kwargs["headers"]
    assert kwargs["verification_method"] == wallet_key.did + "#0"
    assert kwargs["payload"]["client_metadata"]["vp_formats_supported"]


@pytest.mark.asyncio
async def test_fetch_refused_when_identity_changed_since_create(
    profile, admin, root, wallet_key, monkeypatch
):
    await store_active(profile, root, wallet_key)
    request_record = MagicMock(pres_def_id=None, dcql_query_id="query-1")
    request_record.delete_record = AsyncMock()
    # Created while the tenant still used did:jwk
    pres = MagicMock(presentation_id="pres-1", client_id="did:jwk:example")
    monkeypatch.setattr(
        verification.OID4VPRequest,
        "retrieve_by_id",
        AsyncMock(return_value=request_record),
    )
    monkeypatch.setattr(
        verification.OID4VPPresentation,
        "retrieve_by_request_id",
        AsyncMock(return_value=pres),
    )

    response = await call(
        verification.get_request, admin, match_info={"request_id": "r-1"}
    )
    assert response.status == 409
    assert "identity changed" in response.text
    request_record.delete_record.assert_not_called()


def test_expiry_uses_earliest_expiry_in_chain(pki):
    mid_key, mid = make_intermediate(pki["root_key"], pki["root"])
    mid = (
        x509.CertificateBuilder()
        .subject_name(mid.subject)
        .issuer_name(pki["root"].subject)
        .public_key(mid_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(pki["root_key"], hashes.SHA256())
    )
    leaf = make_leaf(pki["wallet_public"], mid_key, mid)
    checked = xid.check_chain([leaf, mid], pki["jwk"])
    record = xid.active_record(checked, "x509_hash", "did:jwk:example#0")

    assert record["valid_until"] == mid.not_valid_after_utc.isoformat()
    status = xid.expiry_status(record)
    assert status["expiry_warning"] is True
    assert status["expires_in_days"] in (9, 10)


@pytest.mark.parametrize(
    "subject, san, message",
    [
        ({"common_name": "x" * 65}, None, "1 to 64"),
        ({"common_name": "Example", "country": "USA"}, None, "two-letter"),
        ({"common_name": "Example", "country": "us"}, None, "two-letter"),
        ({"common_name": "Example", "organization": 5}, None, "must be a string"),
        ({"common_name": "Example\nClinic"}, None, "must be a string"),
        ({"common_name": " "}, None, "common_name is required"),
        ({"common_name": "Example"}, {"dns": "verifier.example.org"}, "list of strings"),
        ({"common_name": "Example"}, {"ip": ["10.0.0.1"]}, "Unknown san"),
    ],
)
def test_csr_input_is_validated(subject, san, message):
    with pytest.raises(xid.X509IdentityError, match=message):
        xid.validate_csr_input(subject, san)


@pytest.mark.asyncio
async def test_refused_csr_leaves_no_key(admin, profile, monkeypatch):
    async with profile.session() as session:
        before = await session.handle.fetch_all_keys()
    with pytest.raises(web.HTTPBadRequest):
        await call(
            vp_request.create_x509_identity_csr,
            admin,
            body={"subject": {"common_name": "Example", "organization": 5}},
        )

    # A failure after the key was made removes the key and its DID again.
    monkeypatch.setattr(
        vp_request, "build_csr", AsyncMock(side_effect=RuntimeError("boom"))
    )
    with pytest.raises(RuntimeError):
        await call(
            vp_request.create_x509_identity_csr,
            admin,
            body={"subject": {"common_name": "Example Clinic"}},
        )
    async with profile.session() as session:
        after = await session.handle.fetch_all_keys()
        assert await xid.get_record(session, xid.PENDING_ID) is None
    assert len(after) == len(before)


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", [None, "x509_hash"])
async def test_client_id_needs_x509_san_dns(admin, root, scheme):
    _, leaf = await csr_and_leaf(admin, root)
    body = {"cert_chain_pem": pem(leaf), "client_id": "verifier.example.org"}
    if scheme:
        body["client_id_scheme"] = scheme
    with pytest.raises(web.HTTPBadRequest, match="x509_san_dns"):
        await call(vp_request.register_x509_identity, admin, body=body)


def test_conflict_is_one_warning_line(caplog):
    response = xid.conflict_response("The verifier certificate chain is not valid now")
    assert response.status == 409
    assert response.text == "409: The verifier certificate chain is not valid now"
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert warnings[0].exc_info is None
