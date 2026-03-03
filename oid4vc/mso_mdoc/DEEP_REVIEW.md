# OID4VCI v1 + MSO-mDoc Deep Code Review

**Reviewer:** GitHub Copilot (Claude Sonnet 4.6)  
**Date:** 2026-03-03  
**Scope:** `oid4vc/mso_mdoc/` and `oid4vc/oid4vc/public_routes/` (token, credential endpoints)  
**Branch:** `feat/mdoc-support`

---

## Critical (Security / Correctness)

---

### C-1: Private key material duplicated in plaintext storage metadata

**Files:** `mso_mdoc/cred_processor.py` (~L97), `mso_mdoc/key_generation.py` (~L349)

`private_key_pem` is stored inside the `metadata` dict alongside the JWK (which already contains the `d` parameter). Both are serialised to JSON and written to the ACA-Py storage record verbatim. Askar encrypts wallet records at rest, but:

- The private key now has two redundant representations in storage.
- If the record is ever logged (DEBUG key routes dump metadata), serialised over an API, or exported, both copies are exposed.
- The `list_keys` response allowlist in `key_routes.py` is the only guard — any future route that returns raw metadata bypasses it.

**Fix:** Remove `private_key_pem` from `key_metadata` before calling `store_signing_key`. The `d` field in the JWK is sufficient to reconstruct the PEM on demand via `serialization.load_jwk`.

```python
# cred_processor.py ~L97 — private_key_pem stored redundantly
key_metadata = {
    "jwk": jwk,                         # already includes "d"
    "public_key_pem": public_key_pem,
    "private_key_pem": private_key_pem,  # <-- redundant and risky; remove this
    ...
}
```

---

### C-2: `codecs.decode(…, "unicode_escape")` on attacker-controlled input

**File:** `mso_mdoc/cred_processor.py` — `_normalize_mdoc_result()`

`codecs.decode(cleaned, "unicode_escape")` is applied to the inner content of a `b'...'`-wrapped string that originates from isomdl-uniffi output derived from CBOR credential data. `unicode_escape` decoding is a superset of arbitrary byte-level escape sequences and can produce unexpected results including:

- Null bytes, surrogate codepoints, and arbitrary byte values injected via `\xNN` sequences.
- Data confusion between the `b'...'` sentinel and a credential payload that intentionally contains those characters.

Modern isomdl-uniffi no longer emits the Python `b'...'` repr; this branch is vestigial. If retained for backward compatibility, replace `codecs.decode` with `bytes.fromhex()` for hex literals, or simply return `cleaned` unchanged.

---

### C-3: DPoP token scheme accepted but proof is not validated

**File:** `oid4vc/oid4vc/public_routes/token.py` — `check_token()`

`check_token` accepts `Authorization: DPoP <token>` but the inline comment confirms:

> "The DPoP proof itself is not cryptographically validated here (full DPoP binding per RFC 9449 is not yet implemented)."

A wallet that upgrades to DPoP specifically to get replay-protection gains none — the bearer JWT is accepted as-is. A stolen token can be replayed despite DPoP.

**Fix:** Either implement RFC 9449 §4 DPoP binding (verify the `DPoP` header JWT, bind to `ath` claim), or explicitly reject the `DPoP` scheme with a standards-compliant error response until it is supported:

```python
if scheme.lower() == "dpop":
    raise web.HTTPUnauthorized(
        text='{"error":"use_dpop_nonce"}',
        headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                 "Content-Type": "application/json"},
    )
```

---

### C-4: Missing `aud` claim validation in proof-of-possession

**File:** `oid4vc/oid4vc/public_routes/token.py` — `handle_proof_of_posession()`

The holder's proof JWT is validated for nonce and signature but the `aud` claim is **not checked**. OID4VCI 1.0 §7.2.2 mandates:

> "The `aud` claim value MUST be the Credential Issuer Identifier."

Without this check, a valid proof JWT issued for issuer A can be replayed at issuer B (cross-issuer replay attack).

**Fix:**
```python
expected_aud = Config.from_settings(profile.settings).endpoint
actual_aud = payload.get("aud")
# aud may be a string or list per RFC 7519
if isinstance(actual_aud, list):
    if expected_aud not in actual_aud:
        raise web.HTTPBadRequest(...)
elif actual_aud != expected_aud:
    raise web.HTTPBadRequest(...)
```

---

### C-5: `_is_preverified_claims_dict` heuristic bypassable

**File:** `mso_mdoc/mdoc/verifier.py` — `_is_preverified_claims_dict()`

A credential dict is classified as "already verified" if any key starts with `"org.iso."` or equals `"status"`. An attacker who can supply a JSON credential body with a key like `"org.iso.forged": "anything"` will have that body accepted as a verified credential without any signature check, bypassing the entire isomdl trust-anchor chain.

**Fix:** The pre-verified path should not be reachable from the public `verify_credential` entry point. If an internal path legitimately produces pre-verified claims, use a typed sentinel dataclass rather than a duck-typed dict:

```python
@dataclass
class PreverifiedMdocClaims:
    """Internal marker: claims already verified by verify_presentation."""
    namespaces: dict
```

---

### C-6: Non-constant-time PIN comparison

**File:** `oid4vc/oid4vc/public_routes/token.py` (~L169)

```python
if user_pin != record.pin:
```

Plain string comparison is not constant-time. Timing attacks can distinguish correct password prefixes, allowing offline enumeration of short PINs.

**Fix:**
```python
import hmac
if not hmac.compare_digest(user_pin, record.pin):
```

---

## Major (Functional Bugs)

---

### M-1: `pem_to_jwk` blindly asserts P-256 curve

**File:** `mso_mdoc/key_generation.py` — `pem_to_jwk()` (~L115)

`"crv": "P-256"` and a fixed coordinate length of 32 bytes are hardcoded unconditionally. If a P-384 or P-521 PEM is loaded via `OID4VC_MDOC_SIGNING_KEY_PATH`, the emitted JWK will have the wrong `crv` value and truncated/incorrect `x`/`y` coordinates (P-384 needs 48 bytes). The isomdl-uniffi Rust layer will then produce a malformed MSO with no clear error.

**Fix:** Inspect `private_key.curve` and branch:
```python
from cryptography.hazmat.primitives.asymmetric import ec

_CURVE_MAP = {
    ec.SECP256R1: ("P-256", 32),
    ec.SECP384R1: ("P-384", 48),
    ec.SECP521R1: ("P-521", 66),
}
crv, length = _CURVE_MAP.get(type(private_key.curve), (None, None))
if crv is None:
    raise ValueError(f"Unsupported EC curve: {type(private_key.curve).__name__}")
```

---

### M-2: `get_certificate_for_key` returns records in undefined order

**File:** `mso_mdoc/storage/certificates.py` — `get_certificate_for_key()` (~L173)

```python
record = records[0]
```

`find_all_records` has no ordering guarantee. After a key rotation that stores a new certificate for the same `key_id`, the old certificate may still be returned. The signing cert and its MSO would then mismatch — a verification failure for all newly issued credentials.

**Fix:** Sort by the stored `created_at` field descending and take the most-recent, or tag the current certificate as `"current": "true"` and filter on it.

---

### M-3: Write side-effect inside a read operation (`get_default_signing_key`)

**File:** `mso_mdoc/storage/__init__.py` (~L206-213)

When no `default_signing_key` config record exists, `get_default_signing_key` auto-selects `key_list[0]` **and persists it** as the new default in the same call. Problems:

1. `list_keys` returns records in unspecified storage order, so the auto-selected key is non-deterministic across database backends.
2. Persisting state inside a getter is surprising and unsafe under concurrent requests (two threads could race to set different defaults).

**Fix:** Remove the write from the getter. Expose a separate `set_default_signing_key(session, key_id)` method and call it explicitly from the setup/startup path.

---

### M-4: Holder private key `d` may reach Rust device-key via fallback path

**File:** `mso_mdoc/cred_processor.py` (~L486-498) — `issue()` fallback branch

When `pop.holder_jwk` is absent but `device_key_str` is set via `json.dumps(device_candidate)`, and if `device_candidate` was itself a JWK dict serialised from `pop.holder_jwk` including the `d` parameter, then the private key is forwarded to `isomdl_mdoc_sign` as the holder device key. The Rust layer does not enforce public-only JWK, so the private key becomes embedded in the MSO.

**Fix:** Apply the same `{kty,crv,x,y}` allowlist stripping unconditionally before any serialisation of the holder key:
```python
def _strip_to_public_jwk(jwk: dict) -> dict:
    return {k: jwk[k] for k in ("kty", "crv", "x", "y") if k in jwk}
```

---

### M-5: Legacy device-auth fallback silently relaxes holder binding

**File:** `mso_mdoc/mdoc/verifier.py` — `_verify_single_presentation()` (~L490)

When device authentication fails but issuer authentication succeeds, `verify_oid4vp_response_legacy` is tried silently. Device authentication is the holder-binding proof per ISO 18013-5 §9.1.4. Accepting a "legacy" format without device auth means:

- Credentials with a stripped or invalid device signature are accepted.
- The replay-protection that device auth provides for OID4VP flows is defeated.
- The caller sees `device_auth: "INVALID"` in the payload but `verified: True`.

**Fix:** If the legacy path is necessary for interoperability, it must produce a distinct result (e.g., `device_auth_method: "legacy"`, `holder_binding: false`), be logged at WARNING, and be explicitly gated by a configuration flag rather than triggered automatically.

---

### M-6: `mdoc_sign` route swallows non-`ValueError` exceptions

**File:** `mso_mdoc/routes.py` — `mdoc_sign()` (~L193)

```python
except ValueError as err:
    raise web.HTTPBadRequest(reason=str(err)) from err
```

Only `ValueError` is caught. `CredProcessorError`, `StorageError`, or file I/O errors from static key loading propagate unhandled. ACA-Py's middleware converts them to HTTP 500 with an unstructured plain-text body, violating the OID4VCI error response format.

**Fix:**
```python
except CredProcessorError as err:
    raise web.HTTPUnprocessableEntity(
        text=json.dumps({"error": "credential_issuance_failed",
                         "error_description": str(err)}),
        content_type="application/json",
    ) from err
except StorageError as err:
    raise web.HTTPServiceUnavailable(
        text=json.dumps({"error": "storage_unavailable",
                         "error_description": str(err)}),
        content_type="application/json",
    ) from err
except (ValueError, Exception) as err:
    raise web.HTTPBadRequest(reason=str(err)) from err
```

---

### M-7: Hardcoded example URIs in generated IACA certificates

**File:** `mso_mdoc/key_generation.py` (~L267-277)

```python
x509.UniformResourceIdentifier("http://example.com/crl")  # CRL
x509.UniformResourceIdentifier("https://example.com")     # IssuerAltName
```

Validators that perform CRL fetching or URI consistency checks against the issued credential will fail in production. Wallets that verify the IACA certificate chain will see `example.com` URIs and may reject.

**Fix:** Make these configurable:
```python
crl_uri = os.getenv("OID4VC_MDOC_CRL_URI", "http://example.com/crl")
issuer_uri = os.getenv("OID4VC_MDOC_ISSUER_URI", "https://example.com")
```
Document clearly in README that the defaults are non-production.

---

### M-8: CBOR key-patch has no version gate

**File:** `mso_mdoc/mdoc/issuer.py` — `_patch_mdoc_keys()`

`_patch_mdoc_keys` rewrites `issuer_auth → issuerAuth` and `namespaces → nameSpaces` in the CBOR output because an older isomdl-uniffi version emitted snake_case keys. If isomdl-uniffi is updated to emit camelCase natively, the old keys will be absent and the patch is silently a no-op — fine. But if the library emits both forms (transition release), `mdoc_map` would gain both keys and verification would pick the wrong one.

**Fix:** Assert pre-conditions (either both old keys are present, or none are) and log the isomdl-uniffi version at startup:
```python
import isomdl_uniffi
LOGGER.info("isomdl_uniffi version: %s", getattr(isomdl_uniffi, "__version__", "unknown"))
```
Remove the patch entirely once the minimum required isomdl-uniffi version emits camelCase.

---

### M-9: `handle_proof_of_posession` typo

**File:** `oid4vc/oid4vc/public_routes/token.py`

Function name is misspelled (`posession` → `possession`). Because this is called from multiple sites and forms part of the protocol implementation, the typo propagates to log search, tracing systems, and any external integrations that reference the symbol name.

**Fix:** Rename to `handle_proof_of_possession` with a deprecation alias for any existing callers.

---

## Minor (Code Quality / Spec Compliance)

---

### m-1: Duplicate key-resolution code paths

**Files:** `mso_mdoc/cred_processor.py` L44 (module-level) and ~L267 (class method)

`resolve_signing_key_for_credential` (module-level) and `_resolve_signing_key` (instance method) implement overlapping env-var static-key loading logic. `_resolve_signing_key` calls the module-level function only as a side-effect generator. Two diverging copies of the same logic will drift over time and produce subtle inconsistencies (e.g., one path may handle an env var the other doesn't).

**Fix:** Consolidate into a single `_resolve_signing_key` implementation; delete the module-level function or make it a thin wrapper.

---

### m-2: `MdocVerifyResult` vs `VerifyResult` inconsistency

**File:** `mso_mdoc/mdoc/verifier.py` (~L775)

The module-level `mdoc_verify()` function returns `MdocVerifyResult` while `MsoMdocCredVerifier` and `MsoMdocPresVerifier` return the framework's `VerifyResult`. Callers that can receive output from either path must handle two incompatible return types.

**Fix:** Have `mdoc_verify()` return `VerifyResult` (wrapping error text in `payload={"error": ...}` for the failure case) and delete `MdocVerifyResult`.

---

### m-3: `credentials` array missing `format` field

**File:** `oid4vc/oid4vc/public_routes/credential.py` (~L295-297)

```python
"credentials": [{"credential": credential}]
```

OID4VCI 1.0 §7.3.1 specifies that objects in the `credentials` array SHOULD include a `format` field so wallets can parse the credential without out-of-band context.

**Fix:**
```python
"credentials": [{"format": supported.format, "credential": credential}]
```

---

### m-4: Non-relative absolute import in `WalletTrustStore`

**File:** `mso_mdoc/mdoc/verifier.py` (~L186)

```python
from mso_mdoc.storage import MdocStorageManager
```

All other imports in the same file use relative paths. This absolute import breaks if the package is installed under a different namespace or renamed.

**Fix:** `from ..storage import MdocStorageManager`

---

### m-5: Flatten/re-wrap round-trip in payload preparation

**Files:** `mso_mdoc/cred_processor.py` (`_prepare_payload`), `mso_mdoc/mdoc/issuer.py` (`_prepare_mdl_namespaces`)

`_prepare_payload` flattens the namespace wrapper dict into a flat key-value map, then `_prepare_mdl_namespaces` immediately re-wraps the flat map back under `"org.iso.18013.5.1"`. The flatten step can silently overwrite keys (warned but not rejected) and loses namespace structure information. Preserve the namespace dict throughout and let `issuer.py` traverse it directly.

---

### m-6: `datetime.utcnow()` deprecated in Python 3.12+

**File:** `oid4vc/oid4vc/public_routes/token.py` (~L245)

```python
if result.payload["exp"] < datetime.datetime.utcnow().timestamp():
```

`datetime.utcnow()` is deprecated in Python 3.12 (removed in 3.14).

**Fix:**
```python
from datetime import UTC
if result.payload["exp"] < datetime.datetime.now(UTC).timestamp():
```

---

### m-7: Env-var file path not restricted to expected directory

**File:** `mso_mdoc/cred_processor.py` (~L291)

`OID4VC_MDOC_SIGNING_KEY_PATH` is opened with `open(key_path, "r")` without sanitising the path against a known-safe base directory. In environments where env vars can be influenced (e.g., `.env` overrides in CI), this could read arbitrary files.

**Fix:** Resolve and validate the path at startup:
```python
safe_base = "/run/secrets/mdoc"
resolved = os.path.realpath(key_path)
if not resolved.startswith(safe_base):
    raise ValueError(f"Key path {key_path!r} is outside allowed directory {safe_base}")
```

---

### m-8: `trust_anchor_pems or None` collapses empty vs disabled semantics

**File:** `mso_mdoc/routes.py` (~L270)

```python
result = mso_mdoc_verify(mso_mdoc, trust_anchors=trust_anchor_pems or None)
```

An empty list `[]` (no trust anchors configured) is falsy, so `None` is passed. The callee skips trust validation entirely when it receives `None`. The two states — "no anchors configured (reject all)" vs "trust validation disabled" — are collapsed into one. In strict deployments this means an mDoc signed by any self-issued key passes when no anchors are in the wallet.

**Fix:** Pass `trust_anchor_pems` directly. If it is `[]`, isomdl-uniffi rejects all issuers (correct behaviour). Add a separate `OID4VC_MDOC_SKIP_TRUST_VALIDATION=true` env var for explicit opt-out.

---

### m-9: `O(n × m)` certificate lookup in `get_signing_key_and_cert`

**File:** `mso_mdoc/storage/__init__.py` (~L175)

For each of `n` signing keys, the method iterates all `m` certificates. With large key stores this is O(n×m) storage reads.

**Fix:** Build a dict keyed by `key_id` from the certificate list before the loop:
```python
cert_by_key = {c["key_id"]: c for c in cert_list}
for key_data in key_list:
    cert = cert_by_key.get(key_data["key_id"])
```

---

### m-10: No idempotency guard in `generate_default_keys_and_certs`

**File:** `mso_mdoc/key_generation.py` and `mso_mdoc/__init__.py` (~L121)

`generate_default_keys_and_certs` is called on every startup but `store_key` raises `StorageDuplicateError` if the key already exists. The outer try/except in `__init__.py` swallows the error silently, masking real storage failures. The function should check for existing keys first and be a no-op if any are found.

---

### m-11: DN fallback parser doesn't handle RFC 4514 escaped commas

**File:** `mso_mdoc/key_generation.py` — `parse_dn()` fallback branch (~L205)

The fallback parser splits on `,` only. An org name like `O=Doe\, Inc` is split into `O=Doe\` and `Inc`, producing incorrect ASN.1. The primary path using `x509.Name.from_rfc4514_string()` handles this correctly; the fallback is only reached on `cryptography < 38.0`.

**Fix:** Assert a minimum `cryptography` version (`>= 38.0`) in `pyproject.toml` to eliminate the fallback branch entirely, or document the limitation explicitly.

---

### m-12: Inheriting from `Protocol` classes unnecessarily

**File:** `mso_mdoc/cred_processor.py` (~L136)

```python
class MsoMdocCredProcessor(Issuer, CredVerifier, PresVerifier):
```

`Issuer`, `CredVerifier`, `PresVerifier` are structural `Protocol` classes. Inheriting from them instead of using structural subtyping suppresses mypy's structural checks and creates a hard dependency on the protocol's internal machinery. Python's `Protocol` is designed to be used structurally (duck typing), not nominally.

**Fix:** Remove the explicit inheritance; the class will still satisfy `isinstance()` checks if `runtime_checkable` decorators are used. Let mypy verify structural compatibility through type annotations alone.

---

## Summary

| ID | Severity | Area | Title |
|----|----------|------|-------|
| C-1 | Critical | Security | Private key PEM stored redundantly in metadata |
| C-2 | Critical | Security | `codecs.decode(unicode_escape)` on untrusted input |
| C-3 | Critical | Security | DPoP accepted but not validated |
| C-4 | Critical | Protocol | Missing `aud` claim validation in PoP JWT |
| C-5 | Critical | Security | Pre-verified-claims heuristic bypassable |
| C-6 | Critical | Security | Non-constant-time PIN comparison |
| M-1 | Major | Correctness | `pem_to_jwk` blindly asserts P-256 |
| M-2 | Major | Correctness | `get_certificate_for_key` returns undefined-order record |
| M-3 | Major | Correctness | Write side-effect inside `get_default_signing_key` getter |
| M-4 | Major | Security | Holder `d` may reach Rust device-key via fallback path |
| M-5 | Major | Protocol | Legacy device-auth fallback silently relaxes holder binding |
| M-6 | Major | API | `mdoc_sign` route swallows non-`ValueError` exceptions |
| M-7 | Major | Protocol | Hardcoded `example.com` URIs in generated IACA certs |
| M-8 | Major | Correctness | CBOR key-patch has no version gate |
| M-9 | Major | Style | `handle_proof_of_posession` typo |
| m-1 | Minor | Quality | Duplicate key-resolution code paths |
| m-2 | Minor | API | `MdocVerifyResult` vs `VerifyResult` inconsistency |
| m-3 | Minor | Protocol | `credentials` array missing `format` field |
| m-4 | Minor | Quality | Non-relative absolute import in `WalletTrustStore` |
| m-5 | Minor | Quality | Flatten/re-wrap round-trip in payload preparation |
| m-6 | Minor | Correctness | `datetime.utcnow()` deprecated in Python 3.12+ |
| m-7 | Minor | Security | Env-var file path not restricted to expected directory |
| m-8 | Minor | Protocol | Empty trust-anchor list collapses to disabled semantics |
| m-9 | Minor | Performance | O(n×m) cert-lookup in `get_signing_key_and_cert` |
| m-10 | Minor | Quality | No idempotency guard in `generate_default_keys_and_certs` |
| m-11 | Minor | Correctness | DN fallback parser doesn't handle RFC 4514 escaped commas |
| m-12 | Minor | Quality | Unnecessary inheritance from `Protocol` classes |
