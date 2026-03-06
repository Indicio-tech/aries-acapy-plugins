# Credential Formats

The `oid4vc` plugin supports three credential formats, each implemented as a separate module. This page describes the format-specific behaviour, data structures, and configuration for each.

---

## Format Comparison

| Feature | `jwt_vc_json` | `sd_jwt_vc` | `mso_mdoc` |
|---|---|---|---|
| Standard | W3C VCDM 1.0 as JWT | SD-JWT VC spec | ISO 18013-5 |
| Encoding | JWT (base64url) | SD-JWT with disclosures | CBOR + COSE |
| Selective disclosure | No | Yes | Yes (per namespace) |
| Plugin flag | (built-in) | `--plugin sd_jwt_vc` | `--plugin mso_mdoc` |
| Extra dependency | None | `jsonpointer` | `cbor2`, `pycose`, `isomdl-uniffi` |
| Format string | `jwt_vc_json` | `vc+sd-jwt` or `dc+sd-jwt` | `mso_mdoc` |
| Admin route | `/create/jwt` | `/create/sd-jwt` | `/create` (generic) |
| Key types | `ed25519`, `p256` | `ed25519`, `p256` | `p256` (COSE EC2) |

---

## jwt_vc_json

### Overview

Issues W3C Verifiable Credentials as JWTs following [W3C VCDM 1.0](https://www.w3.org/TR/vc-data-model/). The JWT payload uses the `vc` claim to carry the credential body.

### Module

`jwt_vc_json/` — automatically registered by `oid4vc/__init__.py`. No separate `--plugin` flag required.

```
Issuer:        jwt_vc_json, jwt_vc
CredVerifier:  jwt_vc_json, jwt_vc
PresVerifier:  jwt_vp_json, jwt_vp
```

### Issued Credential Structure

```json
{
  "alg": "ES256",
  "kid": "did:jwk:eyJ...#0",
  "typ": "JWT"
}
.
{
  "iss": "did:jwk:eyJ...",
  "sub": "did:jwk:<holder>",
  "nbf": 1700000000,
  "jti": "urn:uuid:abc123",
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "credentialSubject": {
      "id": "did:jwk:<holder>",
      "given_name": "Alice",
      "family_name": "Smith",
      "degree": "Bachelor of Science"
    }
  }
}
```

Key JWT claims:

| Claim | Source |
|---|---|
| `iss` | Issuer DID (`exchange.issuer_id`) |
| `sub` | Holder DID (extracted from proof of possession) |
| `nbf` | Issuance time (Unix timestamp) |
| `jti` | Credential ID (`urn:uuid:<exchange_id>`) |
| `vc.credentialSubject` | `exchange.credential_subject` |

### Supported Credential `create/jwt` Schema

The `@context` and `type` arrays defined in the supported credential record are used to populate `vc.@context` and `vc.type` in every issued credential.

```json
{
  "format": "jwt_vc_json",
  "id": "UniversityDegreeCredential",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "credentialSubject": {
    "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
    "degree": {"display": [{"name": "Degree", "locale": "en-US"}]}
  }
}
```

### Status List Integration

When `OID4VCI_STATUS_HANDLER` is configured, the plugin calls `StatusHandler.get_credential_status(profile, exchange)` before issuing. The returned `credentialStatus` object is merged into `vc.credentialStatus`.

---

## sd_jwt_vc

### Overview

Issues SD-JWT Verifiable Credentials following the [SD-JWT VC specification](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html). Selective disclosure allows holders to reveal only a chosen subset of claims when presenting.

### Module

`sd_jwt_vc/` — requires `--plugin sd_jwt_vc` in ACA-Py configuration.

```
Issuer:        vc+sd-jwt, dc+sd-jwt
CredVerifier:  vc+sd-jwt, dc+sd-jwt
PresVerifier:  vc+sd-jwt, dc+sd-jwt
```

### SD-JWT Structure

```
<header>.<payload>.<signature>~<disclosure-1>~<disclosure-2>~...~<kb-jwt>
```

**Header:**

```json
{
  "alg": "ES256",
  "kid": "did:jwk:eyJ...#0",
  "typ": "vc+sd-jwt"
}
```

**Payload (simplified):**

```json
{
  "iss": "did:jwk:eyJ...",
  "iat": 1700000000,
  "vct": "EmployeeCredential",
  "cnf": {
    "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
  },
  "_sd": ["hash1", "hash2", "hash3"],
  "_sd_alg": "sha-256",
  "employee_id": "EMP-12345"
}
```

- Claims in `sd_list` appear as `_sd` hashes in the payload
- Claims *not* in `sd_list` appear in plain text in the payload
- `cnf.jwk` holds the holder's public key (from proof of possession)
- `vct` is the type identifier and is always disclosed

### Protected Claims

The following claims can never be in `sd_list` and are always disclosed:

```
/iss  /exp  /vct  /nbf  /cnf  /status
```

Attempting to include these in `sd_list` will result in a validation error during issuance.

### Selective Disclosure via `sd_list`

`sd_list` contains [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901) paths relative to the credential subject:

```json
"sd_list": [
  "/given_name",
  "/family_name",
  "/address/street_address",
  "/driving_privileges/0/vehicle_category_code"
]
```

Nested paths and array element paths are supported.

### Supported Credential `create/sd-jwt` Schema

```json
{
  "format": "vc+sd-jwt",
  "id": "EmployeeCredential",
  "vct": "EmployeeCredential",
  "display": [{"name": "Employee Credential", "locale": "en-US"}],
  "claims": {
    "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
    "family_name": {"display": [{"name": "Family Name", "locale": "en-US"}]},
    "department": {"display": [{"name": "Department", "locale": "en-US"}]}
  },
  "sd_list": ["/given_name", "/family_name", "/department"]
}
```

### X.509 Certificate Chain in Holder Binding

When the holder's proof of possession includes an `x5c` header (rather than `kid` or `jwk`), the issuer embeds the holder's certificate chain in the `cnf` claim:

```json
"cnf": {
  "x5c": ["<base64-leaf-cert>", "<base64-intermediate>"]
}
```

---

## mso_mdoc

### Overview

Issues mobile Documents (mDOC) following [ISO 18013-5](https://www.iso.org/standard/69084.html) in CBOR encoding with COSE signing. This format is used for digital driving licences, government IDs, and travel documents.

### Module

`mso_mdoc/` — requires `--plugin mso_mdoc` and the `isomdl-uniffi` native library.

```
Issuer:        mso_mdoc
CredVerifier:  mso_mdoc
PresVerifier:  mso_mdoc
```

See [mso_mdoc/README.md](../mso_mdoc/README.md) for detailed installation instructions.

### mDOC Structure

An mDOC is CBOR-encoded data organised into:

- **DocType:** Identifies the document type (e.g. `org.iso.18013.5.1.mDL`)
- **Namespaces:** Groups of related claims. Standard namespaces:
  - `org.iso.18013.5.1` — core driving licence fields
  - `org.iso.18013.5.1.aamva` — North American extension fields
- **MSO (Mobile Security Object):** COSE-signed data structure containing digests of each claim, issuer signature, validity period
- **IssuerSigned:** Per-claim signed data structures

### Credential Subject Structure

When creating an exchange for mDOC, `credential_subject` must be organized by namespace:

```json
{
  "org.iso.18013.5.1": {
    "given_name": "Alice",
    "family_name": "Smith",
    "birth_date": "1990-01-15",
    "document_number": "DL-1234567890",
    "expiry_date": "2030-01-01",
    "issue_date": "2020-01-01",
    "issuing_country": "US",
    "issuing_authority": "Dept. of Motor Vehicles",
    "portrait": "<base64-jpeg>",
    "driving_privileges": [
      {
        "vehicle_category_code": "B",
        "issue_date": "2020-01-01",
        "expiry_date": "2030-01-01"
      }
    ]
  },
  "org.iso.18013.5.1.aamva": {
    "DHS_compliance": "F",
    "EDL_credential": 1
  }
}
```

### Key and Certificate Management

The `mso_mdoc` plugin manages its own signing keys and certificates, separate from ACA-Py's main wallet keys.

**Startup:** Automatically generates a default EC P-256 key and self-signed certificate if none exist.

**Key lifecycle:**

```bash
# Inspect the default certificate (includes public key, validity dates)
curl -s $ADMIN/mso_mdoc/certificates/default | python3 -m json.tool

# Generate a new key + self-signed cert (e.g. for rotation)
curl -X POST $ADMIN/mso_mdoc/generate-keys

# List all keys
curl -s $ADMIN/mso_mdoc/keys | python3 -m json.tool
```

The signing certificate's public key forms the IACA leaf in the document signer certificate chain used in the MSO. Verifiers must have the corresponding root CA in their trust store.

### Trust Anchors

Trust anchors are root CA certificates used when **verifying** received mDOC presentations. Without trust anchors, mDOC verification will fail.

For testing, you can add your own self-signed CA (generated by `POST /mso_mdoc/generate-keys`):

```bash
# Export the default self-signed cert PEM (this acts as its own root for testing)
DEFAULT_CERT=$(curl -s $ADMIN/mso_mdoc/certificates/default | python3 -c \
  "import json,sys; print(json.load(sys.stdin)['certificate_pem'])")

# Add it as a trust anchor
curl -X POST $ADMIN/mso_mdoc/trust-anchors \
  -H "Content-Type: application/json" \
  -d "{
    \"certificate_pem\": \"$DEFAULT_CERT\",
    \"anchor_id\": \"local-self-signed\"
  }"
```

For production, add the IACA (Issuing Authority Certificate Authority) root certificate from the official issuer.

### Trust Store Configuration

| `OID4VC_MDOC_TRUST_STORE_TYPE` | Behaviour |
|---|---|
| `file` (default) | Reads PEM files from `OID4VC_MDOC_TRUST_ANCHORS_PATH` directory on startup |
| `wallet` | Reads trust anchors stored via `POST /mso_mdoc/trust-anchors` API |
| `none` or `disabled` | Disables trust anchor verification (do not use in production) |

### Manual Sign/Verify

Test the mDOC signing flow without going through OID4VCI:

```bash
# Sign a payload manually
SIGNED=$(curl -s -X POST $ADMIN/mso_mdoc/sign \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {
      "org.iso.18013.5.1": {
        "given_name": "Alice",
        "birth_date": "1990-01-15"
      }
    }
  }')
echo $SIGNED

# Verify the signed mDOC
curl -X POST $ADMIN/mso_mdoc/verify \
  -H "Content-Type: application/json" \
  -d "{\"mso_mdoc\": \"$SIGNED\"}"
```
