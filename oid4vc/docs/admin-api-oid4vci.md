# Admin API Reference — OID4VCI (Credential Issuance)

All routes are served on the **ACA-Py Admin Server** (`http://<host>:<admin_port>`). The Swagger UI for the admin server is available at `/api/doc`.

All mutating endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) require an authenticated request in multi-tenant deployments (Bearer token or API key, depending on ACA-Py configuration).

## Error Responses

| HTTP Status | Meaning |
|---|---|
| `400 Bad Request` | Invalid or missing request parameters, validation error, storage error |
| `401 Unauthorized` | Missing or invalid authentication |
| `404 Not Found` | Requested record does not exist |
| `500 Internal Server Error` | Signing failure, key/certificate error, unexpected server error |

Error response body:

```json
{ "reason": "human-readable error message" }
```

---

## Tag: `oid4vci` — Credential Issuance Management

### DID Management

#### `POST /did/jwk/create`

Create a `did:jwk` DID backed by the specified key type.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `key_type` | string | **Yes** | Key algorithm. One of: `ed25519`, `p256` |

**Example request:**

```bash
curl -X POST http://localhost:8021/did/jwk/create \
  -H "Content-Type: application/json" \
  -d '{"key_type": "p256"}'
```

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `did` | string | The created `did:jwk:...` DID |

**Example response:**

```json
{
  "did": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6Ii4uLiIsInkiOiIuLi4ifQ"
}
```

---

### Supported Credentials

Supported credential records define which credential types the issuer can issue — the format, display metadata, and credential schema. They appear in the `credential_configurations_supported` field of the credential issuer metadata (`/.well-known/openid-credential-issuer`).

#### `POST /oid4vci/credential-supported/create`

Register a supported credential using a generic schema (format-agnostic).

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | string | **Yes** | Credential format (e.g. `jwt_vc_json`, `vc+sd-jwt`, `mso_mdoc`) |
| `id` | string | **Yes** | Identifier for this credential configuration (e.g. `UniversityDegreeCredential`) |
| `cryptographic_binding_methods_supported` | array of strings | No | Supported binding methods (e.g. `["did:jwk", "jwk"]`) |
| `cryptographic_suites_supported` | array of strings | No | Supported cryptographic suites (e.g. `["ES256"]`) |
| `proof_types_supported` | object | No | Supported proof types (e.g. `{"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}`) |
| `display` | array of objects | No | Display metadata (name, logo, locale) per language |
| `format_data` | object | No | Format-specific metadata (merged into issuer metadata output) |
| `vc_additional_data` | object | No | Additional VC data such as `@context` and `type` arrays |

**Example request:**

```bash
curl -X POST http://localhost:8021/oid4vci/credential-supported/create \
  -H "Content-Type: application/json" \
  -d '{
    "format": "vc+sd-jwt",
    "id": "EmployeeCredential",
    "cryptographic_binding_methods_supported": ["did:jwk", "jwk"],
    "display": [{"name": "Employee Credential", "locale": "en-US"}]
  }'
```

**Response `200`:** `SupportedCredentialSchema` — the created record.

---

#### `POST /oid4vci/credential-supported/create/jwt`

Register a JWT VC credential configuration (`jwt_vc_json` format). Provides a typed schema for the W3C Verifiable Credential structure.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | string | **Yes** | Must be `jwt_vc_json` |
| `id` | string | **Yes** | Credential configuration identifier |
| `type` | array of strings | **Yes** | W3C VC `type` array (e.g. `["VerifiableCredential", "UniversityDegreeCredential"]`) |
| `@context` | array | **Yes** | JSON-LD contexts (e.g. `["https://www.w3.org/2018/credentials/v1"]`) |
| `cryptographic_binding_methods_supported` | array of strings | No | Supported binding methods |
| `cryptographic_suites_supported` | array of strings | No | Supported suites |
| `proof_types_supported` | object | No | Supported proof types |
| `display` | array of objects | No | Display metadata |
| `credentialSubject` | object | No | Display metadata per claim (shown in wallets) |
| `order` | array of strings | No | Display ordering of claims |

**Example request:**

```bash
curl -X POST http://localhost:8021/oid4vci/credential-supported/create/jwt \
  -H "Content-Type: application/json" \
  -d '{
    "format": "jwt_vc_json",
    "id": "UniversityDegreeCredential",
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "cryptographic_binding_methods_supported": ["did:jwk"],
    "proof_types_supported": {
      "jwt": {"proof_signing_alg_values_supported": ["ES256", "EdDSA"]}
    },
    "display": [{"name": "University Degree", "locale": "en-US"}],
    "credentialSubject": {
      "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
      "family_name": {"display": [{"name": "Family Name", "locale": "en-US"}]},
      "degree": {"display": [{"name": "Degree", "locale": "en-US"}]}
    }
  }'
```

**Response `200`:**

```json
{
  "supported_cred_id": "3f1a2b4c-...",
  "format": "jwt_vc_json",
  "identifier": "UniversityDegreeCredential",
  ...
}
```

---

#### `POST /oid4vci/credential-supported/create/sd-jwt`

Register an SD-JWT VC credential configuration. Requires the `sd_jwt_vc` plugin to be loaded.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | string | **Yes** | `vc+sd-jwt` or `dc+sd-jwt` |
| `id` | string | **Yes** | Credential configuration identifier |
| `vct` | string | **Yes** | Verifiable Credential Type string (e.g. `EmployeeCredential`) |
| `cryptographic_binding_methods_supported` | array of strings | No | |
| `cryptographic_suites_supported` | array of strings | No | |
| `display` | array of objects | No | |
| `claims` | object | No | Per-claim display metadata (keyed by claim name) |
| `order` | array of strings | No | Display ordering of claims |
| `sd_list` | array of strings | No | JSON Pointer paths to claims that should be selectively disclosable (e.g. `["/given_name", "/address/street_address"]`). Claims not in this list are always disclosed. |

**Protected claims** (cannot be in `sd_list`): `/iss`, `/exp`, `/vct`, `/nbf`, `/cnf`, `/status`

**Example request:**

```bash
curl -X POST http://localhost:8021/oid4vci/credential-supported/create/sd-jwt \
  -H "Content-Type: application/json" \
  -d '{
    "format": "vc+sd-jwt",
    "id": "EmployeeCredential",
    "vct": "EmployeeCredential",
    "cryptographic_binding_methods_supported": ["did:jwk", "jwk"],
    "display": [{"name": "Employee Credential", "locale": "en-US"}],
    "claims": {
      "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
      "family_name": {"display": [{"name": "Family Name", "locale": "en-US"}]},
      "department": {"display": [{"name": "Department", "locale": "en-US"}]}
    },
    "sd_list": ["/given_name", "/family_name", "/department"]
  }'
```

**Response `200`:** `SupportedCredentialSchema`

---

#### `GET /oid4vci/credential-supported/records`

List all supported credential configurations.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `supported_cred_id` | string | Filter by record ID |
| `format` | string | Filter by format (e.g. `jwt_vc_json`) |

**Example request:**

```bash
curl http://localhost:8021/oid4vci/credential-supported/records
```

**Response `200`:**

```json
{
  "results": [
    {
      "supported_cred_id": "3f1a2b4c-...",
      "format": "jwt_vc_json",
      "identifier": "UniversityDegreeCredential",
      ...
    }
  ]
}
```

---

#### `GET /oid4vci/credential-supported/records/{supported_cred_id}`

Fetch a single supported credential configuration by ID.

**Path parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `supported_cred_id` | string | **Yes** | Supported credential record ID |

**Example request:**

```bash
curl http://localhost:8021/oid4vci/credential-supported/records/3f1a2b4c-...
```

**Response `200`:** `SupportedCredentialSchema`

---

#### `PUT /oid4vci/credential-supported/records/jwt/{supported_cred_id}`

Replace a JWT VC supported credential record (complete replacement).

**Path parameters:** `supported_cred_id`

**Request body:** Same as `POST /oid4vci/credential-supported/create/jwt`

**Response `200`:**

```json
{
  "supported_cred": { ... },
  "supported_cred_id": "3f1a2b4c-..."
}
```

---

#### `PUT /oid4vci/credential-supported/records/sd-jwt/{supported_cred_id}`

Replace an SD-JWT supported credential record. Requires `sd_jwt_vc` plugin.

**Path parameters:** `supported_cred_id`

**Request body:** Same as `POST /oid4vci/credential-supported/create/sd-jwt`

**Response `200`:**

```json
{
  "supported_cred": { ... },
  "supported_cred_id": "3f1a2b4c-..."
}
```

---

#### `DELETE /oid4vci/credential-supported/records/jwt/{supported_cred_id}`

Remove a supported credential record.

**Example request:**

```bash
curl -X DELETE http://localhost:8021/oid4vci/credential-supported/records/jwt/3f1a2b4c-...
```

**Response `200`:** `{}`

---

### Exchange Records

An exchange record represents a single credential issuance lifecycle.

#### `POST /oid4vci/exchange/create`

Create a new exchange record. This is the primary step that binds a specific holder to a supported credential type before generating an offer.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `supported_cred_id` | string | **Yes** | ID of the supported credential to issue |
| `credential_subject` | object | **Yes** | The claims/values to include in the issued credential |
| `did` | string | No | DID of the issuer. If omitted, ACA-Py's default DID is used |
| `verification_method` | string (URI) | No | Specific verification method URI to use for signing |
| `pin` | string | No | User PIN to be delivered out of band to the holder. Required at token request time if set. |

**Example request:**

```bash
curl -X POST http://localhost:8021/oid4vci/exchange/create \
  -H "Content-Type: application/json" \
  -d '{
    "supported_cred_id": "3f1a2b4c-...",
    "credential_subject": {
      "given_name": "Alice",
      "family_name": "Smith",
      "degree": "Bachelor of Science"
    },
    "did": "did:jwk:eyJjcnYiOiJQLTI1NiIs..."
  }'
```

**Response `200`:** `OID4VCIExchangeRecordSchema`

| Field | Description |
|---|---|
| `exchange_id` | Unique record ID |
| `state` | `created` |
| `supported_cred_id` | Linked supported credential |
| `credential_subject` | Provided claim values |
| `issuer_id` | DID used for signing |
| `verification_method` | Verification method URI |
| `pin` | User PIN (if set) |

---

#### `GET /oid4vci/exchange/records`

List exchange records with optional filtering.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `exchange_id` | string (UUID) | Filter by exchange ID |
| `supported_cred_id` | string | Filter by supported credential ID |
| `state` | string | Filter by state. One of: `created`, `offer`, `issued`, `failed`, `accepted`, `deleted`, `superceded` |

**Example request:**

```bash
curl "http://localhost:8021/oid4vci/exchange/records?state=issued"
```

**Response `200`:**

```json
{
  "results": [
    {
      "exchange_id": "abc123-...",
      "state": "issued",
      ...
    }
  ]
}
```

---

#### `GET /oid4vci/exchange/records/{exchange_id}`

Fetch a single exchange record by ID.

**Example request:**

```bash
curl http://localhost:8021/oid4vci/exchange/records/abc123-...
```

**Response `200`:** `OID4VCIExchangeRecordSchema`

---

#### `DELETE /oid4vci/exchange/records/{exchange_id}`

Delete an exchange record.

**Example request:**

```bash
curl -X DELETE http://localhost:8021/oid4vci/exchange/records/abc123-...
```

**Response `200`:** `{}`

---

### Credential Offers

#### `GET /oid4vci/credential-offer`

Generate a credential offer by value. The entire offer JSON is embedded in the `openid-credential-offer://` URI. Moves the exchange to state `offer`.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `exchange_id` | string | Exchange record ID |
| `user_pin_required` | boolean | Whether the holder must supply the PIN at token time |

**Example request:**

```bash
curl "http://localhost:8021/oid4vci/credential-offer?exchange_id=abc123-..."
```

**Response `200`:**

| Field | Description |
|---|---|
| `credential_offer` | Full `openid-credential-offer://?credential_offer=...` URI (can be shown as QR code) |
| `offer.credential_issuer` | Base URL of the issuer |
| `offer.credential_configuration_ids` | Array of credential type identifiers |
| `offer.grants.pre_authorized_code` | The pre-authorized code |
| `offer.grants.user_pin_required` | Whether a PIN is required |

**Example response:**

```json
{
  "credential_offer": "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22...",
  "offer": {
    "credential_issuer": "https://issuer.example.com",
    "credential_configuration_ids": ["UniversityDegreeCredential"],
    "grants": {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA",
        "user_pin_required": false
      }
    }
  }
}
```

---

#### `GET /oid4vci/credential-offer-by-ref`

Generate a credential offer by reference. Returns a `credential_offer_uri` pointing to an endpoint where the wallet can retrieve the offer. This is useful when the offer JSON is too large to embed in a QR code.

**Query parameters:** Same as `/oid4vci/credential-offer`

**Response `200`:**

| Field | Description |
|---|---|
| `credential_offer_uri` | `openid-credential-offer://?credential_offer_uri=...` URI |
| `offer` | The offer object (same structure as above) |

---

### Credential Refresh

#### `PATCH /oid4vci/credential-refresh/{refresh_id}`

Issue a refreshed credential for an existing exchange. Creates a new exchange record that supersedes the original (original state → `superceded`). Returns the new credential offer.

**Path parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `refresh_id` | string | **Yes** | Refresh identifier from the original exchange record |

**Example request:**

```bash
curl -X PATCH http://localhost:8021/oid4vci/credential-refresh/refresh-abc123
```

**Response `200`:** `OID4VCIExchangeRecordSchema` (new exchange)

---
