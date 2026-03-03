# Admin API Reference

The OID4VC plugin provides a comprehensive Admin API formanaging credential issuance, presentation verification, and DID management. All routes are served on the **ACA-Py Admin Server** (`http://<host>:<admin_port>`).

The Swagger UI for the admin server is available at `/api/doc`.

## API Categories

The Admin API is organized into three main categories:

### [OID4VCI — Credential Issuance Management](admin-api-oid4vci.md)

Endpoints for managing credential issuance using OpenID for Verifiable Credential Issuance (OID4VCI):

- **DID Management** — Create `did:jwk` DIDs for credential signing
- **Supported Credentials** — Configure credential types, formats, and display metadata  
- **Exchange Records** — Track credential issuance lifecycle for individual holders
- **Credential Offers** — Generate QR codes and deep links for holder wallets
- **Credential Refresh** — Issue updated credentials to existing holders

**Supported credential formats:** `jwt_vc_json`, `vc+sd-jwt`, `mso_mdoc`

[View OID4VCI API Reference →](admin-api-oid4vci.md)

---

### [OID4VP — Presentation & Verification Management](admin-api-oid4vp.md)

Endpoints for requesting and verifying credential presentations using OpenID for Verifiable Presentations (OID4VP):

- **Presentation Definitions (PEX v2)** — Define credential requirements and constraints
- **DCQL Queries** — Alternative query language optimized for mDOC and SD-JWT
- **VP Requests** — Generate authorization requests that holders scan as QR codes
- **Presentations** — Poll for presentation results and verified claims
- **X.509 Identity** — Configure DNS-based client authentication for wallet compatibility

**Verification protocols:** PEX v2, DCQL (Digital Credentials Query Language)

[View OID4VP API Reference →](admin-api-oid4vp.md)

---

### [mso_mdoc — ISO 18013-5 mDOC Management](admin-api-mso-mdoc.md)

Endpoints specific to mobile documents (mDOC) per ISO 18013-5, including mobile driver's licenses (mDL):

- **Key & Certificate Management** — Generate signing keys and certificates for mDOC issuance
- **Trust Anchors** — Manage root CA certificates for verifying holder mDOCs
- **Manual Signing & Verification** — Sign and verify CBOR-encoded mDOC credentials

**Note:** Requires the `mso_mdoc` plugin to be loaded. See [Credential Formats](credential-formats.md#mso_mdoc) for setup instructions.

[View mso_mdoc API Reference →](admin-api-mso-mdoc.md)

---

## Common Patterns

### Authentication

All mutating endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) require authentication in multi-tenant deployments. Use Bearer tokens or API keys as configured in ACA-Py.

### Error Responses

All endpoints follow a consistent error response format:

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

### Typical Issuance Flow

1. **Configure** — Create supported credential configurations ([OID4VCI](admin-api-oid4vci.md#supported-credentials))
2. **Exchange** — Create exchange record with holder's claims ([OID4VCI](admin-api-oid4vci.md#exchange-records))
3. **Offer** — Generate credential offer QR code ([OID4VCI](admin-api-oid4vci.md#credential-offers))
4. **Issue** — Holder wallet completes the flow automatically

### Typical Verification Flow

1. **Define Requirements** — Create presentation definition or DCQL query ([OID4VP](admin-api-oid4vp.md#presentation-definitions-pex-v2))
2. **Request** — Generate VP request QR code ([OID4VP](admin-api-oid4vp.md#vp-requests))
3. **Poll** — Check presentation status until verified ([OID4VP](admin-api-oid4vp.md#presentations))
4. **Extract** — Retrieve verified claims from the result

---

## Additional Resources

- [Getting Started](getting-started.md) — Installation and initial configuration
- [Architecture](architecture.md) — Plugin design and credential format registry
- [Cookbook — Issuance](cookbook-issuance.md) — Step-by-step issuance examples with curl
- [Cookbook — Verification](cookbook-verification.md) — Complete verification scenarios
- [Credential Formats](credential-formats.md) — Format-specific implementation details
- [Troubleshooting](troubleshooting.md) — Common errors and debugging tips

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

## Tag: `oid4vp` — Presentation / Verification Management

### Presentation Definitions (PEX v2)

Presentation definitions specify which credentials a verifier wants to receive and what constraints they must satisfy.

#### `POST /oid4vp/presentation-definition`

Create and store a PEX v2 presentation definition.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `pres_def` | object | **Yes** | A valid PEX v2 presentation definition JSON object |

**Example request:**

```bash
curl -X POST http://localhost:8021/oid4vp/presentation-definition \
  -H "Content-Type: application/json" \
  -d '{
    "pres_def": {
      "id": "employee-credential-request",
      "input_descriptors": [
        {
          "id": "employee-credential",
          "format": {
            "jwt_vc_json": {"alg": ["ES256", "EdDSA"]}
          },
          "constraints": {
            "fields": [
              {
                "path": ["$.vc.type"],
                "filter": {
                  "type": "array",
                  "contains": {"const": "UniversityDegreeCredential"}
                }
              }
            ]
          }
        }
      ]
    }
  }'
```

**Response `200`:**

```json
{
  "pres_def": { ... },
  "pres_def_id": "550e8400-..."
}
```

---

#### `GET /oid4vp/presentation-definitions`

List all stored presentation definitions.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `pres_def_id` | string | Filter by ID |

**Response `200`:**

```json
{
  "results": [
    {
      "pres_def_id": "550e8400-...",
      "pres_def": { ... }
    }
  ]
}
```

---

#### `GET /oid4vp/presentation-definition/{pres_def_id}`

Fetch a stored presentation definition by ID.

---

#### `PUT /oid4vp/presentation-definition/{pres_def_id}`

Replace a presentation definition.

**Request body:** `{ "pres_def": { ... } }`

**Response `200`:** `{ "pres_def": {...}, "pres_def_id": "..." }`

---

#### `DELETE /oid4vp/presentation-definition/{pres_def_id}`

Delete a presentation definition.

**Response `200`:** `{}`

---

### DCQL Queries

DCQL (Digital Credentials Query Language) is an alternative to PEX for specifying credential requests. Use DCQL for mDOC/SD-JWT queries where PEX constraints may be insufficient.

#### `POST /oid4vp/dcql/queries`

Create and store a DCQL query.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `credentials` | array | **Yes** | Array of `CredentialQuery` objects describing the required credentials |
| `credential_sets` | array | No | Optional grouping of credential queries with logical AND/OR semantics |

**`CredentialQuery` object:**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | **Yes** | Identifier for this credential query (used as key in `vp_token` response) |
| `format` | string | **Yes** | Expected credential format (e.g. `mso_mdoc`, `vc+sd-jwt`, `jwt_vc_json`) |
| `meta` | object | No | Format-specific metadata (see below) |
| `claims` | array | No | Array of `ClaimsQuery` objects specifying required claims |
| `claim_sets` | array of arrays | No | Alternative claim combinations |

**`meta` object** (format-specific):

| Field | Format | Description |
|---|---|---|
| `doctype_value` | `mso_mdoc` | Required mDoc docType string (e.g. `org.iso.18013.5.1.mDL`) |
| `doctype_values` | `mso_mdoc` | List of acceptable docType strings |
| `vct_values` | `vc+sd-jwt` | List of acceptable `vct` values |

**`ClaimsQuery` object:**

| Field | Description |
|---|---|
| `id` | Claim query identifier |
| `namespace` | mDOC namespace (for `mso_mdoc`) |
| `claim_name` | Claim name (for `mso_mdoc`) |
| `path` | JSON Path array (for JWT/SD-JWT, e.g. `["$.given_name"]`) |
| `values` | Acceptable values (optional constraint) |

**Example request (mDOC driver's license):**

```bash
curl -X POST http://localhost:8021/oid4vp/dcql/queries \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": [
      {
        "id": "mdl",
        "format": "mso_mdoc",
        "meta": {
          "doctype_value": "org.iso.18013.5.1.mDL"
        },
        "claims": [
          {
            "namespace": "org.iso.18013.5.1",
            "claim_name": "given_name"
          },
          {
            "namespace": "org.iso.18013.5.1",
            "claim_name": "family_name"
          },
          {
            "namespace": "org.iso.18013.5.1",
            "claim_name": "birth_date"
          }
        ]
      }
    ]
  }'
```

**Example request (SD-JWT employee credential):**

```bash
curl -X POST http://localhost:8021/oid4vp/dcql/queries \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": [
      {
        "id": "employee",
        "format": "vc+sd-jwt",
        "meta": {
          "vct_values": ["EmployeeCredential"]
        },
        "claims": [
          {"path": ["$.given_name"]},
          {"path": ["$.department"]}
        ]
      }
    ]
  }'
```

**Response `200`:**

```json
{
  "dcql_query": {
    "credentials": [...],
    "credential_sets": null
  }
}
```

> Note: the query `dcql_query_id` is returned in the `Location` header and can be retrieved via `GET /oid4vp/dcql/queries`.

---

#### `GET /oid4vp/dcql/queries`

List all stored DCQL queries.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `dcql_query_id` | string | Filter by ID |

**Response `200`:**

```json
{
  "results": [
    {
      "dcql_query_id": "...",
      "credentials": [...],
      "credential_sets": null
    }
  ]
}
```

---

#### `GET /oid4vp/dcql/query/{dcql_query_id}`

Fetch a DCQL query by ID.

**Response `200`:**

```json
{
  "dcql_query_id": "...",
  "credentials": [...],
  "credential_sets": null
}
```

---

#### `DELETE /oid4vp/dcql/query/{dcql_query_id}`

Delete a DCQL query.

---

### VP Requests

A VP request initiates a presentation exchange. It generates the `openid://` URI that the holder scans.

#### `POST /oid4vp/request`

Create an OID4VP authorization request.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `vp_formats` | object | **Yes** | Format constraints for the expected VP. Keys are format strings; values are alg constraints. |
| `pres_def_id` | string | No | ID of a stored presentation definition (mutually exclusive with `dcql_query_id`) |
| `dcql_query_id` | string | No | ID of a stored DCQL query (mutually exclusive with `pres_def_id`) |

Either `pres_def_id` or `dcql_query_id` must be provided.

**Example request (PEX):**

```bash
curl -X POST http://localhost:8021/oid4vp/request \
  -H "Content-Type: application/json" \
  -d '{
    "pres_def_id": "550e8400-...",
    "vp_formats": {
      "jwt_vc_json": {"alg": ["ES256", "EdDSA"]},
      "jwt_vp_json": {"alg": ["ES256", "EdDSA"]}
    }
  }'
```

**Example request (DCQL):**

```bash
curl -X POST http://localhost:8021/oid4vp/request \
  -H "Content-Type: application/json" \
  -d '{
    "dcql_query_id": "dcql-abc123-...",
    "vp_formats": {
      "mso_mdoc": {"alg": ["ES256"]}
    }
  }'
```

**Response `200`:**

| Field | Description |
|---|---|
| `request_uri` | The `openid://?client_id=...&request_uri=...` URI (present to holder as QR code) |
| `request.request_id` | ID of the VP request record |
| `presentation.presentation_id` | ID of the presentation record to poll for results |
| `presentation.state` | Initial state: `request-created` |

**Example response:**

```json
{
  "request_uri": "openid://?client_id=did:jwk:...&request_uri=https://verifier.example.com/oid4vp/request/abc123",
  "request": {
    "request_id": "abc123-...",
    "pres_def_id": "550e8400-...",
    "vp_formats": { ... }
  },
  "presentation": {
    "presentation_id": "def456-...",
    "state": "request-created",
    "request_id": "abc123-..."
  }
}
```

---

#### `GET /oid4vp/requests`

List VP request records.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `request_id` | string (UUID) | Filter by request ID |
| `pres_def_id` | string | Filter by presentation definition ID |
| `dcql_query_id` | string | Filter by DCQL query ID |

---

#### `GET /oid4vp/request/{request_id}`

Fetch a VP request record by ID. Note: the request record is **deleted after the holder retrieves the JAR** (signed request object), so this endpoint returns `404` after the holder scans the QR code.

---

### Presentations

Presentation records track the lifecycle of a VP exchange from request creation to verification result.

#### `GET /oid4vp/presentations`

List presentation records.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `presentation_id` | string (UUID) | Filter by ID |
| `pres_def_id` | string | Filter by presentation definition |
| `state` | string | Filter by state. One of: `request-created`, `request-retrieved`, `presentation-received`, `presentation-invalid`, `presentation-valid` |

---

#### `GET /oid4vp/presentation/{presentation_id}`

Fetch a presentation record by ID. Poll this endpoint after creating a VP request to check whether the holder has responded and whether verification succeeded.

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `presentation_id` | string | Record ID |
| `state` | string | Current state |
| `errors` | array of strings | Validation errors (non-empty when state is `presentation-invalid`) |
| `verified_claims` | object | Verified claim values (non-empty when state is `presentation-valid`) |
| `matched_credentials` | object | Full matched credential records |

**Presentation states:**

| State | Meaning |
|---|---|
| `request-created` | VP request generated; waiting for holder to scan |
| `request-retrieved` | Holder retrieved the signed request JAR |
| `presentation-received` | Holder submitted a VP (processing underway) |
| `presentation-valid` | VP signature and constraints verified successfully |
| `presentation-invalid` | VP failed verification (see `errors`) |

**Example poll loop:**

```bash
PRES_ID="def456-..."
while true; do
  STATE=$(curl -s http://localhost:8031/oid4vp/presentation/$PRES_ID | python3 -c "import json,sys; print(json.load(sys.stdin)['state'])")
  echo "State: $STATE"
  if [[ "$STATE" == "presentation-valid" || "$STATE" == "presentation-invalid" ]]; then
    break
  fi
  sleep 2
done
```

---

#### `DELETE /oid4vp/presentation/{presentation_id}`

Delete a presentation record.

---

### X.509 Identity

When a verifier needs to use `x509_san_dns` client authentication (required by some wallet protocols), register an X.509 certificate chain here. Once registered, all VP requests use the DNS name as the `client_id` and include the `x5c` header in the signed JAR.

#### `POST /oid4vp/x509-identity`

Register an X.509 identity.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `cert_chain_pem` | string | **Yes** | PEM-encoded certificate chain, leaf certificate first |
| `verification_method` | string | **Yes** | Verification method ID used for signing the JAR (e.g. `did:jwk:...#0`) |
| `client_id` | string | **Yes** | DNS name that will be used as the OID4VP `client_id` (e.g. `verifier.example.com`) |

**Example request:**

```bash
curl -X POST http://localhost:8031/oid4vp/x509-identity \
  -H "Content-Type: application/json" \
  -d '{
    "cert_chain_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
    "verification_method": "did:jwk:eyJ...#0",
    "client_id": "verifier.example.com"
  }'
```

**Response `200`:** `{}`

---

#### `GET /oid4vp/x509-identity`

Retrieve the registered X.509 identity.

**Response `200`:** The stored identity record.

---

#### `DELETE /oid4vp/x509-identity`

Remove the X.509 identity. Subsequent VP requests will revert to using `did:jwk` as the `client_id`.

---

## Tag: `mso_mdoc` — ISO 18013-5 mDOC Management

Requires the `mso_mdoc` plugin to be loaded. See [Credential Formats — mso_mdoc](credential-formats.md#mso_mdoc) for background.

### Key and Certificate Management

On startup the `mso_mdoc` plugin auto-generates a default EC P-256 signing key and a self-signed certificate. You can inspect and extend these via the following endpoints.

#### `GET /mso_mdoc/keys`

List all mDOC signing keys.

**Example request:**

```bash
curl http://localhost:8021/mso_mdoc/keys
```

---

#### `GET /mso_mdoc/certificates`

List all mDOC signing certificates.

---

#### `GET /mso_mdoc/certificates/default`

Get the default (active) signing certificate.

---

#### `POST /mso_mdoc/generate-keys`

Generate a new mDOC signing key and a self-signed certificate.

**Example request:**

```bash
curl -X POST http://localhost:8021/mso_mdoc/generate-keys
```

**Response `200`:** The newly created key and certificate records.

---

### Trust Anchors

Trust anchors are root CA certificates used to verify mDOC credentials received from holders. A trust anchor chain must be established for `POST /oid4vp/response` to verify mDOC presentations.

#### `POST /mso_mdoc/trust-anchors`

Add a trust anchor certificate.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `certificate_pem` | string | **Yes** | PEM-encoded X.509 root CA certificate |
| `anchor_id` | string | No | Custom ID. If not provided, a UUID is generated. |
| `metadata` | object | No | Arbitrary metadata attached to the trust anchor record |

**Example request:**

```bash
curl -X POST http://localhost:8021/mso_mdoc/trust-anchors \
  -H "Content-Type: application/json" \
  -d '{
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "anchor_id": "iso-test-iaca-2024",
    "metadata": {"description": "ISO test IACA root"}
  }'
```

**Response `200`:** Trust anchor record.

---

#### `GET /mso_mdoc/trust-anchors`

List all stored trust anchors.

---

#### `GET /mso_mdoc/trust-anchors/{anchor_id}`

Fetch a trust anchor by ID.

---

#### `DELETE /mso_mdoc/trust-anchors/{anchor_id}`

Remove a trust anchor.

---

### mDOC Signing and Verification

These endpoints are available for manual signing/verification operations, independent of the OID4VCI issuance flow.

#### `POST /mso_mdoc/sign`

Manually sign a payload as an mDOC CBOR binary per ISO 18013-5.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `payload` | object | **Yes** | Claims organized by namespace (e.g. `{"org.iso.18013.5.1": {"given_name": "Alice"}}`) |
| `headers` | object | No | Additional COSE header parameters |
| `did` | string | No | DID to use for signing |
| `verificationMethod` | string | No | Specific verification method to use |

**Example request:**

```bash
curl -X POST http://localhost:8021/mso_mdoc/sign \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {
      "org.iso.18013.5.1": {
        "given_name": "Alice",
        "family_name": "Smith",
        "birth_date": "1990-01-01"
      }
    }
  }'
```

**Response `200`:** CBOR hex-encoded mDOC binary.

---

#### `POST /mso_mdoc/verify`

Verify a CBOR-encoded mDOC binary.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `mso_mdoc` | string | **Yes** | CBOR hex-encoded mDOC device response |

**Example request:**

```bash
curl -X POST http://localhost:8021/mso_mdoc/verify \
  -H "Content-Type: application/json" \
  -d '{"mso_mdoc": "a36776657273...cbor-hex..."}'
```

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `valid` | boolean | Whether verification succeeded |
| `error` | string | Error message if `valid` is `false` |
| `kid` | string | Key ID of the signing key |
| `headers` | object | COSE headers from the signed document |
| `payload` | object | Decoded claims organized by namespace |

**Example response:**

```json
{
  "valid": true,
  "error": null,
  "kid": "did:jwk:eyJ...#0",
  "headers": {"alg": "ES256"},
  "payload": {
    "org.iso.18013.5.1": {
      "given_name": "Alice",
      "family_name": "Smith"
    }
  }
}
```
