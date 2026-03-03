# Admin API Reference — OID4VP (Presentation & Verification)

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
