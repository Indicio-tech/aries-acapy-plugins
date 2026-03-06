# Admin API Reference — mso_mdoc (ISO 18013-5 mDOC Management)

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
