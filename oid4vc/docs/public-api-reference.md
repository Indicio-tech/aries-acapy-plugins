# Public API Reference

These endpoints are served on the **OID4VCI Public Server** (`http://<OID4VCI_HOST>:<OID4VCI_PORT>`). They implement the protocol-level interfaces specified by OID4VCI and OID4VP, consumed by wallets and holder agents — not by the controller.

The Swagger UI for the public server is available at `http://<OID4VCI_HOST>:<OID4VCI_PORT>/api/doc`.

> **Multitenant note:** In a multitenant deployment, all paths below are prefixed with `/tenant/{wallet_id}`.

---

## Well-Known Metadata Endpoints

### `GET /.well-known/openid-credential-issuer`

Returns the credential issuer metadata as defined by OID4VCI §10.2. Wallets call this first to discover what credentials are available and where to request tokens and credentials.

**Accepts:** `application/json` (default) or `application/jwt` (returns a signed JWT metadata object per the JWT Issuer Metadata spec)

**Response `200`:**

| Field | Description |
|---|---|
| `credential_issuer` | The canonical URL of this issuer (from `OID4VCI_ENDPOINT`) |
| `authorization_servers` | List of authorization server URLs (when `OID4VCI_AUTH_SERVER_URL` is configured) |
| `credential_endpoint` | URL for the credential issuance endpoint |
| `nonce_endpoint` | URL for the nonce endpoint (OID4VCI §8) |
| `credential_configurations_supported` | Object mapping credential configuration IDs to their metadata (populated from `SupportedCredential` records) |
| `batch_credential_issuance` | Optional batch issuance parameters |

**Example response:**

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/credential",
  "nonce_endpoint": "https://issuer.example.com/nonce",
  "credential_configurations_supported": {
    "UniversityDegreeCredential": {
      "format": "jwt_vc_json",
      "scope": "UniversityDegreeCredential",
      "cryptographic_binding_methods_supported": ["did:jwk"],
      "proof_types_supported": {
        "jwt": {"proof_signing_alg_values_supported": ["ES256", "EdDSA"]}
      },
      "display": [{"name": "University Degree", "locale": "en-US"}],
      "credential_definition": {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "UniversityDegreeCredential"]
      }
    }
  }
}
```

---

### `GET /.well-known/openid_credential_issuer`

Deprecated variant with an underscore. Adds `Deprecation` and `Link` response headers pointing to the hyphenated form. Wallets should use `/.well-known/openid-credential-issuer` instead.

---

### `GET /.well-known/openid-configuration`

Returns combined OpenID Connect Discovery + OID4VCI authorization server metadata (RFC 8414 §2 + OID4VCI §10.1).

**Example response:**

```json
{
  "issuer": "https://issuer.example.com",
  "token_endpoint": "https://issuer.example.com/token",
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/credential",
  "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
  "response_types_supported": ["token"]
}
```

---

### `GET /.well-known/oauth-authorization-server`

Same content as `/.well-known/openid-configuration`. Provided for OAuth 2.0 AS metadata discovery (RFC 8414).

---

## Token Endpoint

### `POST /token`

Exchange a pre-authorized code for an access token (OID4VCI §4.1). This is the second step in the issuance flow after the wallet scans the credential offer QR code.

**Content-Type:** `application/x-www-form-urlencoded`

**Request parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `grant_type` | string | **Yes** | Must be `urn:ietf:params:oauth:grant-type:pre-authorized_code` |
| `pre-authorized_code` | string | **Yes** | The pre-authorized code from the credential offer (also accepted as `pre_authorized_code`) |
| `tx_code` | string | Conditional | User PIN/transaction code (required when `user_pin_required: true` in the offer). Also accepted as `user_pin`. |

**Example request:**

```bash
curl -X POST https://issuer.example.com/token \
  -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code" \
  -d "pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA"
```

**Response `200`:**

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "c_nonce": "tZignsnFbp",
  "c_nonce_expires_in": 86400
}
```

**Error responses** (per OID4VCI §4.1.3):

| Error Code | Meaning |
|---|---|
| `invalid_request` | Missing or malformed parameters |
| `invalid_grant` | Pre-authorized code is invalid or expired |
| `unsupported_grant_type` | Grant type not supported |

---

## Nonce Endpoint

### `POST /nonce` or `GET /nonce`

Request a fresh server-generated nonce for use in proof of possession (OID4VCI §8). Wallets that do not retain the `c_nonce` from the token response should call this endpoint to obtain a fresh nonce.

**Response `200`:**

```json
{
  "c_nonce": "tZignsnFbp",
  "c_nonce_expires_in": 86400
}
```

---

## Credential Endpoint

### `POST /credential`

Issue a credential (OID4VCI §7.2). Called by the wallet after obtaining an access token.

**Content-Type:** `application/json`

**Authorization:** `Bearer <access_token>`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `credential_identifier` | string | Recommended | Identifies which credential to issue (matches a key in `credential_configurations_supported`). Use this for OID4VCI 1.0 compliance. |
| `format` | string | Alternative | Credential format (older/draft implementations). |
| `proof` | object | **Yes** | Proof of possession of the holder's key |
| `proof.proof_type` | string | **Yes** | Must be `jwt` |
| `proof.jwt` | string | **Yes** | A JWT signed by the holder's key, containing `aud` (issuer URL), `iat`, `nonce` (the `c_nonce`), and `iss`/`kid` identifying the holder key |

**Example request:**

```bash
ACCESS_TOKEN="eyJhbGciOi..."
C_NONCE="tZignsnFbp"

# Build proof JWT (typically done by wallet SDK):
PROOF_JWT="eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKai4uLiMwIn0.eyJhdWQiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTcwMDAwMDAwMCwibm9uY2UiOiJ0WmlnbnNuRmJwIn0.signature"

curl -X POST https://issuer.example.com/credential \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"credential_identifier\": \"UniversityDegreeCredential\",
    \"proof\": {
      \"proof_type\": \"jwt\",
      \"jwt\": \"$PROOF_JWT\"
    }
  }"
```

**Response `200`:**

```json
{
  "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6ey...",
  "credentials": [
    {
      "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  ],
  "notification_id": "3fwe98j..."
}
```

**Error responses** (per OID4VCI §7.3.2):

| Error Code | Meaning |
|---|---|
| `invalid_credential_request` | Missing or malformed request |
| `unsupported_credential_type` | Requested credential type not supported |
| `invalid_proof` | Proof JWT is invalid, missing, or signature verification failed |
| `invalid_nonce` | `nonce` in proof does not match a valid server nonce |
| `invalid_credential_identifier` | `credential_identifier` not found in `credential_configurations_supported` |
| `invalid_credential_configuration` | Internal configuration error |

---

## Notification Endpoint

### `POST /notification`

Send a lifecycle notification to the issuer (OID4VCI §11). Wallets call this to report the outcome of credential processing.

**Authorization:** `Bearer <access_token>`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `notification_id` | string | **Yes** | The `notification_id` from the credential response |
| `event` | string | **Yes** | One of: `credential_accepted`, `credential_failure`, `credential_deleted` |
| `event_description` | string | No | Human-readable description of the event |

**Example request:**

```bash
curl -X POST https://issuer.example.com/notification \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "notification_id": "3fwe98j...",
    "event": "credential_accepted"
  }'
```

**Response `204`:** No content on success.

**Effect:** Updates the exchange record state to `accepted` (for `credential_accepted`) and emits a `oid4vci` webhook event.

---

## Credential Offer Dereference

### `GET /oid4vci/dereference-credential-offer`

Dereference a credential offer by reference. Called by wallets that receive a `credential_offer_uri` (by-reference offer) rather than an inline `credential_offer`.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `exchange_id` | string | The exchange ID embedded in the reference URI |

**Response `200`:** The full credential offer JSON object.

---

## OID4VP — Presentation Endpoints

### `GET /oid4vp/request/{request_id}`

Retrieve a signed OID4VP authorization request (JAR — JWT Authorization Request). Called by wallets after scanning the `openid://` QR code.

**Response:** A signed JWT containing the authorization request parameters:

| JWT Claim | Description |
|---|---|
| `response_uri` | URL where the wallet should POST the VP response (`/oid4vp/response/{presentation_id}`) |
| `nonce` | Server-generated nonce for binding the response |
| `client_id` | Verifier DID or `x509_san_dns:<dns>` |
| `presentation_definition` | PEX v2 presentation definition (when using PEX flow) |
| `dcql_query` | DCQL query object (when using DCQL flow) |
| `response_type` | `"vp_token"` |
| `response_mode` | `"direct_post"` |

**Effect:** Moves the presentation record from `request-created` → `request-retrieved`. The VP request record is deleted.

> **Note:** After calling this endpoint, the `GET /oid4vp/request/{request_id}` admin endpoint will return `404` since the request record is deleted.

---

### `POST /oid4vp/response/{presentation_id}`

Submit a verifiable presentation (OID4VP direct_post response mode). Called by wallets after constructing the VP from the authorization request.

**Content-Type:** `application/x-www-form-urlencoded`

**Path parameters:**

| Parameter | Description |
|---|---|
| `presentation_id` | From the `response_uri` in the JAR |

**Form parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `vp_token` | string | **Yes** | The verifiable presentation. For PEX flows: a JWT VP. For DCQL flows: a JSON object keyed by `credential_query_id`. |
| `presentation_submission` | string | Conditional | JSON string containing the PEX presentation submission descriptor. Required for PEX flows; omitted for DCQL flows. |
| `state` | string | No | Optional state parameter from the JAR |

**PEX example `vp_token`:** A JWT VP

**DCQL example `vp_token`:**

```json
{
  "mdl": "<cbor-hex-encoded-mdoc>"
}
```

where `mdl` is the `id` from the matching `CredentialQuery`.

**Response `200`:** `{}` on success

**Effect:** The plugin verifies the VP signature and evaluates the PEX/DCQL constraints. Updates the presentation record state to `presentation-valid` or `presentation-invalid`. Emits a `oid4vp` webhook event.

---

## Status List Endpoint

### `GET /status/{list_number}`

Return a status list by number. Only available when `OID4VCI_STATUS_HANDLER` is configured (requires the Status List Plugin).

**Response `200`:** Status list token (JWT or bit-encoded format depending on the configured handler).
