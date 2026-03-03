# Troubleshooting

## Common Issues

### Plugin Not Loading

**Symptom:** No `oid4vci`, `oid4vp`, or `mso_mdoc` routes appear in Swagger.

**Checks:**

```bash
# Verify oid4vc plugin is registered
curl -s http://localhost:8021/plugins | python3 -m json.tool | grep oid4vc

# Check ACA-Py startup logs for plugin load errors
docker logs acapy-issuer 2>&1 | grep -i "plugin\|oid4vc\|error"
```

**Fix:** Ensure `--plugin oid4vc` is in the ACA-Py startup arguments and the package is installed in the same Python environment.

---

### OID4VCI Public Server Not Reachable

**Symptom:** `GET /.well-known/openid-credential-issuer` returns connection refused.

**Checks:**

```bash
# Check if OID4VCI_HOST and OID4VCI_PORT are configured
docker inspect acapy-issuer | grep -A2 "OID4VCI"

# Verify the public server started
docker logs acapy-issuer 2>&1 | grep -i "oid4vci\|server"
```

**Fix:** Both `OID4VCI_HOST`, `OID4VCI_PORT`, and `OID4VCI_ENDPOINT` must be set. `OID4VCI_ENDPOINT` must be a publicly reachable URL. See [Getting Started — Configuration](getting-started.md#configuration-reference).

---

### `ConfigError` on Startup

**Error:**

```
oid4vc.config.ConfigError: Required configuration key 'oid4vci.endpoint' is missing
```

**Fix:** Set the `OID4VCI_ENDPOINT` environment variable to the public base URL of the OID4VCI server.

---

## OID4VCI Token Errors

### `invalid_grant`

**Error response:**

```json
{"error": "invalid_grant", "error_description": "Pre-authorized code is invalid or expired"}
```

**Causes:**

1. The pre-authorized code was already used (codes are single-use)
2. The exchange record was deleted before token issuance
3. The offer was generated from an exchange in a non-`offer` state (e.g. `issued`)

**Fix:** Generate a new credential offer for a new or refreshed exchange record.

---

### `invalid_proof`

**Error response:**

```json
{"error": "invalid_proof", "error_description": "Proof verification failed"}
```

**Causes:**

1. The holder's proof JWT signature is invalid
2. The `nonce` in the proof JWT does not match the `c_nonce` from the token response
3. The `aud` in the proof JWT does not match the `credential_issuer` URL
4. The proof JWT is missing `kid`, `jwk`, or `x5c` header — the issuer cannot extract a holder key

**Fix:** Ensure the wallet:
- Signs the proof JWT with the holder's private key
- Sets `aud` to exactly the `credential_issuer` URL from issuer metadata
- Includes the `c_nonce` as the `nonce` claim
- Sets `iat` to the current time
- Includes either `kid` (DID URL), `jwk` (raw JWK), or `x5c` (certificate chain) in the JWT header

---

### `invalid_nonce`

**Error response:**

```json
{"error": "invalid_nonce", "error_description": "Nonce has already been used or has expired"}
```

**Cause:** Nonce replay protection — each `c_nonce` can only be used once. Card wallets that retry a failed credential request with the same nonce will hit this error.

**Fix:** Call `POST /nonce` or re-request a token to get a fresh `c_nonce` before retrying.

---

### `invalid_credential_identifier`

**Error response:**

```json
{"error": "invalid_credential_identifier", "error_description": "Credential identifier not found"}
```

**Cause:** The `credential_identifier` in the credential request does not match any key in `credential_configurations_supported`.

**Fix:** Use the `id` value from a `SupportedCredential` record (visible in issuer metadata under `credential_configurations_supported`).

---

## OID4VP Errors

### `404` on `GET /oid4vp/request/{request_id}`

**Cause:** The VP request record is **deleted after the wallet retrieves the signed JAR**. This is correct — the admin `GET` endpoint reflects that the request was successfully consumed. Use `GET /oid4vp/presentation/{presentation_id}` to check the outcome.

---

### Presentation State Stuck at `request-created`

**Cause:** The wallet has not scanned/fetched the QR code, or the `openid://` deep link was not handled.

**Check:**

```bash
curl -s http://localhost:8031/oid4vp/presentation/$PRES_ID | \
  python3 -c "import json,sys; r=json.load(sys.stdin); print(r['state'], r.get('errors'))"
```

---

### `presentation-invalid` with Errors

**Example errors:**

```json
["Descriptor 'degree' did not match any credential in the presentation"]
```

**Causes for PEX:**

- The holder's credential does not satisfy the `constraints.fields` filter (e.g. missing type, wrong value)
- The `format` in the input descriptor does not match the submitted credential format
- `limit_disclosure: required` is set but the credential format doesn't support selective disclosure

**Causes for DCQL:**

- The submitted `vp_token` key does not match the credential query `id`
- The mDOC `doctype` does not match `meta.doctype_value`
- The SD-JWT `vct` does not match `meta.vct_values`
- A required claim path is absent from the presented credential

---

### mDOC Trust Anchor Verification Failure

**Error in logs:**

```
mso_mdoc verification failed: certificate chain not trusted
```

**Fix:** Add the issuing authority's root certificate as a trust anchor:

```bash
curl -X POST $ADMIN/mso_mdoc/trust-anchors \
  -H "Content-Type: application/json" \
  -d '{"certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"}'
```

Or set `OID4VC_MDOC_TRUST_STORE_TYPE=none` to disable trust anchor verification during development (not for production).

---

## Configuration Issues

### `sd_jwt_vc` or `mso_mdoc` Routes Not Available

**Symptom:** `POST /oid4vci/credential-supported/create/sd-jwt` or `/mso_mdoc/*` routes return `404`.

**Fix:** The `sd_jwt_vc` and `mso_mdoc` sub-plugins must be explicitly loaded:

```
--plugin oid4vc --plugin sd_jwt_vc --plugin mso_mdoc
```

---

### Auth Server Connection Errors

**Error in logs:**

```
AppResources: failed to connect to auth server: Connection refused
```

**Cause:** `OID4VCI_AUTH_SERVER_URL` is set but the auth server is not running or not reachable.

**Fix:** Either start the auth server (see [auth_server/README.md](../auth_server/README.md)) or remove `OID4VCI_AUTH_SERVER_URL` to use the built-in token endpoint.

---

## Error Code Reference

### Admin API

| HTTP Status | Common Cause | Fix |
|---|---|---|
| `400 Bad Request` | Missing required field, schema validation failure | Check request body against the schema in [Admin API Reference](admin-api-reference.md) |
| `404 Not Found` | Record ID does not exist | Verify the ID; records may have been deleted or belong to a different wallet |
| `500 Internal Server Error` | Signing key not found, ` mso_mdoc` library error | Check ACA-Py logs for the full traceback |

### OID4VCI Public Server

| Error Code | HTTP Status | Description |
|---|---|---|
| `invalid_request` | 400 | Malformed request body or missing parameters |
| `invalid_grant` | 400 | Pre-authorized code is invalid, expired, or already used |
| `unsupported_grant_type` | 400 | Grant type other than `pre-authorized_code` was used |
| `invalid_proof` | 400 | Proof JWT signature invalid, wrong `aud`, or holder key cannot be extracted |
| `invalid_nonce` | 400 | Nonce already used or expired |
| `invalid_credential_identifier` | 400 | `credential_identifier` not in issuer metadata |
| `invalid_credential_request` | 400 | Other credential request validation failure |
| `invalid_credential_configuration` | 500 | Internal server configuration error |

---

## Debugging Tips

### Enable Debug Logging

The OID4VCI public server includes a `debug_middleware` that logs all requests and responses when ACA-Py is started with `--log-level debug`:

```bash
aca-py start --log-level debug --plugin oid4vc ...
```

### Inspect Exchange Records

```bash
# List all recent exchanges
curl -s "http://localhost:8021/oid4vci/exchange/records" | \
  python3 -c "import json,sys; [print(r['exchange_id'], r['state']) for r in json.load(sys.stdin)['results']]"

# Get a specific exchange with all fields
curl -s "http://localhost:8021/oid4vci/exchange/records/$EXCHANGE_ID" | python3 -m json.tool
```

### Inspect Issuer Metadata

Verify the credential configurations are correctly populated:

```bash
curl -s "http://localhost:8022/.well-known/openid-credential-issuer" | python3 -m json.tool
```
