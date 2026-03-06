# Architecture Overview

## Two-Server Design

The plugin runs two separate HTTP servers alongside ACA-Py:

```
┌──────────────────────────────────────────────────┐
│                  ACA-Py Process                  │
│                                                  │
│  ┌─────────────────────┐  ┌────────────────────┐ │
│  │   ACA-Py Admin API  │  │  DIDComm Messaging │ │
│  │  (built-in server)  │  │      Server        │ │
│  │  :admin_port        │  │  :inbound_port     │ │
│  │                     │  │                    │ │
│  │  /oid4vci/*         │  └────────────────────┘ │
│  │  /oid4vp/*          │                         │
│  │  /mso_mdoc/*        │  ┌────────────────────┐ │
│  │  /did/*             │  │  OID4VCI Public    │ │
│  │                     │  │  Server (plugin)   │ │
│  │  Swagger at         │  │  OID4VCI_PORT      │ │
│  │  /api/doc           │  │                    │ │
│  └─────────────────────┘  │  /.well-known/*    │ │
│                            │  /token            │ │
│  ← Controller (admin)      │  /credential       │ │
│                            │  /nonce            │ │
│                            │  /oid4vp/request/* │ │
│                            │  /oid4vp/response/*│ │
│                            │  /status/*         │ │
│                            │                    │ │
│                            │  Swagger at        │ │
│                            │  /api/doc          │ │
│                            └────────────────────┘ │
│                              ↑ Wallet / Holder     │
└──────────────────────────────────────────────────┘
```

| Server | Audience | Purpose |
|---|---|---|
| **ACA-Py Admin API** | Controller (back-end application) | Manage credentials, exchanges, presentation definitions, DCQL queries, keys |
| **OID4VCI Public Server** | Wallets / Holders / Verifiers | OID4VCI protocol endpoints — token, credential issuance, metadata, OID4VP response |

The two servers share ACA-Py's wallet/storage layer via a shared `Profile` context.

---

## Plugin Lifecycle

The plugin entry point is `oid4vc/__init__.py`, which registers three hooks with ACA-Py:

### `setup(context)`

Called once at startup before the ACA-Py event loop begins. Registers:

- **`JwkResolver`** — DID resolver that can resolve `did:jwk` DIDs
- **`DID_JWK`** method — enables `did:jwk` creation via `/wallet/did/create`
- **`P256`** key type — EC P-256 key support
- **`jwt_vc_json` credential processor** — the default issuance/verification format
- **`CredProcessors`** instance — the format registry (see below)
- **`StatusHandler`** — optional status list handler (if `OID4VCI_STATUS_HANDLER` configured)

### `startup(profile, event)`

Called when the first wallet profile is opened. Starts:

- **`Oid4vciServer`** — the separate aiohttp public server bound to `OID4VCI_HOST:OID4VCI_PORT`
- **`AppResources`** — shared HTTP client for auth server communication (when `OID4VCI_AUTH_SERVER_URL` is configured)

### `shutdown(profile, event)`

Called on graceful shutdown. Stops the public server and shuts down the HTTP client.

---

## Credential Format Registry (`CredProcessors`)

The `CredProcessors` class (in `oid4vc/cred_processor.py`) is a runtime registry that maps credential format strings to handler implementations. Each handler implements one or more of three protocols:

| Protocol | Method | Responsibility |
|---|---|---|
| `Issuer` | `issue(profile, exchange)` | Sign and return a credential |
| `CredVerifier` | `verify_credential(profile, cred)` | Verify a single credential |
| `PresVerifier` | `verify_presentation(profile, pres)` | Verify a presentation |

### Registered Formats

| Format String | Module | Issuer | CredVerifier | PresVerifier |
|---|---|---|---|---|
| `jwt_vc_json`, `jwt_vc` | `jwt_vc_json` | ✓ | ✓ | — |
| `jwt_vp_json`, `jwt_vp` | `jwt_vc_json` | — | ✓ | ✓ |
| `vc+sd-jwt`, `dc+sd-jwt` | `sd_jwt_vc` | ✓ | ✓ | ✓ |
| `mso_mdoc` | `mso_mdoc` | ✓ | ✓ | ✓ |

Format modules register themselves by calling `setup(context)` during their own plugin initialization. The `jwt_vc_json` module is registered unconditionally by `oid4vc/__init__.py`; `sd_jwt_vc` and `mso_mdoc` only register when their respective plugins are loaded (`--plugin sd_jwt_vc`, `--plugin mso_mdoc`).

---

## Admin API — Swagger Integration

ACA-Py discovers route modules from plugins using a naming convention: any module named `routes` (or a package with a `routes/__init__.py`) that exports `register()` and `post_process_routes()` is loaded automatically.

The `oid4vc` plugin uses `aiohttp_apispec` to generate Swagger documentation from decorators on every handler:

```python
@docs(tags=["oid4vci"], summary="Create a credential exchange record")
@request_schema(ExchangeRecordCreateRequestSchema())
@response_schema(OID4VCIExchangeRecordSchema(), 200)
async def exchange_create(request: web.BaseRequest):
    ...
```

The `post_process_routes()` function injects tag descriptions and links to the OID4VCI/OID4VP specifications into the swagger dictionary so they appear in the Swagger UI's tag section.

---

## Verification Engines

### PEX — Presentation Exchange v2

Used when a verifier creates a `presentation-definition` and includes it in a VP request.

- **Class:** `PresentationExchangeEvaluator` in `oid4vc/pex.py`
- **Flow:** `compile(definition)` → `verify(profile, submission, presentation)` → `PexVerifyResult`
- **Standards:** [DIF Presentation Exchange v2](https://identity.foundation/presentation-exchange/spec/v2.0.0/)

### DCQL — Digital Credentials Query Language

Used when a verifier creates a `dcql_query` and includes it in a VP request instead of a presentation definition.

- **Class:** `DCQLQueryEvaluator` in `oid4vc/dcql.py`
- **Flow:** `compile(query)` → `verify(profile, vp_token, presentation)` → `DCQLVerifyResult`
- **Standards:** [OID4VP §E.1 DCQL](https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html)
- **Key difference from PEX:** No `presentation_submission` in the response; `vp_token` is a JSON object keyed by `credential_query_id`.

---

## Records and Storage

All plugin records use ACA-Py's Askar wallet storage.

| Record Type | Storage Key | Description |
|---|---|---|
| `OID4VCIExchangeRecord` | `"oid4vci"` | One per credential issuance attempt. Tracks state from `created` → `offer` → `issued` → `accepted`. |
| `SupportedCredential` | `"supported_cred"` | Configuration for a credential type that can be issued (format, display metadata, VC schema). |
| `OID4VPPresentation` | `"oid4vp"` | Tracks one VP request+response cycle. States: `request-created` → `request-retrieved` → `presentation-valid`/`presentation-invalid`. |
| `OID4VPRequest` | `"oid4vp"` | Temporary record holding VP request parameters (pres_def_id or dcql_query_id, vp_formats). Deleted after the holder retrieves the JAR. |
| `OID4VPPresDef` | `"oid4vp-pres-def"` | Stored PEX v2 presentation definitions. |
| `DCQLQuery` | `"oid4vp-dcql"` | Stored DCQL query definitions. |
| `Nonce` | `"nonce"` | Short-lived nonces used for proof-of-possession. Atomic mark-used prevents replay. |

---

## Webhook Events

The plugin emits webhook events on the following topics:

| Topic | When Emitted |
|---|---|
| `oid4vci` | Exchange state changes: `created`, `offer`, `issued`, `accepted`, `failed`, `deleted` |
| `oid4vp` | Presentation state changes: `request-created`, `request-retrieved`, `presentation-valid`, `presentation-invalid` |

Controllers subscribe to these via the standard ACA-Py webhook mechanism.

---

## Multitenant Support

In a multitenant ACA-Py deployment, the OID4VCI public server injects the per-wallet `Profile` into each request via a `setup_context` middleware. Wallet-specific routes are prefixed with `/tenant/{wallet_id}`, allowing multiple tenants to share a single public server.

The admin routes use `tenant_authentication` (a decorator from ACA-Py's multitenant module) to authenticate and resolve the requesting tenant's profile.
