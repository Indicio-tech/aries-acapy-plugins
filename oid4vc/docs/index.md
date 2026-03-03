# OID4VC Plugin — Developer Documentation

This section covers everything needed to integrate the OID4VC plugin into an ACA-Py deployment, configure it, and call its APIs.

## Quick Navigation

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Prerequisites, installation, configuration, Docker quick-start |
| [Architecture](architecture.md) | Two-server design, plugin lifecycle, credential format registry |
| [Admin API Reference](admin-api-reference.md) | All `/oid4vci/*`, `/oid4vp/*`, `/mso_mdoc/*`, `/did/*` endpoints |
| [Public API Reference](public-api-reference.md) | OID4VCI/OID4VP wallet-facing endpoints (token, credential, well-known, …) |
| [Issuance Cookbook](cookbook-issuance.md) | Step-by-step curl walkthroughs for `jwt_vc_json`, `sd_jwt_vc`, `mso_mdoc` |
| [Verification Cookbook](cookbook-verification.md) | PEX and DCQL-based VP flows with curl examples |
| [Credential Formats](credential-formats.md) | Format-specific schema details, selective disclosure, mDOC namespaces |
| [Troubleshooting](troubleshooting.md) | Error codes, common failures, debugging tips |

## Finding Endpoints in the Swagger UI

The plugin automatically registers all admin endpoints in the ACA-Py Swagger UI. No extra configuration is required.

| Server | URL | Contents |
|---|---|---|
| ACA-Py Admin Server | `http://<host>:<admin-port>/api/doc` | All `oid4vci`, `oid4vp`, `mso_mdoc`, and `did` tag groups |
| OID4VCI Public Server | `http://<host>:<oid4vci-port>/api/doc` | Public wallet-facing endpoints (token, credential, well-known, …) |

The tags that appear in the admin Swagger UI are:

- **`oid4vci`** — Credential issuance management (exchange records, supported credentials, credential offers)
- **`oid4vp`** — Presentation/verification management (presentation definitions, VP requests, DCQL queries, X.509 identity)
- **`mso_mdoc`** — ISO 18013-5 mDOC signing/verification and key management
- **`did`** — DID:JWK creation

## Common Starting Points

**I want to issue a JWT VC credential:**
→ [Issuance Cookbook — jwt_vc_json](cookbook-issuance.md#jwt_vc_json)

**I want to issue an SD-JWT credential:**
→ [Issuance Cookbook — sd_jwt_vc](cookbook-issuance.md#sd_jwt_vc)

**I want to issue an mDOC (ISO 18013-5) credential:**
→ [Issuance Cookbook — mso_mdoc](cookbook-issuance.md#mso_mdoc)

**I want to verify a credential presentation (VP):**
→ [Verification Cookbook — PEX](cookbook-verification.md#pex-presentation-definition)
→ [Verification Cookbook — DCQL](cookbook-verification.md#dcql-queries)

**I want to look up a specific endpoint:**
→ [Admin API Reference](admin-api-reference.md)

**Something is failing and I don't know why:**
→ [Troubleshooting](troubleshooting.md)
