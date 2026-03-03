# Getting Started

## Prerequisites

| Requirement | Version |
|---|---|
| Python | `^3.12` |
| ACA-Py | `~1.4.0` |
| `mso_mdoc` extra (optional) | `cbor2`, `cbor-diag`, `cwt`, `pycose` |
| `sd_jwt_vc` extra (optional) | `jsonpointer` |

## Installation

Add the plugin to your ACA-Py deployment using the `--plugin` flag and load the appropriate sub-plugin(s) for the credential format(s) you need.

**Minimal issuance (JWT VC only):**

```
--plugin oid4vc
```

**With SD-JWT VC support:**

```
--plugin oid4vc
--plugin sd_jwt_vc
```

**With all formats (including mDOC):**

```
--plugin oid4vc
--plugin sd_jwt_vc
--plugin mso_mdoc
```

### Installing with pip

```bash
# JWT VC only
pip install "oid4vc"

# With SD-JWT support
pip install "oid4vc[sd_jwt_vc]"

# With mDOC support
pip install "oid4vc[mso_mdoc]"

# All formats
pip install "oid4vc[sd_jwt_vc,mso_mdoc]"
```

> **Note:** The `mso_mdoc` format additionally requires the `isomdl-uniffi` native library. See [mso_mdoc/README.md](../mso_mdoc/README.md) for separate installation instructions.

---

## Configuration Reference

Configuration is supplied via environment variables or equivalent plugin config keys in the ACA-Py configuration file.

### Core Plugin Configuration

| Environment Variable | Plugin Config Key | Required | Description |
|---|---|---|---|
| `OID4VCI_HOST` | `oid4vci.host` | **Yes** | Hostname the OID4VCI public server binds to (e.g. `0.0.0.0`) |
| `OID4VCI_PORT` | `oid4vci.port` | **Yes** | Port the OID4VCI public server listens on (e.g. `8022`) |
| `OID4VCI_ENDPOINT` | `oid4vci.endpoint` | **Yes** | Publicly-reachable base URL for the credential issuer (e.g. `https://issuer.example.com`). This value is advertised in `/.well-known/openid-credential-issuer` as `credential_issuer`. Supports `${VAR:-default}` variable expansion. |
| `OID4VP_ENDPOINT` | — | No | Override the public base URL for OID4VP endpoints. Falls back to `OID4VCI_ENDPOINT` if not set. |
| `OID4VCI_STATUS_HANDLER` | `oid4vci.status_handler` | No | Python module path of a status list handler (e.g. `status_list.v1_0.status_handler`). Enables `credentialStatus` in issued credentials. |
| `OID4VCI_AUTH_SERVER_URL` | `oid4vci.auth_server_url` | No | URL of an external OAuth 2.0 authorization server. When set, the plugin delegates token issuance to this server. |
| `OID4VCI_AUTH_SERVER_CLIENT` | `oid4vci.auth_server_client` | No | JSON string describing the auth server client credentials. Supports `client_secret_basic` and `private_key_jwt` auth methods. Example: `{"client_id": "acapy", "client_secret": "secret"}` |

### mso_mdoc Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `OID4VC_MDOC_TRUST_STORE_TYPE` | `file` | Trust anchor storage mechanism. Valid values: `file`, `wallet`, `none` (or `disabled`) |
| `OID4VC_MDOC_TRUST_ANCHORS_PATH` | `/etc/acapy/mdoc/trust-anchors/` | Directory path for file-based trust anchor storage. X.509 PEM files are read from this directory on startup. |

### Status List Integration

When using the [Status List Plugin](https://github.com/openwallet-foundation/acapy-plugins/blob/main/status_list/README.md) together with `OID4VCI_STATUS_HANDLER`:

| Environment Variable | Description |
|---|---|
| `STATUS_LIST_SIZE` | Number of entries in each status list (e.g. `131072`) |
| `STATUS_LIST_SHARD_SIZE` | Shard granularity (e.g. `1024`) |
| `STATUS_LIST_PUBLIC_URI` | URL template for status list resources (e.g. `https://issuer.example.com/tenant/{tenant_id}/status/{list_number}`) |
| `STATUS_LIST_FILE_PATH` | File system path template for bitstring storage (e.g. `/tmp/bitstring/{tenant_id}/{list_number}`) |

### Endpoint Variable Expansion

`OID4VCI_ENDPOINT` (and `OID4VP_ENDPOINT`) support shell-style default-value expansion:

```bash
OID4VCI_ENDPOINT="https://${NGROK_HOST:-localhost:8022}"
```

If `NGROK_HOST` is unset, the endpoint resolves to `https://localhost:8022`.

---

## Docker Quick-Start

The plugin ships with ready-to-use Docker Compose configurations.

### Issuer Stack

```bash
cd oid4vc
cp docker/dev.yml docker-compose.override.yml  # optional, for customisation

# Export required env vars
export OID4VCI_ENDPOINT=http://localhost:8022

docker compose -f docker/dev.yml up
```

Key ports (from `docker/dev.yml`):

| Service | Admin API | OID4VCI Public Server |
|---|---|---|
| ACA-Py Issuer | `http://localhost:8021` | `http://localhost:8022` |

### Verifier Stack

```bash
docker compose -f docker/dev-verifier.yml up
```

| Service | Admin API | OID4VP Public Server |
|---|---|---|
| ACA-Py Verifier | `http://localhost:8031` | `http://localhost:8032` |

---

## Verifying the Setup

Once running, confirm Swagger is accessible at both endpoints:

```bash
# Admin Swagger UI — shows oid4vci, oid4vp, mso_mdoc, did tag groups
open http://localhost:8021/api/doc

# Public server Swagger UI — shows wallet-facing endpoints
open http://localhost:8022/api/doc
```

Check the plugin is active:

```bash
curl -s http://localhost:8021/plugins | python3 -m json.tool | grep oid4vc
```

Expected output:

```json
"oid4vc",
```

---

## Multitenant Deployments

In a multi-wallet (multitenant) ACA-Py deployment the OID4VCI public server prefixes wallet-specific routes with `/tenant/{wallet_id}`. The `OID4VCI_ENDPOINT` value must therefore include a `{tenant_id}` placeholder or be set per-tenant:

```bash
OID4VCI_ENDPOINT="https://issuer.example.com/tenant/${WALLET_ID}"
```

The `credential_issuer` value in issuer metadata is computed per-wallet from this template at request time.

---

## Next Steps

- [Architecture Overview](architecture.md) — understand how the two servers and credential format registry work
- [Issuance Cookbook](cookbook-issuance.md) — issue your first credential with step-by-step curl commands
- [Admin API Reference](admin-api-reference.md) — full endpoint reference
