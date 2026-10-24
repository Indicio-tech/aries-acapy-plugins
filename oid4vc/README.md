# OpenID4VCI Plugin for ACA-Py

This plugin implements [OpenID4VCI 1.0][oid4vci]. This implementation follows the OpenID4VCI 1.0 final specification and is not backwards compatible with earlier drafts.

## Developer Documentation

| Document | Description |
|---|---|
| [Getting Started](docs/getting-started.md) | Prerequisites, installation, configuration, Docker quick-start |
| [Architecture](docs/architecture.md) | Two-server design, plugin lifecycle, credential format registry |
| [Admin API Reference](docs/admin-api-reference.md) | All `/oid4vci/*`, `/oid4vp/*`, `/mso_mdoc/*`, `/did/*` endpoints |
| [Public API Reference](docs/public-api-reference.md) | OID4VCI/OID4VP wallet-facing endpoints |
| [Issuance Cookbook](docs/cookbook-issuance.md) | Step-by-step curl examples for `jwt_vc_json`, `sd_jwt_vc`, `mso_mdoc` |
| [Verification Cookbook](docs/cookbook-verification.md) | PEX and DCQL-based VP flows with curl examples |
| [Credential Formats](docs/credential-formats.md) | Format-specific schema details, selective disclosure, mDOC namespaces |
| [Troubleshooting](docs/troubleshooting.md) | Error codes, common failures, debugging tips |

The plugin's admin endpoints appear automatically in the ACA-Py Swagger UI at `http://<admin-host>:<admin-port>/api/doc` under the `oid4vci`, `oid4vp`, `mso_mdoc`, and `did` tag groups.

## OpenID4VCI Plugin Demo with Sphereon Wallet

### Demo Overview

This repository showcases a simplified demonstration of the OID4VCI (OpenID for Verifiable Credential Issuers) integration with the [Sphereon Wallet app](https://github.com/Sphereon-Opensource/ssi-mobile-wallet). Follow the steps below to run the demo successfully.

### Prerequisites

- Sphereon Wallet App on your mobile device
- Docker + Docker Compose
- Ngrok Account (free tier is okay)

### Steps to Run the Demo

First, you'll have to get your authtoken from ngrok. Note this value down.

```shell
cd oid4vc/demo
docker-compose build
echo "NGROK_AUTHTOKEN=<PASTE YOUR AUTHTOKEN HERE>" > .env
docker-compose up
docker-compose down -v  # Clean up
```

If you're using Apple Silicon, you may have to separately build the image with the appropriate platform flag (from the `demo` directory):

```sh
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build -f docker/Dockerfile --tag oid4vc ../..
```

### Demo Flow

Navigate to `http://localhost:3002` in your browser. You will start at the landing page. The sidebar has buttons to take you to the issuance and presentation pages.

1. Issue Credential

   - This page generates a simple `UniversityCredential` for issuance

     - The demo obscures and automates the necessary `credential-supported/create` call, which is what defines the type and values of a credential that can be issued

   - Preparing a credential offer is simple:
     - Enter your name and email, or use the test value provided, and hit `Register`
     - Once you hit `Register`, you'll be automatically taken to the Credential Offer Page

2. Credential Offer Page
   - Presents a credential offer in the form of a QR code.
   - Scan the QR code using the Sphereon Wallet app.
   - The Sphereon Wallet follows the OID4VC flow, requesting an authentication token and using it to obtain a credential.
   - The OID4VC plugin determines the credential subjects based on the exchange record.

Now you have a `UniversityCredential` in your Sphereon Wallet. To demonstrate the other half of the OID4VC plugin, click on the `Present Credential` button on the sidebar.

3. Present Credential
   - The Present Credential page has a single button on it: Present Credential
   - When you press that button, the demo will prepare a QR code that contains a presentation request
     - Again, the demo obscures and automates some of the necessary calls to prepare the request, but you can see the calls being made in the logs
   - Scan this QR code with your Sphereon Wallet app
   - Follow the steps on the app, which will prompt you to select a University Credential from your wallet

As mentioned, the demo automatically takes care of a lot of the setup calls necessary to prepare credential definitions, presentation requests, and so forth. You can see what calls are being made, and with what values, both in the container logs and on the page.


### Integrating the Status List Plugin

Documentation for the [Status List Plugin] (https://github.com/openwallet-foundation/acapy-plugins/blob/main/status_list/README.md)

1. Configuring the plugin:

     Command Line: *--plugin status_list.v1_0*

     Example Configuration:
```
     OID4VCI_STATUS_HANDLER: status_list.v1_0.status_handler
     STATUS_LIST_SIZE: 131072
     STATUS_LIST_SHARD_SIZE: 1024
     STATUS_LIST_PUBLIC_URI: https://localhost:8082/tenant/{tenant_id}/status/{list_number}
     STATUS_LIST_FILE_PATH: /tmp/bitstring/{tenant_id}/{list_number}
```
3. Binding a status list to a *supported_cred_id*:

     Once bound all credentials issued with the given supported_cred_id will include a status list entry - either w3c or ietf

     API Call - *POST .../status-list/defs*

     Example JSON Body (list_type can be either "w3c" or "ietf"):
```
      {
        "issuer_did": "did....",
        "list_type": "w3c",
        "list_size": 131072,
        "shard_size": 1024,
        "status_message": [
          {
            "status": "0x00",
            "message": "active"
          },
          {
            "status": "0x01",
            "message": "revoked"
          },
        ],
        "status_purpose": "message",
        "status_size": 1,
        "supported_cred_id": "string",
        "verification_method": "did...."
      }
```

### Note

In a production environment, the described processes would be more dynamic and involve additional security measures. This demo provides a streamlined representation for clarity and ease of understanding.

## Architecture

![oid4vci-component](https://raw.githubusercontent.com/openwallet-foundation/acapy-plugins/main/oid4vc/docs/images/oid4vci-component.png)

### Public Routes

ACA-Py provides a pluggable mechanism for registering routes for consumption by the controller, the Admin API. This Admin Server makes it trivial to extend the controller from plugins. ACA-Py does not, however, provide a similar mechanism for publicly accessible HTTP Endpoints. Generally speaking, the only public endpoint ACA-Py provides is the DIDComm Messaging endpoint. The OpenID4VCI protocol requires endpoints that are publicly accessible to present and exchange tokens for credentials. This Plugin accomplishes this by starting a separate [aiohttp server](https://docs.aiohttp.org/en/stable/index.html) (similar to how the Admin server is separate from the DIDComm messaging server) and publishes the OpenID4VCI endpoints through this separate server.

Details of the endpoints can be found at `/api/docs` or in the [OpenId4VCI Specification][oid4vci].

### Admin Routes

The plugin exposes Admin API routes for consumption by the Controller to facilitate Credential Issuance over OpenID4VCI. The Admin API Routes can be found under `/api/docs` of the Admin Server in the `oid4vci` section.

### Records

The plugin adds two records to ACA-Py, `OID4VCIExchangeRecord` and `SupportedCredential`. The exchange record keeps track of user data use during the exchange. The supported credential record keeps track of information a issuer needs to issue a credential.

### How it works

It is the Controller's responsibility to prepare Credential Issuer Metadata, collect and record details about the credential subject, (optionally) generate and deliver a User PIN to the holder out of band, and to generate and present the credential offer to the holder.

### Credential Issuance

```mermaid
sequenceDiagram
autonumber

actor alice as Alice
participant holder as Wallet
participant controller as Controller
box OpenID4VCI Plugin
participant public as Public Routes
participant admin as Admin Routes
end
participant acapy as ACA-Py Core

controller ->> admin: POST /oid4vci/credential-supported/create
admin -->> controller: created (supported_cred_id)
controller ->> admin: POST /wallet/did/create
admin -->> controller: created (did)
alice -> controller: Open URL in browser with form
alice ->> controller: Submit form
activate controller
controller ->> admin: POST /oid4vci/exchange/create (did, supported_cred_id, credential subject)
admin -->> controller: created (record)
alt PIN required
controller -->> alice: Deliver PIN Out of Band (email, sms, etc.)
end
controller ->> admin: GET /oid4vci/credential-offer (exchange id, pin)
admin -->> controller: credential offer
controller ->> alice: redirects alice to a page with cred offer
deactivate controller
alice ->> holder: Scan cred offer
holder --> controller: scanned cred offer (pre-auth code)
holder ->> holder: reads offer, extracts issuer
holder ->> public: Retrieve issuer metadata
public -->> holder: issuer metadata
holder ->> public: token request (pre-auth code)
public ->> holder: token response (access token)
holder ->> public: credential request (access token)
activate public
public ->> acapy: Verify Proof of Possession
acapy -->> public: Verified
public ->> acapy: Recall cred values
public ->> acapy: jwt sign
acapy -->> public: signed cred
public ->> acapy: store exchange result
public ->> holder: credential response
deactivate public
admin ->> controller: POST /topic/oid4vci (issued)
loop alice polling for exchange status
alice ->> controller: get exchange status
controller -->> alice: status
alt complete
controller ->> alice: redirect to success page
end
end
```

### Credential Presentation

```mermaid
sequenceDiagram
autonumber

actor alice as Alice
participant holder as Wallet
participant controller as Controller
box OpenID4VCI Plugin
participant public as Public Routes
participant admin as Admin Routes
end
participant acapy as ACA-Py Core

controller ->> admin: POST /oid4vp/presentation-definition
admin ->> acapy: store presentation definition
admin -->> controller: created presentation definition
alice ->> controller: Hits web page initiating presentation
controller ->> admin: POST /oid4vp/request
admin ->> acapy: save request record associated <br/>with a particular pres def
admin -->> controller: request URI
controller ->> alice: QR Code
alice ->> holder: Scan QR Code
holder ->> public: GET /oid4vp/request/{request_id} (request uri in QR code)
public -> acapy: retrieve stored request
public -->> holder: request
holder ->> public: POST /oid4vp/response/{presentation_id}
acapy ->> controller: POST /topic/oid4vp <br/>(state: presentation-valid/invalid)
controller ->> holder: result
```

## Usage

### Configuration

The Plugin expects the following configuration options. These options can either be set by environment variable (`OID4VCI_*`) or by plugin config value (`-o oid4vci.*`).

- `OID4VCI_HOST` or `oid4vci.host`
  - Host used for the OpenID4VCI public server
- `OID4VCI_PORT` or `oid4vci.port`
  - Port used for the OpenID4VCI public server
- `OID4VCI_ENDPOINT` or `oid4vci.endpoint`
  - `credential_issuer` endpoint, seen in the Credential Offer
- `OID4VCI_CRED_HANDLER` or `oid4vci.cred_handler`
  - Dict of credential handlers. e.g. `{"jwt_vc_json": "jwt_vc_json"}`
- `OID4VCI_AUTH_SERVER_URL` or `oid4vci.auth_server_url`
  - Optional authorization server URL
- `OID4VCI_AUTH_SERVER_CLIENT` or `oid4vci.auth_server_client`
  - Optional authorization server client credential, e.g. `{"auth_type": "client_secret_basic", "client_id": "client_id", "client_secret": "client_secret"}`
- `OID4VP_VERIFIER_TRUST_ROOTS` or `oid4vci.verifier_trust_roots`
  - Optional path to a PEM bundle of roots. When set, a registered verifier certificate chain must end at one of them.

### Verifier X.509 identity (x509_hash)

By default a tenant signs OID4VP request objects with a `did:jwk` and uses that DID as `client_id`. A tenant can instead hold one checked X.509 identity:

1. `POST /oid4vp/x509-identity/csr` with `{"subject": {"common_name": "Example Clinic"}}` makes a P-256 key in the wallet and returns a CSR signed through the wallet. The private key never leaves the wallet.
2. A CA issues a certificate for that CSR. `POST /oid4vp/x509-identity` with `{"cert_chain_pem": "<leaf first>"}` registers it only if every check passes:
   - the leaf holds the wallet key and is not self-signed;
   - each certificate is issued by the next;
   - all certificates are in date;
   - the leaf allows `digitalSignature`;
   - when roots are configured, the chain ends at one of them.

   A failed check is refused with 400. A missing ISO 18013-5 reader EKU is logged, not refused.

   A self-signed trust anchor at the end of the submitted chain is checked but not stored, so it is never sent in `x5c` (HAIP 1.0, clause 5). Intermediates are kept.
3. Requests then use `client_id` `x509_hash:<base64url SHA-256 of the leaf>`, ES256, and the chain in the `x5c` header. `client_id_scheme: "x509_san_dns"` with a matching dNSName SAN is also accepted. A `client_id` sent without `client_id_scheme: "x509_san_dns"` is refused (400); before this change the route took a DNS `client_id` with no scheme.

`GET /oid4vp/x509-identity` shows the identity, any open CSR, `expired`, `expires_in_days` and `expiry_warning` (from 30 days before expiry). `DELETE` removes it (`?pending=true` removes an open CSR). After a renewal the previous identity is kept, and `POST /oid4vp/x509-identity/rollback` restores it while it is in date; older verifier keys are deleted.

An expired or not-yet-valid certificate anywhere in the chain stops request creation and request fetch (409); there is no fallback to `did:jwk`. A request whose verifier identity changed after it was created is refused at fetch (409), because the request object's `client_id` must equal the one in the link (OpenID4VP 1.0, 5.10.1). A record registered before these checks existed is checked on first use and refused if it fails. Tenants without an identity are unchanged.

### Creating Supported Credential Records

To issue a credential using OpenID4VCI, the Issuer must first prepare credential issuer metadata including which credentials the Issuer can issue. Below is an example payload to the `POST /oid4vci/credential-supported/create/jwt` endpoint:

```json
{
  "cryptographic_binding_methods_supported": ["did"],
  "cryptographic_suites_supported": ["ES256K"],
  "display": [
    {
      "name": "University Credential",
      "locale": "en-US",
      "logo": {
        "url": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
        "alt_text": "a square logo of a university"
      },
      "background_color": "#12107C",
      "text_color": "#FFFFFF"
    }
  ],
  "format": "jwt_vc_json",
  "credentialSubject": {
    "degree": {},
    "given_name": {
      "display": [
        {
          "name": "Given Name",
          "locale": "en-US"
        }
      ]
    },
    "gpa": {
      "display": [
        {
          "name": "GPA"
        }
      ]
    },
    "last_name": {
      "display": [
        {
          "name": "Surname",
          "locale": "en-US"
        }
      ]
    }
  },
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "id": "UniversityDegreeCredential",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ]
}
```

For the `id`, `format`, `cryptographic_binding_supported`, `cryptographic_suites_supported`, and `display` attributes, see the [OpenID4VCI Specification, Section 10.2.3][oid4vci].

- `type` is a required attribute for JWT-VC (recorded as `types` in the `SupportedCredential.format_data` dictionary), and `credentialSubject` represents display characteristics of the credential only and is not an exhaustive list of the credential attributes. These values are reported in the credential issuer metadata.
- The `@context` of credential to be issued, as well as the `type` are stored in the `SupportedCredential.vc_additional_data` dictionary. These values are NOT reported in the credential issuer metadata.

When the Controller sets up a Supported Credential record using the Admin API, the holder, upon requesting Credential Issuer Metadata, will receive the following information in response:

```json
{
  "credential_issuer": "https://e116-198-91-62-58.ngrok.io/",
  "credential_endpoint": "https://e116-198-91-62-58.ngrok.io/credential",
  "credentials_supported": [
    {
      "format": "jwt_vc_json",
      "cryptographic_binding_methods_supported": ["did"],
      "cryptographic_suites_supported": ["ES256K"],
      "display": [
        {
          "name": "University Credential",
          "locale": "en-US",
          "logo": {
            "url": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
            "alt_text": "a square logo of a university"
          },
          "background_color": "#12107c",
          "text_color": "#FFFFFF"
        }
      ],
      "id": "UniversityDegreeCredential",
      "credentialSubject": {
        "degree": {},
        "given_name": {
          "display": [
            {
              "name": "Given Name",
              "locale": "en-US"
            }
          ]
        },
        "gpa": {
          "display": [
            {
              "name": "GPA"
            }
          ]
        },
        "last_name": {
          "display": [
            {
              "name": "Surname",
              "locale": "en-US"
            }
          ]
        }
      },
      "types": ["VerifiableCredential", "UniversityDegreeCredential"]
    }
  ]
}
```

## Contributing

This project is managed using Poetry. To get started:

```shell
poetry install --all-extras
poetry run pre-commit install
poetry run pre-commit install --hook-type commit-msg
```

#### Installing mso_mdoc Dependencies (Optional)

The `mso_mdoc` module requires the `isomdl-uniffi` library, which needs Rust to compile. 

**⚠️ Note**: Automated installation through Poetry/pip doesn't currently work due to build system limitations.

For manual installation instructions, see [mso_mdoc/README.md](mso_mdoc/README.md).

### Unit Tests

To run unit tests:

```shell
# Run all tests except mso_mdoc (which requires isomdl-uniffi)
poetry run pytest jwt_vc_json/tests/ oid4vc/tests/ sd_jwt_vc/tests/

# Or run all tests including mso_mdoc (requires isomdl-uniffi installed)
poetry run pytest
```

### Integration Tests

This plugin includes two sets of integration tests:

- Tests against a minimal OpenID4VCI Client written in Python
- Interop Tests against Credo and Sphereon
  - The interop tests require an https endpoint, so they aren't run with the regular integration tests. See `integration/README.md` for instructions on running the interop tests

To run the integration tests:

```shell
cd oid4vc/integration
docker compose build
docker compose run tests
docker compose down -v  # Clean up
```

For Apple Silicon, the `DOCKER_DEFAULT_PLATFORM=linux/amd64` environment variable will be required.

## Not Implemented

- `ldp_vc`
- Authorization Code Flow
- GET /.well-known/openid-configuration
- GET /.well-known/oauth-authorization-server
- Batch Credential Issuance
- We're limited to DID Methods that ACA-Py supports for issuance (more can be added by Plugin, e.g. DID Web); `did:sov`, `did:key`

[oid4vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
