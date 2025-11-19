# OID4VC Integration Tests

Integration tests for OpenID4VC v1 flows implementing the pattern:
**ACA-Py Issues → Credo Receives → Credo Presents → ACA-Py Verifies**

## Architecture

This test suite validates complete OID4VC v1 flows with three components:

1. **ACA-Py Issuer** - Issues both mso_mdoc and SD-JWT credentials using ACA-Py's OID4VCI implementation
2. **Credo Holder/Verifier** - Receives credentials from ACA-Py, then presents them using Credo's OID4VC v1 support
3. **ACA-Py Verifier** - Validates presentations from Credo using the OID4VC plugin

## Credential Types Tested

- **mso_mdoc** - Mobile documents (ISO 18013-5) for driver licenses, ID cards
- **SD-JWT** - Selective disclosure JWT credentials for privacy-preserving presentations

## Quick Start

```bash
# Start all services and run tests
docker-compose up --build

# Run specific test categories
docker-compose run integration-tests -m "mdoc"     # Only mso_mdoc tests
docker-compose run integration-tests -m "sdjwt"    # Only SD-JWT tests
docker-compose run integration-tests -m "interop"  # Only interop tests

# Clean up
docker-compose down -v
```

## Development Setup

For local development without Docker:

```bash
# Install dependencies
uv sync

# Start services individually
cd credo && npm start &       # Port 3020  
cd ../.. && make dev-watch &   # ACA-Py on ports 3030/3031/8032

# Run tests
uv run pytest tests/ -v
```

## Test Structure

```
tests/
├── test_interop/
│   ├── test_acapy_to_credo.py        # Credential issuance flow
│   ├── test_credo_to_acapy.py        # Presentation verification flow
│   └── test_full_flow.py             # End-to-end integration
├── test_mdoc/
│   ├── test_mdoc_issuance.py         # mso_mdoc specific tests
│   └── test_mdoc_presentation.py     # mso_mdoc presentation tests
└── test_sdjwt/
    ├── test_sdjwt_issuance.py        # SD-JWT specific tests
    └── test_sdjwt_presentation.py    # SD-JWT presentation tests
```

## Environment Variables

- `ACAPY_ISSUER_ADMIN_URL` - ACA-Py issuer admin endpoint (default: http://localhost:8021)
- `ACAPY_ISSUER_OID4VCI_URL` - ACA-Py issuer OID4VCI endpoint (default: http://localhost:8022)
- `CREDO_AGENT_URL` - Credo agent endpoint (default: http://localhost:3020)
- `ACAPY_VERIFIER_ADMIN_URL` - ACA-Py verifier admin endpoint (default: http://localhost:8031)
- `ACAPY_VERIFIER_OID4VP_URL` - ACA-Py verifier OID4VP endpoint (default: http://localhost:8032)

## Test Results

Test results are saved to `test-results/`:
- `junit.xml` - JUnit XML format for CI/CD integration  
- `report.html` - HTML test report with detailed results
