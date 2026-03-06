# mDoc Storage Module

This package provides persistent storage capabilities for mDoc-related cryptographic materials, certificates, and configuration data. It implements secure storage patterns following ISO 18013-5 requirements for key management and credential issuance operations.

## Module Structure

| File | Description |
|------|-------------|
| `base.py` | Shared constants and `get_storage()` helper function |
| `keys.py` | ECDSA signing key storage (JWK format per RFC 7517) |
| `certificates.py` | X.509 certificate storage for issuer authentication |
| `trust_anchors.py` | Trust anchor (root CA) certificate storage for verification |
| `config.py` | Configuration storage (default keys, certificates, etc.) |
| `__init__.py` | Re-exports `MdocStorageManager` class for backward compatibility |

## Usage

```python
from mso_mdoc.storage import MdocStorageManager

# Initialize with ACA-Py profile
storage_manager = MdocStorageManager(profile)

async with profile.session() as session:
    # Store a signing key
    await storage_manager.store_key(session, "key-123", jwk, purpose="signing")
    
    # Retrieve a key
    jwk = await storage_manager.get_key(session, "key-123")
    
    # Store a certificate
    await storage_manager.store_certificate(session, "cert-123", pem, key_id="key-123")
    
    # Store a trust anchor
    await storage_manager.store_trust_anchor(session, "anchor-1", ca_pem)
```

## Storage Record Types

- `mdoc_key` - ECDSA signing keys in JWK format
- `mdoc_certificate` - X.509 issuer certificates (PEM encoded)
- `mdoc_trust_anchor` - Root CA certificates for chain validation
- `mdoc_config` - Configuration data (default key/cert settings)

## Protocol Compliance

- **ISO/IEC 18013-5:2021 § 7.2.4** - Issuer authentication mechanisms
- **ISO/IEC 18013-5:2021 § 9.1.3.5** - Cryptographic algorithms
- **RFC 7517** - JSON Web Key (JWK) storage format
- **NIST SP 800-57** - Key management best practices
