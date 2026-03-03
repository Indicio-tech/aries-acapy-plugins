# Production Deployment Guide

This guide covers best practices for deploying the OID4VC plugin in production environments, including security considerations, configuration, and operational concerns.

## Prerequisites

Before deploying to production, ensure you have:

- ACA-Py 1.0.0+ installed and configured
- Required plugins loaded: `oid4vc`, and optionally `sd_jwt_vc`, `mso_mdoc`
- SSL/TLS certificates for HTTPS endpoints
- Proper authentication configured (API keys or JWT tokens for multi-tenant)
- Database backend configured (PostgreSQL recommended for production)

---

## Security Checklist

### 1. Transport Security

**⚠️ Critical:** All OID4VC endpoints MUST be served over HTTPS in production.

```yaml
# docker-compose.yml or deployment config
environment:
  ACAPY_ENDPOINT: "https://issuer.example.com"  # Public HTTPS endpoint
  ACAPY_ADMIN_URL: "https://admin.example.com"  # Admin HTTPS endpoint
```

**Why:** OID4VC exchanges include sensitive data (credential offers, proofs of possession, presentations). HTTP exposes this data to tampering and eavesdropping.

### 2. Authentication & Authorization

Enable authentication for all admin endpoints:

```bash
--admin-api-key <secure-random-key>
# Or for multi-tenancy:
--jwt-secret <secure-random-secret>
--multitenant-admin
```

**Generate secure keys:**

```bash
# Generate 32-byte random key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Key Management

#### Issuer Signing Keys

**Best practices:**
- Use hardware security modules (HSM) or key management services (KMS) for signing keys
- Rotate signing keys periodically (e.g., annually)
- Maintain key backup and recovery procedures
- Never hard-code private keys in configuration files

**For production `did:jwk` issuance:**

1. Generate signing keys with proper entropy:
   ```bash
   curl -X POST https://admin.example.com/did/jwk/create \
     -H "X-API-KEY: $ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{"key_type": "p256"}'
   ```

2. Store the DID and use it consistently:
   ```jsonc
   {
     "did": "did:jwk:eyJjcnYiOiJQLTI1NiIs...",  // Save this
     "verification_method": "did:jwk:...#0"
   }
   ```

3. Document key rotation procedures in your runbooks

#### mDOC Signing Certificates

For mDOC credentials, use proper certificate hierarchies:

```bash
# Generate production signing key and certificate
curl -X POST https://admin.example.com/mso_mdoc/generate-keys \
  -H "X-API-KEY: $ADMIN_KEY"
```

**⚠️ Self-signed certificates are NOT suitable for production.** Use certificates issued by a trusted Certificate Authority (CA) recognized by holder wallets.

### 4. Trust Anchor Management (mDOC)

Establish proper trust anchors for verifying holder-presented mDOCs:

```bash
# Add production root CA certificate
curl -X POST https://admin.example.com/mso_mdoc/trust-anchors \
  -H "X-API-KEY: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "anchor_id": "production-root-ca-2026",
    "metadata": {
      "issuer": "National ID Authority",
      "valid_from": "2026-01-01",
      "valid_until": "2046-01-01",
      "purpose": "Verify government-issued mDL credentials"
    }
  }'
```

**Best practices:**
- Only add trust anchors from verified, authoritative sources
- Document the provenance of each trust anchor
- Implement trust anchor rotation procedures
- Monitor trust anchor expiration dates
- Test trust anchor chains before accepting production credentials

### 5. Credential Status Management

Integrate with the Status List plugin for revocation support:

```bash
# Install status_list plugin
pip install git+https://github.com/openwallet-foundation/acapy-plugins.git#subdirectory=status_list

# Load plugin in ACA-Py
--plugin status_list
```

**Configure status list issuance:**

```jsonc
{
  "format": "vc+sd-jwt",
  "id": "EmployeeCredential",
  "vct": "EmployeeCredential",
  // ... other fields ...
  "status": {
    "status_list": {
      "idx": "auto",  // Assign status list index automatically
      "uri": "https://issuer.example.com/status-lists/1"
    }
  }
}
```

**⚠️ Important:** Publish status lists at stable, public HTTPS URLs. Wallets and verifiers must be able to fetch status lists to check revocation.

---

## Environment Configuration

### Production Environment Variables

```bash
# Core ACA-Py settings
ACAPY_ENDPOINT=https://issuer.example.com
ACAPY_ADMIN_URL=https://admin-internal.example.com
ACAPY_ADMIN_API_KEY=<secure-key>

# Database (PostgreSQL recommended)
ACAPY_WALLET_STORAGE_TYPE=postgres_storage
ACAPY_WALLET_STORAGE_CONFIG='{"url":"postgres://user:pass@db:5432/acapy"}'

# Plugin configuration
ACAPY_PLUGIN=oid4vc
ACAPY_PLUGIN=sd_jwt_vc
ACAPY_PLUGIN=mso_mdoc
ACAPY_PLUGIN=status_list

# Public server for OID4VCI/OID4VP
ACAPY_OID4VCI_PUBLIC_URL=https://issuer.example.com

# Logging
ACAPY_LOG_LEVEL=WARNING  # or INFO for detailed logs
ACAPY_LOG_FILE=/var/log/acapy/acapy.log

# Multi-tenancy (if applicable)
ACAPY_MULTITENANT=true
ACAPY_MULTITENANT_ADMIN=true
ACAPY_JWT_SECRET=<secure-jwt-secret>
```

### Docker Compose Example

```yaml
version: '3.8'

services:
  acapy:
    image: ghcr.io/openwallet-foundation/acapy:latest
    environment:
      ACAPY_ENDPOINT: "https://issuer.example.com"
      ACAPY_ADMIN_URL: "http://0.0.0.0:8021"
      ACAPY_ADMIN_API_KEY: "${ADMIN_API_KEY}"
      ACAPY_WALLET_STORAGE_TYPE: "postgres_storage"
      ACAPY_WALLET_STORAGE_CONFIG: '{"url":"postgres://acapy:${DB_PASSWORD}@postgres:5432/acapy"}'
      ACAPY_PLUGIN: "oid4vc,sd_jwt_vc,mso_mdoc,status_list"
      ACAPY_LOG_LEVEL: "INFO"
    volumes:
      - ./certs:/certs:ro
      - ./logs:/var/log/acapy
    ports:
      - "8020:8020"  # Public server
      - "8021:8021"  # Admin server (internal only)
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: acapy
      POSTGRES_USER: acapy
      POSTGRES_PASSWORD: "${DB_PASSWORD}"
    volumes:
      - pgdata:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  pgdata:
```

### Reverse Proxy Configuration (Nginx)

```nginx
# /etc/nginx/sites-available/issuer.example.com

server {
    listen 443 ssl http2;
    server_name issuer.example.com;

    ssl_certificate /etc/nginx/certs/issuer.example.com.crt;
    ssl_certificate_key /etc/nginx/certs/issuer.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Public OID4VCI/OID4VP endpoints
    location / {
        proxy_pass http://acapy:8020;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Admin interface - internal network only
server {
    listen 443 ssl http2;
    server_name admin-internal.example.com;

    ssl_certificate /etc/nginx/certs/admin-internal.crt;
    ssl_certificate_key /etc/nginx/certs/admin-internal.key;

    # IP whitelist
    allow 10.0.0.0/8;  # Internal network
    deny all;

    location / {
        proxy_pass http://acapy:8021;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Operational Considerations

### 1. Monitoring & Logging

**Key metrics to monitor:**
- Credential issuance rate (exchanges created, offers generated, credentials issued)
- Presentation verification rate (requests created, valid presentations, invalid presentations)
- Error rates by endpoint
- Response times (p50, p95, p99)
- Database connection pool usage
- Storage growth rate

**Recommended logging configuration:**

```bash
# Production: WARNING level for general operation, INFO for troubleshooting
ACAPY_LOG_LEVEL=WARNING

# Enable structured logging for log aggregation
ACAPY_LOG_JSON=true
```

**Example log monitoring with Prometheus:**

```yaml
# Add custom metrics exporter
- name: acapy-exporter
  image: custom/acapy-exporter:latest
  environment:
    ACAPY_ADMIN_URL: http://acapy:8021
    ACAPY_ADMIN_KEY: "${ADMIN_API_KEY}"
```

### 2. Backup & Disaster Recovery

**Critical data to backup:**
- ACA-Py wallet database (contains signing keys)
- Supported credential configurations
- Status list data (if using status_list plugin)
- mDOC trust anchors and certificates

**Backup strategy:**

```bash
# Daily automated PostgreSQL backups
pg_dump -h localhost -U acapy acapy > backup-$(date +%Y%m%d).sql

# Encrypt backups before storage
openssl enc -aes-256-cbc -salt -in backup-$(date +%Y%m%d).sql \
  -out backup-$(date +%Y%m%d).sql.enc -k "$BACKUP_PASSWORD"

# Store encrypted backups off-site
aws s3 cp backup-$(date +%Y%m%d).sql.enc s3://backups/acapy/
```

**Recovery testing:**
- Test backup restoration quarterly
- Document recovery time objective (RTO) and recovery point objective (RPO)
- Maintain runbooks for disaster recovery scenarios

### 3. Scalability

**Horizontal scaling:**

OID4VC endpoints are stateless and can be load-balanced:

```yaml
# docker-compose.yml - multiple ACA-Py instances
services:
  acapy-1:
    image: ghcr.io/openwallet-foundation/acapy:latest
    # ... config ...
  
  acapy-2:
    image: ghcr.io/openwallet-foundation/acapy:latest
    # ... config ...
  
  load-balancer:
    image: nginx:alpine
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf:ro
    ports:
      - "443:443"
    depends_on:
      - acapy-1
      - acapy-2
```

**Database tuning:**

```sql
-- Optimize PostgreSQL for high-throughput credential issuance
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET work_mem = '16MB';

-- Add indexes for common queries
CREATE INDEX idx_exchange_state ON oid4vci_exchanges(state);
CREATE INDEX idx_presentation_state ON oid4vp_presentations(state);
```

### 4. Security Monitoring

**Enable audit logging:**

```bash
# Log all admin API calls
ACAPY_ADMIN_AUDIT_LOG=true
ACAPY_AUDIT_LOG_FILE=/var/log/acapy/audit.log
```

**Monitor for suspicious activity:**
- Unusual credential issuance volumes
- Failed authentication attempts
- Invalid presentation submissions
- Unexpected trust anchor modifications

### 5. Incident Response

**Credential revocation procedure:**

```bash
# Immediately revoke a compromised credential
curl -X POST https://admin.example.com/credentials/{cred_id}/revoke \
  -H "X-API-KEY: $ADMIN_KEY"

# Update and publish status list
curl -X POST https://admin.example.com/status-lists/1/publish \
  -H "X-API-KEY: $ADMIN_KEY"
```

**Key compromise response:**
1. Generate new signing key immediately
2. Issue credentials with new key
3. Revoke all credentials signed with compromised key
4. Notify credential holders to request new credentials
5. Document incident and root cause

---

## Integration with Status List Plugin

The Status List plugin enables credential revocation and suspension:

### Configuration

```bash
# Install alongside oid4vc
pip install git+https://github.com/openwallet-foundation/acapy-plugins.git#subdirectory=status_list

# Load plugin
--plugin status_list
```

### Creating Status Lists

```bash
# Create a new status list
curl -X POST https://admin.example.com/status-list \
  -H "X-API-KEY: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "purpose": "revocation",
    "capacity": 100000
  }'
```

### Issuing Credentials with Status

```bash
# Supported credential with status support
curl -X POST https://admin.example.com/oid4vci/credential-supported/create/sd-jwt \
  -H "X-API-KEY: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "vc+sd-jwt",
    "id": "EmployeeCredential",
    "vct": "EmployeeCredential",
    "status": {
      "status_list": {
        "idx": "auto",
        "uri": "https://issuer.example.com/status-lists/1"
      }
    }
  }'
```

### Revoking Credentials

```bash
# Update credential status
curl -X PATCH https://admin.example.com/oid4vci/exchange/records/{exchange_id}/status \
  -H "X-API-KEY: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status": "revoked"}'

# Publish updated status list (makes revocation effective)
curl -X POST https://admin.example.com/status-lists/1/publish \
  -H "X-API-KEY: $ADMIN_KEY"
```

---

## Testing Production Deployment

### Pre-Deployment Checklist

- [ ] HTTPS enabled for all public endpoints
- [ ] Admin API authentication configured
- [ ] Database backups configured and tested
- [ ] Monitoring and alerting configured
- [ ] Security scanning completed (container images, dependencies)
- [ ] Load testing performed
- [ ] Disaster recovery procedures documented
- [ ] Incident response runbooks prepared

### Smoke Tests

```bash
# Test OID4VCI credential issuer metadata
curl -s https://issuer.example.com/.well-known/openid-credential-issuer | jq

# Test admin API authentication
curl -H "X-API-KEY: $ADMIN_KEY" https://admin.example.com/status/ready

# Test credential issuance flow (end-to-end)
# 1. Create supported credential
# 2. Create exchange
# 3. Generate offer
# 4. Complete issuance with test wallet
```

### Load Testing

```bash
# Use k6 or similar for load testing
k6 run --vus 100 --duration 5m load-test.js
```

---

## Additional Resources

- [Getting Started](getting-started.md) — Initial setup and configuration
- [Architecture](architecture.md) — Understanding the plugin design
- [Admin API Reference](admin-api-reference.md) — Complete endpoint documentation
- [Troubleshooting](troubleshooting.md) — Common issues and solutions
- [ACA-Py Production Guide](https://aca-py.org/latest/deploying/) — General ACA-Py deployment best practices
