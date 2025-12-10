from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime
import os

def generate_key():
    return ec.generate_private_key(ec.SECP256R1())

def get_name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SpruceID"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

def add_iaca_extensions(builder, key, issuer_key, is_ca=True):
    # Basic Constraints
    builder = builder.add_extension(x509.BasicConstraints(ca=is_ca, path_length=None if is_ca else None), critical=True)
    
    # Key Usage
    if is_ca:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    else:
        # Leaf DS
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        # Extended Key Usage for DS
        builder = builder.add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")]), critical=True)

    # SKI
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    builder = builder.add_extension(ski, critical=False)
    
    # AKI
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key())
    builder = builder.add_extension(aki, critical=False)
    
    # CRL Distribution Points (Required for IACA profile)
    builder = builder.add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("https://interopevent.spruceid.com/interop.crl")],
                relative_name=None,
                crl_issuer=None,
                reasons=None,
            )
        ]),
        critical=False,
    )
    
    # Issuer Alternative Name (Required for IACA profile)
    builder = builder.add_extension(
        x509.IssuerAlternativeName([
            x509.UniformResourceIdentifier("https://interopevent.spruceid.com")
        ]),
        critical=False,
    )
    
    return builder

def generate_root_ca(key):
    name = get_name("Test Root CA")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    
    builder = add_iaca_extensions(builder, key, key, is_ca=True)
    
    return builder.sign(key, hashes.SHA256())

def generate_intermediate_ca(key, issuer_key, issuer_name):
    name = get_name("Test Intermediate CA")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    
    builder = add_iaca_extensions(builder, key, issuer_key, is_ca=True)
    
    return builder.sign(issuer_key, hashes.SHA256())

def generate_leaf_ds(key, issuer_key, issuer_name):
    name = get_name("Test Leaf DS")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    
    builder = add_iaca_extensions(builder, key, issuer_key, is_ca=False)
    
    return builder.sign(issuer_key, hashes.SHA256())

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

def save_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def main():
    certs_dir = "certs"
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    # Root CA
    root_key = generate_key()
    root_cert = generate_root_ca(root_key)
    save_key(root_key, f"{certs_dir}/root_ca.key")
    save_cert(root_cert, f"{certs_dir}/root_ca.pem")
    print("Generated Root CA")

    # Intermediate CA
    inter_key = generate_key()
    inter_cert = generate_intermediate_ca(inter_key, root_key, root_cert.subject)
    save_key(inter_key, f"{certs_dir}/intermediate_ca.key")
    save_cert(inter_cert, f"{certs_dir}/intermediate_ca.pem")
    print("Generated Intermediate CA")

    # Leaf DS
    leaf_key = generate_key()
    leaf_cert = generate_leaf_ds(leaf_key, inter_key, inter_cert.subject)
    save_key(leaf_key, f"{certs_dir}/leaf.key")
    save_cert(leaf_cert, f"{certs_dir}/leaf.pem")
    print("Generated Leaf DS Cert")

if __name__ == "__main__":
    main()
