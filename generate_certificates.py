#!/usr/bin/env python3
"""
Generate self-signed SSL certificates for the Unicast Secure Messenger server.
This creates a server certificate and key for TLS/SSL encryption.
"""

import os
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_self_signed_cert(cert_dir):
    """Generate self-signed certificate for the server."""
    
    # Create certs directory if it doesn't exist
    cert_path = Path(cert_dir)
    cert_path.mkdir(parents=True, exist_ok=True)
    
    print("Generating SSL certificates...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"pyMessenger"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.DNSName(u"127.0.0.1"),
            x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1")),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Write private key
    key_file = cert_path / "server.key"
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate
    cert_file = cert_path / "server.crt"
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Set restrictive permissions on Unix systems
    if os.name != 'nt':
        os.chmod(key_file, 0o600)
        os.chmod(cert_file, 0o644)
    
    print(f"✓ SSL certificate generated: {cert_file}")
    print(f"✓ SSL private key generated: {key_file}")
    print(f"✓ Certificate valid for 365 days")
    
    return str(cert_file), str(key_file)

if __name__ == "__main__":
    # Generate certificates in the .secure_messenger directory
    cert_dir = Path.home() / '.secure_messenger' / 'certs'
    
    try:
        cert_file, key_file = generate_self_signed_cert(cert_dir)
        print(f"\n✓ Certificates ready for use!")
    except Exception as e:
        print(f"✗ Error generating certificates: {e}")
        import traceback
        traceback.print_exc()
