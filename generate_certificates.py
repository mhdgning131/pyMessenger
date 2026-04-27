                      
                                                                                    

import argparse
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


DEFAULT_SERVER_HOSTS = ("localhost", "127.0.0.1", "::1", "pymessenger.mohamedg.me")
CA_KEY_FILENAME = "ca.key"
CA_CERT_FILENAME = "ca.crt"
SERVER_KEY_FILENAME = "server.key"
SERVER_CERT_FILENAME = "server.crt"


def _build_name(common_name, organization):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _normalize_hosts(hostnames):
    hosts = []
    seen = set()
    values = hostnames or DEFAULT_SERVER_HOSTS

    for host in values:
        if host is None:
            continue

        text = str(host).strip()
        if not text:
            continue

        key = text.lower()
        if key in seen:
            continue

        seen.add(key)
        hosts.append(text)

    if not hosts:
        hosts = list(DEFAULT_SERVER_HOSTS)

    return hosts


def _build_subject_alternative_names(hostnames):
    alt_names = []
    for host in _normalize_hosts(hostnames):
        try:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            alt_names.append(x509.DNSName(host))
    return alt_names


def _write_private_key(path, private_key):
    with open(path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def _write_certificate(path, certificate):
    with open(path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))


def _set_permissions(path, mode):
    if os.name != 'nt':
        os.chmod(path, mode)


def _load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_certificate(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _generate_ca_material(cert_dir):
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    subject = _build_name("pyMessenger Development Root CA", "pyMessenger Root CA")
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.public_key(ca_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now - timedelta(days=1))
    builder = builder.not_valid_after(now + timedelta(days=3650))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
        critical=False,
    )

    ca_cert = builder.sign(ca_key, hashes.SHA256())

    ca_key_file = cert_dir / CA_KEY_FILENAME
    ca_cert_file = cert_dir / CA_CERT_FILENAME
    _write_private_key(ca_key_file, ca_key)
    _write_certificate(ca_cert_file, ca_cert)
    _set_permissions(ca_key_file, 0o600)
    _set_permissions(ca_cert_file, 0o644)

    return ca_key, ca_cert, ca_key_file, ca_cert_file


def _generate_server_material(cert_dir, ca_key, ca_cert, hostnames):
    server_hosts = _normalize_hosts(hostnames)
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject_common_name = server_hosts[0] if server_hosts else "pyMessenger Server"
    subject = _build_name(subject_common_name, "pyMessenger Server")
    now = datetime.now(timezone.utc)
    alt_names = _build_subject_alternative_names(server_hosts)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(server_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now - timedelta(days=1))
    builder = builder.not_valid_after(now + timedelta(days=365))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName(alt_names),
        critical=False,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
        critical=False,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )

    server_cert = builder.sign(ca_key, hashes.SHA256())

    server_key_file = cert_dir / SERVER_KEY_FILENAME
    server_cert_file = cert_dir / SERVER_CERT_FILENAME
    _write_private_key(server_key_file, server_key)
    _write_certificate(server_cert_file, server_cert)
    _set_permissions(server_key_file, 0o600)
    _set_permissions(server_cert_file, 0o644)

    return server_cert, server_key, server_cert_file, server_key_file


def ensure_certificates(cert_dir, hostnames=None, force=False):
                                                                  
    cert_path = Path(cert_dir)
    cert_path.mkdir(parents=True, exist_ok=True)

    ca_key_file = cert_path / CA_KEY_FILENAME
    ca_cert_file = cert_path / CA_CERT_FILENAME
    server_key_file = cert_path / SERVER_KEY_FILENAME
    server_cert_file = cert_path / SERVER_CERT_FILENAME

    has_ca = ca_key_file.exists() and ca_cert_file.exists()
    has_server = server_key_file.exists() and server_cert_file.exists()

    if has_ca and has_server and not force:
        print("Using existing CA-signed certificate chain")
        return str(ca_cert_file), str(server_cert_file), str(server_key_file)

    if has_ca and not force:
        print("Reusing existing root CA and generating a new server certificate")
        ca_key = _load_private_key(ca_key_file)
        ca_cert = _load_certificate(ca_cert_file)
    else:
        print("Generating private root CA...")
        ca_key, ca_cert, _, _ = _generate_ca_material(cert_path)

    print("Generating CA-signed server certificate...")
    _, _, server_cert_file, server_key_file = _generate_server_material(
        cert_path,
        ca_key,
        ca_cert,
        hostnames,
    )

    print(f"OK: Root CA certificate: {ca_cert_file}")
    print(f"OK: Server certificate: {server_cert_file}")
    print(f"OK: Server private key: {server_key_file}")
    print("OK: Certificate chain valid for 365 days")

    return str(ca_cert_file), str(server_cert_file), str(server_key_file)


def generate_self_signed_cert(cert_dir, hostnames=None, force=False):
                                                           
    return ensure_certificates(cert_dir, hostnames=hostnames, force=force)


def main():
    parser = argparse.ArgumentParser(description="Generate a private CA and CA-signed server certificate for pyMessenger")
    parser.add_argument(
        "--cert-dir",
        type=Path,
        default=Path.home() / '.secure_messenger' / 'certs',
        help="Directory where certificate files are stored",
    )
    parser.add_argument(
        "--host",
        action="append",
        dest="hosts",
        help="Hostname or IP to include in the server certificate SAN. May be repeated.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate the CA and server certificate even if files already exist.",
    )
    args = parser.parse_args()

    try:
        ca_cert_file, server_cert_file, server_key_file = ensure_certificates(
            args.cert_dir,
            hostnames=args.hosts,
            force=args.force,
        )
        print("\nCertificate chain ready for use!")
        print(f"  CA certificate: {ca_cert_file}")
        print(f"  Server certificate: {server_cert_file}")
        print(f"  Server private key: {server_key_file}")
        print("  Distribute ca.crt to each client that should trust this server.")
    except Exception as e:
        print(f"ERROR: Error generating certificates: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
