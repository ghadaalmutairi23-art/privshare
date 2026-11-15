"""Create a self-signed TLS certificate for https://localhost (local testing only).

Run: python scripts/make_cert.py [--force]   ->  certs/cert.pem, certs/key.pem
"""
import argparse
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_DIR = Path(__file__).resolve().parent.parent / "certs"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a self-signed localhost certificate.")
    parser.add_argument("--force", action="store_true", help="overwrite existing files")
    args = parser.parse_args()

    cert_file, key_file = CERT_DIR / "cert.pem", CERT_DIR / "key.pem"
    if cert_file.exists() and not args.force:
        print(f"{cert_file} already exists (use --force to replace it).")
        return 1
    CERT_DIR.mkdir(exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PrivShare (local test)")])
    now = dt.datetime.now(dt.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote {cert_file} and {key_file} (valid 365 days, git-ignored)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
