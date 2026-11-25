"""Create a local CA and a certificate for skyline.localhost and wren.localhost, so the demo runs on HTTPS.

Poppy requires HTTPS for every URL it exchanges (spec 3). Trust the CA once with
`just trust` so your browser accepts the pages.
"""

import datetime as dt
import ipaddress
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from poppy.common import CA_FILE, CERT_DIR

LEAF_CERT = CERT_DIR / "localhost.pem"
LEAF_KEY = CERT_DIR / "localhost-key.pem"


def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def main() -> None:
    if CA_FILE.exists() and LEAF_CERT.exists() and LEAF_KEY.exists():
        print(f"certs already in {CERT_DIR}")
        return
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.UTC)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Poppy Voice Demo local CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=397))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in ("localhost", "skyline.localhost", "wren.localhost")]
                + [x509.IPAddress(ipaddress.ip_address(a)) for a in ("127.0.0.1", "::1")]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    CA_FILE.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    LEAF_CERT.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    LEAF_KEY.write_bytes(_pem_key(leaf_key))
    LEAF_KEY.chmod(0o600)
    print(f"wrote {CA_FILE}, {LEAF_CERT}, {LEAF_KEY}")


if __name__ == "__main__":
    main()
