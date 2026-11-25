"""Minimal ES256 JWT helpers on top of `cryptography`.

Poppy needs custom JOSE headers (`poppy_dlg`, custom `typ` values), so we sign and
verify compact JWS ourselves instead of fighting a library's header allowlist.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def random_id(nbytes: int = 16) -> str:
    """A URL-safe base64 ID, valid for Poppy IDs (spec 8.2)."""
    return b64u(secrets.token_bytes(nbytes))


def sha256_b64u(text: str) -> str:
    return b64u(hashlib.sha256(text.encode()).digest())


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def generate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> dict:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(nums.x.to_bytes(32, "big")),
        "y": b64u(nums.y.to_bytes(32, "big")),
    }


def jwk_to_public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 keys are supported")
    if "d" in jwk:
        raise ValueError("JWK contains private key material")
    x = int.from_bytes(b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint for an EC key."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256_b64u(canonical)


def load_or_create_pem(path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key


# ---------------------------------------------------------------------------
# JWS
# ---------------------------------------------------------------------------
def sign(header: dict, claims: dict, key: ec.EllipticCurvePrivateKey) -> str:
    header = {"alg": "ES256", **header}
    signing_input = (
        b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64u(json.dumps(claims, separators=(",", ":")).encode())
    )
    der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def unverified_parts(token: str) -> tuple[dict, dict]:
    """Header and claims, WITHOUT verifying the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    return json.loads(b64u_decode(parts[0])), json.loads(b64u_decode(parts[1]))


def verify_jwk(token: str, jwk: dict) -> tuple[dict, dict]:
    """Verify with a JWK: ES256 for EC keys, PS384 for RSA keys.

    Companies MUST accept PS384 on delegations and client assertions (spec 4.1, 5.2),
    so a Personal Agent can have them signed blindly.
    """
    header, _ = unverified_parts(token)
    if jwk.get("kty") == "RSA":
        if header.get("alg") != "PS384":
            raise ValueError(f"unsupported alg {header.get('alg')!r} for an RSA key")
        if "d" in jwk:
            raise ValueError("JWK contains private key material")
        pub = rsa.RSAPublicNumbers(
            int.from_bytes(b64u_decode(jwk["e"]), "big"), int.from_bytes(b64u_decode(jwk["n"]), "big")
        ).public_key()
        head_b64, body_b64, sig_b64 = token.split(".")
        pub.verify(
            b64u_decode(sig_b64),
            f"{head_b64}.{body_b64}".encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
            hashes.SHA384(),
        )
        return unverified_parts(token)
    return verify(token, jwk_to_public_key(jwk))


def verify(token: str, public_key: ec.EllipticCurvePublicKey) -> tuple[dict, dict]:
    """Verify an ES256 compact JWS and return (header, claims)."""
    header, claims = unverified_parts(token)
    if header.get("alg") != "ES256":
        raise ValueError(f"unsupported alg {header.get('alg')!r}")
    head_b64, body_b64, sig_b64 = token.split(".")
    raw = b64u_decode(sig_b64)
    if len(raw) != 64:
        raise ValueError("bad ES256 signature length")
    der = encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    public_key.verify(der, f"{head_b64}.{body_b64}".encode(), ec.ECDSA(hashes.SHA256()))
    return header, claims
