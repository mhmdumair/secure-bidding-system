from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import logging
import os
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

logger = logging.getLogger(__name__)

# Scrypt cost parameters
# Authority keys: N=2^20  (~1 s on modern hardware — high value, rarely decrypted)
# Bidder keys:    N=2^17  (~0.1 s — balance of security and usability)
SCRYPT_N_AUTHORITY = 2 ** 20
SCRYPT_N_BIDDER    = 2 ** 17
SCRYPT_R           = 8
SCRYPT_P           = 1
SCRYPT_LEN         = 32


# ── Secure memory zeroing ─────────────────────────────────────────

def _zero_bytearray(b: bytearray) -> None:
    for i in range(len(b)):
        b[i] = 0


def _secure_zero_bytes(data: bytes) -> None:
    """Best-effort CPython-specific zeroing of an immutable bytes object."""
    try:
        size = len(data)
        if size == 0:
            return
        buf = (ctypes.c_char * size).from_address(id(data) + 32)
        ctypes.memset(buf, 0, size)
    except Exception:
        pass


# ── Canonical encoding / hashing ─────────────────────────────────

def canon_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64d(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


# ── AEAD (ChaCha20-Poly1305) ──────────────────────────────────────

def aead_encrypt(key32: bytes, plaintext: bytes, aad: bytes) -> Dict[str, str]:
    if len(key32) != 32:
        raise ValueError("AEAD key must be exactly 32 bytes.")
    nonce = os.urandom(12)
    ct    = ChaCha20Poly1305(key32).encrypt(nonce, plaintext, aad)
    return {"nonce": b64e(nonce), "ct": b64e(ct)}


def aead_decrypt(key32: bytes, blob: Dict[str, str], aad: bytes) -> bytes:
    if len(key32) != 32:
        raise ValueError("AEAD key must be exactly 32 bytes.")
    return ChaCha20Poly1305(key32).decrypt(b64d(blob["nonce"]), b64d(blob["ct"]), aad)


# ── Password-protected key storage ───────────────────────────────

def _derive_key(password: str, salt: bytes, n: int) -> bytearray:
    raw = Scrypt(salt=salt, length=SCRYPT_LEN, n=n, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )
    return bytearray(raw)


def encrypt_private_key_pem(
    sk: ec.EllipticCurvePrivateKey,
    password: str,
    aad: bytes,
    is_authority: bool = False,
) -> Dict[str, str]:
    """
    Serialize private key to PEM then encrypt with password-derived key.
    Authority keys use higher Scrypt cost (N=2^20).
    The scrypt parameters are stored alongside the ciphertext so
    decryption always uses the correct cost regardless of future changes.
    """
    pem  = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    salt = os.urandom(32)
    n    = SCRYPT_N_AUTHORITY if is_authority else SCRYPT_N_BIDDER
    key  = _derive_key(password, salt, n)
    blob = aead_encrypt(bytes(key), pem, aad=aad)
    _zero_bytearray(key)
    return {
        "salt":     b64e(salt),
        "nonce":    blob["nonce"],
        "ct":       blob["ct"],
        "scrypt_n": n,
        "scrypt_r": SCRYPT_R,
        "scrypt_p": SCRYPT_P,
    }


def decrypt_private_key_pem(
    enc_obj: Dict[str, str],
    password: str,
    aad: bytes,
) -> ec.EllipticCurvePrivateKey:
    """
    Decrypt private key PEM.
    Raises ValueError with a plain message on wrong password or corruption.
    """
    salt = b64d(enc_obj["salt"])
    n    = int(enc_obj.get("scrypt_n", SCRYPT_N_BIDDER))
    r    = int(enc_obj.get("scrypt_r", SCRYPT_R))
    p    = int(enc_obj.get("scrypt_p", SCRYPT_P))

    kdf = Scrypt(salt=salt, length=SCRYPT_LEN, n=n, r=r, p=p)
    key = bytearray(kdf.derive(password.encode("utf-8")))

    try:
        pem = aead_decrypt(bytes(key), {"nonce": enc_obj["nonce"], "ct": enc_obj["ct"]}, aad)
    except Exception:
        _zero_bytearray(key)
        raise ValueError("Decryption failed — wrong password or corrupted key file.")
    finally:
        _zero_bytearray(key)

    return serialization.load_pem_private_key(pem, password=None)


# ── ECDSA keys / signatures ───────────────────────────────────────

def gen_ecdsa_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    sk = ec.generate_private_key(ec.SECP256R1())
    return sk, sk.public_key()


def public_key_pem_str(pk: ec.EllipticCurvePublicKey) -> str:
    return pk.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_public_key_from_pem_str(pem_str: str) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def public_key_fingerprint(pk: ec.EllipticCurvePublicKey) -> str:
    """Short human-verifiable SHA-256 fingerprint (first 8 bytes as XX:XX:... pairs)."""
    der    = pk.public_bytes(serialization.Encoding.DER,
                             serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = sha256_hex(der)
    return ":".join(digest[i:i+2] for i in range(0, 16, 2))


def sign(sk: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    return b64e(sk.sign(message, ec.ECDSA(hashes.SHA256())))


def verify(pk: ec.EllipticCurvePublicKey, message: bytes, sig_b64: str) -> bool:
    try:
        pk.verify(b64d(sig_b64), message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ── Meta integrity ────────────────────────────────────────────────

def hash_meta(meta: dict) -> str:
    """
    Canonical SHA-256 of the auction meta dict, excluding dynamic fields
    ('meta_hash', 'meta_sigs') so the hash is stable and re-computable.
    """
    clean = {k: v for k, v in meta.items() if k not in ("meta_hash", "meta_sigs")}
    return sha256_hex(canon_bytes(clean))


# ── ECIES sealed box (ECDH + HKDF + AEAD) ────────────────────────

def _derive_kek(shared: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared)


def seal_to_public(
    receiver_pub: ec.EllipticCurvePublicKey,
    plaintext: bytes,
    aad: bytes,
) -> Dict[str, Any]:
    """Encrypt plaintext to receiver_pub using ephemeral ECDH + HKDF + ChaCha20Poly1305."""
    eph_sk  = ec.generate_private_key(ec.SECP256R1())
    eph_pk  = eph_sk.public_key()
    shared  = bytearray(eph_sk.exchange(ec.ECDH(), receiver_pub))
    salt    = sha256_bytes(b"salt|" + aad)
    kek     = bytearray(_derive_kek(bytes(shared), salt=salt, info=b"sealed-box-v1"))
    _zero_bytearray(shared)
    blob    = aead_encrypt(bytes(kek), plaintext, aad=aad)
    _zero_bytearray(kek)
    return {"eph_pub_pem": public_key_pem_str(eph_pk), "blob": blob}


def open_with_private(
    receiver_sk: ec.EllipticCurvePrivateKey,
    sealed: Dict[str, Any],
    aad: bytes,
) -> bytes:
    eph_pub = load_public_key_from_pem_str(sealed["eph_pub_pem"])
    shared  = bytearray(receiver_sk.exchange(ec.ECDH(), eph_pub))
    salt    = sha256_bytes(b"salt|" + aad)
    kek     = bytearray(_derive_kek(bytes(shared), salt=salt, info=b"sealed-box-v1"))
    _zero_bytearray(shared)
    try:
        result = aead_decrypt(bytes(kek), sealed["blob"], aad=aad)
    finally:
        _zero_bytearray(kek)
    return result