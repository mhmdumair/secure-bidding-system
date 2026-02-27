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

# Scrypt parameters
# Authority keys use higher cost (N=2^20) since they're unlocked rarely and are high-value
# Bidder keys use moderate cost (N=2^17) for reasonable UX
SCRYPT_N_AUTHORITY = 2 ** 20   # ~1 second on modern hardware
SCRYPT_N_BIDDER    = 2 ** 17   # ~0.1 second on modern hardware
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32
MAX_FAILED_ATTEMPTS = 5


# ---------------- Secure memory zeroing ----------------

def _zero_bytes(b: bytearray) -> None:
    """Overwrite a bytearray with zeros in place."""
    for i in range(len(b)):
        b[i] = 0


def _secure_zero(data: bytes) -> None:
    """
    Best-effort zero of a bytes object in CPython.
    bytes are immutable so we use ctypes to reach into the buffer.
    Not guaranteed on all Python implementations.
    """
    try:
        size = len(data)
        if size == 0:
            return
        buf = (ctypes.c_char * size).from_address(id(data) + 32)
        ctypes.memset(buf, 0, size)
    except Exception:
        pass  # Non-fatal; best-effort only


# ---------------- Canonical encoding / hashing ----------------

def canon_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


# ---------------- AEAD (ChaCha20-Poly1305) ----------------

def aead_encrypt(key32: bytes, plaintext: bytes, aad: bytes) -> Dict[str, str]:
    if len(key32) != 32:
        raise ValueError("AEAD key must be 32 bytes")
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key32)
    ct = aead.encrypt(nonce, plaintext, aad)
    return {"nonce": b64e(nonce), "ct": b64e(ct)}


def aead_decrypt(key32: bytes, blob: Dict[str, str], aad: bytes) -> bytes:
    if len(key32) != 32:
        raise ValueError("AEAD key must be 32 bytes")
    nonce = b64d(blob["nonce"])
    ct = b64d(blob["ct"])
    aead = ChaCha20Poly1305(key32)
    return aead.decrypt(nonce, ct, aad)


# ---------------- Password-protected key storage ----------------

def _derive_key_from_password(password: str, salt: bytes, n: int = SCRYPT_N_BIDDER) -> bytes:
    """
    Derive a 32-byte key from password using Scrypt.
    'n' controls cost: use SCRYPT_N_AUTHORITY for authority keys.
    """
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_LEN,
        n=n,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def public_key_fingerprint(pk: ec.EllipticCurvePublicKey) -> str:
    """
    SHA-256 fingerprint of the public key DER encoding.
    Use for display and verification — short human-verifiable identifier.
    """
    der = pk.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = sha256_hex(der)
    # Format as XX:XX:XX:... for readability (first 8 bytes = 16 hex chars = 8 pairs)
    return ":".join(digest[i:i+2] for i in range(0, 16, 2))


def encrypt_private_key_pem(
    sk: ec.EllipticCurvePrivateKey,
    password: str,
    aad: bytes,
    is_authority: bool = False,
) -> Dict[str, str]:
    """
    Serialize private key to PEM and encrypt with password-derived key.
    Authority keys use higher Scrypt cost.
    Returns JSON-serializable dict with scrypt_n recorded for future verification.
    """
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    salt = os.urandom(32)  # Increased from 16 to 32 bytes
    n = SCRYPT_N_AUTHORITY if is_authority else SCRYPT_N_BIDDER
    key = bytearray(_derive_key_from_password(password, salt, n=n))

    blob = aead_encrypt(bytes(key), pem, aad=aad)
    _zero_bytes(key)

    return {
        "salt": b64e(salt),
        "nonce": blob["nonce"],
        "ct": blob["ct"],
        "scrypt_n": n,          # Store so we know cost at decryption time
        "scrypt_r": SCRYPT_R,
        "scrypt_p": SCRYPT_P,
    }


def decrypt_private_key_pem(
    enc_obj: Dict[str, str],
    password: str,
    aad: bytes,
) -> ec.EllipticCurvePrivateKey:
    """
    Decrypt private key PEM. Reads scrypt_n from stored object so cost is preserved.
    Raises ValueError on wrong password or tampered ciphertext.
    """
    salt = b64d(enc_obj["salt"])
    n = int(enc_obj.get("scrypt_n", SCRYPT_N_BIDDER))
    r = int(enc_obj.get("scrypt_r", SCRYPT_R))
    p = int(enc_obj.get("scrypt_p", SCRYPT_P))

    kdf = Scrypt(salt=salt, length=SCRYPT_LEN, n=n, r=r, p=p)
    key = bytearray(kdf.derive(password.encode("utf-8")))

    try:
        pem = aead_decrypt(bytes(key), {"nonce": enc_obj["nonce"], "ct": enc_obj["ct"]}, aad=aad)
    except Exception:
        _zero_bytes(key)
        raise ValueError("Decryption failed: wrong password or corrupted key file.")
    finally:
        _zero_bytes(key)

    sk = serialization.load_pem_private_key(pem, password=None)
    return sk


# ---------------- ECDSA keys / signatures ----------------

def gen_ecdsa_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    sk = ec.generate_private_key(ec.SECP256R1())
    return sk, sk.public_key()


def public_key_pem_str(pk: ec.EllipticCurvePublicKey) -> str:
    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def load_public_key_from_pem_str(pem_str: str) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def sign(sk: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    sig = sk.sign(message, ec.ECDSA(hashes.SHA256()))
    return b64e(sig)


def verify(pk: ec.EllipticCurvePublicKey, message: bytes, sig_b64: str) -> bool:
    try:
        pk.verify(b64d(sig_b64), message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def sign_meta(sk: ec.EllipticCurvePrivateKey, meta_hash: str) -> str:
    """Sign a meta.json hash. Used by authorities to attest auction parameters."""
    return sign(sk, meta_hash.encode("utf-8"))


def verify_meta_sig(pk: ec.EllipticCurvePublicKey, meta_hash: str, sig_b64: str) -> bool:
    return verify(pk, meta_hash.encode("utf-8"), sig_b64)


# ---------------- Meta integrity ----------------

def hash_meta(meta: dict) -> str:
    """
    Canonical SHA-256 hash of auction meta dict.
    Used to detect tampering of meta.json relative to ledger commitment.
    Excludes the 'meta_hash' field itself if present (for re-verification).
    """
    meta_copy = {k: v for k, v in meta.items() if k not in ("meta_hash", "meta_sigs")}
    return sha256_hex(canon_bytes(meta_copy))


# ---------------- ECIES-like sealed box (ECDH + HKDF + AEAD) ----------------

def _derive_kek(shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


def seal_to_public(
    receiver_pub: ec.EllipticCurvePublicKey,
    plaintext: bytes,
    aad: bytes,
) -> Dict[str, Any]:
    """
    Encrypt plaintext to receiver_pub using ephemeral ECDH + HKDF + ChaCha20Poly1305.
    """
    eph_sk = ec.generate_private_key(ec.SECP256R1())
    eph_pk = eph_sk.public_key()
    shared = bytearray(eph_sk.exchange(ec.ECDH(), receiver_pub))

    salt = sha256_bytes(b"salt|" + aad)
    kek = bytearray(_derive_kek(bytes(shared), salt=salt, info=b"sealed-box-v1"))
    _zero_bytes(shared)

    blob = aead_encrypt(bytes(kek), plaintext, aad=aad)
    _zero_bytes(kek)

    return {"eph_pub_pem": public_key_pem_str(eph_pk), "blob": blob}


def open_with_private(
    receiver_sk: ec.EllipticCurvePrivateKey,
    sealed: Dict[str, Any],
    aad: bytes,
) -> bytes:
    eph_pub = load_public_key_from_pem_str(sealed["eph_pub_pem"])
    shared = bytearray(receiver_sk.exchange(ec.ECDH(), eph_pub))

    salt = sha256_bytes(b"salt|" + aad)
    kek = bytearray(_derive_kek(bytes(shared), salt=salt, info=b"sealed-box-v1"))
    _zero_bytes(shared)

    try:
        result = aead_decrypt(bytes(kek), sealed["blob"], aad=aad)
    finally:
        _zero_bytes(kek)

    return result