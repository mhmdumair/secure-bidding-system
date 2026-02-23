from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# ---------------- Canonical encoding / hashing ----------------

def canon_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from password using scrypt.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key_pem(sk: ec.EllipticCurvePrivateKey, password: str, aad: bytes) -> Dict[str, str]:
    """
    Serialize private key to PEM and encrypt it using password-derived key.
    Returns JSON-serializable dict.
    """
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    salt = os.urandom(16)
    key = _derive_key_from_password(password, salt)
    blob = aead_encrypt(key, pem, aad=aad)
    return {"salt": b64e(salt), "nonce": blob["nonce"], "ct": blob["ct"]}


def decrypt_private_key_pem(enc_obj: Dict[str, str], password: str, aad: bytes) -> ec.EllipticCurvePrivateKey:
    salt = b64d(enc_obj["salt"])
    key = _derive_key_from_password(password, salt)
    pem = aead_decrypt(key, {"nonce": enc_obj["nonce"], "ct": enc_obj["ct"]}, aad=aad)
    return serialization.load_pem_private_key(pem, password=None)


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


# ---------------- ECIES-like sealed box (ECDH + HKDF + AEAD) ----------------

def _derive_kek(shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


def seal_to_public(receiver_pub: ec.EllipticCurvePublicKey, plaintext: bytes, aad: bytes) -> Dict[str, Any]:
    """
    Encrypt plaintext to receiver_pub using ephemeral ECDH + HKDF + ChaCha20Poly1305.
    Returns JSON-serializable dict containing ephemeral pubkey pem + ciphertext blob.
    """
    eph_sk = ec.generate_private_key(ec.SECP256R1())
    eph_pk = eph_sk.public_key()
    shared = eph_sk.exchange(ec.ECDH(), receiver_pub)

    salt = hashlib.sha256(b"salt|" + aad).digest()
    kek = _derive_kek(shared, salt=salt, info=b"sealed-box-v1")

    blob = aead_encrypt(kek, plaintext, aad=aad)
    return {"eph_pub_pem": public_key_pem_str(eph_pk), "blob": blob}


def open_with_private(receiver_sk: ec.EllipticCurvePrivateKey, sealed: Dict[str, Any], aad: bytes) -> bytes:
    eph_pub = load_public_key_from_pem_str(sealed["eph_pub_pem"])
    shared = receiver_sk.exchange(ec.ECDH(), eph_pub)

    salt = hashlib.sha256(b"salt|" + aad).digest()
    kek = _derive_kek(shared, salt=salt, info=b"sealed-box-v1")

    return aead_decrypt(kek, sealed["blob"], aad=aad)
