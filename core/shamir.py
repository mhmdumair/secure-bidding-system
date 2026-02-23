from __future__ import annotations

from typing import List, Tuple
import secrets

# Prime > 2^256 (for 32-byte secrets). 2^521-1 is a Mersenne prime.
PRIME_P = (1 << 521) - 1


def _modinv(a: int, p: int) -> int:
    if a == 0:
        raise ZeroDivisionError("inverse of 0")
    return pow(a, p - 2, p)


def _eval_poly(coeffs: List[int], x: int, p: int) -> int:
    y = 0
    for c in reversed(coeffs):
        y = (y * x + c) % p
    return y


def split_secret(secret_bytes: bytes, t: int, n: int, p: int = PRIME_P) -> List[Tuple[int, int]]:
    if not (2 <= t <= n):
        raise ValueError("Require 2 <= t <= n")
    secret_int = int.from_bytes(secret_bytes, "big")
    if secret_int >= p:
        raise ValueError("Secret too large for field")

    coeffs = [secret_int] + [secrets.randbelow(p) for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):
        y = _eval_poly(coeffs, x, p)
        shares.append((x, y))
    return shares


def reconstruct_secret(shares: List[Tuple[int, int]], p: int = PRIME_P, out_len: int = 32) -> bytes:
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("Duplicate x values")

    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        num = 1
        den = 1
        for j, (x_j, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-x_j % p)) % p
            den = (den * ((x_i - x_j) % p)) % p
        lagrange = (num * _modinv(den, p)) % p
        secret = (secret + (y_i * lagrange)) % p

    return int(secret).to_bytes(out_len, "big")
