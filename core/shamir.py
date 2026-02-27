from __future__ import annotations

import logging
import secrets
from typing import List, Tuple

logger = logging.getLogger(__name__)

# 2^521 − 1 is a Mersenne prime, large enough to hold any 32-byte secret.
PRIME_P = (1 << 521) - 1


def _modinv(a: int, p: int) -> int:
    if a == 0:
        raise ZeroDivisionError("Modular inverse of 0 is undefined.")
    return pow(a, p - 2, p)


def _eval_poly(coeffs: List[int], x: int, p: int) -> int:
    """Evaluate polynomial using Horner's method."""
    y = 0
    for c in reversed(coeffs):
        y = (y * x + c) % p
    return y


def split_secret(
    secret_bytes: bytes,
    t: int,
    n: int,
    p: int = PRIME_P,
) -> List[Tuple[int, int]]:
    """
    Split secret_bytes into n shares where any t shares reconstruct it.

    Security properties
    ───────────────────
    • Information-theoretic: t-1 shares reveal nothing about the secret.
    • Randomised: each call produces different shares.
    • Uses secrets.randbelow() (CSPRNG) for polynomial coefficients.

    Args
        secret_bytes : secret to protect (must be < p as big-endian int)
        t            : reconstruction threshold (2 ≤ t ≤ n)
        n            : total shares to produce (≤ 255)
        p            : prime field modulus

    Returns list of (x, y) tuples, x in {1 … n}.
    """
    if not (2 <= t <= n):
        raise ValueError(f"Require 2 ≤ t ≤ n, got t={t}, n={n}.")
    if n > 255:
        raise ValueError("n must be ≤ 255.")

    secret_int = int.from_bytes(secret_bytes, "big")
    if secret_int >= p:
        raise ValueError("Secret is too large for the chosen prime field.")
    if secret_int == 0:
        raise ValueError("Secret must be non-zero.")

    # f(x) = secret + a₁x + a₂x² + … + a_{t-1} x^{t-1}
    coeffs = [secret_int] + [secrets.randbelow(p) for _ in range(t - 1)]
    shares = [(x, _eval_poly(coeffs, x, p)) for x in range(1, n + 1)]

    # Best-effort memory cleanup
    for i in range(len(coeffs)):
        coeffs[i] = 0

    logger.debug("Secret split into %d shares (threshold=%d).", n, t)
    return shares


def reconstruct_secret(
    shares: List[Tuple[int, int]],
    p: int = PRIME_P,
    out_len: int = 32,
) -> bytes:
    """
    Reconstruct secret from ≥ t shares via Lagrange interpolation at x=0.

    Args
        shares  : list of (x, y) tuples
        p       : prime field modulus (must match split_secret)
        out_len : output byte length (must match original secret length)
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct.")

    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("Duplicate x-values detected — possible share forgery.")
    if any(x <= 0 for x in xs):
        raise ValueError("Share x-values must be positive integers.")

    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        num, den = 1, 1
        for j, (x_j, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-x_j % p)) % p
            den = (den * ((x_i - x_j) % p)) % p
        secret = (secret + y_i * (num * _modinv(den, p)) % p) % p

    result = int(secret).to_bytes(out_len, "big")
    secret = 0          # best-effort clear
    return result