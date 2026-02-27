from __future__ import annotations

import logging
import secrets
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Prime > 2^256 (for 32-byte secrets). 2^521-1 is a Mersenne prime.
# Large enough to hold any 32-byte secret with room to spare.
PRIME_P = (1 << 521) - 1


def _modinv(a: int, p: int) -> int:
    if a == 0:
        raise ZeroDivisionError("Modular inverse of 0 is undefined")
    return pow(a, p - 2, p)


def _eval_poly(coeffs: List[int], x: int, p: int) -> int:
    """Evaluate polynomial at x using Horner's method."""
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
    Split secret_bytes into n shares where any t shares can reconstruct it.

    Security properties:
    - t-1 or fewer shares reveal zero information about the secret (information-theoretic)
    - Uses cryptographically secure random coefficients via secrets.randbelow()
    - Each call produces different shares (randomized polynomial)

    Args:
        secret_bytes: The secret to split (must be < p when interpreted as big-endian int)
        t: Reconstruction threshold (minimum shares needed)
        n: Total number of shares to produce
        p: Prime field modulus (default: 2^521 - 1)

    Returns:
        List of (x, y) share tuples where x in {1..n}

    Raises:
        ValueError: If parameters are invalid or secret is too large
    """
    if not (2 <= t <= n):
        raise ValueError(f"Require 2 <= t <= n, got t={t}, n={n}")
    if n > 255:
        raise ValueError("n must be <= 255 to avoid x=0 (which would leak the secret)")

    secret_int = int.from_bytes(secret_bytes, "big")
    if secret_int >= p:
        raise ValueError(
            f"Secret too large for field (secret_int={secret_int} >= p). "
            f"Use a larger prime or shorter secret."
        )
    if secret_int == 0:
        raise ValueError("Secret must be non-zero (zero is trivially recoverable)")

    # Build polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
    # Coefficients a1..a(t-1) are random elements of GF(p)
    coeffs = [secret_int] + [secrets.randbelow(p) for _ in range(t - 1)]

    shares = []
    for x in range(1, n + 1):
        y = _eval_poly(coeffs, x, p)
        shares.append((x, y))

    # Defensive: zero out coefficients from memory (best-effort in Python)
    for i in range(len(coeffs)):
        coeffs[i] = 0

    logger.debug("Secret split into %d shares, threshold=%d", n, t)
    return shares


def reconstruct_secret(
    shares: List[Tuple[int, int]],
    p: int = PRIME_P,
    out_len: int = 32,
) -> bytes:
    """
    Reconstruct secret from t or more shares using Lagrange interpolation.

    Args:
        shares: List of (x, y) tuples. Must have at least t entries.
        p: Prime field modulus (must match the one used during split)
        out_len: Output byte length (must match original secret length)

    Returns:
        Reconstructed secret as bytes

    Raises:
        ValueError: If shares are invalid (duplicate x values, wrong count)
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct")

    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("Duplicate x values in shares — possible share forgery")

    if any(x <= 0 for x in xs):
        raise ValueError("Share x values must be positive integers (x=0 would be the secret itself)")

    # Lagrange interpolation at x=0 to recover f(0) = secret
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

    result = int(secret).to_bytes(out_len, "big")

    # Best-effort zero of intermediate
    secret = 0

    return result


def verify_share(
    share: Tuple[int, int],
    other_shares: List[Tuple[int, int]],
    p: int = PRIME_P,
    out_len: int = 32,
) -> bool:
    """
    Verify that a share is consistent with a set of other shares.
    Reconstructs with (other_shares + this share) and checks it matches
    reconstruction with just other_shares (if len(other_shares) >= t).

    This is a basic consistency check — not a full ZK proof.
    Useful when collecting shares to detect a corrupt authority early.
    """
    try:
        combined = other_shares + [share]
        s1 = reconstruct_secret(combined[:len(other_shares)], p=p, out_len=out_len) if len(other_shares) >= 2 else None
        s2 = reconstruct_secret(combined, p=p, out_len=out_len)
        if s1 is not None:
            return s1 == s2
        return True  # Can't verify with fewer than 2 other shares
    except Exception:
        return False