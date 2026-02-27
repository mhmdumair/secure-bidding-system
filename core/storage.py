from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Auction state machine
AUCTION_STATE_OPEN     = "OPEN"
AUCTION_STATE_CLOSED   = "CLOSED"    # Past deadline, not yet revealed
AUCTION_STATE_REVEALED = "REVEALED"  # Bids decrypted and winner declared


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def atomic_write_text(path: Path, text: str) -> None:
    """Write text to path atomically using a temp file + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    atomic_write_text(path, _canon_json(obj))


@dataclass(frozen=True)
class StorePaths:
    root: Path

    @property
    def auctions_dir(self) -> Path:
        return self.root / "auctions"

    @property
    def users_dir(self) -> Path:
        return self.root / "users"

    # ---------------- Auctions ----------------
    def auction_dir(self, auction_id: str) -> Path:
        return self.auctions_dir / auction_id

    def auction_meta(self, auction_id: str) -> Path:
        return self.auction_dir(auction_id) / "meta.json"

    def auction_ledger(self, auction_id: str) -> Path:
        return self.auction_dir(auction_id) / "ledger.log"

    def bids_dir(self, auction_id: str) -> Path:
        return self.auction_dir(auction_id) / "bids"

    def bid_file(self, auction_id: str, bid_id: str) -> Path:
        return self.bids_dir(auction_id) / f"{bid_id}.json"

    def auction_authorities_dir(self, auction_id: str) -> Path:
        return self.auction_dir(auction_id) / "authorities"

    def auction_authority_dir(self, auction_id: str, authority_id: str) -> Path:
        return self.auction_authorities_dir(auction_id) / authority_id

    def auction_authority_pub(self, auction_id: str, authority_id: str) -> Path:
        return self.auction_authority_dir(auction_id, authority_id) / "pub.pem"

    def auction_authority_priv_enc(self, auction_id: str, authority_id: str) -> Path:
        return self.auction_authority_dir(auction_id, authority_id) / "priv.enc.json"

    def failed_attempts_file(self, auction_id: str, authority_id: str) -> Path:
        return self.auction_authority_dir(auction_id, authority_id) / "failed_attempts.json"

    # ---------------- Bidder registry ----------------
    def bidders_dir(self) -> Path:
        return self.users_dir / "bidders"

    def bidder_dir(self, bidder_id: str) -> Path:
        return self.bidders_dir() / bidder_id

    def bidder_profile(self, bidder_id: str) -> Path:
        return self.bidder_dir(bidder_id) / "profile.json"

    def bidder_pub(self, bidder_id: str) -> Path:
        return self.bidder_dir(bidder_id) / "pub.pem"

    def bidder_priv_enc(self, bidder_id: str) -> Path:
        return self.bidder_dir(bidder_id) / "priv.enc.json"

    def bidder_failed_attempts(self, bidder_id: str) -> Path:
        return self.bidder_dir(bidder_id) / "failed_attempts.json"


# ---------------- Listing helpers ----------------

def list_auction_ids(paths: StorePaths) -> List[str]:
    d = paths.auctions_dir
    if not d.exists():
        return []
    return sorted([p.name for p in d.iterdir() if p.is_dir()])


def list_bid_ids(paths: StorePaths, auction_id: str) -> List[str]:
    d = paths.bids_dir(auction_id)
    if not d.exists():
        return []
    return sorted([p.stem for p in d.glob("*.json")])


def list_registered_bidders(paths: StorePaths) -> List[str]:
    d = paths.bidders_dir()
    if not d.exists():
        return []
    return sorted([p.name for p in d.iterdir() if p.is_dir()])


# ---------------- Auction meta ----------------

def load_auction_meta(paths: StorePaths, auction_id: str) -> Dict[str, Any]:
    p = paths.auction_meta(auction_id)
    if not p.exists():
        raise FileNotFoundError(f"Auction not found: {auction_id}")
    return read_json(p)


def save_auction_meta(paths: StorePaths, auction_id: str, meta: Dict[str, Any]) -> None:
    write_json(paths.auction_meta(auction_id), meta)


def verify_meta_integrity(
    paths: StorePaths,
    auction_id: str,
    committed_hash: Optional[str],
) -> None:
    """
    Verify that meta.json has not been tampered with since auction creation.
    Compares current hash against the hash committed in the ledger.
    Raises RuntimeError if mismatch detected.
    """
    if committed_hash is None:
        logger.warning("No committed meta hash found in ledger — skipping meta integrity check.")
        return

    from core.crypto import hash_meta
    meta = load_auction_meta(paths, auction_id)
    current_hash = hash_meta(meta)

    if current_hash != committed_hash:
        raise RuntimeError(
            f"SECURITY ALERT: meta.json has been tampered with!\n"
            f"  Committed hash (ledger): {committed_hash}\n"
            f"  Current hash (file):     {current_hash}\n"
            f"  Auction parameters (deadline, t, n, authority keys) may have been changed."
        )

    logger.debug("Meta integrity OK for auction %s", auction_id)


# ---------------- Auction state ----------------

def get_auction_state(paths: StorePaths, auction_id: str) -> str:
    """
    Derive auction state from ledger events.
    Returns one of: OPEN, CLOSED, REVEALED
    """
    from core.ledger import Ledger
    from core.timeutil import now_utc, parse_deadline_any

    led = Ledger(paths.auction_ledger(auction_id))

    if led.is_revealed():
        return AUCTION_STATE_REVEALED

    try:
        meta = load_auction_meta(paths, auction_id)
        deadline_utc = parse_deadline_any(meta["deadline_utc"])
        if now_utc(skip_ntp=True) >= deadline_utc:
            return AUCTION_STATE_CLOSED
    except Exception:
        pass

    return AUCTION_STATE_OPEN


# ---------------- Failed attempt tracking ----------------

MAX_FAILED_ATTEMPTS = 5


def _load_failed_attempts(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"count": 0, "locked": False}
    try:
        return read_json(path)
    except Exception:
        return {"count": 0, "locked": False}


def _save_failed_attempts(path: Path, data: Dict[str, Any]) -> None:
    write_json(path, data)


def check_not_locked(paths: StorePaths, auction_id: Optional[str], entity_id: str, is_authority: bool) -> None:
    """Raise RuntimeError if entity is locked due to too many failed attempts."""
    if is_authority and auction_id:
        path = paths.failed_attempts_file(auction_id, entity_id)
    else:
        path = paths.bidder_failed_attempts(entity_id)

    data = _load_failed_attempts(path)
    if data.get("locked"):
        raise RuntimeError(
            f"Account '{entity_id}' is locked after {MAX_FAILED_ATTEMPTS} failed attempts. "
            f"Contact the system administrator to unlock."
        )


def record_failed_attempt(paths: StorePaths, auction_id: Optional[str], entity_id: str, is_authority: bool) -> int:
    """
    Record a failed authentication attempt.
    Returns remaining attempts before lockout.
    Locks account if MAX_FAILED_ATTEMPTS reached.
    """
    if is_authority and auction_id:
        path = paths.failed_attempts_file(auction_id, entity_id)
    else:
        path = paths.bidder_failed_attempts(entity_id)

    data = _load_failed_attempts(path)
    data["count"] = data.get("count", 0) + 1

    remaining = MAX_FAILED_ATTEMPTS - data["count"]
    if remaining <= 0:
        data["locked"] = True
        logger.warning("SECURITY: Account '%s' locked after %d failed attempts", entity_id, MAX_FAILED_ATTEMPTS)

    _save_failed_attempts(path, data)
    return max(0, remaining)


def reset_failed_attempts(paths: StorePaths, auction_id: Optional[str], entity_id: str, is_authority: bool) -> None:
    """Reset failed attempt counter after successful authentication."""
    if is_authority and auction_id:
        path = paths.failed_attempts_file(auction_id, entity_id)
    else:
        path = paths.bidder_failed_attempts(entity_id)

    if path.exists():
        _save_failed_attempts(path, {"count": 0, "locked": False})


# ---------------- Bids ----------------

def bid_exists(paths: StorePaths, auction_id: str, bid_id: str) -> bool:
    return paths.bid_file(auction_id, bid_id).exists()


def save_bid(paths: StorePaths, auction_id: str, bid_id: str, bid_obj: Dict[str, Any]) -> None:
    if bid_exists(paths, auction_id, bid_id):
        raise RuntimeError(f"Bid {bid_id} already exists — duplicate submission rejected.")
    write_json(paths.bid_file(auction_id, bid_id), bid_obj)


def load_bid(paths: StorePaths, auction_id: str, bid_id: str) -> Dict[str, Any]:
    return read_json(paths.bid_file(auction_id, bid_id))


# ---------------- Bidder registry ----------------

def bidder_exists(paths: StorePaths, bidder_id: str) -> bool:
    return paths.bidder_profile(bidder_id).exists() and paths.bidder_priv_enc(bidder_id).exists()


def load_bidder_profile(paths: StorePaths, bidder_id: str) -> Dict[str, Any]:
    p = paths.bidder_profile(bidder_id)
    if not p.exists():
        raise FileNotFoundError(f"Bidder not registered: {bidder_id}")
    return read_json(p)


def save_bidder_profile(paths: StorePaths, bidder_id: str, profile: Dict[str, Any]) -> None:
    write_json(paths.bidder_profile(bidder_id), profile)


def save_bidder_priv_enc(paths: StorePaths, bidder_id: str, enc_obj: Dict[str, Any]) -> None:
    write_json(paths.bidder_priv_enc(bidder_id), enc_obj)


def load_bidder_priv_enc(paths: StorePaths, bidder_id: str) -> Dict[str, Any]:
    return read_json(paths.bidder_priv_enc(bidder_id))