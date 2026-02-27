from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Auction state constants ───────────────────────────────────────
AUCTION_STATE_OPEN     = "OPEN"
AUCTION_STATE_CLOSED   = "CLOSED"
AUCTION_STATE_REVEALED = "REVEALED"

MAX_FAILED_ATTEMPTS = 5


# ── Low-level file helpers ────────────────────────────────────────

def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pretty_json(obj: Any) -> str:
    """Human-readable JSON with 2-space indent — used for reveal records."""
    return json.dumps(obj, indent=2, ensure_ascii=False)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    atomic_write_text(path, _canon_json(obj))


def write_pretty_json(path: Path, obj: Any) -> None:
    """Write human-readable JSON (for reveal records / receipts)."""
    atomic_write_text(path, _pretty_json(obj))


# ── Path registry ─────────────────────────────────────────────────

@dataclass(frozen=True)
class StorePaths:
    root: Path

    @property
    def auctions_dir(self) -> Path:
        return self.root / "auctions"

    @property
    def users_dir(self) -> Path:
        return self.root / "users"

    # Auction paths
    def auction_dir(self, aid: str) -> Path:
        return self.auctions_dir / aid

    def auction_meta(self, aid: str) -> Path:
        return self.auction_dir(aid) / "meta.json"

    def auction_ledger(self, aid: str) -> Path:
        return self.auction_dir(aid) / "ledger.log"

    def bids_dir(self, aid: str) -> Path:
        return self.auction_dir(aid) / "bids"

    def bid_file(self, aid: str, bid_id: str) -> Path:
        return self.bids_dir(aid) / f"{bid_id}.json"

    def auction_authorities_dir(self, aid: str) -> Path:
        return self.auction_dir(aid) / "authorities"

    def auction_authority_dir(self, aid: str, auth_id: str) -> Path:
        return self.auction_authorities_dir(aid) / auth_id

    def auction_authority_pub(self, aid: str, auth_id: str) -> Path:
        return self.auction_authority_dir(aid, auth_id) / "pub.pem"

    def auction_authority_priv_enc(self, aid: str, auth_id: str) -> Path:
        return self.auction_authority_dir(aid, auth_id) / "priv.enc.json"

    def failed_attempts_file(self, aid: str, auth_id: str) -> Path:
        return self.auction_authority_dir(aid, auth_id) / "failed_attempts.json"

    # Bidder paths
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


# ── Listing helpers ───────────────────────────────────────────────

def list_auction_ids(paths: StorePaths) -> List[str]:
    d = paths.auctions_dir
    return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.exists() else []


def list_bid_ids(paths: StorePaths, aid: str) -> List[str]:
    d = paths.bids_dir(aid)
    return sorted(p.stem for p in d.glob("*.json")) if d.exists() else []


def list_registered_bidders(paths: StorePaths) -> List[str]:
    d = paths.bidders_dir()
    return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.exists() else []


# ── Auction meta ──────────────────────────────────────────────────

def load_auction_meta(paths: StorePaths, aid: str) -> Dict[str, Any]:
    p = paths.auction_meta(aid)
    if not p.exists():
        raise FileNotFoundError(
            f"Auction '{aid}' not found.\n"
            "  → Create an auction first using option 2 from the main menu."
        )
    return read_json(p)


def save_auction_meta(paths: StorePaths, aid: str, meta: Dict[str, Any]) -> None:
    write_json(paths.auction_meta(aid), meta)


def verify_meta_integrity(
    paths: StorePaths,
    aid: str,
    committed_hash: Optional[str],
) -> None:
    """
    Compare the current meta.json hash against the hash committed in the ledger.
    Raises RuntimeError with a clear message if they differ.
    """
    if committed_hash is None:
        logger.warning("No committed meta hash in ledger — skipping meta integrity check.")
        return

    from core.crypto import hash_meta
    meta         = load_auction_meta(paths, aid)
    current_hash = hash_meta(meta)

    if current_hash != committed_hash:
        raise RuntimeError(
            "[SECURITY ALERT] Auction configuration (meta.json) has been altered!\n\n"
            f"  Hash recorded in ledger : {committed_hash}\n"
            f"  Hash of current file    : {current_hash}\n\n"
            "  The deadline, threshold (t/n), or authority public keys may have been\n"
            "  changed since the auction was created. This auction cannot be trusted."
        )

    logger.debug("Meta integrity OK for auction %s.", aid)


# ── Auction state machine ─────────────────────────────────────────

def get_auction_state(paths: StorePaths, aid: str) -> str:
    """Derive state from ledger events + deadline, without trusting meta.json alone."""
    from core.ledger import Ledger
    from core.timeutil import now_utc, parse_deadline_any

    led = Ledger(paths.auction_ledger(aid))
    if led.is_revealed():
        return AUCTION_STATE_REVEALED

    try:
        meta         = load_auction_meta(paths, aid)
        deadline_utc = parse_deadline_any(meta["deadline_utc"])
        if now_utc(skip_ntp=True) >= deadline_utc:
            return AUCTION_STATE_CLOSED
    except Exception:
        pass

    return AUCTION_STATE_OPEN


# ── Failed-attempt tracking ───────────────────────────────────────

def _load_attempts(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"count": 0, "locked": False}
    try:
        return read_json(path)
    except Exception:
        return {"count": 0, "locked": False}


def check_not_locked(
    paths: StorePaths,
    aid: Optional[str],
    entity_id: str,
    is_authority: bool,
) -> None:
    path = (paths.failed_attempts_file(aid, entity_id)
            if is_authority and aid else
            paths.bidder_failed_attempts(entity_id))
    data = _load_attempts(path)
    if data.get("locked"):
        raise RuntimeError(
            f"Account '{entity_id}' is LOCKED after too many failed password attempts.\n"
            "  → Contact the system administrator to unlock this account."
        )


def record_failed_attempt(
    paths: StorePaths,
    aid: Optional[str],
    entity_id: str,
    is_authority: bool,
) -> int:
    """Increment counter. Returns remaining attempts. Locks account when exhausted."""
    path = (paths.failed_attempts_file(aid, entity_id)
            if is_authority and aid else
            paths.bidder_failed_attempts(entity_id))
    data = _load_attempts(path)
    data["count"] = data.get("count", 0) + 1
    remaining     = MAX_FAILED_ATTEMPTS - data["count"]
    if remaining <= 0:
        data["locked"] = True
        logger.warning("SECURITY: Account '%s' locked after %d failed attempts.",
                       entity_id, MAX_FAILED_ATTEMPTS)
    write_json(path, data)
    return max(0, remaining)


def reset_failed_attempts(
    paths: StorePaths,
    aid: Optional[str],
    entity_id: str,
    is_authority: bool,
) -> None:
    path = (paths.failed_attempts_file(aid, entity_id)
            if is_authority and aid else
            paths.bidder_failed_attempts(entity_id))
    if path.exists():
        write_json(path, {"count": 0, "locked": False})


# ── Bid file helpers ──────────────────────────────────────────────

def bid_exists(paths: StorePaths, aid: str, bid_id: str) -> bool:
    return paths.bid_file(aid, bid_id).exists()


def save_bid(paths: StorePaths, aid: str, bid_id: str, bid_obj: Dict[str, Any]) -> None:
    if bid_exists(paths, aid, bid_id):
        raise RuntimeError(
            f"Bid '{bid_id}' already exists — duplicate submission rejected."
        )
    write_json(paths.bid_file(aid, bid_id), bid_obj)


def load_bid(paths: StorePaths, aid: str, bid_id: str) -> Dict[str, Any]:
    return read_json(paths.bid_file(aid, bid_id))


# ── Bidder registry ───────────────────────────────────────────────

def bidder_exists(paths: StorePaths, bidder_id: str) -> bool:
    return (paths.bidder_profile(bidder_id).exists()
            and paths.bidder_priv_enc(bidder_id).exists())


def load_bidder_profile(paths: StorePaths, bidder_id: str) -> Dict[str, Any]:
    p = paths.bidder_profile(bidder_id)
    if not p.exists():
        raise FileNotFoundError(
            f"Bidder '{bidder_id}' is not registered.\n"
            "  → Please register first using option 1 from the main menu."
        )
    return read_json(p)


def save_bidder_profile(paths: StorePaths, bidder_id: str, profile: Dict[str, Any]) -> None:
    write_json(paths.bidder_profile(bidder_id), profile)


def save_bidder_priv_enc(paths: StorePaths, bidder_id: str, enc_obj: Dict[str, Any]) -> None:
    write_json(paths.bidder_priv_enc(bidder_id), enc_obj)


def load_bidder_priv_enc(paths: StorePaths, bidder_id: str) -> Dict[str, Any]:
    return read_json(paths.bidder_priv_enc(bidder_id))