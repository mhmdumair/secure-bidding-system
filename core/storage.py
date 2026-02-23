from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def atomic_write_text(path: Path, text: str) -> None:
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

    # ---------------- Bidders registry ----------------
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
        raise FileNotFoundError(f"Auction meta not found: {p}")
    return read_json(p)


def save_auction_meta(paths: StorePaths, auction_id: str, meta: Dict[str, Any]) -> None:
    write_json(paths.auction_meta(auction_id), meta)


# ---------------- Bids ----------------

def save_bid(paths: StorePaths, auction_id: str, bid_id: str, bid_obj: Dict[str, Any]) -> None:
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
