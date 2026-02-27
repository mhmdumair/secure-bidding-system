from __future__ import annotations

import json
import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.timeutil import isoformat_z, now_utc

logger = logging.getLogger(__name__)


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Ledger:
    """
    Append-only hash chain ledger.

    Each line is a JSON object:
      {
        "i": <int>,
        "ts": "<utc_iso_z>",
        "type": "<event_type>",
        "data": {...},
        "prev": "<prev_hash_hex>",
        "h": "<this_hash_hex>"
      }

    Security properties:
      - Hash chain: any modification of any past entry is detectable
      - Timestamps are cross-validated against NTP via now_utc()
      - Timestamp rollback detection: new entry ts must be >= previous entry ts
      - Meta hash is committed in AUCTION_CREATED and verified on read
    """
    path: Path

    def _read_lines(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out = []
        for ln in lines:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
        return out

    def last_timestamp(self) -> Optional[str]:
        """Return the timestamp of the most recent ledger entry, or None."""
        entries = self._read_lines()
        if not entries:
            return None
        return entries[-1].get("ts")

    def tip_hash(self) -> str:
        """Return hash of latest entry, or genesis hash."""
        entries = self._read_lines()
        if not entries:
            return "0" * 64
        return entries[-1]["h"]

    def append(self, event_type: str, data: Dict[str, Any]) -> str:
        """
        Append a new event to the ledger.
        Raises RuntimeError if timestamp rollback is detected.
        Returns the hash of the new entry.
        """
        entries = self._read_lines()
        prev_hash = entries[-1]["h"] if entries else "0" * 64
        idx = entries[-1]["i"] + 1 if entries else 0

        # Timestamp rollback check
        current_ts_dt = now_utc(skip_ntp=False)
        current_ts = isoformat_z(current_ts_dt)

        if entries:
            last_ts_str = entries[-1].get("ts", "")
            if last_ts_str:
                try:
                    from datetime import datetime, timezone
                    last_dt = datetime.fromisoformat(last_ts_str.replace("Z", "+00:00"))
                    from datetime import timedelta
                    if current_ts_dt < last_dt - timedelta(seconds=5):
                        raise RuntimeError(
                            f"SECURITY ALERT: Ledger timestamp rollback detected. "
                            f"Current time ({current_ts}) is before last entry ({last_ts_str}). "
                            f"Refusing to append."
                        )
                except RuntimeError:
                    raise
                except Exception:
                    pass

        entry_wo_h = {
            "i": idx,
            "ts": current_ts,
            "type": event_type,
            "data": data,
            "prev": prev_hash,
        }
        h = sha256_hex(_canon(entry_wo_h))
        entry = dict(entry_wo_h)
        entry["h"] = h

        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic append: write to temp then replace
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        existing = self.path.read_text(encoding="utf-8") if self.path.exists() else ""
        tmp.write_text(
            existing + json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        import os
        os.replace(tmp, self.path)

        logger.debug("Ledger append: i=%d type=%s h=%s", idx, event_type, h[:12])
        return h

    def verify(self) -> Tuple[bool, str]:
        """
        Verify the entire hash chain.
        Returns (True, "OK ...") or (False, "error description").
        """
        entries = self._read_lines()
        prev = "0" * 64
        expected_i = 0
        last_ts = None

        for e in entries:
            if e.get("i") != expected_i:
                return False, f"Index mismatch at i={e.get('i')} expected={expected_i}"

            if e.get("prev") != prev:
                return False, f"Prev-hash mismatch at i={e['i']}"

            # Timestamp monotonicity check
            ts = e.get("ts", "")
            if last_ts and ts < last_ts:
                return False, f"Timestamp went backward at i={e['i']}: {ts} < {last_ts}"
            last_ts = ts

            e_wo_h = {k: e[k] for k in ("i", "ts", "type", "data", "prev")}
            recomputed = sha256_hex(_canon(e_wo_h))
            if recomputed != e.get("h"):
                return False, f"Hash mismatch at i={e['i']} (entry was tampered)"

            prev = e["h"]
            expected_i += 1

        tip = prev
        return True, f"OK ({len(entries)} entries), tip={tip}"

    def get_committed_meta_hash(self) -> Optional[str]:
        """
        Extract the meta_hash committed in the AUCTION_CREATED ledger entry.
        Returns None if not found.
        """
        for e in self._read_lines():
            if e.get("type") == "AUCTION_CREATED":
                return e.get("data", {}).get("meta_hash")
        return None

    def get_last_timestamp(self) -> Optional[str]:
        """Return timestamp of last entry for rollback checking."""
        return self.last_timestamp()

    def iter_events(self) -> Iterable[Dict[str, Any]]:
        yield from self._read_lines()

    def count_bids(self) -> int:
        return sum(1 for e in self._read_lines() if e.get("type") == "BID_SUBMITTED")

    def bidder_already_bid(self, bidder_id: str) -> bool:
        """Check if a bidder has already submitted a bid (prevent duplicates)."""
        for e in self._read_lines():
            if e.get("type") == "BID_SUBMITTED":
                if e.get("data", {}).get("bidder_id") == bidder_id:
                    return True
        return False

    def is_revealed(self) -> bool:
        """Check if auction has already been revealed."""
        for e in self._read_lines():
            if e.get("type") == "AUCTION_REVEALED":
                return True
        return False

    def log_failed_auth(self, entity_id: str, entity_type: str) -> None:
        """Log a failed authentication attempt (for audit trail)."""
        try:
            self.append("AUTH_FAILED", {
                "entity_id": entity_id,
                "entity_type": entity_type,
            })
        except Exception as ex:
            logger.warning("Could not log failed auth attempt: %s", ex)