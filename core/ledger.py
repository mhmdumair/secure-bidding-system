from __future__ import annotations

import json
import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.timeutil import isoformat_z, now_utc

logger = logging.getLogger(__name__)


def _canon(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Ledger:
    """
    Append-only hash-chain ledger stored as newline-delimited JSON.

    Each line:
      { "i": int, "ts": "UTC-Z", "type": str, "data": {...},
        "prev": "<prev_hash>", "h": "<this_hash>" }

    Security properties
    ───────────────────
    • Hash chain  – any past modification breaks all subsequent hashes.
    • Timestamp monotonicity – new entry ts must be ≥ previous entry ts;
      backwards jump is flagged as a clock-rollback attack.
    • meta_hash committed in AUCTION_CREATED – tampering with meta.json
      is detectable by comparing against the ledger value.
    • Atomic writes via temp-file + os.replace.
    """

    path: Path

    # ── Internal helpers ──────────────────────────────────────────

    def _read_lines(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        for ln in self.path.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
        return out

    # ── Public read API ───────────────────────────────────────────

    def tip_hash(self) -> str:
        entries = self._read_lines()
        return entries[-1]["h"] if entries else "0" * 64

    def last_timestamp(self) -> Optional[str]:
        entries = self._read_lines()
        return entries[-1].get("ts") if entries else None

    # Alias used by cli.py
    get_last_timestamp = last_timestamp

    def get_committed_meta_hash(self) -> Optional[str]:
        for e in self._read_lines():
            if e.get("type") == "AUCTION_CREATED":
                return e.get("data", {}).get("meta_hash")
        return None

    def bidder_already_bid(self, bidder_id: str) -> bool:
        return any(
            e.get("type") == "BID_SUBMITTED"
            and e.get("data", {}).get("bidder_id") == bidder_id
            for e in self._read_lines()
        )

    def is_revealed(self) -> bool:
        return any(e.get("type") == "AUCTION_REVEALED" for e in self._read_lines())

    def count_bids(self) -> int:
        return sum(1 for e in self._read_lines() if e.get("type") == "BID_SUBMITTED")

    def iter_events(self) -> Iterable[Dict[str, Any]]:
        yield from self._read_lines()

    # ── Append ────────────────────────────────────────────────────

    def append(self, event_type: str, data: Dict[str, Any]) -> str:
        """
        Append a new event.
        Raises RuntimeError if a timestamp rollback is detected.
        Returns the hash of the new entry.
        """
        entries   = self._read_lines()
        prev_hash = entries[-1]["h"] if entries else "0" * 64
        idx       = entries[-1]["i"] + 1 if entries else 0

        current_dt = now_utc(skip_ntp=False)
        current_ts = isoformat_z(current_dt)

        # Timestamp rollback check
        if entries:
            last_ts_str = entries[-1].get("ts", "")
            try:
                last_dt = datetime.fromisoformat(last_ts_str.replace("Z", "+00:00"))
                if current_dt < last_dt - timedelta(seconds=5):
                    raise RuntimeError(
                        f"[SECURITY ALERT] Ledger timestamp rollback detected.\n"
                        f"  Current time      : {current_ts}\n"
                        f"  Last ledger entry : {last_ts_str}\n"
                        f"  The system clock appears to have been moved backward."
                    )
            except ValueError:
                pass

        entry_wo_h = {
            "i":    idx,
            "ts":   current_ts,
            "type": event_type,
            "data": data,
            "prev": prev_hash,
        }
        h     = sha256_hex(_canon(entry_wo_h))
        entry = dict(entry_wo_h)
        entry["h"] = h

        # Atomic write
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existing = self.path.read_text(encoding="utf-8") if self.path.exists() else ""
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            existing + json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, self.path)

        logger.debug("Ledger append i=%d type=%s h=%s…", idx, event_type, h[:12])
        return h

    # ── Verify ────────────────────────────────────────────────────

    def verify(self) -> Tuple[bool, str]:
        """
        Re-compute every hash and check the chain.
        Also checks timestamp monotonicity.
        Returns (True, description) or (False, error).
        """
        entries    = self._read_lines()
        prev       = "0" * 64
        expected_i = 0
        last_ts    = None

        for e in entries:
            if e.get("i") != expected_i:
                return False, f"Index mismatch — expected {expected_i}, found {e.get('i')}."

            if e.get("prev") != prev:
                return False, (
                    f"Hash chain broken at entry {e['i']}.\n"
                    f"  Stored 'prev' does not match the previous entry's hash.\n"
                    f"  This indicates the ledger has been tampered with."
                )

            ts = e.get("ts", "")
            if last_ts and ts < last_ts:
                return False, (
                    f"Timestamp went backward at entry {e['i']}.\n"
                    f"  Previous: {last_ts}  Current: {ts}\n"
                    f"  This may indicate a clock-rollback attack."
                )
            last_ts = ts

            e_wo_h    = {k: e[k] for k in ("i", "ts", "type", "data", "prev")}
            recomputed = sha256_hex(_canon(e_wo_h))
            if recomputed != e.get("h"):
                return False, (
                    f"Hash mismatch at entry {e['i']}.\n"
                    f"  The entry content does not match its stored hash.\n"
                    f"  This indicates the ledger has been tampered with."
                )

            prev       = e["h"]
            expected_i += 1

        return True, f"OK ({len(entries)} entries) — tip hash: {prev[:16]}…"

    def log_failed_auth(self, entity_id: str, entity_type: str) -> None:
        """Record a failed authentication attempt in the audit trail."""
        try:
            self.append("AUTH_FAILED", {"entity_id": entity_id, "entity_type": entity_type})
        except Exception as exc:
            logger.warning("Could not log failed auth: %s", exc)