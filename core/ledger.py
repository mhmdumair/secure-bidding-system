from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from core.timeutil import isoformat_z, now_utc


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
    Hash is computed over the object without field "h" (canonical json).
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

    def append(self, event_type: str, data: Dict[str, Any]) -> str:
        entries = self._read_lines()
        prev_hash = entries[-1]["h"] if entries else "0" * 64
        idx = entries[-1]["i"] + 1 if entries else 0

        entry_wo_h = {
            "i": idx,
            "ts": isoformat_z(now_utc()),
            "type": event_type,
            "data": data,
            "prev": prev_hash,
        }
        h = sha256_hex(_canon(entry_wo_h))
        entry = dict(entry_wo_h)
        entry["h"] = h

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")

        return h

    def verify(self) -> Tuple[bool, str]:
        entries = self._read_lines()
        prev = "0" * 64
        expected_i = 0

        for e in entries:
            if e.get("i") != expected_i:
                return False, f"Ledger index mismatch at i={e.get('i')} expected={expected_i}"
            if e.get("prev") != prev:
                return False, f"Ledger prev-hash mismatch at i={e['i']}"

            e_wo_h = {k: e[k] for k in ("i", "ts", "type", "data", "prev")}
            recomputed = sha256_hex(_canon(e_wo_h))
            if recomputed != e.get("h"):
                return False, f"Ledger hash mismatch at i={e['i']}"

            prev = e["h"]
            expected_i += 1

        return True, f"OK ({len(entries)} entries), tip={prev}"

    def iter_events(self) -> Iterable[Dict[str, Any]]:
        yield from self._read_lines()
