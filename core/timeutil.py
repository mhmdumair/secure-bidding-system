from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import re

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:
    ZoneInfo = None


_ISO_Z_RE = re.compile(r"Z$", re.IGNORECASE)
_REL_RE = re.compile(r"^\s*in\s+(\d+)\s*(minute|minutes|hour|hours|day|days)\s*$", re.IGNORECASE)

# Sri Lanka fixed offset (safe: no DST)
SL_OFFSET = timezone(timedelta(hours=5, minutes=30), name="UTC+05:30")
LOCAL_TZ_NAME = "Asia/Colombo"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _get_local_tz():
    """
    Prefer ZoneInfo('Asia/Colombo') if available, otherwise fallback to fixed UTC+05:30.
    Avoids tzdata dependency on Windows.
    """
    if ZoneInfo is not None:
        try:
            return ZoneInfo(LOCAL_TZ_NAME)
        except Exception:
            pass
    return SL_OFFSET


def parse_deadline_any(user_input: str) -> datetime:
    """
    Accepts:
      - ISO8601 with tz: 2026-02-04T09:00:00Z or +00:00
      - Local human time (Sri Lanka): 2026-02-04 14:45[:00]
      - Relative: 'in 10 minutes' / 'in 2 hours' / 'in 1 day'
      - Optional prefix 'local ' allowed: 'local 2026-02-04 14:45:00'

    Returns timezone-aware datetime in UTC.
    """
    s = user_input.strip()

    if s.lower().startswith("local "):
        s = s[6:].strip()

    # Relative
    m = _REL_RE.match(s)
    if m:
        qty = int(m.group(1))
        unit = m.group(2).lower()
        if "minute" in unit:
            delta = timedelta(minutes=qty)
        elif "hour" in unit:
            delta = timedelta(hours=qty)
        else:
            delta = timedelta(days=qty)
        return (now_utc() + delta).astimezone(timezone.utc)

    # ISO8601 with timezone
    s_iso = s.replace(" ", "T")
    s_iso = _ISO_Z_RE.sub("+00:00", s_iso)
    try:
        dt = datetime.fromisoformat(s_iso)
        if dt.tzinfo is None:
            raise ValueError("Timezone missing")
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    # Local human time (Sri Lanka)
    local_tz = _get_local_tz()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            dt_local = datetime.strptime(s, fmt).replace(tzinfo=local_tz)
            return dt_local.astimezone(timezone.utc)
        except Exception:
            continue

    raise ValueError(
        "Unrecognized deadline format. Use ISO8601 with Z, 'YYYY-MM-DD HH:MM:SS' (local), or 'in N minutes/hours/days'."
    )


def ensure_before_deadline(deadline_utc: datetime) -> None:
    if now_utc() >= deadline_utc:
        raise RuntimeError(f"Auction closed: now >= {isoformat_z(deadline_utc)}")


def ensure_after_deadline(deadline_utc: datetime) -> None:
    if now_utc() < deadline_utc:
        raise RuntimeError(f"Deadline not reached: now < {isoformat_z(deadline_utc)}")


@dataclass(frozen=True)
class Deadline:
    deadline_utc: datetime

    @classmethod
    def from_any(cls, s: str) -> "Deadline":
        return cls(parse_deadline_any(s))

    def as_iso_utc(self) -> str:
        return isoformat_z(self.deadline_utc)
