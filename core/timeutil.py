from __future__ import annotations

import logging
import re
import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import List, Optional

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

logger = logging.getLogger(__name__)

_ISO_Z_RE = re.compile(r"Z$", re.IGNORECASE)
_REL_RE   = re.compile(
    r"^\s*in\s+(\d+)\s*(minute|minutes|hour|hours|day|days)\s*$",
    re.IGNORECASE,
)

SL_OFFSET      = timezone(timedelta(hours=5, minutes=30), name="UTC+05:30")
LOCAL_TZ_NAME  = "Asia/Colombo"

# ── NTP configuration ─────────────────────────────────────────────
NTP_SERVERS           = ["pool.ntp.org", "time.google.com",
                         "time.cloudflare.com", "time.windows.com"]
NTP_PORT              = 123
NTP_TIMEOUT           = 3.0   # seconds per server
MAX_CLOCK_DRIFT_SECS  = 30    # reject if local clock drifts more than this
NTP_QUERY_INTERVAL    = 300   # re-query every 5 minutes at most
_NTP_DELTA            = 2208988800  # NTP epoch (1900) → Unix epoch (1970)

# Module-level NTP cache
_last_ntp_check:  float          = 0.0
_last_ntp_offset: Optional[float] = None


# ── Timezone helper ───────────────────────────────────────────────

def _get_local_tz():
    if ZoneInfo is not None:
        try:
            return ZoneInfo(LOCAL_TZ_NAME)
        except Exception:
            pass
    return SL_OFFSET


# ── NTP internals ─────────────────────────────────────────────────

def _query_single_ntp(server: str) -> Optional[float]:
    """Query one NTP server. Returns UTC Unix timestamp or None."""
    try:
        packet = bytearray(48)
        packet[0] = 0x23          # LI=0, VN=4, Mode=3 (client)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(NTP_TIMEOUT)
        send_time = time.time()
        sock.sendto(bytes(packet), (server, NTP_PORT))
        data, _ = sock.recvfrom(1024)
        recv_time = time.time()
        sock.close()
        if len(data) < 48:
            return None
        tx_secs = struct.unpack("!I", data[40:44])[0]
        tx_frac = struct.unpack("!I", data[44:48])[0]
        ntp_ts  = tx_secs - _NTP_DELTA + tx_frac / 2 ** 32
        return ntp_ts + (recv_time - send_time) / 2   # midpoint correction
    except Exception as exc:
        logger.debug("NTP query failed for %s: %s", server, exc)
        return None


def _fetch_ntp_time() -> Optional[float]:
    """Query multiple NTP servers; return median of successes."""
    results: List[float] = []
    for srv in NTP_SERVERS:
        ts = _query_single_ntp(srv)
        if ts is not None:
            results.append(ts)
        if len(results) >= 2:
            break
    if not results:
        return None
    results.sort()
    mid = len(results) // 2
    return results[mid] if len(results) % 2 == 1 else (results[mid-1] + results[mid]) / 2


def _update_ntp_offset(force: bool = False) -> None:
    """Refresh cached NTP offset; raise RuntimeError on clock manipulation."""
    global _last_ntp_check, _last_ntp_offset
    now_mono = time.monotonic()
    if not force and (now_mono - _last_ntp_check) < NTP_QUERY_INTERVAL:
        return

    ntp_ts   = _fetch_ntp_time()
    local_ts = time.time()

    if ntp_ts is None:
        if _last_ntp_offset is None:
            logger.warning("Cannot reach NTP servers. Time integrity cannot be guaranteed.")
        else:
            logger.warning("NTP unreachable; using cached offset (%.1fs).", _last_ntp_offset)
        _last_ntp_check = now_mono
        return

    offset = ntp_ts - local_ts
    _last_ntp_check = now_mono

    # Detect sudden jump since last check (rollback / forward attack)
    if _last_ntp_offset is not None:
        delta = abs(offset - _last_ntp_offset)
        if delta > MAX_CLOCK_DRIFT_SECS:
            raise RuntimeError(
                f"[SECURITY ALERT] System clock changed by {delta:.1f}s since last check.\n"
                f"  Previous NTP offset : {_last_ntp_offset:+.1f}s\n"
                f"  Current  NTP offset : {offset:+.1f}s\n"
                f"  This may indicate the system clock was manually altered."
            )

    if abs(offset) > MAX_CLOCK_DRIFT_SECS:
        raise RuntimeError(
            f"[SECURITY ALERT] System clock is {offset:+.1f}s out of sync with NTP.\n"
            f"  Maximum allowed drift : {MAX_CLOCK_DRIFT_SECS}s\n"
            f"  This may indicate the system clock has been tampered with."
        )

    _last_ntp_offset = offset
    logger.debug("NTP sync OK. Clock offset: %+.3fs.", offset)


# ── Public time API ───────────────────────────────────────────────

def now_utc(skip_ntp: bool = False) -> datetime:
    """
    Current UTC time, cross-validated against NTP.
    Raises RuntimeError if clock manipulation is detected.
    Pass skip_ntp=True only for non-security-critical display purposes.
    """
    if not skip_ntp:
        try:
            _update_ntp_offset()
        except RuntimeError:
            raise
        except Exception as exc:
            logger.warning("NTP check error (non-fatal): %s", exc)

    local_ts = time.time()
    if _last_ntp_offset is not None:
        local_ts += _last_ntp_offset
    return datetime.fromtimestamp(local_ts, tz=timezone.utc)


def isoformat_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def friendly_local(dt: datetime) -> str:
    """Return datetime formatted in Sri Lanka local time for display."""
    sl = dt.astimezone(_get_local_tz())
    return sl.strftime("%Y-%m-%d %H:%M:%S (UTC+05:30)")


def parse_deadline_any(user_input: str) -> datetime:
    """
    Accept multiple formats and always return a UTC-aware datetime.

    Formats accepted:
      • 2026-03-01 14:45:00     → treated as Sri Lanka local time
      • 2026-03-01T09:15:00Z   → explicit UTC
      • 2026-03-01T09:15:00+05:30 → any tz offset
      • in 10 minutes / in 2 hours / in 1 day
    """
    s = user_input.strip()
    if s.lower().startswith("local "):
        s = s[6:].strip()

    # Relative
    m = _REL_RE.match(s)
    if m:
        qty  = int(m.group(1))
        unit = m.group(2).lower()
        delta = (timedelta(minutes=qty) if "minute" in unit
                 else timedelta(hours=qty) if "hour" in unit
                 else timedelta(days=qty))
        return (now_utc() + delta).astimezone(timezone.utc)

    # ISO 8601 with tz
    s_iso = _ISO_Z_RE.sub("+00:00", s.replace(" ", "T"))
    try:
        dt = datetime.fromisoformat(s_iso)
        if dt.tzinfo is None:
            raise ValueError
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    # Local Sri Lanka time (no tz in string)
    local_tz = _get_local_tz()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=local_tz).astimezone(timezone.utc)
        except Exception:
            continue

    raise ValueError(
        "Unrecognised deadline format.\n"
        "  Accepted formats:\n"
        "    • 2026-03-01 14:45:00  (Sri Lanka local time)\n"
        "    • 2026-03-01T09:15:00Z (UTC with Z)\n"
        "    • in 30 minutes  /  in 2 hours  /  in 1 day"
    )


def seconds_until(deadline_utc: datetime) -> float:
    """Return seconds remaining until deadline (negative if past)."""
    return (deadline_utc - now_utc(skip_ntp=True)).total_seconds()


def human_remaining(deadline_utc: datetime) -> str:
    """Human-readable time remaining string."""
    secs = seconds_until(deadline_utc)
    if secs <= 0:
        return "deadline has passed"
    h, rem = divmod(int(secs), 3600)
    m, s   = divmod(rem, 60)
    parts  = []
    if h:
        parts.append(f"{h} hour{'s' if h != 1 else ''}")
    if m:
        parts.append(f"{m} minute{'s' if m != 1 else ''}")
    if s or not parts:
        parts.append(f"{s} second{'s' if s != 1 else ''}")
    return ", ".join(parts)


def ensure_before_deadline(deadline_utc: datetime,
                           last_ledger_ts: Optional[str] = None) -> None:
    """Raise if deadline has passed or if clock rollback is detected."""
    current = now_utc()

    if last_ledger_ts:
        try:
            last_ts = datetime.fromisoformat(last_ledger_ts.replace("Z", "+00:00"))
            if current < last_ts - timedelta(seconds=5):
                raise RuntimeError(
                    f"[SECURITY ALERT] Clock rollback detected.\n"
                    f"  Current time      : {isoformat_z(current)}\n"
                    f"  Last ledger entry : {last_ledger_ts}\n"
                    f"  The system clock appears to have been moved backward."
                )
        except ValueError:
            pass

    if current >= deadline_utc:
        raise RuntimeError("deadline_passed")


def ensure_after_deadline(deadline_utc: datetime,
                          last_ledger_ts: Optional[str] = None) -> None:
    """Raise if deadline has not yet been reached or if clock rollback is detected."""
    current = now_utc()

    if last_ledger_ts:
        try:
            last_ts = datetime.fromisoformat(last_ledger_ts.replace("Z", "+00:00"))
            if current < last_ts - timedelta(seconds=5):
                raise RuntimeError(
                    f"[SECURITY ALERT] Clock rollback detected.\n"
                    f"  Current time      : {isoformat_z(current)}\n"
                    f"  Last ledger entry : {last_ledger_ts}\n"
                    f"  The system clock appears to have been moved backward."
                )
        except ValueError:
            pass

    if current < deadline_utc:
        raise RuntimeError("deadline_not_reached")


def verify_ntp_sync() -> dict:
    """Explicit NTP check for startup. Returns status dict."""
    try:
        _update_ntp_offset(force=True)
        offset = _last_ntp_offset
        return {
            "ok": True,
            "offset_seconds": round(offset, 3) if offset is not None else None,
            "message": (
                f"Clock is accurate (NTP offset: {offset:+.3f}s)"
                if offset is not None else
                "NTP unavailable — using local clock"
            ),
        }
    except RuntimeError as exc:
        return {"ok": False, "offset_seconds": None, "message": str(exc)}


@dataclass(frozen=True)
class Deadline:
    deadline_utc: datetime

    @classmethod
    def from_any(cls, s: str) -> "Deadline":
        return cls(parse_deadline_any(s))

    def as_iso_utc(self) -> str:
        return isoformat_z(self.deadline_utc)