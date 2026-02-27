from __future__ import annotations

import logging
import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import List, Optional
import re

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

logger = logging.getLogger(__name__)

_ISO_Z_RE = re.compile(r"Z$", re.IGNORECASE)
_REL_RE = re.compile(r"^\s*in\s+(\d+)\s*(minute|minutes|hour|hours|day|days)\s*$", re.IGNORECASE)

SL_OFFSET = timezone(timedelta(hours=5, minutes=30), name="UTC+05:30")
LOCAL_TZ_NAME = "Asia/Colombo"

# NTP configuration
NTP_SERVERS = [
    "pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com",
    "time.windows.com",
]
NTP_PORT = 123
NTP_TIMEOUT = 3.0          # seconds per server
MAX_CLOCK_DRIFT_SECONDS = 30  # reject if local clock drifts more than this
NTP_QUERY_INTERVAL = 300   # re-query NTP at most every 5 minutes

# NTP epoch offset: difference between NTP epoch (1900) and Unix epoch (1970)
_NTP_DELTA = 2208988800

# Module-level cache
_last_ntp_check: float = 0.0          # local monotonic time of last check
_last_ntp_offset: Optional[float] = None  # seconds: ntp_time - local_time


def _get_local_tz():
    if ZoneInfo is not None:
        try:
            return ZoneInfo(LOCAL_TZ_NAME)
        except Exception:
            pass
    return SL_OFFSET


def _query_single_ntp(server: str) -> Optional[float]:
    """
    Query one NTP server. Returns UTC Unix timestamp or None on failure.
    Uses RFC 5905 NTP v4 client packet (48 bytes).
    """
    try:
        # Build NTP request packet
        packet = bytearray(48)
        packet[0] = 0x23  # LI=0, VN=4, Mode=3 (client)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(NTP_TIMEOUT)

        send_time = time.time()
        sock.sendto(bytes(packet), (server, NTP_PORT))
        data, _ = sock.recvfrom(1024)
        recv_time = time.time()
        sock.close()

        if len(data) < 48:
            return None

        # Transmit timestamp is at bytes 40-47
        tx_secs = struct.unpack("!I", data[40:44])[0]
        tx_frac = struct.unpack("!I", data[44:48])[0]

        ntp_timestamp = tx_secs - _NTP_DELTA + tx_frac / 2**32

        # Use midpoint of round-trip as our estimate
        rtt = recv_time - send_time
        estimated_server_time = ntp_timestamp + rtt / 2

        return estimated_server_time

    except Exception as e:
        logger.debug("NTP query failed for %s: %s", server, e)
        return None


def _fetch_ntp_time() -> Optional[float]:
    """
    Query multiple NTP servers, return median of successful responses.
    Returns UTC Unix timestamp or None if all servers fail.
    """
    results: List[float] = []
    for server in NTP_SERVERS:
        ts = _query_single_ntp(server)
        if ts is not None:
            results.append(ts)
        if len(results) >= 2:
            break  # enough for a basic sanity check

    if not results:
        return None

    results.sort()
    # Median
    mid = len(results) // 2
    return results[mid] if len(results) % 2 == 1 else (results[mid - 1] + results[mid]) / 2


def _update_ntp_offset(force: bool = False) -> None:
    """
    Update the cached NTP offset if enough time has passed or forced.
    Raises RuntimeError if clock drift is unacceptable.
    """
    global _last_ntp_check, _last_ntp_offset

    now_mono = time.monotonic()
    if not force and (now_mono - _last_ntp_check) < NTP_QUERY_INTERVAL:
        return  # Use cached offset

    ntp_ts = _fetch_ntp_time()
    local_ts = time.time()

    if ntp_ts is None:
        # Cannot reach any NTP server — warn but don't block if we have a cached offset
        if _last_ntp_offset is None:
            logger.warning(
                "Cannot reach NTP servers and no cached offset. "
                "Time integrity cannot be guaranteed."
            )
        else:
            logger.warning("NTP unreachable; using cached offset (%.1fs)", _last_ntp_offset)
        _last_ntp_check = now_mono
        return

    offset = ntp_ts - local_ts
    _last_ntp_check = now_mono

    if _last_ntp_offset is not None:
        # Check if offset changed dramatically since last check (rolling-back attack)
        delta = abs(offset - _last_ntp_offset)
        if delta > MAX_CLOCK_DRIFT_SECONDS:
            raise RuntimeError(
                f"SECURITY ALERT: System clock appears to have been manipulated. "
                f"NTP offset changed by {delta:.1f}s since last check. "
                f"Previous offset={_last_ntp_offset:.1f}s, current={offset:.1f}s. "
                f"Refusing to operate."
            )

    if abs(offset) > MAX_CLOCK_DRIFT_SECONDS:
        raise RuntimeError(
            f"SECURITY ALERT: System clock is out of sync with NTP by {offset:.1f}s "
            f"(max allowed: {MAX_CLOCK_DRIFT_SECONDS}s). "
            f"Possible clock manipulation. Refusing to operate."
        )

    _last_ntp_offset = offset
    logger.debug("NTP sync OK. Local clock offset: %.3fs", offset)


def now_utc(skip_ntp: bool = False) -> datetime:
    """
    Return current UTC time, cross-validated against NTP.
    Raises RuntimeError if clock manipulation is detected.
    """
    if not skip_ntp:
        try:
            _update_ntp_offset()
        except RuntimeError:
            raise
        except Exception as e:
            logger.warning("NTP check error (non-fatal): %s", e)

    # Apply cached offset if available for better accuracy
    local_ts = time.time()
    if _last_ntp_offset is not None:
        local_ts += _last_ntp_offset

    return datetime.fromtimestamp(local_ts, tz=timezone.utc)


def monotonic_seconds() -> float:
    """
    Return monotonic clock seconds. Cannot be manipulated by system time changes.
    Use for measuring elapsed time within a session.
    """
    return time.monotonic()


def isoformat_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_deadline_any(user_input: str) -> datetime:
    """
    Accepts:
      - ISO8601 with tz: 2026-02-04T09:00:00Z or +00:00
      - Local human time (Sri Lanka): 2026-02-04 14:45[:00]
      - Relative: 'in 10 minutes' / 'in 2 hours' / 'in 1 day'
      - Optional prefix 'local ': 'local 2026-02-04 14:45:00'

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
        "Unrecognized deadline format. Use ISO8601 with Z, "
        "'YYYY-MM-DD HH:MM:SS' (local Sri Lanka), or 'in N minutes/hours/days'."
    )


def ensure_before_deadline(deadline_utc: datetime, last_ledger_ts: Optional[str] = None) -> None:
    """
    Raise if it is at or past the deadline.
    Also checks that current time is not before the last ledger timestamp (rollback detection).
    """
    current = now_utc()

    # Rollback detection: time must never go backward relative to ledger
    if last_ledger_ts:
        try:
            last_ts = datetime.fromisoformat(last_ledger_ts.replace("Z", "+00:00"))
            if current < last_ts - timedelta(seconds=5):
                raise RuntimeError(
                    f"SECURITY ALERT: Current time ({isoformat_z(current)}) is before "
                    f"last ledger entry ({last_ledger_ts}). "
                    f"Possible clock rollback attack. Refusing to operate."
                )
        except ValueError:
            pass

    if current >= deadline_utc:
        raise RuntimeError(f"Auction closed: now ({isoformat_z(current)}) >= deadline ({isoformat_z(deadline_utc)})")


def ensure_after_deadline(deadline_utc: datetime, last_ledger_ts: Optional[str] = None) -> None:
    """
    Raise if deadline has not yet been reached.
    Also checks rollback detection.
    """
    current = now_utc()

    # Rollback detection
    if last_ledger_ts:
        try:
            last_ts = datetime.fromisoformat(last_ledger_ts.replace("Z", "+00:00"))
            if current < last_ts - timedelta(seconds=5):
                raise RuntimeError(
                    f"SECURITY ALERT: Current time ({isoformat_z(current)}) is before "
                    f"last ledger entry ({last_ledger_ts}). "
                    f"Possible clock rollback attack. Refusing to operate."
                )
        except ValueError:
            pass

    if current < deadline_utc:
        raise RuntimeError(
            f"Deadline not reached: now ({isoformat_z(current)}) < deadline ({isoformat_z(deadline_utc)})"
        )


def verify_ntp_sync() -> dict:
    """
    Explicit NTP check. Returns status dict. Call at startup.
    """
    try:
        _update_ntp_offset(force=True)
        offset = _last_ntp_offset
        return {
            "ok": True,
            "offset_seconds": round(offset, 3) if offset is not None else None,
            "message": f"NTP sync OK. Offset={offset:.3f}s" if offset is not None else "NTP unavailable (using local clock)"
        }
    except RuntimeError as e:
        return {"ok": False, "offset_seconds": None, "message": str(e)}


@dataclass(frozen=True)
class Deadline:
    deadline_utc: datetime

    @classmethod
    def from_any(cls, s: str) -> "Deadline":
        return cls(parse_deadline_any(s))

    def as_iso_utc(self) -> str:
        return isoformat_z(self.deadline_utc)