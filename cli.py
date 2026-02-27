from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
import uuid
import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core import crypto, ledger, shamir, storage, timeutil

# ── Logging (full trace to file, nothing noisy on screen) ─────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("audit.log", encoding="utf-8")],
)
logger = logging.getLogger(__name__)

STORE_ROOT       = Path("store")
PATHS            = storage.StorePaths(STORE_ROOT)
PASSWORD_TIMEOUT = 60   # seconds before unattended-terminal auto-exit


# ════════════════════════════════════════════════════════════════════
#  PASSWORD STRENGTH
# ════════════════════════════════════════════════════════════════════

def _password_issues(pw: str) -> List[str]:
    issues = []
    if len(pw) < 8:
        issues.append(f"  * At least 8 characters  (yours has {len(pw)})")
    if not re.search(r"[A-Z]", pw):
        issues.append("  * At least 1 UPPERCASE letter  (A-Z)")
    if not re.search(r"[0-9]", pw):
        issues.append("  * At least 1 number  (0-9)")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:',.<>?/\\|`~]", pw):
        issues.append("  * At least 1 special symbol  (! @ # $ % ^ & * etc.)")
    return issues


def prompt_strong_password(label: str) -> str:
    """Loop until user supplies a strong password, then confirm it."""
    print(f"\n  Password requirements for {label}:")
    print("    * Minimum 8 characters")
    print("    * At least 1 uppercase letter  (A-Z)")
    print("    * At least 1 number  (0-9)")
    print("    * At least 1 special symbol  (! @ # $ % ^ & * ...)")

    while True:
        pw1 = _getpass(f"Create password for {label}: ")
        if not pw1:
            _err("Password cannot be empty.")
            continue

        issues = _password_issues(pw1)
        if issues:
            print("\n  [PASSWORD TOO WEAK] Your password does not meet these rules:")
            for iss in issues:
                print(iss)
            print("  Please choose a stronger password.\n")
            continue

        pw2 = _getpass(f"Confirm password for {label}: ")
        if pw1 != pw2:
            _err("Passwords do not match. Please try again.")
            continue

        print(f"  [OK] Password accepted for {label}.")
        return pw1


# ════════════════════════════════════════════════════════════════════
#  CONSOLE HELPERS
# ════════════════════════════════════════════════════════════════════

def _err(msg: str) -> None:
    print(f"\n  [ERROR] {msg}\n")


def _ok(msg: str) -> None:
    print(f"\n  [OK] {msg}")


def _security_alert(msg: str) -> None:
    print("\n" + "!" * 68)
    print("  SECURITY ALERT")
    print("!" * 68)
    print(msg)
    print("!" * 68 + "\n")


def ensure_base_dirs() -> None:
    PATHS.auctions_dir.mkdir(parents=True, exist_ok=True)
    PATHS.users_dir.mkdir(parents=True, exist_ok=True)
    PATHS.bidders_dir().mkdir(parents=True, exist_ok=True)


def header(title: str) -> None:
    print("\n" + "=" * 68)
    print(f"  {title}")
    print("=" * 68)


def pause() -> None:
    input("\n  Press Enter to continue...")


def confirm(prompt: str) -> bool:
    while True:
        ans = input(f"  {prompt} (Y/N): ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Please enter Y or N.")


def prompt_nonempty(prompt: str) -> str:
    while True:
        v = input(f"  {prompt}").strip()
        if v:
            return v
        _err("Input cannot be empty.")


def prompt_int(prompt: str,
               min_value: Optional[int] = None,
               max_value: Optional[int] = None) -> int:
    while True:
        raw = input(f"  {prompt}").strip()
        try:
            v = int(raw)
        except ValueError:
            _err("Please enter a whole number (e.g. 100).")
            continue
        if min_value is not None and v < min_value:
            _err(f"Must be {min_value} or greater.")
            continue
        if max_value is not None and v > max_value:
            _err(f"Must be {max_value} or less.")
            continue
        return v


def _timeout_handler(signum, frame):
    print("\n\n  [SECURITY] Password prompt timed out. Exiting.")
    sys.exit(1)


def _getpass(prompt: str) -> str:
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(PASSWORD_TIMEOUT)
        try:
            pw = getpass.getpass(f"  {prompt}")
        finally:
            signal.alarm(0)
        return pw
    return getpass.getpass(f"  {prompt}")


def json_load_bytes(b: bytes) -> Any:
    return json.loads(b.decode("utf-8"))


def pem_public_key_str(pk) -> str:
    return crypto.public_key_pem_str(pk)


# ════════════════════════════════════════════════════════════════════
#  NTP STARTUP CHECK
# ════════════════════════════════════════════════════════════════════

def run_ntp_check() -> None:
    print("\n  Checking system clock against NTP time servers...")
    result = timeutil.verify_ntp_sync()
    if result["ok"]:
        off = result.get("offset_seconds")
        msg = f"Clock verified (NTP offset: {off:+.3f}s)" if off is not None else "NTP check passed"
        _ok(msg)
    else:
        print(f"\n  [WARNING] System clock could not be verified.")
        print(f"  Reason : {result['message']}\n")
        print("  Possible causes:")
        print("    * No internet connection to NTP servers")
        print("    * System clock has been manually altered")
        print("    * Deadline enforcement may be unreliable\n")
        if not confirm("Continue anyway? (not recommended for production)"):
            print("  Exiting for security.")
            sys.exit(1)


# ════════════════════════════════════════════════════════════════════
#  DEADLINE INPUT
# ════════════════════════════════════════════════════════════════════

def prompt_deadline() -> str:
    print("\n  Accepted deadline formats:")
    print("    1)  2026-03-15 14:30:00        (Sri Lanka local time, UTC+05:30)")
    print("    2)  2026-03-15T09:00:00Z       (UTC with Z suffix)")
    print("    3)  in 30 minutes  /  in 2 hours  /  in 1 day")

    while True:
        raw = input("\n  Enter deadline: ").strip()
        if not raw:
            _err("Deadline cannot be empty.")
            continue
        try:
            dt_utc = timeutil.parse_deadline_any(raw)
            now    = timeutil.now_utc(skip_ntp=True)
            if dt_utc <= now:
                _err("Deadline must be in the future. Please enter a later time.")
                continue
            utc_str = timeutil.isoformat_z(dt_utc)
            lk_str  = timeutil.friendly_local(dt_utc)
            print(f"\n    Sri Lanka time : {lk_str}")
            print(f"    UTC (stored)   : {utc_str}")
            print(f"    Time remaining : {timeutil.human_remaining(dt_utc)}")
            if confirm("Use this deadline?"):
                return utc_str
        except Exception as exc:
            _err(f"Could not understand that deadline.\n    Reason: {exc}")


# ════════════════════════════════════════════════════════════════════
#  AUCTION LIST / SELECTION
# ════════════════════════════════════════════════════════════════════

def list_auctions_pretty() -> List[Tuple[str, Dict[str, Any]]]:
    out = []
    for aid in storage.list_auction_ids(PATHS):
        try:
            out.append((aid, storage.load_auction_meta(PATHS, aid)))
        except Exception:
            pass
    return out


def choose_auction_id() -> str:
    auctions = list_auctions_pretty()
    if not auctions:
        raise RuntimeError(
            "No auctions found.\n"
            "    -> Create one first using option 2 from the main menu."
        )

    state_labels = {
        storage.AUCTION_STATE_OPEN:     "OPEN      <- accepting bids",
        storage.AUCTION_STATE_CLOSED:   "CLOSED    <- past deadline, not revealed",
        storage.AUCTION_STATE_REVEALED: "REVEALED  <- winner announced",
    }

    print(f"\n  {'#':<4} {'Name':<22} {'Deadline (UTC)':<28} State")
    print("  " + "-" * 72)
    for i, (aid, meta) in enumerate(auctions, 1):
        state = storage.get_auction_state(PATHS, aid)
        slbl  = state_labels.get(state, state)
        print(f"  [{i}]  {meta.get('name','?'):<22} {meta.get('deadline_utc','?'):<28} {slbl}")

    idx = prompt_int("Select auction number: ", min_value=1, max_value=len(auctions))
    return auctions[idx - 1][0]


# ════════════════════════════════════════════════════════════════════
#  BIDDER REGISTRATION
# ════════════════════════════════════════════════════════════════════

def register_bidder() -> None:
    ensure_base_dirs()
    header("Register Bidder")

    bidder_id = prompt_nonempty("Choose a bidder ID (e.g. B1, Alice): ")
    if storage.bidder_exists(PATHS, bidder_id):
        _err(f"Bidder ID '{bidder_id}' is already taken.\n"
             "    -> Please choose a different ID.")
        pause()
        return

    bidder_name = prompt_nonempty("Full name: ")
    password    = prompt_strong_password(f"bidder '{bidder_id}'")

    sk, pk = crypto.gen_ecdsa_keypair()
    PATHS.bidder_dir(bidder_id).mkdir(parents=True, exist_ok=True)
    pub_pem     = pem_public_key_str(pk)
    fingerprint = crypto.public_key_fingerprint(pk)
    PATHS.bidder_pub(bidder_id).write_text(pub_pem, encoding="utf-8")

    aad = f"bidder|{bidder_id}".encode()
    storage.save_bidder_priv_enc(
        PATHS, bidder_id,
        crypto.encrypt_private_key_pem(sk, password, aad=aad, is_authority=False),
    )
    storage.save_bidder_profile(PATHS, bidder_id, {
        "bidder_id":          bidder_id,
        "name":               bidder_name,
        "pubkey_pem":         pub_pem,
        "pubkey_fingerprint": fingerprint,
        "created_at_utc":     timeutil.isoformat_z(timeutil.now_utc()),
    })
    logger.info("Bidder registered: %s (%s)", bidder_id, bidder_name)

    print("\n  +------------------------------------------+")
    print("  |  Bidder registered successfully!         |")
    print("  +------------------------------------------+")
    print(f"  Bidder ID   : {bidder_id}")
    print(f"  Name        : {bidder_name}")
    print(f"  Key ID      : {fingerprint}")
    print("\n  IMPORTANT: Keep your password safe - it cannot be recovered.")
    pause()


def authenticate_bidder(bidder_id: str,
                        auction_id: Optional[str] = None) -> Tuple[Any, str]:
    if not storage.bidder_exists(PATHS, bidder_id):
        raise RuntimeError(
            f"Bidder '{bidder_id}' is not registered.\n"
            "    -> Register first using option 1 from the main menu."
        )
    storage.check_not_locked(PATHS, None, bidder_id, is_authority=False)

    profile  = storage.load_bidder_profile(PATHS, bidder_id)
    enc_priv = storage.load_bidder_priv_enc(PATHS, bidder_id)
    password = _getpass(f"Password for bidder '{bidder_id}': ")
    aad      = f"bidder|{bidder_id}".encode()

    try:
        sk = crypto.decrypt_private_key_pem(enc_priv, password, aad=aad)
        storage.reset_failed_attempts(PATHS, None, bidder_id, is_authority=False)
        return sk, profile["pubkey_pem"]
    except Exception:
        remaining = storage.record_failed_attempt(PATHS, None, bidder_id, is_authority=False)
        logger.warning("Failed auth bidder '%s'. Remaining: %d", bidder_id, remaining)
        if remaining == 0:
            raise RuntimeError(
                f"Wrong password for '{bidder_id}'.\n"
                "    -> Account is now LOCKED. Contact the system administrator."
            )
        raise RuntimeError(
            f"Wrong password for '{bidder_id}'.\n"
            f"    -> {remaining} attempt(s) remaining before this account is locked."
        )


# ════════════════════════════════════════════════════════════════════
#  AUCTION CREATION
# ════════════════════════════════════════════════════════════════════

def create_auction() -> None:
    ensure_base_dirs()
    header("Create Auction")

    auction_name = prompt_nonempty("Auction name: ")
    deadline_str = prompt_deadline()

    n = prompt_int("Number of authorities  (minimum 2): ", min_value=2)
    t = prompt_int(
        f"Threshold - how many authorities must cooperate to reveal bids\n"
        f"  (between 2 and {n}): ",
        min_value=2, max_value=n,
    )

    # Optional bid limits
    print("\n  -- Bid Amount Limits ----------------------------------------")
    print("  You may optionally restrict the allowed bid amounts.")

    min_bid: Optional[int] = None
    max_bid: Optional[int] = None

    if confirm("Set a MINIMUM bid amount?"):
        min_bid = prompt_int("  Minimum bid amount: ", min_value=1)
        print(f"  Minimum set to: {min_bid:,}")

    if confirm("Set a MAXIMUM bid amount?"):
        low     = (min_bid + 1) if min_bid is not None else 1
        max_bid = prompt_int(f"  Maximum bid amount (must be > {low - 1:,}): ", min_value=low)
        print(f"  Maximum set to: {max_bid:,}")

    if min_bid is None and max_bid is None:
        print("  No limits set - any positive amount will be accepted.")

    # Authority key generation
    auction_id = uuid.uuid4().hex[:16]
    PATHS.auction_authorities_dir(auction_id).mkdir(parents=True, exist_ok=True)

    authority_ids:          List[str]      = []
    authority_pubkeys:      Dict[str, str] = {}
    authority_fingerprints: Dict[str, str] = {}

    print(f"\n  -- Authority Setup ({n} authorities) --------------------------")
    for i in range(1, n + 1):
        print(f"\n  Authority {i} of {n}:")
        auth_id = prompt_nonempty(f"  Authority {i} ID (e.g. A{i}): ")
        if auth_id in authority_ids:
            _err(f"Authority ID '{auth_id}' already used. Restarting.")
            pause()
            return
        authority_ids.append(auth_id)

        password = prompt_strong_password(f"authority '{auth_id}'")

        sk, pk      = crypto.gen_ecdsa_keypair()
        pub_pem     = pem_public_key_str(pk)
        fingerprint = crypto.public_key_fingerprint(pk)

        auth_dir = PATHS.auction_authority_dir(auction_id, auth_id)
        auth_dir.mkdir(parents=True, exist_ok=True)
        PATHS.auction_authority_pub(auction_id, auth_id).write_text(pub_pem, encoding="utf-8")
        authority_pubkeys[auth_id]      = pub_pem
        authority_fingerprints[auth_id] = fingerprint

        aad = f"authority|{auction_id}|{auth_id}".encode()
        storage.write_json(
            PATHS.auction_authority_priv_enc(auction_id, auth_id),
            crypto.encrypt_private_key_pem(sk, password, aad=aad, is_authority=True),
        )
        print(f"  [OK] '{auth_id}' key fingerprint: {fingerprint}")

    # Build and hash meta
    meta: Dict[str, Any] = {
        "auction_id":               auction_id,
        "name":                     auction_name,
        "deadline_utc":             deadline_str,
        "n":                        n,
        "t":                        t,
        "authority_ids":            authority_ids,
        "authority_pubkeys_pem":    authority_pubkeys,
        "authority_fingerprints":   authority_fingerprints,
        "created_at_utc":           timeutil.isoformat_z(timeutil.now_utc()),
        "state":                    storage.AUCTION_STATE_OPEN,
        "crypto": {
            "bid_aead":     "ChaCha20-Poly1305",
            "sealed_share": "ECDH(P-256)+HKDF-SHA256+ChaCha20-Poly1305",
            "sign":         "ECDSA(P-256)+SHA256",
            "shamir":       "GF(p) p=2^521-1",
            "authority_kdf":"scrypt(N=2^20,r=8,p=1)",
            "bidder_kdf":   "scrypt(N=2^17,r=8,p=1)",
        },
    }
    if min_bid is not None:
        meta["min_bid"] = min_bid
    if max_bid is not None:
        meta["max_bid"] = max_bid

    meta_hash        = crypto.hash_meta(meta)
    meta["meta_hash"] = meta_hash
    storage.save_auction_meta(PATHS, auction_id, meta)

    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    led.append("AUCTION_CREATED", {
        "auction_id": auction_id, "name": auction_name,
        "deadline_utc": deadline_str, "meta_hash": meta_hash,
        "t": t, "n": n,
    })
    logger.info("Auction created: %s '%s' deadline=%s", auction_id, auction_name, deadline_str)

    print(f"\n  +----------------------------------------------------------+")
    print(f"  |  Auction created successfully!                           |")
    print(f"  +----------------------------------------------------------+")
    print(f"  Auction ID    : {auction_id}")
    print(f"  Name          : {auction_name}")
    print(f"  Deadline (UTC): {deadline_str}")
    print(f"  Deadline (LK) : {timeutil.friendly_local(timeutil.parse_deadline_any(deadline_str))}")
    print(f"  Threshold     : {t} of {n} authorities must cooperate to reveal")
    limits = []
    if min_bid is not None:
        limits.append(f"min={min_bid:,}")
    if max_bid is not None:
        limits.append(f"max={max_bid:,}")
    print(f"  Bid limits    : {', '.join(limits) if limits else 'none (any positive amount)'}")
    print(f"  Meta hash     : {meta_hash[:32]}...")
    print(f"\n  Authority fingerprints (verify with each authority out-of-band):")
    for aid, fp in authority_fingerprints.items():
        print(f"    {aid}: {fp}")
    pause()


# ════════════════════════════════════════════════════════════════════
#  META INTEGRITY GUARD
# ════════════════════════════════════════════════════════════════════

def _verify_meta(auction_id: str) -> Dict[str, Any]:
    led            = ledger.Ledger(PATHS.auction_ledger(auction_id))
    committed_hash = led.get_committed_meta_hash()
    storage.verify_meta_integrity(PATHS, auction_id, committed_hash)
    return storage.load_auction_meta(PATHS, auction_id)


# ════════════════════════════════════════════════════════════════════
#  BID SUBMISSION
# ════════════════════════════════════════════════════════════════════

def submit_bid() -> None:
    ensure_base_dirs()
    header("Submit Bid")

    auction_id = choose_auction_id()
    meta       = _verify_meta(auction_id)
    state      = storage.get_auction_state(PATHS, auction_id)

    if state == storage.AUCTION_STATE_CLOSED:
        print(f"\n  [AUCTION CLOSED]  The deadline for this auction has passed.")
        print(f"\n  Deadline was : {meta.get('deadline_utc', '?')}")
        print(f"  Current time : {timeutil.isoformat_z(timeutil.now_utc(skip_ntp=True))}")
        print("\n  Bids can no longer be submitted.")
        pause()
        return

    if state == storage.AUCTION_STATE_REVEALED:
        _err("This auction is already REVEALED and complete.\n"
             "    -> No more bids can be submitted.")
        pause()
        return

    led          = ledger.Ledger(PATHS.auction_ledger(auction_id))
    last_ts      = led.get_last_timestamp()
    deadline_utc = timeutil.parse_deadline_any(meta["deadline_utc"])

    try:
        timeutil.ensure_before_deadline(deadline_utc, last_ledger_ts=last_ts)
    except RuntimeError as exc:
        raw = str(exc)
        if "SECURITY ALERT" in raw or "rollback" in raw.lower():
            _security_alert(raw)
        else:
            print(f"\n  [AUCTION CLOSED]  The deadline for this auction has passed.")
            print(f"\n  Deadline     : {timeutil.isoformat_z(deadline_utc)}")
            print(f"  Current time : {timeutil.isoformat_z(timeutil.now_utc(skip_ntp=True))}")
            print(f"\n  Bids can no longer be submitted.")
        pause()
        return

    bidder_id = prompt_nonempty("Bidder ID: ")

    if led.bidder_already_bid(bidder_id):
        _err(f"Bidder '{bidder_id}' has already submitted a bid in this auction.\n"
             "    -> Only one bid per bidder is allowed.")
        pause()
        return

    print(f"\n  Authenticating bidder '{bidder_id}'...")
    try:
        sk, pub_pem = authenticate_bidder(bidder_id, auction_id=auction_id)
    except RuntimeError as exc:
        _err(str(exc))
        pause()
        return

    min_bid = int(meta.get("min_bid", 1))
    max_bid = int(meta.get("max_bid", 10 ** 15))

    print(f"\n  Enter your bid amount:")
    if "min_bid" in meta or "max_bid" in meta:
        limits = []
        if "min_bid" in meta:
            limits.append(f"minimum: {min_bid:,}")
        if "max_bid" in meta:
            limits.append(f"maximum: {max_bid:,}")
        print(f"    Allowed range - {',  '.join(limits)}")
    else:
        print("    Any positive amount is accepted.")

    amount = prompt_int("  Bid amount: ", min_value=min_bid, max_value=max_bid)

    bid_id = uuid.uuid4().hex[:16]
    aad    = f"{auction_id}|{bid_id}".encode()

    bid_plain = {
        "auction_id": auction_id,
        "bid_id":     bid_id,
        "bidder_id":  bidder_id,
        "amount":     int(amount),
        "ts_utc":     timeutil.isoformat_z(timeutil.now_utc()),
    }
    hidden_nonce = os.urandom(32)
    commitment   = crypto.sha256_hex(crypto.canon_bytes(bid_plain) + hidden_nonce)

    bid_key    = bytearray(os.urandom(32))
    bid_cipher = crypto.aead_encrypt(
        bytes(bid_key),
        crypto.canon_bytes({"bid": bid_plain, "nonce_b64": crypto.b64e(hidden_nonce)}),
        aad=aad,
    )

    n_auth = int(meta["n"])
    t_auth = int(meta["t"])
    auth_ids  = list(meta["authority_ids"])
    auth_pems = dict(meta["authority_pubkeys_pem"])

    shares_xy      = shamir.split_secret(bytes(bid_key), t=t_auth, n=n_auth)
    sealed_shares: Dict[str, Any] = {}
    for (x, y), aid in zip(shares_xy, auth_ids):
        share_bytes       = crypto.canon_bytes({"x": x, "y_hex": hex(y)})
        auth_pub          = crypto.load_public_key_from_pem_str(auth_pems[aid])
        sealed_shares[aid] = crypto.seal_to_public(auth_pub, share_bytes, aad=aad)

    for i in range(len(bid_key)):
        bid_key[i] = 0

    pkg_unsigned = {
        "auction_id":        auction_id,
        "bid_id":            bid_id,
        "bidder_pubkey_pem": pub_pem,
        "commitment_sha256": commitment,
        "bid_cipher":        bid_cipher,
        "sealed_shares":     sealed_shares,
        "t": t_auth, "n": n_auth,
    }
    sig = crypto.sign(sk, crypto.canon_bytes(pkg_unsigned))
    bid_package = dict(pkg_unsigned)
    bid_package["bidder_sig_b64"] = sig

    led.append("BID_SUBMITTED", {
        "auction_id":        auction_id,
        "bid_id":            bid_id,
        "bidder_id":         bidder_id,
        "commitment_sha256": commitment,
    })
    storage.save_bid(PATHS, auction_id, bid_id, bid_package)

    # Human-readable receipt
    receipt = {
        "title":             "Bid Submission Receipt",
        "bid_id":            bid_id,
        "auction_id":        auction_id,
        "auction_name":      meta.get("name", ""),
        "bidder_id":         bidder_id,
        "submitted_at_utc":  bid_plain["ts_utc"],
        "submitted_at_lk":   timeutil.friendly_local(timeutil.now_utc(skip_ntp=True)),
        "commitment_sha256": commitment,
        "ledger_tip":        led.tip_hash(),
        "note": (
            "This receipt proves your bid was recorded before the deadline. "
            "The commitment hash cryptographically binds this receipt to your "
            "actual bid amount without revealing it."
        ),
    }
    receipt["bidder_sig_b64"] = crypto.sign(sk, crypto.canon_bytes(receipt))
    receipt_path = Path(f"receipt_{bid_id}.json")
    storage.write_pretty_json(receipt_path, receipt)

    logger.info("Bid submitted: auction=%s bid=%s bidder=%s", auction_id, bid_id, bidder_id)

    print(f"\n  +----------------------------------------------------------+")
    print(f"  |  Bid submitted and encrypted successfully!               |")
    print(f"  +----------------------------------------------------------+")
    print(f"  Bid ID     : {bid_id}")
    print(f"  Auction    : {meta.get('name')}  ({auction_id})")
    print(f"  Commitment : {commitment[:32]}...")
    print(f"\n  Receipt saved to: {receipt_path}")
    print("  -> Keep this file as cryptographic proof of your submission.")
    pause()


# ════════════════════════════════════════════════════════════════════
#  AUTHORITY UNLOCK
# ════════════════════════════════════════════════════════════════════

def _unlock_authority(auction_id: str, authority_id: str) -> Any:
    enc_path = PATHS.auction_authority_priv_enc(auction_id, authority_id)
    if not enc_path.exists():
        raise RuntimeError(
            f"Authority '{authority_id}' does not exist in this auction.\n"
            "    -> Check the authority IDs listed above."
        )
    storage.check_not_locked(PATHS, auction_id, authority_id, is_authority=True)

    enc_obj  = storage.read_json(enc_path)
    password = _getpass(f"Password for authority '{authority_id}': ")
    aad      = f"authority|{auction_id}|{authority_id}".encode()

    try:
        sk = crypto.decrypt_private_key_pem(enc_obj, password, aad=aad)
        storage.reset_failed_attempts(PATHS, auction_id, authority_id, is_authority=True)
        return sk
    except Exception:
        remaining = storage.record_failed_attempt(PATHS, auction_id, authority_id, is_authority=True)
        logger.warning("SECURITY: Failed auth authority '%s' auction '%s'. Remaining: %d",
                       authority_id, auction_id, remaining)
        if remaining == 0:
            raise RuntimeError(
                f"Wrong password for authority '{authority_id}'.\n"
                "    -> Account is now LOCKED."
            )
        raise RuntimeError(
            f"Wrong password for authority '{authority_id}'.\n"
            f"    -> {remaining} attempt(s) remaining before this account is locked."
        )


# ════════════════════════════════════════════════════════════════════
#  AUDITOR REVEAL
# ════════════════════════════════════════════════════════════════════

def auditor_reveal_and_winner() -> None:
    ensure_base_dirs()
    header("Auditor: Reveal Bids & Determine Winner")

    auction_id = choose_auction_id()

    try:
        meta = _verify_meta(auction_id)
    except RuntimeError as exc:
        _security_alert(str(exc))
        print("  This auction cannot be safely revealed. Contact administrator.")
        pause()
        return

    led = ledger.Ledger(PATHS.auction_ledger(auction_id))

    if led.is_revealed():
        _err("This auction has already been revealed.\n"
             "    -> The winner was already announced.")
        pause()
        return

    ok, ledger_msg = led.verify()
    if not ok:
        _security_alert(
            f"Ledger integrity check FAILED:\n\n  {ledger_msg}\n\n"
            "  The audit log may have been tampered with."
        )
        pause()
        return
    print(f"\n  [OK] Ledger integrity verified - {ledger_msg}")

    last_ts      = led.get_last_timestamp()
    deadline_utc = timeutil.parse_deadline_any(meta["deadline_utc"])

    try:
        timeutil.ensure_after_deadline(deadline_utc, last_ledger_ts=last_ts)
    except RuntimeError as exc:
        raw = str(exc)
        if "SECURITY ALERT" in raw or "rollback" in raw.lower():
            _security_alert(raw)
            pause()
            return

        # Deadline has not passed — show clear, friendly message
        now_dt      = timeutil.now_utc(skip_ntp=True)
        remaining   = timeutil.human_remaining(deadline_utc)
        deadline_lk = timeutil.friendly_local(deadline_utc)
        now_lk      = timeutil.friendly_local(now_dt)

        print(f"\n  +----------------------------------------------------------+")
        print(f"  |  CANNOT REVEAL BIDS YET - Auction is still OPEN         |")
        print(f"  +----------------------------------------------------------+")
        print(f"\n  The auction deadline has not passed yet.\n")
        print(f"  Auction deadline   : {timeutil.isoformat_z(deadline_utc)}")
        print(f"  Deadline (LK time) : {deadline_lk}")
        print(f"  Current time (LK)  : {now_lk}")
        print(f"  Time remaining     : {remaining}")
        print(f"\n  -> Please wait until the deadline has passed, then try again.")
        pause()
        return

    bid_ids = storage.list_bid_ids(PATHS, auction_id)
    if not bid_ids:
        print("\n  No bids were submitted to this auction.")
        pause()
        return

    t             = int(meta["t"])
    n_auth        = int(meta["n"])
    authority_ids = list(meta["authority_ids"])

    print(f"\n  Auction      : {meta.get('name')}  ({auction_id})")
    print(f"  Deadline     : {meta.get('deadline_utc')}")
    print(f"  Threshold    : {t} of {n_auth} authorities must provide passwords")
    print(f"  Total bids   : {len(bid_ids)}")
    print(f"\n  Authorities  : {', '.join(authority_ids)}")
    print(f"\n  At least {t} authority/authorities must now enter their password(s).")

    selected: List[str] = []
    while len(selected) < t:
        need    = t - len(selected)
        auth_id = prompt_nonempty(
            f"Enter authority ID  [{len(selected)} done, {need} more needed]: "
        )
        if auth_id not in authority_ids:
            _err(f"'{auth_id}' is not a valid authority.\n"
                 f"    Valid IDs: {', '.join(authority_ids)}")
            continue
        if auth_id in selected:
            _err(f"Authority '{auth_id}' has already been entered.")
            continue
        selected.append(auth_id)

    unlocked: Dict[str, Any] = {}
    print(f"\n  Unlocking authority keys...")
    for auth_id in selected:
        try:
            unlocked[auth_id] = _unlock_authority(auction_id, auth_id)
            print(f"  [OK] '{auth_id}' unlocked.")
        except RuntimeError as exc:
            _err(f"Could not unlock '{auth_id}':\n    {exc}\n    Reveal aborted.")
            pause()
            return

    print(f"\n  Decrypting {len(bid_ids)} bid(s)...")
    decrypted_bids: List[Dict[str, Any]] = []
    errors:         List[str]            = []

    for bid_id in bid_ids:
        try:
            bid_obj   = storage.load_bid(PATHS, auction_id, bid_id)
            bidder_pk = crypto.load_public_key_from_pem_str(bid_obj["bidder_pubkey_pem"])
            signed_part = {k: v for k, v in bid_obj.items() if k != "bidder_sig_b64"}
            if not crypto.verify(bidder_pk, crypto.canon_bytes(signed_part),
                                 bid_obj["bidder_sig_b64"]):
                raise RuntimeError("Bidder signature is invalid - bid may have been tampered with.")

            aad       = f"{auction_id}|{bid_id}".encode()
            shares_xy: List[Tuple[int, int]] = []

            for auth_id, auth_sk in unlocked.items():
                sealed = bid_obj["sealed_shares"].get(auth_id)
                if sealed is None:
                    continue
                sobj = json_load_bytes(crypto.open_with_private(auth_sk, sealed, aad=aad))
                shares_xy.append((int(sobj["x"]), int(sobj["y_hex"], 16)))

            if len(shares_xy) < t:
                raise RuntimeError(f"Only {len(shares_xy)} share(s) collected, need {t}.")

            bid_key     = bytearray(shamir.reconstruct_secret(shares_xy[:t], out_len=32))
            payload_raw = crypto.aead_decrypt(bytes(bid_key), bid_obj["bid_cipher"], aad=aad)
            for i in range(len(bid_key)):
                bid_key[i] = 0

            payload      = json_load_bytes(payload_raw)
            bid_plain    = payload["bid"]
            hidden_nonce = crypto.b64d(payload["nonce_b64"])

            commit_calc = crypto.sha256_hex(crypto.canon_bytes(bid_plain) + hidden_nonce)
            if commit_calc != bid_obj["commitment_sha256"]:
                raise RuntimeError(
                    "Commitment mismatch - bid content does not match the recorded commitment."
                )
            decrypted_bids.append(bid_plain)

        except Exception as exc:
            msg = f"Bid {bid_id}: {exc}"
            errors.append(msg)
            logger.error("Decrypt failed - %s", msg)

    if not decrypted_bids:
        _err("No bids could be decrypted. Check audit.log for details.")
        pause()
        return

    if errors:
        print(f"\n  [WARNING] {len(errors)} bid(s) failed to decrypt:")
        for e in errors:
            print(f"    * {e}")

    sorted_bids = sorted(decrypted_bids, key=lambda b: int(b["amount"]))
    winner      = sorted_bids[0]

    led.append("AUCTION_REVEALED", {
        "auction_id":               auction_id,
        "winner_bid_id":            winner["bid_id"],
        "winner_bidder_id":         winner["bidder_id"],
        "winner_amount":            winner["amount"],
        "bids_decrypted":           len(decrypted_bids),
        "bids_failed":              len(errors),
        "authorities_participated": selected,
    })

    # Human-readable reveal record
    reveal_record = {
        "title":                    "Auction Reveal Record",
        "auction_id":               auction_id,
        "auction_name":             meta.get("name", ""),
        "deadline_utc":             meta.get("deadline_utc", ""),
        "revealed_at_utc":          timeutil.isoformat_z(timeutil.now_utc()),
        "revealed_at_lk":           timeutil.friendly_local(timeutil.now_utc(skip_ntp=True)),
        "threshold":                f"{t} of {n_auth}",
        "authorities_participated": selected,
        "total_bids_submitted":     len(bid_ids),
        "total_bids_decrypted":     len(decrypted_bids),
        "total_bids_failed":        len(errors),
        "winner": {
            "bidder_id":  winner["bidder_id"],
            "bid_id":     winner["bid_id"],
            "amount":     winner["amount"],
            "bid_placed": winner.get("ts_utc", ""),
        },
        "all_bids_ranked_lowest_first": [
            {
                "rank":      rank,
                "bidder_id": b["bidder_id"],
                "bid_id":    b["bid_id"],
                "amount":    b["amount"],
                "is_winner": b["bid_id"] == winner["bid_id"],
            }
            for rank, b in enumerate(sorted_bids, start=1)
        ],
        "ledger_integrity": ledger_msg,
        "ledger_tip":       led.tip_hash(),
        "note": (
            "This record is produced by the sealed-bid auction system. "
            "All bids were encrypted until reveal time. "
            "The winner is the bidder who submitted the LOWEST valid bid amount. "
            "Anyone can verify the winner independently using this file."
        ),
    }
    reveal_path = Path(f"reveal_{auction_id}.json")
    storage.write_pretty_json(reveal_path, reveal_record)

    logger.info("Auction revealed: %s winner=%s amount=%s",
                auction_id, winner["bidder_id"], winner["amount"])

    # On-screen result
    print(f"\n  +----------------------------------------------------------+")
    print(f"  |  REVEAL COMPLETE                                         |")
    print(f"  +----------------------------------------------------------+")
    print(f"\n  Auction  : {meta.get('name')}  ({auction_id})")
    print(f"  Deadline : {meta.get('deadline_utc')}")
    print(f"  Bids     : {len(decrypted_bids)} decrypted of {len(bid_ids)} submitted")

    print(f"\n  -- All Bids (lowest to highest) ----------------------------")
    for rank, b in enumerate(sorted_bids, 1):
        tag = "  <-- WINNER" if b["bid_id"] == winner["bid_id"] else ""
        print(f"    #{rank}  Bidder: {b['bidder_id']:<14}  Amount: {b['amount']:>15,}{tag}")

    print(f"\n  +----------------------------------------------------------+")
    print(f"  |  WINNER                                                  |")
    print(f"  +----------------------------------------------------------+")
    print(f"  Bidder ID : {winner['bidder_id']}")
    print(f"  Amount    : {winner['amount']:,}")
    print(f"  Bid ID    : {winner['bid_id']}")
    print(f"\n  Ledger    : {ledger_msg}")
    print(f"  Record    : {reveal_path}  (readable JSON, for independent verification)")
    pause()


# ════════════════════════════════════════════════════════════════════
#  LEDGER VERIFY
# ════════════════════════════════════════════════════════════════════

def verify_ledger() -> None:
    header("Verify Ledger Integrity")
    auction_id = choose_auction_id()

    try:
        _verify_meta(auction_id)
        _ok("meta.json integrity verified against ledger commitment.")
    except RuntimeError as exc:
        _security_alert(str(exc))
        pause()
        return

    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    ok, msg = led.verify()

    if ok:
        _ok(f"Ledger is intact - {msg}")
        print(f"\n  All recorded events:")
        print(f"  {'#':<5} {'Timestamp (UTC)':<28} Event")
        print("  " + "-" * 58)
        for e in led.iter_events():
            print(f"  [{e['i']}]   {e['ts']:<28} {e['type']}")
    else:
        _security_alert(f"Ledger verification FAILED:\n\n  {msg}")

    pause()


# ════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ════════════════════════════════════════════════════════════════════

def main_menu() -> None:
    ensure_base_dirs()
    run_ntp_check()

    while True:
        header("Sealed-Bid Auction System")
        print("  1)  Register Bidder")
        print("  2)  Create Auction")
        print("  3)  Submit Bid")
        print("  4)  Reveal Bids & Determine Winner  (Auditor)")
        print("  5)  Verify Ledger Integrity")
        print("  6)  Exit")

        choice = prompt_int("Choose: ", min_value=1, max_value=6)

        try:
            if   choice == 1: register_bidder()
            elif choice == 2: create_auction()
            elif choice == 3: submit_bid()
            elif choice == 4: auditor_reveal_and_winner()
            elif choice == 5: verify_ledger()
            else:
                print("\n  Goodbye.")
                return
        except KeyboardInterrupt:
            print("\n  [Interrupted]")
        except Exception as exc:
            logger.error("Unhandled error: %s", exc, exc_info=True)
            print(f"\n  [ERROR] {exc}")
            pause()


if __name__ == "__main__":
    main_menu()