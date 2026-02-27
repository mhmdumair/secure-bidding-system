from __future__ import annotations

import logging
import os
import sys
import uuid
import json
import getpass
import signal
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization

from core import crypto, ledger, shamir, storage, timeutil

# Configure logging — file + stderr warnings
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("audit.log", encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger(__name__)

STORE_ROOT = Path("store")
PATHS = storage.StorePaths(STORE_ROOT)

# Password prompt timeout (seconds) — prevents unattended terminal exposure
PASSWORD_TIMEOUT = 60


# ------------------------------------------------------------------ #
#  Console helpers                                                     #
# ------------------------------------------------------------------ #

def ensure_base_dirs() -> None:
    PATHS.auctions_dir.mkdir(parents=True, exist_ok=True)
    PATHS.users_dir.mkdir(parents=True, exist_ok=True)
    PATHS.bidders_dir().mkdir(parents=True, exist_ok=True)


def header(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def pause() -> None:
    input("\nPress Enter to continue...")


def confirm(prompt: str) -> bool:
    while True:
        ans = input(f"{prompt} (Y/N): ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please enter Y or N.")


def prompt_nonempty(prompt: str) -> str:
    while True:
        v = input(prompt).strip()
        if v:
            return v
        print("Input cannot be empty.")


def prompt_int(prompt: str, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
    while True:
        s = input(prompt).strip()
        try:
            v = int(s)
        except ValueError:
            print("Please enter a valid integer.")
            continue
        if min_value is not None and v < min_value:
            print(f"Must be >= {min_value}.")
            continue
        if max_value is not None and v > max_value:
            print(f"Must be <= {max_value}.")
            continue
        return v


def _timeout_handler(signum, frame):
    print("\n[TIMEOUT] Password prompt timed out. Exiting for security.")
    sys.exit(1)


def prompt_password_with_timeout(prompt: str) -> str:
    """
    Prompt for password with a timeout to prevent unattended terminal exposure.
    Falls back to plain getpass on Windows (no SIGALRM).
    """
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(PASSWORD_TIMEOUT)
        try:
            pw = getpass.getpass(prompt)
        finally:
            signal.alarm(0)
        return pw
    else:
        return getpass.getpass(prompt)


def prompt_deadline_human_to_utc_z() -> str:
    while True:
        raw = input("Deadline (e.g. '2026-02-04 14:45:00' local LK, or 'in 5 minutes'): ").strip()
        try:
            dt_utc = timeutil.parse_deadline_any(raw)
            utc_str = timeutil.isoformat_z(dt_utc)
            print(f"→ Stored as UTC: {utc_str}")
            if confirm("Use this deadline?"):
                return utc_str
        except Exception as e:
            print(f"Invalid deadline: {e}")


def json_load_bytes(b: bytes) -> Any:
    return json.loads(b.decode("utf-8"))


def pem_public_key_str(pk) -> str:
    return crypto.public_key_pem_str(pk)


# ------------------------------------------------------------------ #
#  NTP check at startup                                                #
# ------------------------------------------------------------------ #

def run_ntp_check() -> None:
    print("Checking time integrity against NTP servers...")
    result = timeutil.verify_ntp_sync()
    if result["ok"]:
        print(f"[OK] {result['message']}")
    else:
        print(f"[WARNING] {result['message']}")
        if not confirm("NTP check failed. Time-sensitive operations may be unsafe. Continue anyway?"):
            sys.exit(1)


# ------------------------------------------------------------------ #
#  Auction selection                                                   #
# ------------------------------------------------------------------ #

def list_auctions_pretty() -> List[Tuple[str, Dict[str, Any]]]:
    auction_ids = storage.list_auction_ids(PATHS)
    out: List[Tuple[str, Dict[str, Any]]] = []
    for auction_id in auction_ids:
        try:
            meta = storage.load_auction_meta(PATHS, auction_id)
            out.append((auction_id, meta))
        except Exception:
            continue
    return out


def choose_auction_id() -> str:
    auctions = list_auctions_pretty()
    if not auctions:
        raise RuntimeError("No auctions found. Create an auction first.")

    print("\nAvailable Auctions:")
    for i, (auction_id, meta) in enumerate(auctions, start=1):
        state = storage.get_auction_state(PATHS, auction_id)
        print(
            f"  [{i}] {auction_id}  |  {meta.get('name','?')}  "
            f"|  deadline={meta.get('deadline_utc','?')}  |  state={state}"
        )

    idx = prompt_int("Select auction number: ", min_value=1, max_value=len(auctions))
    return auctions[idx - 1][0]


# ------------------------------------------------------------------ #
#  Bidder registration                                                 #
# ------------------------------------------------------------------ #

def register_bidder() -> None:
    ensure_base_dirs()
    header("Register Bidder")

    bidder_id = prompt_nonempty("Choose a bidder ID (e.g. B1, U1): ")
    if storage.bidder_exists(PATHS, bidder_id):
        print("[ERROR] Bidder ID already exists. Choose another.")
        return

    bidder_name = prompt_nonempty("Bidder name: ")

    password1 = prompt_password_with_timeout("Create password: ")
    password2 = prompt_password_with_timeout("Confirm password: ")
    if not password1 or password1 != password2:
        print("[ERROR] Passwords do not match or are empty.")
        return

    bidder_private, bidder_public = crypto.gen_ecdsa_keypair()

    bidder_dir = PATHS.bidder_dir(bidder_id)
    bidder_dir.mkdir(parents=True, exist_ok=True)

    pub_pem = pem_public_key_str(bidder_public)
    fingerprint = crypto.public_key_fingerprint(bidder_public)
    PATHS.bidder_pub(bidder_id).write_text(pub_pem, encoding="utf-8")

    # Encrypt private key with bidder-scoped AAD (is_authority=False → lower Scrypt cost)
    aad = f"bidder|{bidder_id}".encode("utf-8")
    enc_priv = crypto.encrypt_private_key_pem(bidder_private, password1, aad=aad, is_authority=False)
    storage.save_bidder_priv_enc(PATHS, bidder_id, enc_priv)

    profile = {
        "bidder_id": bidder_id,
        "name": bidder_name,
        "pubkey_pem": pub_pem,
        "pubkey_fingerprint": fingerprint,
        "created_at_utc": timeutil.isoformat_z(timeutil.now_utc()),
    }
    storage.save_bidder_profile(PATHS, bidder_id, profile)

    logger.info("Bidder registered: %s (%s)", bidder_id, bidder_name)
    print("[OK] Bidder registered.")
    print(f"  Bidder ID:          {bidder_id}")
    print(f"  Public key SHA-256: {fingerprint}")
    print("  Keep your password safe — it cannot be recovered.")
    pause()


def authenticate_bidder(bidder_id: str, auction_id: Optional[str] = None) -> Tuple[Any, str]:
    """
    Returns (private_key, pubkey_pem) if password correct.
    Enforces lockout after MAX_FAILED_ATTEMPTS.
    """
    if not storage.bidder_exists(PATHS, bidder_id):
        raise RuntimeError("Bidder not registered.")

    # Check lockout before prompting
    storage.check_not_locked(PATHS, None, bidder_id, is_authority=False)

    profile = storage.load_bidder_profile(PATHS, bidder_id)
    pub_pem = profile["pubkey_pem"]
    enc_priv = storage.load_bidder_priv_enc(PATHS, bidder_id)

    password = prompt_password_with_timeout("Password: ")
    aad = f"bidder|{bidder_id}".encode("utf-8")

    try:
        sk = crypto.decrypt_private_key_pem(enc_priv, password, aad=aad)
        storage.reset_failed_attempts(PATHS, None, bidder_id, is_authority=False)
        return sk, pub_pem
    except Exception:
        remaining = storage.record_failed_attempt(PATHS, None, bidder_id, is_authority=False)
        logger.warning("Failed auth for bidder '%s'. Remaining attempts: %d", bidder_id, remaining)
        if remaining == 0:
            raise RuntimeError("Invalid password. Account is now LOCKED. Contact administrator.")
        raise RuntimeError(f"Invalid password. {remaining} attempt(s) remaining before lockout.")


# ------------------------------------------------------------------ #
#  Auction creation                                                    #
# ------------------------------------------------------------------ #

def create_auction() -> None:
    ensure_base_dirs()
    header("Create Auction")

    auction_name = prompt_nonempty("Auction name: ")
    deadline_utc_str = prompt_deadline_human_to_utc_z()

    num_authorities = prompt_int("Number of authorities (n): ", min_value=2)
    threshold_t = prompt_int(
        f"Threshold (t) — minimum authorities needed to reveal (2 <= t <= {num_authorities}): ",
        min_value=2,
        max_value=num_authorities,
    )

    auction_id = uuid.uuid4().hex[:16]
    authorities_root = PATHS.auction_authorities_dir(auction_id)
    authorities_root.mkdir(parents=True, exist_ok=True)

    authority_ids: List[str] = []
    authority_pubkeys: Dict[str, str] = {}
    authority_fingerprints: Dict[str, str] = {}

    print("\nAuthority setup:")
    for i in range(1, num_authorities + 1):
        auth_id = prompt_nonempty(f"Authority {i} ID (e.g. A1): ")
        if auth_id in authority_ids:
            print("[ERROR] Duplicate authority ID.")
            return
        authority_ids.append(auth_id)

        auth_password1 = prompt_password_with_timeout(f"Create password for {auth_id}: ")
        auth_password2 = prompt_password_with_timeout(f"Confirm password for {auth_id}: ")
        if not auth_password1 or auth_password1 != auth_password2:
            raise RuntimeError("Authority password mismatch or empty. Restart.")

        auth_private, auth_public = crypto.gen_ecdsa_keypair()

        pub_pem = pem_public_key_str(auth_public)
        fingerprint = crypto.public_key_fingerprint(auth_public)
        auth_dir = PATHS.auction_authority_dir(auction_id, auth_id)
        auth_dir.mkdir(parents=True, exist_ok=True)
        PATHS.auction_authority_pub(auction_id, auth_id).write_text(pub_pem, encoding="utf-8")

        authority_pubkeys[auth_id] = pub_pem
        authority_fingerprints[auth_id] = fingerprint

        # Authority keys get higher Scrypt cost (is_authority=True)
        aad = f"authority|{auction_id}|{auth_id}".encode("utf-8")
        enc_priv = crypto.encrypt_private_key_pem(auth_private, auth_password1, aad=aad, is_authority=True)
        storage.write_json(PATHS.auction_authority_priv_enc(auction_id, auth_id), enc_priv)

        print(f"  [{auth_id}] Key fingerprint: {fingerprint}")

    # Build meta WITHOUT meta_hash first
    meta: Dict[str, Any] = {
        "auction_id": auction_id,
        "name": auction_name,
        "deadline_utc": deadline_utc_str,
        "n": num_authorities,
        "t": threshold_t,
        "authority_ids": authority_ids,
        "authority_pubkeys_pem": authority_pubkeys,
        "authority_fingerprints": authority_fingerprints,
        "created_at_utc": timeutil.isoformat_z(timeutil.now_utc()),
        "state": storage.AUCTION_STATE_OPEN,
        "crypto": {
            "bid_aead": "ChaCha20-Poly1305",
            "sealed_share": "ECDH(P-256)+HKDF-SHA256+ChaCha20-Poly1305",
            "sign": "ECDSA(P-256)+SHA256",
            "shamir": "GF(p) p=2^521-1",
            "authority_kdf": "scrypt(N=2^20,r=8,p=1)",
            "bidder_kdf": "scrypt(N=2^17,r=8,p=1)",
        },
    }

    # Compute canonical hash of meta and embed it
    meta_hash = crypto.hash_meta(meta)
    meta["meta_hash"] = meta_hash

    storage.save_auction_meta(PATHS, auction_id, meta)

    # Commit meta_hash to the ledger — this is the tamper-detection anchor
    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    led.append("AUCTION_CREATED", {
        "auction_id": auction_id,
        "name": auction_name,
        "deadline_utc": deadline_utc_str,
        "meta_hash": meta_hash,          # ← Critical: committed to hash chain
        "t": threshold_t,
        "n": num_authorities,
    })

    print(f"\n[OK] Auction created")
    print(f"  auction_id:   {auction_id}")
    print(f"  deadline_utc: {deadline_utc_str}")
    print(f"  threshold:    t={threshold_t} of n={num_authorities}")
    print(f"  meta_hash:    {meta_hash[:32]}...")
    print("\n  Authority fingerprints (verify these out-of-band with each authority):")
    for auth_id, fp in authority_fingerprints.items():
        print(f"    {auth_id}: {fp}")
    pause()


# ------------------------------------------------------------------ #
#  Meta integrity verification (called before every sensitive op)      #
# ------------------------------------------------------------------ #

def _verify_auction_meta_integrity(auction_id: str) -> Dict[str, Any]:
    """
    Load meta.json and verify it hasn't been tampered with.
    Raises RuntimeError on mismatch.
    Returns meta dict.
    """
    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    committed_hash = led.get_committed_meta_hash()
    storage.verify_meta_integrity(PATHS, auction_id, committed_hash)
    return storage.load_auction_meta(PATHS, auction_id)


# ------------------------------------------------------------------ #
#  Bid submission                                                      #
# ------------------------------------------------------------------ #

def submit_bid() -> None:
    ensure_base_dirs()
    header("Submit Bid (Registered Bidder Only)")

    auction_id = choose_auction_id()

    # Verify meta integrity before trusting deadline / authority keys
    meta = _verify_auction_meta_integrity(auction_id)

    # Check auction state
    state = storage.get_auction_state(PATHS, auction_id)
    if state != storage.AUCTION_STATE_OPEN:
        print(f"[ERROR] Auction is not open (state={state}). Cannot submit bid.")
        pause()
        return

    # Get last ledger timestamp for rollback protection
    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    last_ts = led.get_last_timestamp()

    deadline_utc = timeutil.parse_deadline_any(meta["deadline_utc"])
    timeutil.ensure_before_deadline(deadline_utc, last_ledger_ts=last_ts)

    bidder_id = prompt_nonempty("Bidder ID: ")

    # Prevent duplicate bids from same bidder
    if led.bidder_already_bid(bidder_id):
        print(f"[ERROR] Bidder '{bidder_id}' has already submitted a bid in this auction.")
        pause()
        return

    print("Authentication required:")
    bidder_private_key, bidder_pub_pem = authenticate_bidder(bidder_id, auction_id=auction_id)

    # Validate bid amount
    min_bid = int(meta.get("min_bid", 1))
    max_bid = int(meta.get("max_bid", 10 ** 15))
    amount = prompt_int(f"Bid amount (integer, {min_bid} - {max_bid}): ", min_value=min_bid, max_value=max_bid)

    bid_id = uuid.uuid4().hex[:16]
    aad = f"{auction_id}|{bid_id}".encode("utf-8")

    bid_plain = {
        "auction_id": auction_id,
        "bid_id": bid_id,
        "bidder_id": bidder_id,
        "amount": int(amount),
        "ts_utc": timeutil.isoformat_z(timeutil.now_utc()),
    }

    # Commitment: binds bid content to a hidden nonce, prevents later modification
    hidden_nonce = os.urandom(32)   # Increased from 16 to 32 bytes
    commitment = crypto.sha256_hex(crypto.canon_bytes(bid_plain) + hidden_nonce)

    # Per-bid symmetric encryption key (never stored directly)
    bid_key = bytearray(os.urandom(32))
    bid_cipher = crypto.aead_encrypt(bytes(bid_key), crypto.canon_bytes({
        "bid": bid_plain,
        "nonce_b64": crypto.b64e(hidden_nonce),
    }), aad=aad)

    # Split bid_key via Shamir and seal each share to its authority's public key
    n = int(meta["n"])
    t = int(meta["t"])
    authority_ids: List[str] = list(meta["authority_ids"])
    authority_pub_pems: Dict[str, str] = dict(meta["authority_pubkeys_pem"])

    shares_xy = shamir.split_secret(bytes(bid_key), t=t, n=n)
    sealed_shares: Dict[str, Any] = {}

    for (x, y), auth_id in zip(shares_xy, authority_ids):
        share_obj = {"x": x, "y_hex": hex(y)}
        share_bytes = crypto.canon_bytes(share_obj)
        auth_pub = crypto.load_public_key_from_pem_str(authority_pub_pems[auth_id])
        sealed = crypto.seal_to_public(auth_pub, share_bytes, aad=aad)
        sealed_shares[auth_id] = sealed

    # Zero bid_key from memory immediately after use
    for i in range(len(bid_key)):
        bid_key[i] = 0

    bid_package_unsigned = {
        "auction_id": auction_id,
        "bid_id": bid_id,
        "bidder_pubkey_pem": bidder_pub_pem,
        "commitment_sha256": commitment,
        "bid_cipher": bid_cipher,
        "sealed_shares": sealed_shares,
        "t": t,
        "n": n,
    }

    signature = crypto.sign(bidder_private_key, crypto.canon_bytes(bid_package_unsigned))
    bid_package = dict(bid_package_unsigned)
    bid_package["bidder_sig_b64"] = signature

    # Record intent to ledger BEFORE writing bid file (so partial writes are detectable)
    led.append("BID_SUBMITTED", {
        "auction_id": auction_id,
        "bid_id": bid_id,
        "bidder_id": bidder_id,
        "commitment_sha256": commitment,
    })

    storage.save_bid(PATHS, auction_id, bid_id, bid_package)

    # Generate signed receipt for the bidder
    receipt = {
        "bid_id": bid_id,
        "auction_id": auction_id,
        "bidder_id": bidder_id,
        "commitment_sha256": commitment,
        "submitted_at_utc": bid_plain["ts_utc"],
        "ledger_tip": led.tip_hash(),
    }
    receipt_sig = crypto.sign(bidder_private_key, crypto.canon_bytes(receipt))
    receipt["bidder_sig_b64"] = receipt_sig

    receipt_path = Path(f"receipt_{bid_id}.json")
    storage.write_json(receipt_path, receipt)

    logger.info("Bid submitted: auction=%s bid=%s bidder=%s", auction_id, bid_id, bidder_id)
    print("\n[OK] Bid submitted (encrypted)")
    print(f"  auction_id:  {auction_id}")
    print(f"  bid_id:      {bid_id}")
    print(f"  commitment:  {commitment[:32]}...")
    print(f"  receipt:     {receipt_path}  ← keep this as proof of submission")
    pause()


# ------------------------------------------------------------------ #
#  Authority unlock                                                    #
# ------------------------------------------------------------------ #

def _unlock_authority_private_key(auction_id: str, authority_id: str) -> Any:
    """
    Prompt password and decrypt authority private key.
    Enforces lockout after MAX_FAILED_ATTEMPTS.
    """
    enc_path = PATHS.auction_authority_priv_enc(auction_id, authority_id)
    if not enc_path.exists():
        raise RuntimeError(f"Authority '{authority_id}' not found in auction '{auction_id}'.")

    # Check lockout
    storage.check_not_locked(PATHS, auction_id, authority_id, is_authority=True)

    enc_obj = storage.read_json(enc_path)
    password = prompt_password_with_timeout(f"Password for authority {authority_id}: ")
    aad = f"authority|{auction_id}|{authority_id}".encode("utf-8")

    try:
        sk = crypto.decrypt_private_key_pem(enc_obj, password, aad=aad)
        storage.reset_failed_attempts(PATHS, auction_id, authority_id, is_authority=True)
        return sk
    except Exception:
        remaining = storage.record_failed_attempt(PATHS, auction_id, authority_id, is_authority=True)
        logger.warning(
            "SECURITY: Failed auth for authority '%s' in auction '%s'. Remaining: %d",
            authority_id, auction_id, remaining,
        )
        if remaining == 0:
            raise RuntimeError(f"Invalid password for {authority_id}. Account LOCKED.")
        raise RuntimeError(f"Invalid password for {authority_id}. {remaining} attempt(s) remaining.")


# ------------------------------------------------------------------ #
#  Auditor reveal                                                      #
# ------------------------------------------------------------------ #

def auditor_reveal_and_winner() -> None:
    ensure_base_dirs()
    header("Auditor: Reveal Bids & Determine Winner")

    auction_id = choose_auction_id()

    # --- Verify meta integrity ---
    meta = _verify_auction_meta_integrity(auction_id)

    # --- State check ---
    led = ledger.Ledger(PATHS.auction_ledger(auction_id))

    if led.is_revealed():
        print("[ERROR] Auction has already been revealed.")
        pause()
        return

    # --- Ledger integrity ---
    ok, msg = led.verify()
    if not ok:
        raise RuntimeError(f"Ledger verification FAILED: {msg}")
    print(f"[OK] Ledger integrity: {msg}")

    # --- Deadline enforcement with rollback protection ---
    last_ts = led.get_last_timestamp()
    deadline_utc = timeutil.parse_deadline_any(meta["deadline_utc"])
    timeutil.ensure_after_deadline(deadline_utc, last_ledger_ts=last_ts)

    bid_ids = storage.list_bid_ids(PATHS, auction_id)
    if not bid_ids:
        print("No bids found.")
        pause()
        return

    t = int(meta["t"])
    authority_ids: List[str] = list(meta["authority_ids"])

    print(f"\nAuction:    {meta.get('name')} ({auction_id})")
    print(f"Deadline:   {meta.get('deadline_utc')}")
    print(f"Threshold:  t={t} of n={meta.get('n')}")
    print(f"Total bids: {len(bid_ids)}")
    print(f"\nAuthorities: {', '.join(authority_ids)}")
    print(f"\nAt least {t} authorities must unlock their keys.")

    # --- Collect authority keys ---
    selected: List[str] = []
    while len(selected) < t:
        auth_id = prompt_nonempty(f"Enter authority ID to unlock ({len(selected)}/{t} done): ")
        if auth_id not in authority_ids:
            print(f"'{auth_id}' is not a valid authority for this auction.")
            continue
        if auth_id in selected:
            print("Already selected.")
            continue
        selected.append(auth_id)

    unlocked_authorities: Dict[str, Any] = {}
    for auth_id in selected:
        try:
            unlocked_authorities[auth_id] = _unlock_authority_private_key(auction_id, auth_id)
            print(f"  [{auth_id}] Unlocked successfully.")
        except RuntimeError as e:
            print(f"  [{auth_id}] FAILED: {e}")
            pause()
            return

    # --- Decrypt each bid ---
    decrypted_bids: List[Dict[str, Any]] = []
    errors: List[str] = []

    for bid_id in bid_ids:
        try:
            bid_obj = storage.load_bid(PATHS, auction_id, bid_id)

            # Verify bidder signature
            bidder_pk = crypto.load_public_key_from_pem_str(bid_obj["bidder_pubkey_pem"])
            signed_part = {k: bid_obj[k] for k in bid_obj if k != "bidder_sig_b64"}
            if not crypto.verify(bidder_pk, crypto.canon_bytes(signed_part), bid_obj["bidder_sig_b64"]):
                raise RuntimeError("Invalid bidder signature")

            aad = f"{auction_id}|{bid_id}".encode("utf-8")

            # Collect Shamir shares from unlocked authorities
            shares_xy: List[Tuple[int, int]] = []
            for auth_id, auth_sk in unlocked_authorities.items():
                sealed = bid_obj["sealed_shares"].get(auth_id)
                if sealed is None:
                    continue
                share_bytes = crypto.open_with_private(auth_sk, sealed, aad=aad)
                share_obj = json_load_bytes(share_bytes)
                x = int(share_obj["x"])
                y = int(share_obj["y_hex"], 16)
                shares_xy.append((x, y))

            if len(shares_xy) < t:
                raise RuntimeError(f"Only {len(shares_xy)} shares collected, need {t}")

            # Reconstruct bid_key and decrypt
            bid_key = bytearray(shamir.reconstruct_secret(shares_xy[:t], out_len=32))
            payload_bytes = crypto.aead_decrypt(bytes(bid_key), bid_obj["bid_cipher"], aad=aad)

            # Zero bid_key immediately
            for i in range(len(bid_key)):
                bid_key[i] = 0

            payload = json_load_bytes(payload_bytes)
            bid_plain = payload["bid"]
            hidden_nonce = crypto.b64d(payload["nonce_b64"])

            # Verify commitment
            commit_calc = crypto.sha256_hex(crypto.canon_bytes(bid_plain) + hidden_nonce)
            if commit_calc != bid_obj["commitment_sha256"]:
                raise RuntimeError("Commitment mismatch — bid may have been tampered with")

            decrypted_bids.append(bid_plain)

        except Exception as e:
            error_msg = f"Failed to decrypt bid {bid_id}: {e}"
            errors.append(error_msg)
            logger.error(error_msg)

    if not decrypted_bids:
        raise RuntimeError("No bids could be decrypted. Check errors above.")

    if errors:
        print(f"\n[WARNING] {len(errors)} bid(s) could not be decrypted:")
        for err in errors:
            print(f"  - {err}")

    # --- Determine winner (lowest bid) ---
    winner = min(decrypted_bids, key=lambda b: int(b["amount"]))

    # --- Publish all decrypted bids for independent verification ---
    reveal_record = {
        "auction_id": auction_id,
        "revealed_at_utc": timeutil.isoformat_z(timeutil.now_utc()),
        "authorities_participated": selected,
        "total_bids": len(bid_ids),
        "decrypted_count": len(decrypted_bids),
        "all_bids": sorted(decrypted_bids, key=lambda b: int(b["amount"])),
        "winner": winner,
    }

    reveal_path = Path(f"reveal_{auction_id}.json")
    storage.write_json(reveal_path, reveal_record)

    # Commit reveal to ledger
    led.append("AUCTION_REVEALED", {
        "auction_id": auction_id,
        "winner_bid_id": winner["bid_id"],
        "winner_bidder_id": winner["bidder_id"],
        "winner_amount": winner["amount"],
        "bids_decrypted": len(decrypted_bids),
        "bids_failed": len(errors),
        "authorities_participated": selected,
        "reveal_record_path": str(reveal_path),
    })

    logger.info(
        "Auction revealed: %s | winner=%s | amount=%s | authorities=%s",
        auction_id, winner["bidder_id"], winner["amount"], selected,
    )

    print(f"\n{'=' * 68}")
    print("[OK] REVEAL COMPLETED")
    print(f"{'=' * 68}")
    print(f"  Decrypted bids: {len(decrypted_bids)} of {len(bid_ids)}")
    print(f"\n  All bids (sorted by amount):")
    for b in sorted(decrypted_bids, key=lambda b: int(b["amount"])):
        marker = " ← WINNER" if b["bid_id"] == winner["bid_id"] else ""
        print(f"    bidder={b['bidder_id']}  amount={b['amount']}  bid_id={b['bid_id']}{marker}")
    print(f"\n  WINNER:")
    print(f"    bidder_id: {winner['bidder_id']}")
    print(f"    amount:    {winner['amount']}")
    print(f"    bid_id:    {winner['bid_id']}")
    print(f"\n  Ledger: {msg}")
    print(f"  Full reveal record saved to: {reveal_path}")
    print("  Anyone can verify the winner independently using this file.")
    pause()


# ------------------------------------------------------------------ #
#  Ledger verification                                                 #
# ------------------------------------------------------------------ #

def verify_ledger() -> None:
    header("Verify Ledger Integrity")
    auction_id = choose_auction_id()

    # Also verify meta integrity
    try:
        _verify_auction_meta_integrity(auction_id)
        print("[OK] meta.json integrity verified against ledger commitment.")
    except RuntimeError as e:
        print(f"[FAIL] {e}")
        pause()
        return

    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    ok, msg = led.verify()
    print("\n" + ("[OK] " if ok else "[FAIL] ") + msg)

    if ok:
        print("\nAll ledger events:")
        for e in led.iter_events():
            print(f"  [{e['i']}] {e['ts']}  {e['type']}")

    pause()


# ------------------------------------------------------------------ #
#  Main menu                                                           #
# ------------------------------------------------------------------ #

def main_menu() -> None:
    ensure_base_dirs()

    # NTP check at startup
    run_ntp_check()

    while True:
        header("Sealed-Bid Auction System")

        print("1) Register Bidder")
        print("2) Create Auction")
        print("3) Submit Bid")
        print("4) Auditor: Reveal Bids & Winner")
        print("5) Verify Ledger")
        print("6) Exit")

        choice = prompt_int("Choose: ", min_value=1, max_value=6)

        try:
            if choice == 1:
                register_bidder()
            elif choice == 2:
                create_auction()
            elif choice == 3:
                submit_bid()
            elif choice == 4:
                auditor_reveal_and_winner()
            elif choice == 5:
                verify_ledger()
            else:
                print("Bye.")
                return
        except KeyboardInterrupt:
            print("\n[Interrupted]")
        except Exception as e:
            logger.error("Unhandled error: %s", e, exc_info=True)
            # Show minimal info to user, full details go to audit.log
            print(f"\n[ERROR] {e}")
            pause()


if __name__ == "__main__":
    main_menu()