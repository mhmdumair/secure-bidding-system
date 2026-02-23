from __future__ import annotations

import os
import sys
import uuid
import json
import getpass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cryptography.hazmat.primitives import serialization

from core import crypto, ledger, shamir, storage, timeutil


STORE_ROOT = Path("store")
PATHS = storage.StorePaths(STORE_ROOT)


# ------------------------ Console helpers ------------------------

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


def prompt_int(prompt: str, min_value: int | None = None, max_value: int | None = None) -> int:
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


def prompt_deadline_human_to_utc_z() -> str:
    """
    Accept:
      - 2026-02-04 14:45:00  (local Sri Lanka)
      - 2026-02-04 14:45
      - 2026-02-04T09:15:00Z
      - in 5 minutes
    Store always as UTC Z string.
    """
    while True:
        raw = input("Deadline (e.g. 2026-02-04 14:45:00 OR 'in 5 minutes'): ").strip()
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


# ------------------------ Auction selection ------------------------

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
        print(f"  [{i}] {auction_id}  |  {meta.get('name','?')}  |  deadline={meta.get('deadline_utc','?')}")

    idx = prompt_int("Select auction number: ", min_value=1, max_value=len(auctions))
    return auctions[idx - 1][0]


# ------------------------ Bidder registration (name + password) ------------------------

def register_bidder() -> None:
    ensure_base_dirs()
    header("Register Bidder")

    bidder_id = prompt_nonempty("Choose a bidder ID (e.g. B1, U1): ")
    if storage.bidder_exists(PATHS, bidder_id):
        print("[ERROR] Bidder ID already exists. Choose another ID.")
        return

    bidder_name = prompt_nonempty("Bidder name: ")
    password1 = getpass.getpass("Create password: ")
    password2 = getpass.getpass("Confirm password: ")
    if password1 != password2 or not password1:
        print("[ERROR] Passwords do not match (or empty).")
        return

    bidder_private, bidder_public = crypto.gen_ecdsa_keypair()

    # Store public key as PEM string in profile + pub.pem
    bidder_dir = PATHS.bidder_dir(bidder_id)
    bidder_dir.mkdir(parents=True, exist_ok=True)

    pub_pem = pem_public_key_str(bidder_public)
    (PATHS.bidder_pub(bidder_id)).write_text(pub_pem, encoding="utf-8")

    # Store encrypted private key
    aad = f"bidder|{bidder_id}".encode("utf-8")
    enc_priv = crypto.encrypt_private_key_pem(bidder_private, password1, aad=aad)
    storage.save_bidder_priv_enc(PATHS, bidder_id, enc_priv)

    profile = {
        "bidder_id": bidder_id,
        "name": bidder_name,
        "pubkey_pem": pub_pem,
        "created_at_utc": timeutil.isoformat_z(timeutil.now_utc()),
    }
    storage.save_bidder_profile(PATHS, bidder_id, profile)

    print("[OK] Bidder registered.")
    print(f"Bidder ID: {bidder_id}")
    pause()


def authenticate_bidder(bidder_id: str) -> Tuple[Any, str]:
    """
    Returns (private_key, pubkey_pem) if password is correct.
    """
    if not storage.bidder_exists(PATHS, bidder_id):
        raise RuntimeError("Bidder not registered. Register first.")

    profile = storage.load_bidder_profile(PATHS, bidder_id)
    pub_pem = profile["pubkey_pem"]
    enc_priv = storage.load_bidder_priv_enc(PATHS, bidder_id)

    password = getpass.getpass("Password: ")
    aad = f"bidder|{bidder_id}".encode("utf-8")

    try:
        sk = crypto.decrypt_private_key_pem(enc_priv, password, aad=aad)
        return sk, pub_pem
    except Exception:
        raise RuntimeError("Invalid password for bidder.")


# ------------------------ Auction creation (creates authorities with passwords) ------------------------

def create_auction() -> None:
    ensure_base_dirs()
    header("Create Auction")

    auction_name = prompt_nonempty("Auction name: ")
    deadline_utc_str = prompt_deadline_human_to_utc_z()

    num_authorities = prompt_int("Number of authorities (n): ", min_value=2)
    threshold_t = prompt_int("Threshold (t) (must be <= n): ", min_value=2, max_value=num_authorities)

    authority_ids: List[str] = []
    authority_pubkeys: Dict[str, str] = {}

    auction_id = uuid.uuid4().hex[:16]
    authorities_root = PATHS.auction_authorities_dir(auction_id)
    authorities_root.mkdir(parents=True, exist_ok=True)

    print("\nAuthority setup (created WITH auction):")
    for i in range(1, num_authorities + 1):
        auth_id = prompt_nonempty(f"Authority {i} ID (e.g. A1): ")
        authority_ids.append(auth_id)

        auth_password1 = getpass.getpass(f"Create password for {auth_id}: ")
        auth_password2 = getpass.getpass(f"Confirm password for {auth_id}: ")
        if auth_password1 != auth_password2 or not auth_password1:
            raise RuntimeError("Authority password mismatch (or empty). Restart auction creation.")

        auth_private, auth_public = crypto.gen_ecdsa_keypair()

        # Save authority public key
        pub_pem = pem_public_key_str(auth_public)
        auth_dir = PATHS.auction_authority_dir(auction_id, auth_id)
        auth_dir.mkdir(parents=True, exist_ok=True)
        PATHS.auction_authority_pub(auction_id, auth_id).write_text(pub_pem, encoding="utf-8")
        authority_pubkeys[auth_id] = pub_pem

        # Save encrypted private key (bound to auction + authority)
        aad = f"authority|{auction_id}|{auth_id}".encode("utf-8")
        enc_priv = crypto.encrypt_private_key_pem(auth_private, auth_password1, aad=aad)
        storage.write_json(PATHS.auction_authority_priv_enc(auction_id, auth_id), enc_priv)

    # Create auction meta
    meta: Dict[str, Any] = {
        "auction_id": auction_id,
        "name": auction_name,
        "deadline_utc": deadline_utc_str,
        "n": num_authorities,
        "t": threshold_t,
        "authority_ids": authority_ids,
        "authority_pubkeys_pem": authority_pubkeys,
        "created_at_utc": timeutil.isoformat_z(timeutil.now_utc()),
        "crypto": {
            "bid_aead": "ChaCha20-Poly1305",
            "sealed_share": "ECDH(P-256)+HKDF-SHA256+ChaCha20-Poly1305",
            "sign": "ECDSA(P-256)+SHA256",
            "shamir": "GF(p) with p=2^521-1",
            "authority_priv_storage": "scrypt(password)+ChaCha20Poly1305 over PEM",
            "bidder_priv_storage": "scrypt(password)+ChaCha20Poly1305 over PEM",
        },
    }

    storage.save_auction_meta(PATHS, auction_id, meta)
    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    led.append("AUCTION_CREATED", {"auction_id": auction_id, "name": auction_name, "deadline_utc": deadline_utc_str})

    print("\n[OK] Auction created")
    print(f"auction_id: {auction_id}")
    print(f"deadline_utc: {deadline_utc_str}")
    print(f"threshold: t={threshold_t} of n={num_authorities}")
    pause()


# ------------------------ Bid submission (ONLY registered bidders) ------------------------

def submit_bid() -> None:
    ensure_base_dirs()
    header("Submit Bid (Registered Bidder Only)")

    auction_id = choose_auction_id()
    meta = storage.load_auction_meta(PATHS, auction_id)

    deadline_utc = timeutil.parse_deadline_any(meta["deadline_utc"])
    timeutil.ensure_before_deadline(deadline_utc)

    bidder_id = prompt_nonempty("Bidder ID: ")
    print("(authentication required)")
    bidder_private_key, bidder_pub_pem = authenticate_bidder(bidder_id)

    amount = prompt_int("Bid amount (integer): ", min_value=1)

    bid_id = uuid.uuid4().hex[:16]
    aad = f"{auction_id}|{bid_id}".encode("utf-8")

    bid_plain = {
        "auction_id": auction_id,
        "bid_id": bid_id,
        "bidder_id": bidder_id,
        "amount": int(amount),
        "ts_utc": timeutil.isoformat_z(timeutil.now_utc()),
    }

    # Commitment binds bid to hidden nonce (prevents later bid modification)
    hidden_nonce = os.urandom(16)
    commitment = crypto.sha256_hex(crypto.canon_bytes(bid_plain) + hidden_nonce)

    # Encrypt payload using random per-bid symmetric key
    bid_key = os.urandom(32)
    payload = {"bid": bid_plain, "nonce_b64": crypto.b64e(hidden_nonce)}
    bid_cipher = crypto.aead_encrypt(bid_key, crypto.canon_bytes(payload), aad=aad)

    # Split bid_key into shares and seal to each authority public key
    n = int(meta["n"])
    t = int(meta["t"])
    authority_ids: List[str] = list(meta["authority_ids"])
    authority_pub_pems: Dict[str, str] = dict(meta["authority_pubkeys_pem"])

    shares_xy = shamir.split_secret(bid_key, t=t, n=n)
    sealed_shares: Dict[str, Any] = {}

    for (x, y), auth_id in zip(shares_xy, authority_ids):
        share_obj = {"x": x, "y_hex": hex(y)}
        share_bytes = crypto.canon_bytes(share_obj)

        auth_pub = crypto.load_public_key_from_pem_str(authority_pub_pems[auth_id])
        sealed = crypto.seal_to_public(auth_pub, share_bytes, aad=aad)
        sealed_shares[auth_id] = sealed

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

    storage.save_bid(PATHS, auction_id, bid_id, bid_package)

    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    led.append("BID_SUBMITTED", {"auction_id": auction_id, "bid_id": bid_id, "bidder_id": bidder_id})

    print("\n[OK] Bid submitted (encrypted)")
    print(f"auction_id: {auction_id}")
    print(f"bid_id: {bid_id}")
    pause()


# ------------------------ Auditor reveal (inline authority share release) ------------------------

def _unlock_authority_private_key(auction_id: str, authority_id: str) -> Any:
    """
    Prompt password and decrypt the authority private key stored inside the auction folder.
    """
    enc_path = PATHS.auction_authority_priv_enc(auction_id, authority_id)
    if not enc_path.exists():
        raise RuntimeError(f"Authority does not exist in this auction: {authority_id}")

    enc_obj = storage.read_json(enc_path)
    password = getpass.getpass(f"Password for authority {authority_id}: ")
    aad = f"authority|{auction_id}|{authority_id}".encode("utf-8")

    try:
        return crypto.decrypt_private_key_pem(enc_obj, password, aad=aad)
    except Exception:
        raise RuntimeError(f"Invalid password for authority {authority_id}.")


def auditor_reveal_and_winner() -> None:
    ensure_base_dirs()
    header("Auditor: Reveal Bids & Winner (Authorities Provide Passwords)")

    auction_id = choose_auction_id()
    meta = storage.load_auction_meta(PATHS, auction_id)

    deadline_utc = timeutil.parse_deadline_any(meta["deadline_utc"])
    timeutil.ensure_after_deadline(deadline_utc)

    # Verify ledger integrity first
    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    ok, msg = led.verify()
    if not ok:
        raise RuntimeError(f"Ledger verification failed: {msg}")

    bid_ids = storage.list_bid_ids(PATHS, auction_id)
    if not bid_ids:
        print("No bids found.")
        pause()
        return

    t = int(meta["t"])
    authority_ids: List[str] = list(meta["authority_ids"])

    print("\nAuction details:")
    print(f"auction_id: {auction_id}")
    print(f"name: {meta.get('name')}")
    print(f"deadline_utc: {meta.get('deadline_utc')}")
    print(f"threshold: t={t} of n={meta.get('n')}")

    print("\nAuthorities in this auction:")
    print("  " + ", ".join(authority_ids))
    print("\nTo reveal bids, at least t authorities must provide passwords.")

    # Choose which authorities will participate (must be >= t)
    selected: List[str] = []
    while len(selected) < t:
        auth_id = prompt_nonempty(f"Enter authority ID to unlock ({len(selected)}/{t}): ")
        if auth_id not in authority_ids:
            print("Not a valid authority for this auction.")
            continue
        if auth_id in selected:
            print("Already selected.")
            continue
        selected.append(auth_id)

    # Unlock their private keys
    unlocked_authorities: Dict[str, Any] = {}
    for auth_id in selected:
        unlocked_authorities[auth_id] = _unlock_authority_private_key(auction_id, auth_id)

    decrypted_bids: List[Dict[str, Any]] = []

    # Decrypt each bid
    for bid_id in bid_ids:
        bid_obj = storage.load_bid(PATHS, auction_id, bid_id)

        # Verify bidder signature
        bidder_pk = crypto.load_public_key_from_pem_str(bid_obj["bidder_pubkey_pem"])
        signed_part = {k: bid_obj[k] for k in bid_obj if k != "bidder_sig_b64"}
        if not crypto.verify(bidder_pk, crypto.canon_bytes(signed_part), bid_obj["bidder_sig_b64"]):
            raise RuntimeError(f"Invalid bidder signature for bid {bid_id}")

        aad = f"{auction_id}|{bid_id}".encode("utf-8")

        # Collect shares by asking unlocked authorities to open their sealed share
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
            raise RuntimeError(f"Not enough shares collected for bid {bid_id}. Needed {t}, got {len(shares_xy)}")

        # Reconstruct per-bid key and decrypt
        bid_key = shamir.reconstruct_secret(shares_xy[:t], out_len=32)
        payload_bytes = crypto.aead_decrypt(bid_key, bid_obj["bid_cipher"], aad=aad)
        payload = json_load_bytes(payload_bytes)

        bid_plain = payload["bid"]
        hidden_nonce = crypto.b64d(payload["nonce_b64"])

        # Verify commitment
        commit_calc = crypto.sha256_hex(crypto.canon_bytes(bid_plain) + hidden_nonce)
        if commit_calc != bid_obj["commitment_sha256"]:
            raise RuntimeError(f"Commitment mismatch for bid {bid_id}")

        decrypted_bids.append(bid_plain)

    # Compute winner (lowest bid)
    winner = min(decrypted_bids, key=lambda b: int(b["amount"]))

    led.append("AUCTION_REVEALED", {"auction_id": auction_id, "bids": len(decrypted_bids), "winner_bid_id": winner["bid_id"]})

    print("\n[OK] Reveal completed")
    print(f"Decrypted bids: {len(decrypted_bids)}")
    print("Winner (lowest amount):")
    print(f"  bidder_id: {winner['bidder_id']}")
    print(f"  amount: {winner['amount']}")
    print(f"  bid_id: {winner['bid_id']}")
    print(f"Ledger: {msg}")
    pause()


# ------------------------ Ledger verify ------------------------

def verify_ledger() -> None:
    header("Verify Ledger Integrity")
    auction_id = choose_auction_id()
    led = ledger.Ledger(PATHS.auction_ledger(auction_id))
    ok, msg = led.verify()
    print("\n" + ("[OK] " if ok else "[FAIL] ") + msg)
    pause()


# ------------------------ Main menu ------------------------

def main_menu() -> None:
    ensure_base_dirs()

    while True:
        header("Sealed-Bid System (Interactive Terminal)")

        print("1) Register Bidder (name + password)")
        print("2) Create Auction (creates authorities with passwords)")
        print("3) Submit Bid (registered bidder only)")
        print("4) Auditor: Reveal bids & winner (authority passwords required)")
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
        except Exception as e:
            print(f"\n[ERROR] {e}")
            pause()


if __name__ == "__main__":
    # Interactive only (as your lecturer wants)
    main_menu()
