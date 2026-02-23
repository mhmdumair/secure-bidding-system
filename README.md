# Terminal Sealed-Bid Auction (Security-Focused)

This project implements a **sealed-bid bidding/procurement system** where:
- bids are **encrypted end-to-end**
- the storage/server is **blind** (cannot read bids)
- bids can be decrypted only **after a deadline**, and only if **t-of-n authorities** release shares
- all actions are recorded in a **tamper-evident hash-chained ledger**

## Security Model (What is guaranteed)
1. **Confidentiality (Authority-blind server)**  
   The server stores only ciphertext. Plaintext bids are never written to disk.

2. **Threshold Reveal (t-of-n)**  
   Each bid uses a random symmetric key `k_bid` (32 bytes).  
   `k_bid` is split into Shamir shares (threshold `t`).  
   Each share is encrypted (sealed) to an authority using ECDH+HKDF+AEAD.  
   After the deadline, authorities release their decrypted shares; auditors reconstruct `k_bid` to decrypt the bid.

3. **Integrity & Non-repudiation**
   - Bidder signs bid package using ECDSA.
   - Authorities sign their share-release files.
   - Bid commitment hash binds the bid contents.

4. **Tamper-evident history**
   - Ledger is a hash chain. Any modification to past entries breaks verification.

## Requirements
- Python 3.10+
- `cryptography`

Install:
```bash
pip install -r requirements.txt
