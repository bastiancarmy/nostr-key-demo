# Nostr Multi-Address Derivation Demo

This Python script extends the basic Nostr key compatibility demo by showing how to derive multiple Bitcoin Cash (BCH) addresses from a single Nostr npub (public key) using nonces. This enables senders (who only have the npub) to generate unique, deterministic addresses for scenarios like zapping or payments, without needing the private key. The recipient, holding the nsec (private key), can derive the corresponding child private keys to spend the funds. All operations use the secp256k1 curve for compatibility with BTC, BCH, and ETH.

## Key Findings
- **Multi-Address Derivation**: Using elliptic curve point addition, child public keys are derived by adding a nonce-derived point (nonce * G) to the base public key. Senders use only the npub and a public nonce (e.g., "zap-0"). Recipients add the same nonce scalar to their private key to get the child private key.
  - Deterministic and secure: Nonces are hashed to scalars, ensuring uniqueness and preventing collisions.
  - Compatibility: Child keys are standard secp256k1 pairs, usable for BCH (CashAddr shown here), BTC, or ETH addresses.
  - Verification: The script checks that sender-derived public keys match recipient-computed ones from child privkeys (should always be True for matching keypairs).
- **Zapping Implications**: Enables multiple payments to a Nostr user without reusing addresses, improving privacy. Integrates with Nostr clients for BCH zaps alongside Lightning.
- **Parity Handling**: Nostr npubs assume even y-parity (0x02 prefix). The script verifies this against the nsec-derived pubkey.
- **Limitations**: Sender can't sign txs (no privkey access). For odd parity (rare in Nostr), adjust to 0x03 prefix and negate privkey. Script is demo-only; use secure nonces in production.

## Requirements
- Python 3.8+ (tested on 3.12).
- `ecdsa` library (for secp256k1 operations).

## Installation and Setup
Follow these steps to run in an isolated environment.

1. **Clone or Create the Script**:
   - Save the script as `nostr_multi_address_demo.py` in this folder.

2. **Create a Virtual Environment**:
   - Open Terminal and navigate to the folder: `cd /path/to/multi-key-demo`.
   - Run: `python3 -m venv nostr_env`.

3. **Activate the Environment**:
   - Run: `source nostr_env/bin/activate`.

4. **Install Dependencies**:
   - Run: `python3 -m pip install ecdsa`.

5. **Run the Script**:
   - Run: `python3 nostr_multi_address_demo.py`.
   - Expected output: Decoded keys, verification checks, and 3 sample child BCH addresses with matching pubkeys (True).

6. **Deactivate**:
   - Run: `deactivate` when finished.

## Usage
- Edit the `npub` and `nsec` variables to use your own Nostr keys (for testing only—never share real nsecs).
- Adjust the nonce loop (e.g., more iterations or custom nonces like event IDs).
- Run as above. Outputs include child addresses, privkeys (recipient-side), and match checks.
- For advanced use: Extend to BTC/ETH addresses or integrate with BCH tx libraries like `libauth`.

## Troubleshooting
- **ModuleNotFoundError: No module named 'ecdsa'**: Ensure venv is activated and installed.
- **ValueError: Parity mismatch**: Your keys have odd parity—switch to b'\x03' + pub_bytes and negate priv_int (mod order) on recipient side.
- **Matches False**: Ensure npub and nsec are a matching pair; the script verifies this upfront.
- **Other Platforms**: Similar steps on Windows/Linux (use `venv\Scripts\activate` on Windows).

## License
MIT License. Feel free to modify and extend.