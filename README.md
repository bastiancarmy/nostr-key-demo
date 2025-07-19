# Nostr Key Compatibility Demo

This Python script demonstrates how Nostr private/public keys (encoded as nsec/npub via Bech32) are compatible with Bitcoin (BTC), Bitcoin Cash (BCH), and Ethereum (ETH) for address derivation. All use the secp256k1 elliptic curve, allowing the same private key to generate valid addresses across these chains. It also includes a simple illustration of CashTokens data (BCH's native token standard) for embedding in transaction outputs.

## Key Findings
- **Key Compatibility**: Nostr keys are standard secp256k1 pairs, identical in format to those used in BTC, BCH, and ETH. The private key (32 bytes) can be decoded from nsec and used directly to derive public keys and addresses without modification.
  - BTC/BCH: Use hash160 (SHA256 + RIPEMD-160) of the compressed public key, then encode in Base58Check (legacy) or CashAddr (modern BCH).
  - ETH: Use Keccak-256 of the uncompressed public key (last 20 bytes), with checksum encoding.
  - No fundamental differences in key generation—differences are in encoding (e.g., Base58 vs. Bech32/CashAddr) and signing algorithms (e.g., ECDSA for tx vs. Schnorr for Nostr events), but the raw keys are interchangeable.
- **CashTokens Demo**: CashTokens (fungible/NFTs on BCH) are not derived from keys but embedded as prefixes in BCH transaction outputs (e.g., token category ID + amount). The script shows sample bytes for a fungible token, which would be prepended to an output's value field in a real tx. Signing such tx uses the same ECDSA/secp256k1 as standard BCH.
- **Implications for Nostr**: This enables seamless integrations like BCH/ETH payments in Nostr clients without new key pairs—e.g., derive addresses from Nostr npub for sends, coexisting with Lightning zaps.
- **Limitations**: Monero (Ed25519 curve) is incompatible. Script is for demo only; real wallets handle edge cases like compressed vs. uncompressed keys.

## Requirements
- Python 3.8+ (tested on 3.12 via Homebrew on macOS).
- `ecdsa` library (for secp256k1 operations).

## Installation and Setup
Follow these steps to run in an isolated environment (recommended on macOS to avoid PEP 668 errors with Homebrew Python).

1. **Clone or Create the Script**:
   - Save the script as `nostr_key_demo.py` in a directory.

2. **Create a Virtual Environment**:
   - Open Terminal and navigate to the directory: `cd /path/to/script`.
   - Run: `python3 -m venv nostr_env`.

3. **Activate the Environment**:
   - Run: `source nostr_env/bin/activate`.

4. **Install Dependencies**:
   - Run: `python3 -m pip install ecdsa`.

5. **Run the Script**:
   - Run: `python3 nostr_key_demo.py`.
   - Expected output includes decoded private key, public key, hash160, addresses (BTC legacy, BCH CashAddr, ETH), and sample CashToken data.

6. **Deactivate**:
   - Run: `deactivate` when finished.

## Usage
- Edit the `nsec` variable in the script to use your own Nostr private key (for testing only—never share real keys).
- Run as above. Outputs are printed to console.
- For advanced use: Integrate with libraries like `libauth` for full BCH tx building/signing.

## Troubleshooting
- **ModuleNotFoundError: No module named 'ecdsa'**: Ensure you're in the activated venv and have installed it.
- **Externally-managed-environment Error**: This is PEP 668 protection—always use venv as above; avoid `--break-system-packages`.
- **Other Platforms**: On Windows/Linux, steps are similar (use `venv\Scripts\activate` on Windows).

## License
MIT License. Feel free to modify and extend.