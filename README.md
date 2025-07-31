# Nostr Key Demo

This repository demonstrates how Nostr private and public keys (encoded as nsec/npub via Bech32) can be used to derive valid addresses for Bitcoin (BTC), Bitcoin Cash (BCH), and Ethereum (ETH), leveraging their shared secp256k1 elliptic curve. It includes two Python scripts: one for basic single-key compatibility and another for deriving multiple addresses from a single npub for use cases like zapping or payments.

## Repository Structure
- **single-key-demo/**: Contains `nostr_key_demo.py`, which decodes a Nostr nsec to derive a private key, generates corresponding BTC (legacy), BCH (CashAddr), and ETH addresses, and illustrates CashTokens data for BCH transactions.
  - [Read more](./single-key-demo/README.md)
- **multi-key-demo/**: Contains `nostr_multi_address_demo.py`, which shows how to generate multiple BCH addresses from a Nostr npub using nonces, enabling senders to create unique addresses without the private key. Recipients use the nsec to derive child private keys.
  - [Read more](./multi-key-demo/README.md)
- **requirements.txt**: Lists shared dependencies (e.g., `ecdsa`).
- **.gitignore**: Ignores Python virtual environments and temporary files.

## Key Insights
- Nostr keys are standard secp256k1 keypairs, compatible with BTC, BCH, and ETH address derivation.
- Single-key demo shows direct address generation; multi-key demo enables privacy-preserving payments via nonce-based child keys.
- Useful for integrating BCH/ETH payments or zaps in Nostr clients without new keypairs.

## Getting Started
1. Clone the repo: `git clone <repo-url>`.
2. Navigate to a subfolder (`single-key-demo` or `multi-key-demo`).
3. Follow the folder-specific README for setup, installation, and usage instructions.

## Requirements
- Python 3.8+ (tested on 3.12).
- `ecdsa` library (install via `pip install ecdsa` in a virtual environment).

## License
MIT License. Feel free to modify and extend.