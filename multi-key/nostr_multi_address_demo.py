from enum import Enum
import hashlib
import ecdsa

# Bech32 reference implementation (pure Python)
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2bc830a3

class Encoding(Enum):
    BECH32 = 1
    BECH32M = 2

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    return None

def bech32_decode(bech):
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    spec = bech32_verify_checksum(hrp, data)
    if spec is None:
        return (None, None, None)
    return (hrp, data[:-6], spec)

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

# CashAddr encoding function
def bech32_create_checksum(hrp, data, spec):
    values = bech32_hrp_expand(hrp) + data
    mod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ (spec.value if spec else 1)
    return [(mod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec=Encoding.BECH32):
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + ':' + ''.join([CHARSET[d] for d in combined])

# Hash160 for pubkeyhash
def hash160(x):
    return hashlib.new('ripemd160', hashlib.sha256(x).digest()).digest()

# Sample Nostr keys (npub and nsec for demo—now matching pair)
npub = 'npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg'
nsec = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5'

# Decode npub to public key bytes
hrp, data5, spec = bech32_decode(npub)
if hrp != 'npub':
    raise ValueError("Invalid npub")
pub_data = convertbits(data5, 5, 8, False)
pub_bytes = bytes(pub_data)  # x-only pubkey (32 bytes)
print(f"Public key (x-only) from npub: {pub_bytes.hex()}")

# Decode nsec to private key bytes (for recipient's use)
hrp, data5, spec = bech32_decode(nsec)
if hrp != 'nsec':
    raise ValueError("Invalid nsec")
priv_data = convertbits(data5, 5, 8, False)
priv_bytes = bytes(priv_data)
print(f"Private key from nsec: {priv_bytes.hex()}")

# Reconstruct compressed public key (use even parity as per Nostr/BIP-340 convention)
pub_compressed = b'\x02' + pub_bytes

# Verify it matches the actual pub derived from priv (for demo validation)
sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
vk_from_priv = sk.verifying_key
actual_pub_compressed = vk_from_priv.to_string("compressed")
print(f"Actual compressed public key from priv: {actual_pub_compressed.hex()}")
print(f"Assumed compressed public key from npub: {pub_compressed.hex()}")
if actual_pub_compressed != pub_compressed:
    raise ValueError("Parity mismatch—Nostr keys should have even y, but check failed.")

vk = ecdsa.VerifyingKey.from_string(pub_compressed, curve=ecdsa.SECP256k1)
print(f"Compressed public key used: {pub_compressed.hex()}")

# Generate child public keys and addresses using a nonce
def derive_child_pubkey(base_pubkey, nonce):
    # Convert nonce to a scalar (hash to ensure it's in valid range)
    nonce_hash = hashlib.sha256(nonce.encode()).digest()
    scalar = int.from_bytes(nonce_hash, 'big') % ecdsa.SECP256k1.order
    # Get generator point
    G = ecdsa.SECP256k1.generator
    # Compute nonce * G
    nonce_point = scalar * G
    # Parse base public key
    base_point = ecdsa.VerifyingKey.from_string(base_pubkey, curve=ecdsa.SECP256k1).pubkey.point
    # Add points: child_pub = base_pub + nonce * G
    child_point = base_point + nonce_point
    # Convert back to compressed public key
    child_vk = ecdsa.VerifyingKey.from_public_point(child_point, curve=ecdsa.SECP256k1)
    return child_vk.to_string("compressed")

def derive_child_privkey(base_privkey, nonce):
    # Same nonce hash as above
    nonce_hash = hashlib.sha256(nonce.encode()).digest()
    scalar = int.from_bytes(nonce_hash, 'big') % ecdsa.SECP256k1.order
    # Add scalar to private key modulo order
    priv_int = int.from_bytes(base_privkey, 'big')
    child_priv = (priv_int + scalar) % ecdsa.SECP256k1.order
    return child_priv.to_bytes(32, 'big')

# Derive BCH CashAddr from public key
def pubkey_to_cashaddr(pubkey):
    pkh = hash160(pubkey)
    version_byte = 0  # P2PKH, 160-bit
    cash_payload = [version_byte] + list(pkh)
    cash_data5 = convertbits(cash_payload, 8, 5, True)
    return bech32_encode('bitcoincash', cash_data5)

# Demo: Generate 3 child addresses for zapping
print("\nGenerating 3 child addresses from npub for zapping:")
for i in range(3):
    nonce = f"zap-{i}"
    # Sender derives child public key
    child_pub = derive_child_pubkey(pub_compressed, nonce)
    child_address = pubkey_to_cashaddr(child_pub)
    print(f"Child address {i} (nonce: {nonce}): {child_address}")
    # Recipient derives corresponding private key
    child_priv = derive_child_privkey(priv_bytes, nonce)
    child_sk = ecdsa.SigningKey.from_string(child_priv, curve=ecdsa.SECP256k1)
    child_vk = child_sk.verifying_key
    computed_pub = child_vk.to_string("compressed")
    print(f"Recipient's computed pubkey matches: {computed_pub == child_pub}")
    print(f"Child private key (hex): {child_priv.hex()}\n")