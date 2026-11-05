from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization

from pathlib import Path

path = Path(__file__).resolve().parent

def Generate():
    """Standalone utility. Not intended to be called from production code.

    Generates a fresh key pair and writes the key files next to this file.
    """
    priv = X25519PrivateKey.generate()
    privB = priv.private_bytes_raw()
    pubB = priv.public_key().public_bytes_raw()

    (path / "public_key.bin").write_bytes(pubB)
    (path / "private_key.bin").write_bytes(privB)

Generate()