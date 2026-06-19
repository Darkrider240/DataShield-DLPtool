"""
AES-256-GCM symmetric encryption and PBKDF2-HMAC-SHA256 key derivation.
Used by the envelope encryption service to protect Data Encryption Keys (DEKs).
"""
import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derives a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.
    Returns (key_bytes, salt_bytes).
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=310_000,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return key, salt


def encrypt(plaintext: str | bytes, key: bytes) -> str:
    """
    Encrypts plaintext using AES-256-GCM.
    Returns a Base64-encoded string: nonce(12) + tag(16) + ciphertext.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    # AESGCM appends the 16-byte tag at the end of ciphertext_with_tag
    blob = nonce + ciphertext_with_tag
    return base64.b64encode(blob).decode("utf-8")


def decrypt(encoded_blob: str, key: bytes) -> str:
    """
    Decrypts a Base64-encoded AES-256-GCM blob.
    Returns the decrypted plaintext string.
    """
    blob = base64.b64decode(encoded_blob.encode("utf-8"))
    nonce = blob[:12]
    ciphertext_with_tag = blob[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext.decode("utf-8")


def generate_dek() -> bytes:
    """Generates a random 256-bit Data Encryption Key."""
    return os.urandom(32)


def encode_key(key: bytes) -> str:
    """Base64-encodes a raw key for storage."""
    return base64.b64encode(key).decode("utf-8")


def decode_key(encoded_key: str) -> bytes:
    """Decodes a Base64-encoded key back to raw bytes."""
    return base64.b64decode(encoded_key.encode("utf-8"))
