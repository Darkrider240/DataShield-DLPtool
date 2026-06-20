"""
Envelope encryption service.
Master key encrypts/decrypts per-employee Data Encryption Keys (DEKs).
DEKs encrypt/decrypt sensitive event fields (file_path, ai_explanation).
"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from crypto.encryption import encrypt, decrypt, generate_dek, encode_key, decode_key, derive_key
from server.config import get_settings

settings = get_settings()

# ── Master key derivation (cached at process startup) ─────────────────────────
_master_key: bytes | None = None
_master_salt: bytes | None = None

def _get_master_key() -> bytes:
    global _master_key, _master_salt
    if _master_key is not None:
        return _master_key
    salt_hex = settings.MASTER_KEY_SALT_HEX
    if salt_hex:
        _master_salt = bytes.fromhex(salt_hex)
        _master_key, _ = derive_key(settings.MASTER_KEY_PASSPHRASE, _master_salt)
    else:
        _master_key, _master_salt = derive_key(settings.MASTER_KEY_PASSPHRASE)
        print(f"[crypto] Generated new master salt. Add to .env: MASTER_KEY_SALT_HEX={_master_salt.hex()}")
    return _master_key


# ── DEK management ────────────────────────────────────────────────────────────
def create_employee_dek() -> str:
    """
    Generate a fresh DEK, encrypt it with the master key, and return the
    encrypted DEK as a Base64 string suitable for storing in the DB.
    """
    dek = generate_dek()
    master_key = _get_master_key()
    return encrypt(encode_key(dek), master_key)


def get_employee_dek(encrypted_dek: str) -> bytes:
    """
    Decrypt the employee's stored DEK using the master key.
    Returns raw 32-byte key. Never cache this beyond the request scope.
    """
    master_key = _get_master_key()
    encoded = decrypt(encrypted_dek, master_key)
    return decode_key(encoded)


# ── Field-level encryption helpers ────────────────────────────────────────────
def encrypt_field(plaintext: str, dek: bytes) -> str:
    """Encrypt a single sensitive string field using the employee DEK."""
    if not plaintext:
        return ""
    return encrypt(plaintext, dek)


def decrypt_field(ciphertext: str, dek: bytes) -> str:
    """Decrypt a single sensitive string field using the employee DEK."""
    if not ciphertext:
        return ""
    return decrypt(ciphertext, dek)


# ── Key rotation ──────────────────────────────────────────────────────────────
async def rotate_all_employee_deks(db) -> int:
    """
    Re-encrypt all employees' DEKs and re-encrypt their event fields with new DEKs.
    Returns the number of employees whose keys were rotated.
    """
    from sqlalchemy import select
    from server.models.employee import Employee
    from server.models.event import DLPEvent

    result = await db.execute(select(Employee))
    employees = result.scalars().all()
    count = 0

    for emp in employees:
        old_dek = get_employee_dek(emp.encrypted_dek)
        new_dek = generate_dek()
        master_key = _get_master_key()
        emp.encrypted_dek = encrypt(encode_key(new_dek), master_key)

        # Re-encrypt all event fields for this employee
        ev_result = await db.execute(select(DLPEvent).where(DLPEvent.employee_id == emp.id))
        events = ev_result.scalars().all()
        for ev in events:
            if ev.file_path_encrypted:
                plain = decrypt_field(ev.file_path_encrypted, old_dek)
                ev.file_path_encrypted = encrypt_field(plain, new_dek)
            if ev.ai_explanation_encrypted:
                plain = decrypt_field(ev.ai_explanation_encrypted, old_dek)
                ev.ai_explanation_encrypted = encrypt_field(plain, new_dek)

        count += 1

    await db.commit()
    return count
