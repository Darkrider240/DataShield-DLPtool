"""
Seeds the initial superadmin user.
Run once: python -m server.init_db
"""
import asyncio
import warnings

# Suppress harmless passlib/bcrypt version mismatch warning
warnings.filterwarnings("ignore", message=".*bcrypt.*")

from passlib.context import CryptContext
from server.database import AsyncSessionFactory, create_all_tables
from server.models.user import AdminUser

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ADMIN_EMAIL    = "admin@datashield.local"
ADMIN_PASSWORD = "DataShield@2025!"
ADMIN_NAME     = "Super Admin"


async def seed():
    print("[init_db] Creating database tables...")
    await create_all_tables()
    print("[init_db] Tables ready.")

    # Trigger master key derivation.
    # If MASTER_KEY_SALT_HEX is blank, a new salt is generated and printed.
    import server.services.crypto_service as _cs
    _cs._get_master_key()
    if _cs._master_salt:
        salt_hex = _cs._master_salt.hex()
        from server.config import get_settings
        if not get_settings().MASTER_KEY_SALT_HEX:
            print(f"\n[init_db] MASTER_KEY_SALT_HEX={salt_hex}")
            print("[init_db] >> Add the line above to server/.env now, then restart.\n")
        else:
            print(f"[init_db] Master key salt loaded OK.")

    async with AsyncSessionFactory() as db:
        from sqlalchemy import select
        existing = (
            await db.execute(
                select(AdminUser).where(AdminUser.email == ADMIN_EMAIL)
            )
        ).scalar_one_or_none()

        if existing:
            print(f"[init_db] Admin already exists: {ADMIN_EMAIL} — skipping.")
        else:
            # bcrypt max is 72 bytes
            hashed = pwd_context.hash(ADMIN_PASSWORD.encode("utf-8")[:72].decode("utf-8"))
            admin = AdminUser(
                email=ADMIN_EMAIL,
                hashed_password=hashed,
                full_name=ADMIN_NAME,
                role="superadmin",
            )
            db.add(admin)
            await db.commit()
            print(f"[init_db] [OK] Superadmin created: {ADMIN_EMAIL}")
            print(f"[init_db] [OK] Password:           {ADMIN_PASSWORD}")

    print("\n[init_db] Done! Start the server with:")
    print("    uvicorn server.main:app --reload --port 8000\n")


if __name__ == "__main__":
    asyncio.run(seed())
