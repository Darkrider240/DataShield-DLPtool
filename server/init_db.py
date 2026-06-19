"""
Seeds the initial superadmin user.
Run once: python -m server.init_db
"""
import asyncio
from passlib.context import CryptContext
from server.database import AsyncSessionFactory, create_all_tables
from server.models.user import AdminUser

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ADMIN_EMAIL = "admin@datashield.local"
ADMIN_PASSWORD = "DataShield@2025!"
ADMIN_NAME = "Super Admin"


async def seed():
    await create_all_tables()
    async with AsyncSessionFactory() as db:
        from sqlalchemy import select
        existing = (await db.execute(select(AdminUser).where(AdminUser.email == ADMIN_EMAIL))).scalar_one_or_none()
        if existing:
            print(f"[init_db] Admin user already exists: {ADMIN_EMAIL}")
            return
        admin = AdminUser(
            email=ADMIN_EMAIL,
            hashed_password=pwd_context.hash(ADMIN_PASSWORD),
            full_name=ADMIN_NAME,
            role="superadmin",
        )
        db.add(admin)
        await db.commit()
        print(f"[init_db] Created superadmin: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")


if __name__ == "__main__":
    asyncio.run(seed())
