"""
Reset / seed the admin user. Run once:
    python -m server.reset_admin
"""
import asyncio, warnings
warnings.filterwarnings("ignore")

from passlib.context import CryptContext
from server.database import AsyncSessionFactory
from server.models.user import AdminUser
from sqlalchemy import delete

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

ADMIN_EMAIL    = "darshak@datashield.com"
ADMIN_PASSWORD = "datashield"
ADMIN_NAME     = "Darshak (Admin)"


async def reset():
    async with AsyncSessionFactory() as db:
        await db.execute(delete(AdminUser))
        await db.commit()
        hashed = pwd.hash(ADMIN_PASSWORD)
        db.add(AdminUser(
            email=ADMIN_EMAIL,
            hashed_password=hashed,
            full_name=ADMIN_NAME,
            role="superadmin",
            is_active=True,
        ))
        await db.commit()
        ok = pwd.verify(ADMIN_PASSWORD, hashed)
        print(f"[reset] Admin set: {ADMIN_EMAIL}")
        print(f"[reset] Password:  {ADMIN_PASSWORD}")
        print(f"[reset] Hash test: {'PASS' if ok else 'FAIL'}")


if __name__ == "__main__":
    asyncio.run(reset())
