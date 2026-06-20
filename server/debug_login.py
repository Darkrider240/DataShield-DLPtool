"""
Full login diagnostic. Run with:
    python -m server.debug_login
"""
import asyncio, warnings
warnings.filterwarnings("ignore")

async def diagnose():
    print("=" * 50)
    print("DATASHIELD LOGIN DIAGNOSTICS")
    print("=" * 50)

    # 1. Check DB connection
    try:
        from server.database import AsyncSessionFactory
        print("\n[1] DB connection ... ", end="")
        async with AsyncSessionFactory() as db:
            from sqlalchemy import text
            await db.execute(text("SELECT 1"))
        print("OK")
    except Exception as e:
        print(f"FAIL: {e}")
        return

    # 2. Check admin user in DB
    print("[2] Admin user in DB ... ", end="")
    try:
        from server.models.user import AdminUser
        from sqlalchemy import select
        async with AsyncSessionFactory() as db:
            result = await db.execute(select(AdminUser))
            users = result.scalars().all()
        if not users:
            print("FAIL: No users found in admin_users table!")
            print("      Run: python -m server.reset_admin")
            return
        for u in users:
            print(f"\n      Found user: {u.email} | role={u.role} | active={u.is_active}")
            print(f"      Hash preview: {u.hashed_password[:30]}...")
    except Exception as e:
        print(f"FAIL: {e}")
        return

    # 3. Verify password hash
    print("\n[3] Password hash verify ... ", end="")
    try:
        from passlib.context import CryptContext
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        test_password = "Datashield2025"
        async with AsyncSessionFactory() as db:
            result = await db.execute(select(AdminUser))
            user = result.scalars().first()
        ok = ctx.verify(test_password, user.hashed_password)
        print(f"{'OK' if ok else 'FAIL'} (password={test_password})")
        if not ok:
            print("      Hash does not match — resetting now...")
            async with AsyncSessionFactory() as db:
                from sqlalchemy import delete
                await db.execute(delete(AdminUser))
                await db.commit()
                new_hash = ctx.hash(test_password)
                db.add(AdminUser(
                    email="admin@datashield.com",
                    hashed_password=new_hash,
                    full_name="Super Admin",
                    role="superadmin",
                    is_active=True,
                ))
                await db.commit()
            verify2 = ctx.verify(test_password, new_hash)
            print(f"      New admin created. Re-verify: {'OK' if verify2 else 'FAIL'}")
            print(f"      Email: admin@datashield.com")
            print(f"      Password: {test_password}")
    except Exception as e:
        print(f"FAIL: {e}")
        return

    # 4. Check schema
    print("\n[4] LoginRequest schema ... ", end="")
    try:
        from server.schemas import LoginRequest
        req = LoginRequest(email="admin@datashield.com", password="Datashield2025")
        print(f"OK (email type={type(req.email).__name__})")
    except Exception as e:
        print(f"FAIL: {e}")

    # 5. Check settings
    print("[5] Config/settings ... ", end="")
    try:
        from server.config import get_settings
        s = get_settings()
        print(f"OK (DB={s.DATABASE_URL[:40]}...)")
    except Exception as e:
        print(f"FAIL: {e}")

    print("\n" + "=" * 50)
    print("Use these credentials:")
    print("  Email:    admin@datashield.com")
    print("  Password: Datashield2025")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(diagnose())
