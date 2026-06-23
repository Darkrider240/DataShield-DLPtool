import asyncio
import asyncpg

async def check():
    try:
        conn = await asyncpg.connect(
            host="localhost",
            port=5432,
            user="datashield",
            password="datashield",
            database="datashield",
            timeout=5,
        )
        ver   = await conn.fetchval("SELECT version()")
        rows  = await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        await conn.close()
        print("Connected: OK")
        print("PG:", ver[:60])
        names = [r["tablename"] for r in rows]
        if names:
            print("Tables:", names)
        else:
            print("Tables: (none yet) run: venv\\Scripts\\python server\\init_db.py")
    except Exception as e:
        print("ERROR:", type(e).__name__, str(e))

asyncio.run(check())
