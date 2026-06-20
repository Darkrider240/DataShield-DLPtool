"""
Run this once to apply schema changes without dropping existing data.
    python -m server.migrate
"""
import asyncio
from server.database import engine
from sqlalchemy import text

MIGRATIONS = [
    # Fix 1: Employee PIN
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS pin_hash VARCHAR",
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS pin_set BOOLEAN DEFAULT FALSE",
    # Fix 2: Server settings table
    """
    CREATE TABLE IF NOT EXISTS server_settings (
        key VARCHAR PRIMARY KEY,
        value VARCHAR NOT NULL DEFAULT '',
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    # Per-employee monitoring controls
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS monitor_clipboard BOOLEAN DEFAULT TRUE",
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS monitor_usb BOOLEAN DEFAULT TRUE",
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS monitor_webmail BOOLEAN DEFAULT TRUE",
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS monitor_file_scan BOOLEAN DEFAULT TRUE",
]

async def run():
    async with engine.begin() as conn:
        for sql in MIGRATIONS:
            await conn.execute(text(sql.strip()))
            print(f"[migrate] OK: {sql.strip()[:60]}...")
    print("[migrate] All migrations applied.")

if __name__ == "__main__":
    asyncio.run(run())
