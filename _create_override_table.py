"""
Migration: create override_requests table and run all pending server-side features.
"""
import sys, os
sys.path.insert(0, '.')

from server.config import get_settings
s = get_settings()

pg_url = s.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

import psycopg2
conn = psycopg2.connect(pg_url)
conn.autocommit = True
cur = conn.cursor()

# 1. override_requests table
cur.execute("""
CREATE TABLE IF NOT EXISTS override_requests (
    id            VARCHAR PRIMARY KEY,
    employee_id   VARCHAR NOT NULL,
    agent_id      VARCHAR DEFAULT '',
    event_channel VARCHAR NOT NULL,
    event_detail  TEXT    DEFAULT '',
    pattern       VARCHAR DEFAULT '',
    justification TEXT    NOT NULL,
    status        VARCHAR DEFAULT 'PENDING',
    admin_note    TEXT,
    reviewed_by   VARCHAR,
    created_at    TIMESTAMPTZ DEFAULT now(),
    reviewed_at   TIMESTAMPTZ
)
""")
cur.execute("CREATE INDEX IF NOT EXISTS ix_override_employee ON override_requests(employee_id)")
cur.execute("CREATE INDEX IF NOT EXISTS ix_override_status   ON override_requests(status)")
print("[+] override_requests table: OK")

conn.close()
print("All migrations complete.")
