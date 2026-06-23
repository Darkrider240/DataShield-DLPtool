"""
local_history.py — LOCAL FALLBACK CACHE for the employee threat feed.

Primary source of truth is PostgreSQL (via GET /api/events/my-feed).
This SQLite cache is used ONLY when the server is unreachable so the
employee's feed still shows their history after a restart.

Architecture:
  1. On startup: try to fetch from PostgreSQL → populate feed.
     If fetch fails: load from this SQLite cache instead.
  2. On every push_threat(): write to this cache so it stays in sync.
  3. On logout: wipe cache so next employee starts fresh.
"""
import sqlite3
import threading
import os
from datetime import datetime
from pathlib import Path

_DB_DIR  = Path(__file__).parent.parent / "output"
_DB_PATH = _DB_DIR / "scan_history_cache.db"
_lock    = threading.Lock()

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    saved_at    TEXT NOT NULL,
    time        TEXT NOT NULL,
    channel     TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT NOT NULL,
    risk_level  TEXT NOT NULL DEFAULT 'HIGH',
    pattern     TEXT NOT NULL DEFAULT '',
    file_path   TEXT NOT NULL DEFAULT '',
    ai_text     TEXT
);
"""

_conn: sqlite3.Connection | None = None

def _conn_():
    global _conn
    if _conn is None:
        _DB_DIR.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute(_CREATE_SQL)
        _conn.commit()
    return _conn


def save_event(entry: dict) -> None:
    """Write one event to the local cache. Called in background thread."""
    with _lock:
        try:
            _conn_().execute(
                """INSERT INTO events
                   (saved_at, time, channel, action, detail, risk_level, pattern, file_path, ai_text)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(),
                    entry.get("time", ""),
                    entry.get("channel", ""),
                    entry.get("action", ""),
                    entry.get("detail", ""),
                    entry.get("risk_level", "HIGH"),
                    entry.get("pattern", ""),
                    entry.get("file_path", ""),
                    entry.get("ai_text"),
                ),
            )
            _conn_().commit()
        except Exception as e:
            print(f"[cache] save_event: {e}")


def load_recent(limit: int = 100) -> list[dict]:
    """Fallback: load last N events from local cache (newest-first)."""
    try:
        cur = _conn_().execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        )
        result = []
        for row in cur.fetchall():
            result.append({
                "time":       row["time"],
                "channel":    row["channel"],
                "action":     row["action"],
                "detail":     row["detail"],
                "risk_level": row["risk_level"],
                "pattern":    row["pattern"],
                "file_path":  row["file_path"],
                "ai_text":    row["ai_text"],
                "match":      None,
            })
        return result
    except Exception as e:
        print(f"[cache] load_recent: {e}")
        return []


def cache_events(events: list[dict]) -> None:
    """
    Bulk-replace the cache with events freshly fetched from PostgreSQL.
    Called after a successful server fetch so the cache stays current.
    """
    with _lock:
        try:
            db = _conn_()
            db.execute("DELETE FROM events")
            for entry in events:
                db.execute(
                    """INSERT INTO events
                       (saved_at, time, channel, action, detail, risk_level, pattern, file_path, ai_text)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        datetime.now().isoformat(),
                        entry.get("time", ""),
                        entry.get("channel", ""),
                        entry.get("action", ""),
                        entry.get("detail", ""),
                        entry.get("risk_level", "HIGH"),
                        entry.get("pattern", ""),
                        entry.get("file_path", ""),
                        entry.get("ai_text"),
                    ),
                )
            db.commit()
        except Exception as e:
            print(f"[cache] cache_events: {e}")


def clear_all() -> None:
    """Wipe cache on logout so next employee starts fresh."""
    with _lock:
        try:
            _conn_().execute("DELETE FROM events")
            _conn_().commit()
        except Exception as e:
            print(f"[cache] clear_all: {e}")
