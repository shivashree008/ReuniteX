import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent


def _store_path(camp_id):
    normalized_id = str(uuid.UUID(str(camp_id)))
    configured_root = os.getenv("OFFLINE_STORE_DIR", "").strip()
    root = Path(configured_root) if configured_root else PROJECT_DIR / "instance" / "camp_stores"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{normalized_id}.sqlite3"


def connect_camp(camp_id):
    connection = sqlite3.connect(_store_path(camp_id), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript(
        "CREATE TABLE IF NOT EXISTS local_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "INSERT OR IGNORE INTO local_settings (key, value) VALUES ('online', 'true');"
        "CREATE TABLE IF NOT EXISTS sync_queue ("
        "event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, payload_json TEXT NOT NULL, "
        "status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'synced', 'failed')), "
        "attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TEXT NOT NULL, synced_at TEXT);"
    )
    connection.commit()
    return connection


@contextmanager
def camp_connection(camp_id):
    connection = connect_camp(camp_id)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def is_online(camp_id):
    with camp_connection(camp_id) as connection:
        value = connection.execute(
            "SELECT value FROM local_settings WHERE key = 'online'"
        ).fetchone()["value"]
    return value == "true"


def set_online(camp_id, online):
    with camp_connection(camp_id) as connection:
        connection.execute(
            "INSERT INTO local_settings (key, value) VALUES ('online', ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            ("true" if online else "false",),
        )
    return bool(online)


def queue_event(camp_id, event_type, payload, event_id=None):
    event_id = str(uuid.UUID(str(event_id))) if event_id else str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    with camp_connection(camp_id) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO sync_queue (event_id, event_type, payload_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (event_id, event_type, json.dumps(payload, ensure_ascii=False), created_at),
        )
        row = connection.execute(
            "SELECT event_id, event_type, payload_json, status, attempts, last_error, created_at "
            "FROM sync_queue WHERE event_id = ?",
            (event_id,),
        ).fetchone()
    return dict(row)


def pending_events(camp_id):
    with camp_connection(camp_id) as connection:
        rows = connection.execute(
            "SELECT event_id, event_type, payload_json, attempts FROM sync_queue "
            "WHERE status IN ('pending', 'failed') ORDER BY created_at, event_id"
        ).fetchall()
    return [
        {**dict(row), "payload": json.loads(row["payload_json"])}
        for row in rows
    ]


def mark_synced(camp_id, event_id):
    with camp_connection(camp_id) as connection:
        connection.execute(
            "UPDATE sync_queue SET status = 'synced', attempts = attempts + 1, "
            "last_error = NULL, synced_at = ? WHERE event_id = ?",
            (datetime.now(timezone.utc).isoformat(), event_id),
        )


def mark_failed(camp_id, event_id, error):
    with camp_connection(camp_id) as connection:
        connection.execute(
            "UPDATE sync_queue SET status = 'failed', attempts = attempts + 1, "
            "last_error = ? WHERE event_id = ?",
            (str(error)[:500], event_id),
        )


def queue_status(camp_id):
    with camp_connection(camp_id) as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS count FROM sync_queue GROUP BY status"
        ).fetchall()
    return {row["status"]: row["count"] for row in rows}