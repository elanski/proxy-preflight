from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

DB_PATH = Path("configs") / "notworkers.db"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utc_now_str() -> str:
    return datetime.utcnow().strftime(DATETIME_FORMAT)


def init_db(db_path=DB_PATH) -> sqlite3.Connection:
    """Создаёт БД и таблицу notworkers, возвращает подключение."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notworkers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            raw TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            fail_count INTEGER NOT NULL DEFAULT 1,
            source TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notworkers_last_seen ON notworkers(last_seen)"
    )
    conn.commit()
    return conn


def upsert_notworker(
    conn: sqlite3.Connection,
    key: str,
    raw: str,
    source: Optional[str] = None,
    seen_at: Optional[str] = None,
) -> None:
    """Добавляет или обновляет запись о нерабочем прокси."""
    if not key:
        return
    if seen_at is None:
        seen_at = _utc_now_str()
    conn.execute(
        """
        INSERT INTO notworkers (key, raw, first_seen, last_seen, fail_count, source)
        VALUES (?, ?, ?, ?, 1, ?)
        ON CONFLICT(key) DO UPDATE SET
            raw = excluded.raw,
            last_seen = excluded.last_seen,
            fail_count = notworkers.fail_count + 1,
            source = COALESCE(excluded.source, notworkers.source)
        """,
        (key, raw, seen_at, seen_at, source),
    )


def is_notworker(conn: sqlite3.Connection, key: str) -> bool:
    if not key:
        return False
    cur = conn.execute("SELECT 1 FROM notworkers WHERE key = ? LIMIT 1", (key,))
    return cur.fetchone() is not None


def expire_old(conn: sqlite3.Connection, max_age_days: int) -> int:
    if max_age_days <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(days=max_age_days)
    cur = conn.execute("DELETE FROM notworkers WHERE last_seen < ?",
                       (cutoff.strftime(DATETIME_FORMAT),))
    conn.commit()
    return cur.rowcount


def prune_to_max(conn: sqlite3.Connection, max_rows: int) -> int:
    if max_rows <= 0:
        return 0
    total = conn.execute("SELECT COUNT(*) FROM notworkers").fetchone()[0] or 0
    if total <= max_rows:
        return 0
    cur = conn.execute(
        "DELETE FROM notworkers WHERE id IN "
        "(SELECT id FROM notworkers ORDER BY last_seen ASC LIMIT ?)",
        (total - max_rows,),
    )
    conn.commit()
    return cur.rowcount


@dataclass
class NotworkersStats:
    total: int
    min_first_seen: Optional[str]
    max_last_seen: Optional[str]


def get_stats(conn: sqlite3.Connection) -> NotworkersStats:
    row = conn.execute(
        "SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM notworkers"
    ).fetchone()
    if not row:
        return NotworkersStats(total=0, min_first_seen=None, max_last_seen=None)
    return NotworkersStats(total=int(row[0]), min_first_seen=row[1], max_last_seen=row[2])


def normalize_proxy_key(line: str) -> str:
    """Нормализует строку прокси в ключ (убирает комментарий)."""
    return line.split("#")[0].strip()
