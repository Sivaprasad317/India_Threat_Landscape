"""
SQLite storage for the India threat landscape.

One file, no server. Schema is intentionally small: victims, sector
snapshots, and the groups seen operating against Indian entities.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .window import window_end_date

DEFAULT_DB = "cache/india_threats.db"


@contextmanager
def connect(db_path: str = DEFAULT_DB):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DEFAULT_DB) -> None:
    with connect(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS victims (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            victim_name       TEXT NOT NULL,
            normalized_name   TEXT NOT NULL,
            group_name        TEXT,
            sector            TEXT,
            sector_confidence REAL DEFAULT 0.0,
            raw_activity      TEXT,
            country           TEXT,
            india_confidence  REAL DEFAULT 0.0,
            india_reason      TEXT,
            discovered_at     TEXT,
            published_at      TEXT,
            description       TEXT,
            source            TEXT,
            source_url        TEXT,
            annexure_categories TEXT,
            nciipc_critical   INTEGER DEFAULT 0,
            first_seen        TEXT,
            UNIQUE(normalized_name, group_name)
        );

        CREATE INDEX IF NOT EXISTS idx_victims_sector
            ON victims(sector);
        CREATE INDEX IF NOT EXISTS idx_victims_group
            ON victims(group_name);
        CREATE INDEX IF NOT EXISTS idx_victims_discovered
            ON victims(discovered_at);

        CREATE TABLE IF NOT EXISTS group_activity (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name    TEXT NOT NULL UNIQUE,
            india_victims INTEGER DEFAULT 0,
            global_victims INTEGER DEFAULT 0,
            sectors_hit   TEXT,
            first_seen_in TEXT,
            last_seen_in  TEXT,
            notes         TEXT
        );

        CREATE TABLE IF NOT EXISTS sector_snapshots (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_date TEXT NOT NULL,
            sector       TEXT NOT NULL,
            victim_count INTEGER DEFAULT 0,
            group_count  INTEGER DEFAULT 0,
            risk_score   REAL DEFAULT 0.0,
            risk_band    TEXT,
            UNIQUE(snapshot_date, sector)
        );

        CREATE TABLE IF NOT EXISTS intel_items (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            title         TEXT,
            url           TEXT UNIQUE,
            source        TEXT,
            published_at  TEXT,
            india_relevant INTEGER DEFAULT 0,
            india_reason  TEXT,
            sectors       TEXT,
            annexure_categories TEXT,
            summary       TEXT,
            collected_at  TEXT
        );
        """)


def _norm(name: str) -> str:
    return " ".join((name or "").lower().split())


def upsert_victim(record: Dict, db_path: str = DEFAULT_DB) -> bool:
    """Insert a victim. Returns True when newly added."""
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO victims
               (victim_name, normalized_name, group_name, sector,
                sector_confidence, raw_activity, country, india_confidence,
                india_reason, discovered_at, published_at, description,
                source, source_url, annexure_categories, nciipc_critical,
                first_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                record.get("victim_name", ""),
                _norm(record.get("victim_name", "")),
                record.get("group_name", ""),
                record.get("sector", "UNCLASSIFIED"),
                record.get("sector_confidence", 0.0),
                record.get("raw_activity", ""),
                record.get("country", ""),
                record.get("india_confidence", 0.0),
                record.get("india_reason", ""),
                record.get("discovered_at", now),
                record.get("published_at", ""),
                record.get("description", ""),
                record.get("source", ""),
                record.get("source_url", ""),
                json.dumps(record.get("annexure_categories", [])),
                1 if record.get("nciipc_critical") else 0,
                now,
            ),
        )
        return cur.rowcount > 0


def get_victims(days: Optional[int] = None, sector: Optional[str] = None,
                group: Optional[str] = None,
                db_path: str = DEFAULT_DB) -> List[Dict]:
    clauses, params = [], []
    if days:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        clauses.append("discovered_at >= ?")
        params.append(cutoff)
    if sector:
        clauses.append("sector = ?")
        params.append(sector)
    if group:
        clauses.append("LOWER(group_name) = ?")
        params.append(group.lower())

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM victims {where} ORDER BY discovered_at DESC",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def sector_counts(days: int = 90, db_path: str = DEFAULT_DB) -> List[Dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT sector,
                      COUNT(*)                        AS victim_count,
                      COUNT(DISTINCT group_name)      AS group_count,
                      MAX(discovered_at)              AS last_hit
               FROM victims
               WHERE discovered_at >= ?
               GROUP BY sector
               ORDER BY victim_count DESC""",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def group_counts(days: int = 90, db_path: str = DEFAULT_DB) -> List[Dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT group_name,
                      COUNT(*)                   AS victim_count,
                      COUNT(DISTINCT sector)     AS sector_count,
                      MAX(discovered_at)         AS last_hit
               FROM victims
               WHERE discovered_at >= ? AND group_name != ''
               GROUP BY group_name
               ORDER BY victim_count DESC""",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def save_snapshot(sector: str, victim_count: int, group_count: int,
                  risk_score: float, risk_band: str,
                  db_path: str = DEFAULT_DB) -> None:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with connect(db_path) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO sector_snapshots
               (snapshot_date, sector, victim_count, group_count,
                risk_score, risk_band)
               VALUES (?,?,?,?,?,?)""",
            (today, sector, victim_count, group_count, risk_score, risk_band),
        )


def previous_snapshot(sector: str, before_days: int = 7,
                      db_path: str = DEFAULT_DB) -> Optional[Dict]:
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=before_days)).strftime("%Y-%m-%d")
    with connect(db_path) as conn:
        row = conn.execute(
            """SELECT * FROM sector_snapshots
               WHERE sector = ? AND snapshot_date <= ?
               ORDER BY snapshot_date DESC LIMIT 1""",
            (sector, cutoff),
        ).fetchone()
    return dict(row) if row else None


def stats(db_path: str = DEFAULT_DB) -> Dict:
    with connect(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) c FROM victims").fetchone()["c"]
        groups = conn.execute(
            "SELECT COUNT(DISTINCT group_name) c FROM victims").fetchone()["c"]
        critical = conn.execute(
            "SELECT COUNT(*) c FROM victims WHERE nciipc_critical = 1"
        ).fetchone()["c"]
        intel = conn.execute("SELECT COUNT(*) c FROM intel_items").fetchone()["c"]
    return {"total_victims": total, "distinct_groups": groups,
            "nciipc_critical_victims": critical, "intel_items": intel}


def upsert_intel_item(item: Dict, db_path: str = DEFAULT_DB) -> bool:
    """Store a news story keyed by URL. Returns True when newly added."""
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        exists = conn.execute("SELECT 1 FROM intel_items WHERE url = ?",
                              (item["url"],)).fetchone()
        conn.execute(
            """INSERT INTO intel_items
               (title, url, source, published_at, india_relevant,
                india_reason, summary, collected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(url) DO UPDATE SET
                 title = excluded.title, summary = excluded.summary,
                 india_relevant = excluded.india_relevant,
                 india_reason = excluded.india_reason""",
            (item["title"], item["url"], item.get("source", ""),
             item.get("published_at", ""), int(bool(item.get("india_relevant"))),
             item.get("india_reason", ""), item.get("summary", ""), now))
    return exists is None


def get_intel_items(since: str, until: str,
                    db_path: str = DEFAULT_DB) -> List[Dict]:
    """News stories published in [since, until), ISO strings."""
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT title, url, source, published_at, india_relevant,
                      india_reason, summary
               FROM intel_items
               WHERE published_at >= ? AND published_at < ?
               ORDER BY published_at DESC""", (since, until)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Signal store (multi-source)
# ---------------------------------------------------------------------------

SIGNAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS signals (
    signal_id           TEXT PRIMARY KEY,
    signal_type         TEXT NOT NULL,
    title               TEXT,
    description         TEXT,
    source              TEXT,
    source_url          TEXT,
    observed_at         TEXT,
    severity            TEXT,
    confidence          REAL DEFAULT 0.5,
    india_relevance     REAL DEFAULT 0.0,
    india_reason        TEXT,
    sectors             TEXT,
    entities            TEXT,
    annexure_categories TEXT,
    tags                TEXT,
    risk_contribution   REAL DEFAULT 0.0,
    raw                 TEXT,
    first_stored        TEXT,
    last_seen           TEXT
);
CREATE INDEX IF NOT EXISTS idx_sig_type ON signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_sig_source ON signals(source);
CREATE INDEX IF NOT EXISTS idx_sig_observed ON signals(observed_at);

CREATE TABLE IF NOT EXISTS collection_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    collector    TEXT,
    started_at   TEXT,
    finished_at  TEXT,
    signals_new  INTEGER DEFAULT 0,
    signals_seen INTEGER DEFAULT 0,
    errors       TEXT
);
"""


def init_signals(db_path: str = DEFAULT_DB) -> None:
    with connect(db_path) as conn:
        conn.executescript(SIGNAL_SCHEMA)


def upsert_signal(signal, db_path: str = DEFAULT_DB) -> bool:
    """Store a Signal. Returns True when newly added, False when updated."""
    row = signal.to_row()
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        existing = conn.execute(
            "SELECT 1 FROM signals WHERE signal_id = ?",
            (row["signal_id"],),
        ).fetchone()
        conn.execute(
            """INSERT INTO signals
               (signal_id, signal_type, title, description, source, source_url,
                observed_at, severity, confidence, india_relevance,
                india_reason, sectors, entities, annexure_categories, tags,
                risk_contribution, raw, first_stored, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(signal_id) DO UPDATE SET
                 last_seen = excluded.last_seen,
                 confidence = MAX(signals.confidence, excluded.confidence),
                 risk_contribution = excluded.risk_contribution""",
            (row["signal_id"], row["signal_type"], row["title"],
             row["description"], row["source"], row["source_url"],
             row["observed_at"], row["severity"], row["confidence"],
             row["india_relevance"], row["india_reason"], row["sectors"],
             row["entities"], row["annexure_categories"], row["tags"],
             row["risk_contribution"], row["raw"], now, now),
        )
        return existing is None


def get_signals(days: int = 90, signal_type: str = None,
                sector: str = None, min_relevance: float = 0.0,
                db_path: str = DEFAULT_DB,
                end_date: Optional[Any] = None) -> List[Dict]:
    anchor = end_date.date() if isinstance(end_date, datetime) else (end_date or window_end_date())
    cutoff = (anchor - timedelta(days=days)).isoformat()
    upper = (anchor + timedelta(days=1)).isoformat()
    clauses = ["observed_at >= ?", "observed_at < ?", "india_relevance >= ?"]
    params = [cutoff, upper, min_relevance]
    if signal_type:
        clauses.append("signal_type = ?")
        params.append(signal_type)
    if sector:
        clauses.append("sectors LIKE ?")
        params.append(f'%"{sector}"%')
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM signals WHERE {' AND '.join(clauses)} "
            f"ORDER BY observed_at DESC", params).fetchall()
    return [dict(r) for r in rows]


def signal_counts_by_source(days: int = 90,
                            db_path: str = DEFAULT_DB,
                            end_date: Optional[Any] = None) -> List[Dict]:
    anchor = end_date.date() if isinstance(end_date, datetime) else (end_date or window_end_date())
    cutoff = (anchor - timedelta(days=days)).isoformat()
    upper = (anchor + timedelta(days=1)).isoformat()
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT source, signal_type, COUNT(*) AS n,
                      AVG(india_relevance) AS avg_relevance
               FROM signals WHERE observed_at >= ? AND observed_at < ?
               GROUP BY source, signal_type
               ORDER BY n DESC""", (cutoff, upper)).fetchall()
    return [dict(r) for r in rows]


def latest_signal_date(db_path: str = DEFAULT_DB) -> str:
    with connect(db_path) as conn:
        row = conn.execute("SELECT MAX(observed_at) m FROM signals").fetchone()
    return (row["m"] or "")[:10]


def record_run(collector: str, started: str, finished: str,
               new_count: int, seen_count: int, errors: List[str],
               db_path: str = DEFAULT_DB) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO collection_runs
               (collector, started_at, finished_at, signals_new,
                signals_seen, errors)
               VALUES (?,?,?,?,?,?)""",
            (collector, started, finished, new_count, seen_count,
             json.dumps(errors[:20])))


def signal_stats(db_path: str = DEFAULT_DB) -> Dict:
    with connect(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) c FROM signals").fetchone()["c"]
        by_type = {r["signal_type"]: r["n"] for r in conn.execute(
            "SELECT signal_type, COUNT(*) n FROM signals GROUP BY signal_type"
        ).fetchall()}
        sources = conn.execute(
            "SELECT COUNT(DISTINCT source) c FROM signals").fetchone()["c"]
        high = conn.execute(
            "SELECT COUNT(*) c FROM signals WHERE india_relevance >= 0.8"
        ).fetchone()["c"]
    return {"total_signals": total, "by_type": by_type,
            "distinct_sources": sources, "high_relevance": high}
