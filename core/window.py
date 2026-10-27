"""
Reporting window anchor.

Scoring, signal loading and the bulletin all measure their window back from
one fixed end date, so repeated runs over the same database give identical
numbers. Override it with SCORING_ANCHOR (ISO 8601, or "now"); naive
timestamps are read as IST.
"""

import os
from datetime import date, datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))
BUILTIN_ANCHOR_DT = datetime(2026, 10, 11, 23, 59, 59, tzinfo=IST)


def resolve_anchor() -> datetime:
    raw = os.getenv("SCORING_ANCHOR", "").strip()
    if not raw:
        return BUILTIN_ANCHOR_DT
    if raw.lower() == "now":
        return datetime.now(IST)
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return BUILTIN_ANCHOR_DT
    return dt if dt.tzinfo else dt.replace(tzinfo=IST)


ANCHOR_DT = resolve_anchor()


def window_end_date() -> date:
    return ANCHOR_DT.date()


def is_builtin_anchor() -> bool:
    return ANCHOR_DT == BUILTIN_ANCHOR_DT
