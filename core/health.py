"""
Source health: is each feed actually being collected, and is its data fresh?

Two separate questions, because a feed that refreshed five minutes ago can
still hand back records that are weeks old:

  last collected   when the collector last ran without failing outright
  newest record    the most recent observed_at among that feed's signals

A feed is FAILING when its latest run returned nothing and logged errors,
DEGRADED when it returned data but logged errors (retries, partial pages),
STALE when its last good collection or newest record is older than the
feed's expected cadence, and NOT COLLECTED when it has never run.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .database import DEFAULT_DB, connect

# collector name -> (signal source label, days before data counts as stale)
FEEDS: Dict[str, Dict] = {
    "cisa_kev":          {"source": "CISA KEV", "max_age_days": 7},
    "nvd_critical":      {"source": "NVD", "max_age_days": 3},
    "certin_advisories": {"source": "CERT-In", "max_age_days": 10},
    "ransomware_live":   {"source": "ransomware.live", "max_age_days": 3},
    "ransomlook":        {"source": "ransomlook.io", "max_age_days": 3},
    "threatfox":         {"source": "abuse.ch ThreatFox", "max_age_days": 3},
    "urlhaus":           {"source": "abuse.ch URLhaus", "max_age_days": 7},
    "malwarebazaar":     {"source": "abuse.ch MalwareBazaar", "max_age_days": 7},
    "openphish":         {"source": "OpenPhish", "max_age_days": 3},
    "crtsh_typosquat":   {"source": "crt.sh", "max_age_days": 14},
    "otx":               {"source": "AlienVault OTX", "max_age_days": 14},
    "shodan_exposure":   {"source": "Shodan (aggregate counts)", "max_age_days": 14},
    "security_news":     {"source": None, "max_age_days": 3},
    # Analyst-maintained files: freshness depends on the analyst, not a feed
    "hacktivism":        {"source": "Hacktivist claim tracking", "max_age_days": None},
    "leak_tracker":      {"source": None, "max_age_days": None},
}

STATUS_ORDER = ["FAILING", "STALE", "DEGRADED", "NOT COLLECTED", "OK", "MANUAL"]


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _age_days(ts: Optional[datetime], now: datetime) -> Optional[float]:
    return round((now - ts).total_seconds() / 86400, 1) if ts else None


def source_health(now: Optional[datetime] = None, db_path: str = DEFAULT_DB,
                  feeds: Optional[Dict[str, Dict]] = None) -> List[Dict]:
    """One row per feed, worst status first."""
    now = now or datetime.now(timezone.utc)
    feeds = feeds or FEEDS
    with connect(db_path) as conn:
        runs = conn.execute(
            "SELECT collector, started_at, signals_seen, errors FROM collection_runs "
            "ORDER BY started_at").fetchall()
        newest = {r["source"]: r["m"] for r in conn.execute(
            "SELECT source, MAX(observed_at) m FROM signals GROUP BY source").fetchall()}

    by_collector: Dict[str, List] = {}
    for r in runs:
        by_collector.setdefault(r["collector"], []).append(r)

    rows = []
    for name, spec in feeds.items():
        history = by_collector.get(name, [])
        last = history[-1] if history else None
        last_errors = json.loads(last["errors"] or "[]") if last else []
        good = [r for r in history if r["signals_seen"] or not json.loads(r["errors"] or "[]")]
        last_good = _parse(good[-1]["started_at"]) if good else None
        consecutive_failures = 0
        for r in reversed(history):
            if r["signals_seen"] == 0 and json.loads(r["errors"] or "[]"):
                consecutive_failures += 1
            else:
                break

        newest_record = _parse(newest.get(spec["source"])) if spec["source"] else None
        collected_age = _age_days(last_good, now)
        record_age = _age_days(newest_record, now)
        max_age = spec["max_age_days"]

        if not history:
            status = "NOT COLLECTED"
        elif max_age is None:
            status = "MANUAL"
        elif consecutive_failures:
            status = "FAILING"
        elif collected_age is None or collected_age > max_age or (record_age is not None and record_age > max_age):
            status = "STALE"
        elif last_errors:
            status = "DEGRADED"
        else:
            status = "OK"

        rows.append({
            "collector": name,
            "source": spec["source"] or name,
            "status": status,
            "last_run": last["started_at"][:16].replace("T", " ") if last else "",
            "last_collected": last_good.isoformat()[:10] if last_good else "",
            "newest_record": newest_record.isoformat()[:10] if newest_record else "",
            "collected_age_days": collected_age,
            "record_age_days": record_age,
            "max_age_days": max_age,
            "consecutive_failures": consecutive_failures,
            "last_error": last_errors[-1][:160] if last_errors else "",
        })
    rows.sort(key=lambda r: (STATUS_ORDER.index(r["status"]), r["collector"]))
    return rows


def problems(rows: List[Dict], include_missing: bool = False) -> List[Dict]:
    """Rows that need attention: failing or stale feeds (and never-run ones if asked)."""
    bad = {"FAILING", "STALE"} | ({"NOT COLLECTED"} if include_missing else set())
    return [r for r in rows if r["status"] in bad]
