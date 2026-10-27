"""
Validation for the hand-maintained data files.

These files are edited by people, so a typo should be caught by
`python main.py validate` (and CI) rather than surfacing as a silently
skipped entry or a crash halfway through a bulletin.
"""

import json
import os
from datetime import date, datetime
from typing import Callable, Dict, List

from .geo_india import STATE_GEO_COORDS
from .headlines import validate_headline
from .sectors import SECTORS

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
VALID_STATES = set(STATE_GEO_COORDS) | {"Location Unresolved"}


def _is_iso_datetime(value) -> bool:
    try:
        datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _is_iso_date(value) -> bool:
    try:
        date.fromisoformat(str(value)[:10])
        return True
    except ValueError:
        return False


def _check_sector(entry: Dict, where: str, problems: List[str]) -> None:
    if entry.get("sector") and entry["sector"] not in SECTORS:
        problems.append(f"{where}: unknown sector '{entry['sector']}' (use one of {', '.join(SECTORS)})")


def check_headlines(doc) -> List[str]:
    if not isinstance(doc, list):
        return ["file must contain a JSON list"]
    problems, seen = [], set()
    for i, e in enumerate(doc):
        where = f"entry {i + 1} ({e.get('id', '?')})"
        problems += [f"{where}: {p}" for p in validate_headline(e)]
        if e.get("id") in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(e.get("id"))
        for sec in e.get("sectors", []):
            if sec not in SECTORS:
                problems.append(f"{where}: unknown sector '{sec}'")
    return problems


def check_entity_overrides(doc) -> List[str]:
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return ["file must be an object with an 'entries' list"]
    problems = []
    for i, e in enumerate(entries):
        where = f"entry {i + 1} ({', '.join(e.get('match', []))[:40]})"
        if not e.get("match") or not all(isinstance(m, str) and m.strip() for m in e["match"]):
            problems.append(f"{where}: 'match' must be a non-empty list of strings")
        if not any(k in e for k in ("name", "sector", "state")):
            problems.append(f"{where}: sets none of name, sector or state")
        _check_sector(e, where, problems)
        if e.get("state") and e["state"] not in VALID_STATES:
            problems.append(f"{where}: unknown state '{e['state']}'")
        if not e.get("reason"):
            problems.append(f"{where}: missing 'reason'")
        if not _is_iso_date(e.get("reviewed", "")):
            problems.append(f"{where}: 'reviewed' must be YYYY-MM-DD")
    return problems


def check_hacktivist_claims(doc) -> List[str]:
    if not isinstance(doc, list):
        return ["file must contain a JSON list"]
    problems = []
    for i, c in enumerate(doc):
        where = f"claim {i + 1}"
        for field in ("group", "target", "claimed_at"):
            if not c.get(field):
                problems.append(f"{where}: missing '{field}'")
        if c.get("claimed_at") and not _is_iso_datetime(c["claimed_at"]):
            problems.append(f"{where}: 'claimed_at' is not an ISO 8601 time")
        if "verified" in c and not isinstance(c["verified"], bool):
            problems.append(f"{where}: 'verified' must be true or false")
        _check_sector(c, where, problems)
    return problems


def check_leak_observations(doc) -> List[str]:
    if not isinstance(doc, list):
        return ["file must contain a JSON list"]
    problems = []
    for i, o in enumerate(doc):
        where = f"observation {i + 1}"
        for field in ("forum", "target", "observed_at"):
            if not o.get(field):
                problems.append(f"{where}: missing '{field}'")
        if o.get("observed_at") and not _is_iso_datetime(o["observed_at"]):
            problems.append(f"{where}: 'observed_at' is not an ISO 8601 time")
        if o.get("claimed_records") is not None and not isinstance(o["claimed_records"], int):
            problems.append(f"{where}: 'claimed_records' must be a whole number")
        if "verified" in o and not isinstance(o["verified"], bool):
            problems.append(f"{where}: 'verified' must be true or false")
        _check_sector(o, where, problems)
    return problems


def check_asn_cache(doc) -> List[str]:
    hosts = doc.get("hosts") if isinstance(doc, dict) else None
    if not isinstance(hosts, dict):
        return ["file must be an object with a 'hosts' map"]
    return [f"host {h}: needs asn, asn_country and origin_hidden"
            for h, v in hosts.items()
            if not all(v.get(k) for k in ("asn", "asn_country", "origin_hidden"))]


CHECKS: Dict[str, Callable] = {
    "headline_threats.json": check_headlines,
    "entity_overrides.json": check_entity_overrides,
    "hacktivist_claims.json": check_hacktivist_claims,
    "leak_observations.json": check_leak_observations,
    "host_asn_cache.json": check_asn_cache,
}


def validate_data_files(data_dir: str = DATA_DIR) -> Dict[str, List[str]]:
    """Problems per file; an empty dict means everything is valid."""
    results = {}
    for name, check in CHECKS.items():
        path = os.path.join(data_dir, name)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except json.JSONDecodeError as exc:
            results[name] = [f"not valid JSON: {exc}"]
            continue
        found = check(doc)
        if found:
            results[name] = found
    return results
