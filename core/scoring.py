"""
Sector risk scoring.

The score answers a specific question: if I run an organisation in this
sector in India, how much attention does the current threat picture warrant?

Four components, deliberately transparent so a client can see why a number
came out the way it did:

  Volume    how many Indian victims in this sector recently
  Breadth   how many distinct groups are hitting it
  Recency   how fresh the most recent hit is
  Criticality  whether the sector is Section 70A critical infrastructure

Scores are relative to the observed data, not absolute. A sector scoring 80
is not "80% likely to be attacked" — it means it is among the most heavily
and broadly targeted sectors in the window being measured.
"""

import math
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .sectors import is_nciipc_critical, sector_label

WEIGHTS = {
    "volume": 0.40,
    "breadth": 0.25,
    "recency": 0.20,
    "criticality": 0.15,
}

BANDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Moderate"),
    (20, "Low"),
    (0, "Minimal"),
]


def _days_since(iso_ts: Optional[str]) -> Optional[float]:
    if not iso_ts:
        return None
    try:
        ts = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - ts).total_seconds() / 86400, 0.0)


def _volume_score(count: int, max_count: int) -> float:
    """
    Log scale, so one sector with 40 victims does not flatten every other
    sector to near zero.
    """
    if count <= 0 or max_count <= 0:
        return 0.0
    return min(math.log1p(count) / math.log1p(max_count), 1.0) * 100


def _breadth_score(group_count: int, max_groups: int) -> float:
    """
    Many distinct groups hitting one sector is a stronger signal than one
    group being busy, because it implies the sector itself is attractive.
    """
    if group_count <= 0 or max_groups <= 0:
        return 0.0
    return min(group_count / max_groups, 1.0) * 100


def _recency_score(days: Optional[float]) -> float:
    if days is None:
        return 0.0
    if days <= 7:
        return 100.0
    if days <= 14:
        return 85.0
    if days <= 30:
        return 65.0
    if days <= 60:
        return 40.0
    if days <= 90:
        return 20.0
    return 5.0


def score_sector(sector: str, victim_count: int, group_count: int,
                 last_hit: Optional[str], max_count: int,
                 max_groups: int) -> Dict:
    volume = _volume_score(victim_count, max_count)
    breadth = _breadth_score(group_count, max_groups)
    days = _days_since(last_hit)
    recency = _recency_score(days)
    criticality = 100.0 if is_nciipc_critical(sector) else 30.0

    total = (volume * WEIGHTS["volume"]
             + breadth * WEIGHTS["breadth"]
             + recency * WEIGHTS["recency"]
             + criticality * WEIGHTS["criticality"])

    band = next(name for threshold, name in BANDS if total >= threshold)

    return {
        "sector": sector,
        "label": sector_label(sector),
        "risk_score": round(total, 1),
        "risk_band": band,
        "victim_count": victim_count,
        "group_count": group_count,
        "days_since_last_hit": round(days, 1) if days is not None else None,
        "nciipc_critical": is_nciipc_critical(sector),
        "components": {
            "volume": round(volume, 1),
            "breadth": round(breadth, 1),
            "recency": round(recency, 1),
            "criticality": round(criticality, 1),
        },
        "explanation": _explain(sector, victim_count, group_count, days, band),
    }


def _explain(sector: str, victims: int, groups: int,
             days: Optional[float], band: str) -> str:
    parts = []
    if victims:
        parts.append(f"{victims} Indian victim{'s' if victims != 1 else ''} observed")
    else:
        parts.append("no Indian victims observed in this window")
    if groups:
        parts.append(f"attributed to {groups} distinct group{'s' if groups != 1 else ''}")
    if days is not None:
        if days <= 7:
            parts.append("most recent within the past week")
        elif days <= 30:
            parts.append(f"most recent {int(days)} days ago")
        else:
            parts.append(f"nothing new for {int(days)} days")
    if is_nciipc_critical(sector):
        parts.append("designated critical infrastructure under Section 70A")
    return "; ".join(parts) + f". Assessed {band}."


def rank_sectors(sector_rows: List[Dict]) -> List[Dict]:
    """Score every sector in one pass so the scales are shared."""
    if not sector_rows:
        return []
    usable = [r for r in sector_rows if r.get("sector") != "UNCLASSIFIED"]
    if not usable:
        return []

    max_count = max((r["victim_count"] for r in usable), default=1) or 1
    max_groups = max((r["group_count"] for r in usable), default=1) or 1

    scored = [
        score_sector(
            sector=r["sector"],
            victim_count=r["victim_count"],
            group_count=r["group_count"],
            last_hit=r.get("last_hit"),
            max_count=max_count,
            max_groups=max_groups,
        )
        for r in usable
    ]
    scored.sort(key=lambda s: -s["risk_score"])
    return scored


def compare_to_previous(current: Dict, previous: Optional[Dict]) -> Dict:
    """Week-on-week movement for a sector, for the bulletin."""
    if not previous:
        return {"delta_score": None, "delta_victims": None, "direction": "new"}
    delta_score = round(current["risk_score"] - (previous.get("risk_score") or 0), 1)
    delta_victims = current["victim_count"] - (previous.get("victim_count") or 0)
    if delta_score > 3:
        direction = "rising"
    elif delta_score < -3:
        direction = "falling"
    else:
        direction = "steady"
    return {"delta_score": delta_score, "delta_victims": delta_victims,
            "direction": direction}
