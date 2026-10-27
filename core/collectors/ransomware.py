"""
Ransomware victims and dark web leak activity.

Two independent ransomware sources rather than one, because leak-site
scrapers disagree: each covers a different subset of groups and one going
offline should not blind the platform.

Scope boundary: this tracks *that* an Indian organisation was named and what
the group claims to hold. It does not retrieve, store or index leaked data.
Knowing a company is on a leak site is defensive intelligence. Holding their
stolen data is not, and would create legal exposure for you.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

from ..certin import map_to_annexure
from ..sectors import classify_sector, is_indian_entity, is_nciipc_critical
from ..signals import Entities, Severity, Signal, SignalType, now_iso
from .base import BaseCollector, register

RANSOMWARE_LIVE = "https://api.ransomware.live/v2"
RANSOMLOOK = "https://www.ransomlook.io/api"


def _first(record: Dict, *keys: str, default: str = "") -> str:
    for key in keys:
        value = record.get(key)
        if value:
            return str(value)
    return default


def _victim_to_signal(raw: Dict, source: str, source_url: str = "") -> Signal:
    victim_name = _first(raw, "victim", "post_title", "name", "title")
    country = _first(raw, "country", "victim_country")
    activity = _first(raw, "activity", "sector", "industry")
    description = _first(raw, "description", "post_description", "summary")
    group_name = _first(raw, "group_name", "group", "gang")

    _, india_conf, india_reason = is_indian_entity(
        country=country, victim_name=victim_name, description=description)
    sector, sector_conf = classify_sector(activity, victim_name, description)

    discovered = _first(raw, "discovered", "published", "date", "attackdate")
    discovered = discovered.replace(" ", "T") if discovered else now_iso()

    annexure = map_to_annexure(
        "ransomware leak site posting data leak exfiltration encrypted "
        + activity + " " + description, sector=sector)

    severity = (Severity.CRITICAL if is_nciipc_critical(sector)
                else Severity.HIGH)

    return Signal(
        signal_type=SignalType.VICTIM,
        title=f"{group_name or 'Unknown group'} named {victim_name}"[:280],
        description=(
            f"{victim_name} was posted on the {group_name} leak site. "
            f"Sector: {sector}. "
            f"{'Designated critical infrastructure under Section 70A. ' if is_nciipc_critical(sector) else ''}"
            f"{description[:500]}"),
        source=source,
        source_url=source_url or _first(raw, "post_url", "url"),
        observed_at=discovered,
        severity=severity,
        confidence=round(sector_conf, 2) if sector_conf else 0.6,
        india_relevance=india_conf,
        india_reason=india_reason,
        sectors=[sector] if sector != "UNCLASSIFIED" else [],
        entities=Entities(organisations=[victim_name],
                          actors=[group_name] if group_name else []),
        annexure_categories=[a["roman"] for a in annexure],
        tags=["ransomware", "leak-site",
              "nciipc-critical" if is_nciipc_critical(sector) else "standard"],
        raw={k: raw.get(k) for k in list(raw)[:15]},
    )


@register
class RansomwareLiveCollector(BaseCollector):
    name = "ransomware_live"
    description = "ransomware.live leak-site victims, India-filtered"
    signal_types = ["victim"]
    required_env: List[str] = []
    free = True

    async def collect(self) -> List[Signal]:
        signals: List[Signal] = []
        seen = set()

        async with self.client() as client:
            batches = []
            country = await self.get_json(
                client, f"{RANSOMWARE_LIVE}/countryvictims/IN")
            if isinstance(country, list):
                batches.append(country)

            recent = await self.get_json(
                client, f"{RANSOMWARE_LIVE}/recentvictims")
            if isinstance(recent, list):
                batches.append(recent)

            for batch in batches:
                for raw in batch:
                    sig = _victim_to_signal(raw, "ransomware.live")
                    if sig.india_relevance <= 0:
                        continue
                    if sig.signal_id in seen:
                        continue
                    seen.add(sig.signal_id)
                    signals.append(sig)

        return signals


@register
class RansomLookCollector(BaseCollector):
    name = "ransomlook"
    description = "ransomlook.io leak-site victims, second independent source"
    signal_types = ["victim"]
    required_env: List[str] = []
    free = True

    async def collect(self) -> List[Signal]:
        signals: List[Signal] = []
        seen = set()

        async with self.client() as client:
            data = await self.get_json(client, f"{RANSOMLOOK}/recent/50")
            if not isinstance(data, list):
                data = await self.get_json(client, f"{RANSOMLOOK}/recent")
            if not isinstance(data, list):
                return signals

            for raw in data:
                sig = _victim_to_signal(raw, "ransomlook.io")
                if sig.india_relevance <= 0:
                    continue
                if sig.signal_id in seen:
                    continue
                seen.add(sig.signal_id)
                signals.append(sig)

        return signals


@register
class LeakSiteTrackerCollector(BaseCollector):
    name = "leak_tracker"
    description = "Leak-site and forum activity from your own monitoring notes"
    signal_types = ["data_leak"]
    required_env: List[str] = []
    free = True

    def _notes_path(self) -> Path:
        return Path(self.options.get("notes", "data/leak_observations.json"))

    async def collect(self) -> List[Signal]:
        """
        Structures the dark web monitoring you already do by hand.

        Format: a list of objects like
          {"forum": "BreachForums", "seller": "handle",
           "target": "Example Bank Ltd", "sector": "BFSI",
           "claimed_records": 1200000, "data_types": ["PII", "KYC"],
           "asking_price_usd": 5000, "observed_at": "2026-09-01T00:00:00Z",
           "onion": "abc...onion", "verified": false,
           "notes": "sample of 100 rows posted"}

        Record what is being claimed and offered. Do not download or store
        the data itself.
        """
        path = self._notes_path()
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("[]", encoding="utf-8")
            self.errors.append(
                f"No observations yet. Created {path} — record leak-site and "
                f"forum findings there and they will feed the bulletin.")
            return []

        try:
            items = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.errors.append(f"{path} is not valid JSON: {exc}")
            return []

        days = int(self.options.get("days", 60))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        signals: List[Signal] = []

        for item in items:
            target = str(item.get("target", "")).strip()
            if not target:
                continue

            observed = item.get("observed_at") or now_iso()
            try:
                observed_dt = datetime.fromisoformat(
                    observed.replace("Z", "+00:00"))
                if observed_dt.tzinfo is None:
                    observed_dt = observed_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                observed_dt = datetime.now(timezone.utc)
            if observed_dt < cutoff:
                continue

            sector = item.get("sector")
            if not sector:
                sector, _ = classify_sector("", target, item.get("notes", ""))

            records = item.get("claimed_records")
            data_types = item.get("data_types") or []
            verified = bool(item.get("verified"))

            if verified and records and int(records) > 100000:
                severity = Severity.CRITICAL
            elif verified:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            signals.append(Signal(
                signal_type=SignalType.DATA_LEAK,
                title=f"Data on {target} offered on "
                      f"{item.get('forum', 'a forum')}"[:280],
                description=(
                    f"A seller on {item.get('forum', 'an underground forum')} "
                    f"is offering data attributed to {target}. "
                    f"Claimed volume: {records or 'not stated'}. "
                    f"Data types claimed: "
                    f"{', '.join(str(d) for d in data_types) or 'not stated'}. "
                    f"Asking price: {item.get('asking_price_usd', 'not stated')}. "
                    f"{'Claim independently checked.' if verified else 'Claim not verified; forum sellers routinely recycle and inflate.'} "
                    f"{item.get('notes', '')}"),
                source=f"Dark web monitoring — {item.get('forum', 'forum')}",
                source_url=item.get("source_url", ""),
                observed_at=observed_dt.isoformat(),
                severity=severity,
                confidence=0.9 if verified else 0.45,
                india_relevance=0.95,
                india_reason="Indian organisation named in a data sale listing",
                sectors=[sector] if sector and sector != "UNCLASSIFIED" else [],
                entities=Entities(
                    organisations=[target],
                    actors=[item["seller"]] if item.get("seller") else [],
                    onions=[item["onion"]] if item.get("onion") else []),
                annexure_categories=["xi", "xii"],
                tags=["data-leak", "underground-forum",
                      "verified" if verified else "unverified"],
                raw={k: v for k, v in item.items() if k != "notes"},
            ))

        return signals
