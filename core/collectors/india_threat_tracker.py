"""
India Threat Tracker (github.com/sohankanna/india-threat-tracker).

Hand-curated, sourced records of state-nexus actors targeting India and of
the fake-APK / UPI smishing campaigns hitting Indian users, published as
open data under CC BY 4.0 (Sohan Kanna). Those are the two areas this
platform's feeds see least, so each campaign becomes a campaign-reporting
signal here: it feeds the pressure component and correlation, keeps the
tracker's own confidence and attribution notes, and carries the attribution
the licence requires.

Indicators from the tracker's iocs.csv are attached as entities (domains and
SHA-256 hashes) so they can match other feeds. They are "as reported; not
re-validated" by the tracker, and are not exported to this platform's IOC
sheet.
"""

import csv
import io
from typing import Dict, List

from ..certin import map_to_annexure
from ..signals import Entities, Severity, Signal, SignalType
from .base import BaseCollector, register

BASE_URL = "https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data/"
SOURCE = "India Threat Tracker"
LICENSE = "CC BY 4.0, Sohan Kanna, github.com/sohankanna/india-threat-tracker"
TRACKER_URL = "https://www.sohankanna.com/tracker"

CONFIDENCE = {"high": 0.8, "medium": 0.6, "low": 0.4}
RELEVANCE = {"high": 1.0, "medium": 0.7, "global": 0.4}

# Tracker target labels -> this platform's sectors
TARGET_SECTORS = [
    (("government", "ministry", "defence", "defense", "military", "rto"), "GOVERNMENT"),
    (("education", "academia", "university", "research", "student"), "EDUCATION"),
    (("bank", "upi", "card", "payment", "fintech", "wallet", "loan", "bfsi"), "BFSI"),
    (("startup", "it services", "software", "cybersecurity firm", "osint"), "IT_ITES"),
    (("telecom",), "TELECOM"),
    (("energy", "power", "grid"), "ENERGY"),
    (("health", "hospital", "pharma"), "HEALTHCARE"),
    (("transport", "logistics", "aviation", "port"), "TRANSPORT"),
]


def sectors_for_targets(targets: List[str]) -> List[str]:
    blob = " ".join(t.lower().replace("-", " ") for t in targets or [])
    return sorted({sector for words, sector in TARGET_SECTORS if any(w in blob for w in words)})


def _refang(value: str) -> str:
    return value.replace("[.]", ".").replace("hxxp", "http").strip()


def indicators_by_campaign(csv_text: str) -> Dict[str, Dict[str, List[str]]]:
    out: Dict[str, Dict[str, List[str]]] = {}
    for row in csv.DictReader(io.StringIO(csv_text or "")):
        cid = row.get("campaign_id") or ""
        kind = row.get("type") or ""
        value = _refang(row.get("indicator") or "")
        if not cid or not value:
            continue
        bucket = out.setdefault(cid, {"domains": [], "hashes": [], "other": []})
        if kind == "domains":
            bucket["domains"].append(value.lower())
        elif kind in ("sha256", "sha1", "md5"):
            bucket["hashes"].append(value.lower())
        else:
            bucket["other"].append(f"{kind}:{value}")
    return out


def _date(item: Dict) -> str:
    d = item.get("last_updated") or item.get("date_added") or ""
    return f"{d[:10]}T00:00:00+00:00" if d else ""


def _annexure(text: str) -> List[str]:
    return [m["roman"] for m in map_to_annexure(text)[:2]]


def _source_url(item: Dict) -> str:
    sources = item.get("sources") or []
    return sources[0].get("url", TRACKER_URL) if sources else TRACKER_URL


def parse_tracker(apt_doc: Dict, smishing_doc: Dict, iocs_csv: str = "") -> List[Signal]:
    """Campaign records from the tracker's JSON feeds as Signals."""
    indicators = indicators_by_campaign(iocs_csv)
    signals: List[Signal] = []

    for item in (apt_doc or {}).get("items", []):
        if item.get("status") == "historical" or not item.get("actor"):
            continue
        ind = indicators.get(item.get("id", ""), {})
        conf = item.get("confidence", "medium")
        findings = " ".join((item.get("key_findings") or [])[:2])
        signals.append(Signal(
            signal_type=SignalType.RESEARCH,
            title=f"{item['actor']} activity against Indian targets ({SOURCE})"[:280],
            description=(f"{item.get('summary', '')} {findings} Attribution as reported: "
                         f"{item.get('suspected_origin', 'not stated')}. {item.get('attribution_note', '')} "
                         f"Tracker confidence ({conf}) rates the evidence for the activity, not the attribution.").strip(),
            source=SOURCE,
            source_url=_source_url(item),
            observed_at=_date(item),
            severity=Severity.HIGH if item.get("status") == "active" and conf == "high" else Severity.MEDIUM,
            confidence=CONFIDENCE.get(conf, 0.6),
            india_relevance=RELEVANCE.get(item.get("india_relevance", "high"), 1.0),
            india_reason="curated India-targeting campaign (India Threat Tracker)",
            sectors=sectors_for_targets(item.get("targets", [])),
            entities=Entities(actors=[item["actor"]],
                              malware_families=list(item.get("known_tools") or []),
                              domains=ind.get("domains", []), hashes=ind.get("hashes", [])),
            annexure_categories=_annexure(item.get("summary", "")),
            tags=["india-threat-tracker", "apt", "campaign"] + list(item.get("tags") or []),
            raw={"id": item.get("id"), "aliases": item.get("aliases", []),
                 "mitre_group": item.get("mitre_group"), "attack": item.get("attack", []),
                 "last_verified": item.get("last_verified"), "sources": item.get("sources", []),
                 "license": LICENSE},
        ))

    for item in (smishing_doc or {}).get("items", []):
        if item.get("status") == "historical" or not item.get("title"):
            continue
        ind = indicators.get(item.get("id", ""), {})
        conf = item.get("confidence", "medium")
        sectors = sectors_for_targets(item.get("targets", [])) or ["BFSI"]
        signals.append(Signal(
            signal_type=SignalType.RESEARCH,
            title=f"{item['title']} ({SOURCE})"[:280],
            description=(f"{item.get('summary', '')} Attribution as reported: "
                         f"{item.get('attribution', 'not stated')}.").strip(),
            source=SOURCE,
            source_url=_source_url(item),
            observed_at=_date(item),
            severity=Severity.HIGH if item.get("status") == "active" and conf == "high" else Severity.MEDIUM,
            confidence=CONFIDENCE.get(conf, 0.6),
            india_relevance=RELEVANCE.get(item.get("india_relevance", "high"), 1.0),
            india_reason="curated campaign against Indian users (India Threat Tracker)",
            sectors=sectors,
            entities=Entities(domains=ind.get("domains", []), hashes=ind.get("hashes", [])),
            annexure_categories=_annexure(f"{item.get('summary', '')} digital payment UPI"),
            tags=["india-threat-tracker", "smishing", "campaign"] + list(item.get("tags") or []),
            raw={"id": item.get("id"), "category": item.get("category"),
                 "impersonates": item.get("impersonates", []), "attack": item.get("attack", []),
                 "other_indicators": ind.get("other", []), "last_verified": item.get("last_verified"),
                 "sources": item.get("sources", []), "license": LICENSE},
        ))
    return signals


@register
class IndiaThreatTrackerCollector(BaseCollector):
    name = "india_threat_tracker"
    description = "India Threat Tracker APT and smishing campaigns (CC BY 4.0)"
    signal_types = ["research"]
    required_env: List[str] = []
    free = True

    async def collect(self) -> List[Signal]:
        async with self.client() as client:
            apt = await self.get_json(client, BASE_URL + "apt-campaigns.json")
            smishing = await self.get_json(client, BASE_URL + "smishing-apk.json")
            iocs = await self.get_text(client, BASE_URL + "iocs.csv")
        if apt is None and smishing is None:
            return []
        return parse_tracker(apt or {}, smishing or {}, iocs or "")
