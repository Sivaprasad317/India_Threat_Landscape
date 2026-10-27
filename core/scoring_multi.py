"""
Multi-source sector risk scoring.

The single-source version scored on victim counts alone. This version reads
every signal type, which changes the answer in ways that matter:

  A sector with no victims but an actively exploited edge-device CVE and
  rising phishing infrastructure is a sector about to have victims. The
  old model scored it Minimal.

Six components:

  Impact      confirmed victims and data leaks — what already went wrong
  Exploit     actively exploited CVEs affecting the sector's technology
  Infra       malware C2, payload hosts, phishing and lookalike domains
  Pressure    hacktivist claims and campaign reporting naming the sector
  Exposure    aggregate attack surface on Indian networks
  Criticality Section 70A designation

Each component is built from signals, and every signal carries its own
india_relevance and confidence, so weak evidence contributes weakly rather
than counting the same as a confirmed breach.
"""

import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from .sectors import SECTORS, clean_victim_name, is_nciipc_critical, sector_label
from .signals import Signal, SignalType
from .window import ANCHOR_DT

SCORING_VERSION = "2.5"

DEFAULT_ANCHOR_DT = ANCHOR_DT

COMPONENT_WEIGHTS = {
    "impact": 0.30,
    "exploit": 0.20,
    "infra": 0.15,
    "pressure": 0.10,
    "exposure": 0.10,
    "criticality": 0.15,
}

COMPONENT_TYPES = {
    "impact": {SignalType.VICTIM, SignalType.DATA_LEAK},
    "exploit": {SignalType.VULNERABILITY},
    "infra": {SignalType.MALWARE_INFRA, SignalType.PHISHING,
              SignalType.TYPOSQUAT},
    "pressure": {SignalType.HACKTIVISM, SignalType.RESEARCH,
                 SignalType.ADVISORY},
    "exposure": {SignalType.EXPOSURE},
}

BANDS = [(80, "Critical"), (60, "High"), (40, "Moderate"),
         (20, "Low"), (0, "Minimal")]


def assign_risk_band(score: float) -> str:
    """Assigns standard risk band: Critical 80+, High 60-79, Moderate 40-59, Low 20-39, Minimal <20."""
    return next(name for threshold, name in BANDS if score >= threshold)


RECENCY_HALFLIFE_DAYS = 21.0


def _age_days(iso_ts: Optional[str], anchor_dt: Optional[datetime] = None) -> float:
    if not iso_ts:
        return 999.0
    try:
        ts = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return 999.0
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    if anchor_dt is None:
        anchor_dt = DEFAULT_ANCHOR_DT
    if anchor_dt.tzinfo is None:
        anchor_dt = anchor_dt.replace(tzinfo=timezone.utc)
    anchor_utc = anchor_dt.astimezone(timezone.utc)
    ts_utc = ts.astimezone(timezone.utc)
    return max((anchor_utc - ts_utc).total_seconds() / 86400, 0.0)


def _recency_factor(days: float) -> float:
    """Exponential decay. A 21-day-old signal counts half a fresh one."""
    return 0.5 ** (days / RECENCY_HALFLIFE_DAYS)


def _component_score(signals: List[Signal], cap: float,
                     anchor_dt: Optional[datetime] = None) -> float:
    """
    Sum recency-weighted risk contributions, then compress with a log so a
    flood of low-grade signals cannot outrank a handful of severe ones.
    """
    total = sum(s.risk_contribution * _recency_factor(_age_days(s.observed_at, anchor_dt=anchor_dt))
                for s in signals)
    if total <= 0 or cap <= 0:
        return 0.0
    return min(math.log1p(total) / math.log1p(cap), 1.0) * 100


def score_sector_multi(sector: str, signals: List[Signal],
                       caps: Dict[str, float],
                       anchor_dt: Optional[datetime] = None) -> Dict:
    by_component: Dict[str, List[Signal]] = defaultdict(list)
    for sig in signals:
        for component, types in COMPONENT_TYPES.items():
            if sig.signal_type in types:
                by_component[component].append(sig)

    components = {}
    for component in COMPONENT_TYPES:
        components[component] = round(
            _component_score(by_component.get(component, []),
                             caps.get(component, 1.0), anchor_dt=anchor_dt), 1)
    components["criticality"] = 100.0 if is_nciipc_critical(sector) else 30.0

    total = sum(components[c] * COMPONENT_WEIGHTS[c] for c in COMPONENT_WEIGHTS)
    band = next(name for threshold, name in BANDS if total >= threshold)

    victims = by_component.get("impact", [])
    victim_pairs = []
    seen_victim_keys = set()
    for s in victims:
        orgs = s.entities.organisations or ([s.title] if s.signal_type == SignalType.VICTIM else [])
        actor = ""
        if s.entities.actors:
            for a in s.entities.actors:
                if a and a.strip().lower() not in ("unknown", "none", ""):
                    actor = a.strip()
                    break
        if not actor:
            actor = "Unattributed"

        for org in orgs:
            clean_org = org.strip()
            key = (clean_org.lower(), actor.lower())
            if key not in seen_victim_keys:
                seen_victim_keys.add(key)
                victim_pairs.append({
                    "victim": clean_org,
                    "actor": actor,
                    "formatted": f"{clean_org} ({actor})",
                    "source": s.source,
                    "date": (s.observed_at or "")[:10],
                    "signal_type": s.signal_type.value,
                })

    victim_formatted = list(dict.fromkeys([clean_victim_name(v["formatted"]) for v in victim_pairs]))[:6]
    groups = sorted({_normalize_actor(a) for s in signals for a in s.entities.actors if a and a.lower() not in ("unknown", "none", "")})
    cves = sorted({c for s in by_component.get("exploit", [])
                   for c in s.entities.cves})
    sources = sorted({s.source for s in signals})

    return {
        "sector": sector,
        "label": sector_label(sector),
        "risk_score": round(total, 1),
        "risk_band": band,
        "components": components,
        "signal_count": len(signals),
        "victim_count": sum(1 for s in signals
                            if s.signal_type == SignalType.VICTIM),
        "unique_victim_count": len({
            clean_victim_name(
                s.entities.organisations[0] if s.entities.organisations else s.title
            ).strip().lower()
            for s in signals if s.signal_type == SignalType.VICTIM
        }),
        "leak_count": sum(1 for s in signals
                          if s.signal_type == SignalType.DATA_LEAK),
        "exploited_cve_count": len(cves),
        "infra_count": len({
            (s.raw.get("ioc") or s.raw.get("url") or s.title.split(":")[-1].strip()
             if isinstance(s.raw, dict) else s.title.split(":")[-1].strip())
            for s in by_component.get("infra", [])
            if not (s.title.endswith(".in.ua") or s.description.endswith(".in.ua"))
        }),
        "hacktivism_count": sum(1 for s in signals
                                if s.signal_type == SignalType.HACKTIVISM),
        "source_count": len(sources),
        "sources": sources,
        "top_cves": cves[:6],
        "groups": groups[:8],
        "victim_examples": victim_formatted,
        "victim_attributions": victim_pairs,
        "nciipc_critical": is_nciipc_critical(sector),
        "explanation": _explain(sector, components, by_component, band),
    }


ACTOR_CANONICAL = {
    "clop": "Clop",
    "krybit": "Krybit",
    "umbra": "UmBra",
    "vexy": "Vexy",
    "vexy ransomware": "Vexy",
    "auditteam": "AuditTeam",
    "thegentlemen": "TheGentlemen",
    "globalsecretgroup": "Global Secret Group",
    "global secret group": "Global Secret Group",
    "emperador": "Emperador",
    "orova": "Orova",
    "direwolf": "DireWolf",
    "eclipse": "Eclipse",
    "dysphor1a": "DYSPHOR1A",
    "majinahanashi": "Majinahanashi",
    "blackwater": "BlackWater",
    "medusalocker": "MedusaLocker",
    "qilin": "Qilin",
    "doommageddon": "Doommageddon",
}


def _normalize_actor(name: str) -> str:
    n = (name or "").strip()
    return ACTOR_CANONICAL.get(n.lower(), n.title() if n.islower() else n)


def _explain(sector: str, components: Dict, by_component: Dict,
             band: str) -> str:
    parts = []
    victims = [s for s in by_component.get("impact", [])
               if s.signal_type == SignalType.VICTIM]
    leaks = [s for s in by_component.get("impact", [])
             if s.signal_type == SignalType.DATA_LEAK]
    exploits = by_component.get("exploit", [])
    infra = by_component.get("infra", [])
    pressure = by_component.get("pressure", [])

    if victims:
        uniq_v = len({
            clean_victim_name(
                s.entities.organisations[0] if s.entities.organisations else s.title
            ).strip().lower()
            for s in victims
        })
        if uniq_v == len(victims):
            parts.append(f"{len(victims)} claimed victim{'s' if len(victims) != 1 else ''}")
        else:
            parts.append(f"{uniq_v} unique claimed victim{'s' if uniq_v != 1 else ''} ({len(victims)} leak postings)")
    if leaks:
        parts.append(f"{len(leaks)} data-sale listing"
                     f"{'s' if len(leaks) != 1 else ''}")
    if exploits:
        cves = sorted({c for s in exploits for c in s.entities.cves})
        ransomware_linked = sum(1 for s in exploits
                                if "ransomware-campaign-use" in s.tags)
        detail = f"{len(cves)} monitored sector CVE{'s' if len(cves) != 1 else ''} (KEV + NVD)"
        if ransomware_linked:
            detail += f" ({ransomware_linked} KEV actively exploited)"
        parts.append(detail)
    if infra:
        parts.append(f"{len(infra)} compromised or impersonated sector site"
                     f"{'s' if len(infra) != 1 else ''}")
    if pressure:
        parts.append(f"{len(pressure)} campaign or hacktivist signal"
                     f"{'s' if len(pressure) != 1 else ''}")

    if not parts:
        parts.append("no signals in this window")

    if is_nciipc_critical(sector):
        parts.append("Section 70A critical infrastructure")

    # Call out the case the single-source model got wrong
    if not victims and (exploits or infra):
        parts.append("no victims yet, but attacker preconditions present")

    return "; ".join(parts) + f". Assessed {band}."


INFRA_DOMAIN_KEYWORD_MAP = {
    "RETAIL_ECOM": [r"furniture", r"trader", r"store", r"shop", r"style", r"bazaar", r"retail", r"gift", r"super", r"apparel", r"fashion"],
    "TRANSPORT": [r"mover", r"transport", r"logistics", r"freight", r"cargo", r"courier"],
    "MANUFACTURING": [r"cartec", r"steel", r"chem", r"valve", r"motor", r"engg", r"industrial", r"makerman", r"foundry"],
    "REAL_ESTATE": [r"interior", r"realty", r"square", r"builder", r"construction"],
    "NGO_LEGAL": [r"foundation", r"trust", r"legal", r"advocate"],
    "HEALTHCARE": [r"hospital", r"health", r"clinic", r"cure", r"jeh\."],
    "PHARMA": [r"pharma", r"biopharm"],
    "BFSI": [r"\bbank\b", r"\bfinance\b", r"\bfintech\b", r"\bmdfs\b", r"\bwealth\b", r"\bcapital\b", r"\bupi\b", r"\bpayment\b"],
    "EDUCATION": [r"school", r"college", r"academy", r"univ", r"\.ac\.in\b", r"aimst", r"vidya", r"shiksha"],
    "GOVERNMENT": [r"\.gov\.in\b", r"police", r"nic\.in\b"],
    "ENERGY": [r"renew", r"solar", r"energy", r"power", r"discom"],
    "MEDIA": [r"media", r"cinema", r"film", r"broadcast"],
    "IT_ITES": [r"tech", r"soft", r"cloud", r"host", r"cyber", r"network", r"server", r"search", r"digital", r"prognosis", r"highsky", r"data\b"],
}


def _infer_infra_sectors(sig: Signal) -> List[str]:
    target = ""
    if ":" in sig.title:
        target = sig.title.split(":", 1)[1].strip()
    elif "http" in sig.description:
        m = re.search(r"https?://[^\s/]+", sig.description)
        if m:
            target = m.group(0)
    domain = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0].lower()
    if not domain:
        domain = sig.title.lower()

    hits = []
    for sec, patterns in INFRA_DOMAIN_KEYWORD_MAP.items():
        if any(re.search(p, domain, re.IGNORECASE) for p in patterns):
            hits.append(sec)
    return hits


def rank_sectors_multi(signals: List[Signal],
                       min_relevance: float = 0.3,
                       anchor_dt: Optional[datetime] = None) -> List[Dict]:
    """Score every sector from the full signal set with shared scales anchored to a fixed timestamp."""
    if anchor_dt is None:
        anchor_dt = DEFAULT_ANCHOR_DT

    relevant = [s for s in signals if s.india_relevance >= min_relevance]
    by_sector: Dict[str, List[Signal]] = defaultdict(list)

    for sig in relevant:
        secs = sig.sectors
        if not secs and sig.signal_type in (SignalType.MALWARE_INFRA, SignalType.PHISHING):
            secs = _infer_infra_sectors(sig)

        for sector in secs:
            if sector in SECTORS and sector != "UNCLASSIFIED":
                by_sector[sector].append(sig)

    if not by_sector:
        return []

    # Shared caps so components are comparable across sectors
    caps: Dict[str, float] = {}
    for component, types in COMPONENT_TYPES.items():
        totals = []
        for sector, sigs in by_sector.items():
            subset = [s for s in sigs if s.signal_type in types]
            totals.append(sum(
                s.risk_contribution * _recency_factor(_age_days(s.observed_at, anchor_dt=anchor_dt))
                for s in subset))
        caps[component] = max(totals + [0.5])

    scored = [score_sector_multi(sector, sigs, caps, anchor_dt=anchor_dt)
              for sector, sigs in by_sector.items()]
    scored.sort(key=lambda s: -s["risk_score"])
    return scored


def unsectored_signals(signals: List[Signal],
                       min_relevance: float = 0.5) -> List[Signal]:
    """
    India-relevant signals that carry no sector. These still matter — a
    malicious host on an Indian network is a compromised Indian server even
    when we cannot say whose.
    """
    return [s for s in signals
            if s.india_relevance >= min_relevance and not s.sectors]
