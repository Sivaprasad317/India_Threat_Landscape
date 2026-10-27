"""
Research intelligence and attack-surface exposure.

OTX gives community-shared pulses; filtering for India-relevant ones brings
in campaign reporting that never reaches a leak site.

Shodan is deliberately used for **aggregate counts only** — how many systems
running a given exposed service sit on Indian networks. That is what sector
risk assessment needs. This module does not build, store or output lists of
named vulnerable Indian hosts: that artefact is a targeting package whoever
holds it, and it is not needed to tell a client their sector has an exposure
problem.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from ..sectors import classify_sector
from ..signals import Entities, Severity, Signal, SignalType, now_iso
from .base import BaseCollector, register

OTX_API = "https://otx.alienvault.com/api/v1"
SHODAN_COUNT = "https://api.shodan.io/shodan/host/count"

INDIA_TERMS = re.compile(
    r"\b(india|indian|bharat|new delhi|mumbai|bengaluru|bangalore|hyderabad|"
    r"chennai|kolkata|pune|cert-in|nciipc|rbi|npci|upi|aadhaar|uidai)\b",
    re.IGNORECASE)

# Exposed services that materially raise breach likelihood, with the sector
# each matters most to. Queries are country-scoped aggregate counts.
EXPOSURE_QUERIES = [
    {"query": 'country:IN port:3389', "label": "RDP exposed to the internet",
     "sectors": ["IT_ITES", "BFSI", "HEALTHCARE", "MANUFACTURING"],
     "severity": Severity.HIGH},
    {"query": 'country:IN port:445', "label": "SMB exposed to the internet",
     "sectors": ["IT_ITES", "MANUFACTURING", "GOVERNMENT"],
     "severity": Severity.HIGH},
    {"query": 'country:IN product:"MongoDB"', "label": "MongoDB exposed",
     "sectors": ["IT_ITES", "RETAIL_ECOM"], "severity": Severity.HIGH},
    {"query": 'country:IN product:"Elasticsearch"',
     "label": "Elasticsearch exposed",
     "sectors": ["IT_ITES"], "severity": Severity.HIGH},
    {"query": 'country:IN port:9200', "label": "Elasticsearch port open",
     "sectors": ["IT_ITES"], "severity": Severity.MEDIUM},
    {"query": 'country:IN port:502', "label": "Modbus exposed",
     "sectors": ["ENERGY", "MANUFACTURING"], "severity": Severity.CRITICAL},
    {"query": 'country:IN port:20000', "label": "DNP3 exposed",
     "sectors": ["ENERGY"], "severity": Severity.CRITICAL},
    {"query": 'country:IN port:47808', "label": "BACnet exposed",
     "sectors": ["ENERGY", "REAL_ESTATE"], "severity": Severity.HIGH},
    {"query": 'country:IN product:"Fortinet"', "label": "Fortinet appliances",
     "sectors": ["BFSI", "IT_ITES", "GOVERNMENT"], "severity": Severity.MEDIUM},
    {"query": 'country:IN product:"Citrix"', "label": "Citrix appliances",
     "sectors": ["BFSI", "IT_ITES", "HEALTHCARE"], "severity": Severity.MEDIUM},
]


@register
class OTXCollector(BaseCollector):
    name = "otx"
    description = "AlienVault OTX pulses relevant to India"
    signal_types = ["research"]
    required_env = ["OTX_API_KEY"]
    free = True

    async def collect(self) -> List[Signal]:
        key = self.env("OTX_API_KEY")
        if not key:
            return []
        days = int(self.options.get("days", 14))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        signals: List[Signal] = []
        headers = {"X-OTX-API-KEY": key}

        async with self.client() as client:
            for endpoint in (f"{OTX_API}/pulses/subscribed?limit=100",
                             f"{OTX_API}/search/pulses?q=India&limit=50"):
                data = await self.get_json(client, endpoint, headers=headers)
                if not data:
                    continue

                for pulse in data.get("results", []):
                    name = pulse.get("name", "")
                    desc = pulse.get("description", "") or ""
                    tags = pulse.get("tags") or []
                    countries = pulse.get("targeted_countries") or []
                    industries = pulse.get("industries") or []

                    blob = f"{name} {desc} {' '.join(map(str, tags))}"
                    india_named = any(
                        str(c).lower() in ("india", "in") for c in countries)

                    if india_named:
                        relevance, reason = 0.95, "OTX lists India as a target country"
                    elif INDIA_TERMS.search(blob):
                        relevance, reason = 0.7, "pulse text references India"
                    else:
                        continue

                    created = pulse.get("created", "")
                    try:
                        created_dt = datetime.fromisoformat(
                            created.replace("Z", "+00:00"))
                        if created_dt.tzinfo is None:
                            created_dt = created_dt.replace(tzinfo=timezone.utc)
                        if created_dt < cutoff:
                            continue
                    except (ValueError, AttributeError):
                        created_dt = datetime.now(timezone.utc)

                    ent = Entities()
                    for ind in (pulse.get("indicators") or [])[:120]:
                        itype = ind.get("type", "")
                        val = ind.get("indicator", "")
                        if not val:
                            continue
                        if itype in ("IPv4", "IPv6"):
                            ent.ips.append(val)
                        elif itype in ("domain", "hostname"):
                            ent.domains.append(val)
                        elif itype == "URL":
                            ent.urls.append(val)
                        elif itype in ("FileHash-SHA256", "FileHash-MD5",
                                       "FileHash-SHA1"):
                            ent.hashes.append(val)
                        elif itype == "CVE":
                            ent.cves.append(val)

                    sectors = []
                    for ind_name in industries:
                        sec, _ = classify_sector(str(ind_name))
                        if sec != "UNCLASSIFIED" and sec not in sectors:
                            sectors.append(sec)
                    if not sectors:
                        sec, _ = classify_sector("", "", blob)
                        if sec != "UNCLASSIFIED":
                            sectors.append(sec)

                    signals.append(Signal(
                        signal_type=SignalType.RESEARCH,
                        title=f"OTX pulse: {name}"[:280],
                        description=(
                            f"{desc[:900]} "
                            f"Targeted countries: "
                            f"{', '.join(map(str, countries[:8])) or 'not stated'}. "
                            f"Industries: "
                            f"{', '.join(map(str, industries[:8])) or 'not stated'}."),
                        source="AlienVault OTX",
                        source_url=f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                        observed_at=created_dt.isoformat(),
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        india_relevance=relevance,
                        india_reason=reason,
                        sectors=sectors,
                        entities=ent,
                        annexure_categories=["iii", "v"],
                        tags=["otx"] + [str(t) for t in tags[:6]],
                        raw={"industries": industries[:8],
                             "countries": countries[:8]},
                    ))

        return signals


@register
class ExposureCollector(BaseCollector):
    name = "shodan_exposure"
    description = "Aggregate Indian attack-surface counts (no host lists)"
    signal_types = ["exposure"]
    required_env = ["SHODAN_API_KEY"]
    free = False

    async def collect(self) -> List[Signal]:
        key = self.env("SHODAN_API_KEY")
        if not key:
            return []
        signals: List[Signal] = []

        async with self.client() as client:
            for spec in EXPOSURE_QUERIES:
                data = await self.get_json(
                    client, SHODAN_COUNT,
                    params={"key": key, "query": spec["query"]})
                if not data:
                    continue

                total = data.get("total", 0)
                if not total:
                    continue

                # Deliberately store only the count. The Shodan count endpoint
                # returns no host records, and none are requested elsewhere.
                signals.append(Signal(
                    signal_type=SignalType.EXPOSURE,
                    title=f"{total:,} Indian systems: {spec['label']}"[:280],
                    description=(
                        f"Shodan reports {total:,} systems on Indian networks "
                        f"matching '{spec['label']}'. This is an aggregate "
                        f"count for sector context. No host list is retrieved "
                        f"or stored — the point is to size the exposure, not "
                        f"to enumerate targets."),
                    source="Shodan (aggregate counts)",
                    source_url="https://www.shodan.io/",
                    observed_at=now_iso(),
                    severity=spec["severity"],
                    confidence=0.85,
                    india_relevance=1.0,
                    india_reason="country-scoped query on Indian networks",
                    sectors=spec["sectors"],
                    entities=Entities(),
                    annexure_categories=["i", "ix"] if "Modbus" in spec["label"]
                                        or "DNP3" in spec["label"] else ["i"],
                    tags=["exposure", "attack-surface", "aggregate-only"],
                    raw={"query": spec["query"], "total": total},
                ))

        return signals
