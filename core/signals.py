"""
Unified signal schema.

Every collector, whatever it talks to, emits Signal objects. That is what
makes cross-source correlation possible: a CVE from CISA KEV, a ThreatFox C2
referencing the same exploit, and a blog post describing an Indian victim all
become comparable records rather than three incompatible blobs.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class SignalType(str, Enum):
    VICTIM = "victim"              # named organisation hit
    VULNERABILITY = "vulnerability"  # CVE, especially actively exploited
    MALWARE_INFRA = "malware_infra"  # C2, payload host, distribution URL
    PHISHING = "phishing"          # phishing page or lookalike domain
    TYPOSQUAT = "typosquat"        # lookalike domain registered
    HACKTIVISM = "hacktivism"      # claimed attack, DDoS, defacement
    DATA_LEAK = "data_leak"        # data offered or dumped
    EXPOSURE = "exposure"          # aggregate attack-surface statistic
    ADVISORY = "advisory"          # official CERT-In or vendor advisory
    RESEARCH = "research"          # vendor blog reporting


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}

# How much each signal type contributes to sector risk. A named victim is
# hard evidence; an aggregate exposure statistic is context.
TYPE_WEIGHT = {
    SignalType.VICTIM: 1.00,
    SignalType.DATA_LEAK: 0.85,
    SignalType.HACKTIVISM: 0.60,
    SignalType.VULNERABILITY: 0.70,
    SignalType.MALWARE_INFRA: 0.55,
    SignalType.PHISHING: 0.50,
    SignalType.TYPOSQUAT: 0.45,
    SignalType.ADVISORY: 0.40,
    SignalType.RESEARCH: 0.35,
    SignalType.EXPOSURE: 0.30,
}


@dataclass
class Entities:
    """Observable artefacts attached to a signal."""
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    organisations: List[str] = field(default_factory=list)
    actors: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    onions: List[str] = field(default_factory=list)

    def all_values(self) -> List[str]:
        out = []
        for value in asdict(self).values():
            out.extend(value)
        return out

    def is_empty(self) -> bool:
        return not self.all_values()


@dataclass
class Signal:
    signal_type: SignalType
    title: str
    source: str
    observed_at: str
    description: str = ""
    source_url: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    india_relevance: float = 0.0
    india_reason: str = ""
    sectors: List[str] = field(default_factory=list)
    entities: Entities = field(default_factory=Entities)
    annexure_categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw: Dict = field(default_factory=dict)
    signal_id: str = ""

    def __post_init__(self):
        if not self.signal_id:
            self.signal_id = self.compute_id()
        if isinstance(self.signal_type, str):
            self.signal_type = SignalType(self.signal_type)
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)

    def compute_id(self) -> str:
        """
        Stable identity so re-running a collector does not duplicate rows.
        Built from source, type and the most distinctive available artefact.
        """
        anchor = ""
        for candidate in (self.entities.cves, self.entities.hashes,
                          self.entities.urls, self.entities.domains,
                          self.entities.organisations):
            if candidate:
                anchor = sorted(candidate)[0]
                break
        basis = f"{self.source}|{self.signal_type}|{anchor or self.title}"
        return hashlib.sha256(basis.lower().encode()).hexdigest()[:20]

    @property
    def risk_contribution(self) -> float:
        """
        Weighted contribution to sector risk.

        Multiplying by india_relevance and confidence means a weak,
        heuristically-attributed signal cannot move a sector score the way a
        confirmed named victim does.
        """
        type_w = TYPE_WEIGHT.get(self.signal_type, 0.3)
        sev_w = SEVERITY_WEIGHT.get(self.severity, 0.5)
        return round(type_w * sev_w * self.confidence
                     * max(self.india_relevance, 0.0), 4)

    def to_row(self) -> Dict:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type.value,
            "title": self.title[:500],
            "description": self.description[:2000],
            "source": self.source,
            "source_url": self.source_url,
            "observed_at": self.observed_at,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "india_relevance": self.india_relevance,
            "india_reason": self.india_reason,
            "sectors": json.dumps(self.sectors),
            "entities": json.dumps(asdict(self.entities)),
            "annexure_categories": json.dumps(self.annexure_categories),
            "tags": json.dumps(self.tags),
            "risk_contribution": self.risk_contribution,
            "raw": json.dumps(self.raw)[:8000],
        }

    @staticmethod
    def from_row(row: Dict) -> "Signal":
        ent = json.loads(row.get("entities") or "{}")
        return Signal(
            signal_id=row["signal_id"],
            signal_type=SignalType(row["signal_type"]),
            title=row["title"],
            description=row.get("description", ""),
            source=row["source"],
            source_url=row.get("source_url", ""),
            observed_at=row["observed_at"],
            severity=Severity(row.get("severity", "Medium")),
            confidence=row.get("confidence", 0.5),
            india_relevance=row.get("india_relevance", 0.0),
            india_reason=row.get("india_reason", ""),
            sectors=json.loads(row.get("sectors") or "[]"),
            entities=Entities(**{k: v for k, v in ent.items()
                                 if k in Entities.__annotations__}),
            annexure_categories=json.loads(row.get("annexure_categories") or "[]"),
            tags=json.loads(row.get("tags") or "[]"),
            raw=json.loads(row.get("raw") or "{}"),
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
