"""
India-specific sources.

CERT-In advisories are the official national position and belong in any
bulletin claiming to cover India.

Hacktivism is the gap Western CTI tooling misses almost entirely. Groups
announce campaigns against Indian targets on Telegram and X, usually around
geopolitical flashpoints, and the claims are public. Most claims are inflated
or recycled, which is exactly why they need tracking rather than repeating —
the value is telling a client "this group claimed you, here is their track
record of exaggeration."

Only public claims are recorded. This does not touch leaked data.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

from ..certin import map_to_annexure
from ..sectors import classify_sector
from ..signals import Entities, Severity, Signal, SignalType, now_iso
from .base import BaseCollector, register
from .vulns import _sectors_for

CERTIN_ADV_YEAR_URL = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year={year}"
CERTIN_VLN_YEAR_URL = "https://www.cert-in.org.in/s2cMainServlet?pageid=VLNLIST02&year={year}"
CERTIN_VULN_NOTES = "https://www.cert-in.org.in/s2cMainServlet?pageid=VLNLIST"
CERTIN_ADVISORY_LIST = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST"

SEVERITY_WORDS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
}


@register
class CertInAdvisoryCollector(BaseCollector):
    name = "certin_advisories"
    description = "CERT-In vulnerability notes and advisories"
    signal_types = ["advisory"]
    required_env: List[str] = []
    free = True
    timeout = 45

    async def collect(self) -> List[Signal]:
        signals: List[Signal] = []
        days = int(self.options.get("days", 30))
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=days)
        years = [now.year]
        if cutoff.year < now.year:
            years.append(cutoff.year)

        urls = []
        for y in years:
            urls.append(CERTIN_ADV_YEAR_URL.format(year=y))
            urls.append(CERTIN_VLN_YEAR_URL.format(year=y))

        seen = set()
        async with self.client() as client:
            try:
                from bs4 import BeautifulSoup
            except ImportError:
                self.errors.append(
                    "beautifulsoup4 not installed; CERT-In parsing skipped")
                return signals

            # CERT-In publishes notes as CIVN-YYYY-NNNN / CIAD-YYYY-NNNN
            pattern = re.compile(r"(CIVN|CIAD|CIAP)-\d{4}-\d{4,}", re.I)

            for target_url in urls:
                html = await self.get_text(client, target_url)
                if not html:
                    continue

                soup = BeautifulSoup(html, "html.parser")

                for anchor in soup.find_all("a", href=True):
                    text = anchor.get_text(" ", strip=True)
                    match = pattern.search(text) or pattern.search(anchor["href"])
                    if not match:
                        continue
                    ref = match.group(0).upper()
                    if ref in seen:
                        continue
                    seen.add(ref)

                    href = anchor["href"]
                    if href.startswith("/"):
                        href = "https://www.cert-in.org.in" + href
                    elif not href.startswith("http"):
                        href = "https://www.cert-in.org.in/" + href.lstrip("./")

                    tr = anchor.find_parent("tr")
                    d_tr = tr.find_next_sibling("tr") if tr else None
                    s_tr = d_tr.find_next_sibling("tr") if d_tr else None

                    date_text = d_tr.get_text(" ", strip=True) if d_tr else ""
                    subject = s_tr.get_text(" ", strip=True) if s_tr else ""

                    dm = re.search(r"\(([A-Za-z]+\s+\d{1,2},\s*\d{4})\)", date_text)
                    observed_dt = now
                    if dm:
                        try:
                            observed_dt = datetime.strptime(
                                " ".join(dm.group(1).split()), "%B %d, %Y"
                            ).replace(tzinfo=timezone.utc)
                        except ValueError:
                            pass

                    if observed_dt < cutoff:
                        continue

                    full_text = f"{text} {subject}"
                    lowered = full_text.lower()
                    severity = Severity.HIGH
                    for word, sev in SEVERITY_WORDS.items():
                        if word in lowered:
                            severity = sev
                            break

                    cves = re.findall(r"CVE-\d{4}-\d{4,7}", full_text, re.I)
                    tech_sectors = _sectors_for(full_text)
                    kw_sector, _ = classify_sector("", "", full_text)
                    if kw_sector and kw_sector != "UNCLASSIFIED" and kw_sector not in tech_sectors:
                        tech_sectors.append(kw_sector)

                    annexure = map_to_annexure(
                        full_text,
                        sector=tech_sectors[0] if tech_sectors else None
                    )

                    title_summary = subject or text
                    signals.append(Signal(
                        signal_type=SignalType.ADVISORY,
                        title=f"CERT-In {ref}: {title_summary}"[:300],
                        description=(
                            f"Official CERT-In publication {ref}. {subject or text}. "
                            f"CERT-In notes set the national baseline for what Indian "
                            f"organisations are expected to have acted on."
                        ),
                        source="CERT-In",
                        source_url=href,
                        observed_at=observed_dt.isoformat(),
                        severity=severity,
                        confidence=0.95,
                        india_relevance=1.0,
                        india_reason="official Indian national CERT publication",
                        sectors=sorted(set(tech_sectors)),
                        entities=Entities(cves=[c.upper() for c in sorted(set(cves))]),
                        annexure_categories=[a["roman"] for a in annexure],
                        tags=["cert-in", "official", ref.split("-")[0].lower()],
                        raw={"reference": ref, "subject": subject, "date": date_text},
                    ))

        if not signals and not self.errors:
            self.errors.append(
                "CERT-In page fetched but no advisory references matched; "
                "the page structure may have changed")
        return signals


@register
class HacktivismCollector(BaseCollector):
    name = "hacktivism"
    description = "Hacktivist claims against Indian targets, from a local watchlist"
    signal_types = ["hacktivism"]
    required_env: List[str] = []
    free = True

    # Groups with a documented history of claiming attacks on Indian targets.
    # Reputation reflects how often past claims held up under checking.
    KNOWN_GROUPS: Dict[str, Dict] = {
        "team insane pk":        {"reliability": 0.25, "typical": "DDoS, defacement"},
        "mysterious team bangladesh": {"reliability": 0.3, "typical": "DDoS, defacement"},
        "keymous+":              {"reliability": 0.3, "typical": "DDoS"},
        "anonymous sudan":       {"reliability": 0.5, "typical": "DDoS"},
        "noname057(16)":         {"reliability": 0.6, "typical": "DDoS"},
        "sylhet gang":           {"reliability": 0.25, "typical": "DDoS, defacement"},
        "hacktivist indonesia":  {"reliability": 0.2, "typical": "defacement"},
        "ganosec team":          {"reliability": 0.2, "typical": "defacement"},
        "eagle cyber crew":      {"reliability": 0.25, "typical": "DDoS"},
    }

    def _watchlist_path(self) -> Path:
        return Path(self.options.get("watchlist", "data/hacktivist_claims.json"))

    async def collect(self) -> List[Signal]:
        """
        Reads claims from a local JSON file that you maintain from your own
        Telegram and X monitoring. Nothing is scraped from those platforms
        here — this structures work you already do so it lands in the
        bulletin alongside everything else.

        File format: a list of objects like
          {"group": "Team Insane PK", "target": "example.gov.in",
           "sector": "GOVERNMENT", "claim_type": "DDoS",
           "claimed_at": "2026-09-01T10:00:00Z",
           "evidence": "screenshot only", "verified": false,
           "source_url": "https://t.me/..."}
        """
        path = self._watchlist_path()
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("[]", encoding="utf-8")
            self.errors.append(
                f"No claims file yet. Created {path} — add entries from your "
                f"Telegram and X monitoring.")
            return []

        try:
            claims = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.errors.append(f"{path} is not valid JSON: {exc}")
            return []

        days = int(self.options.get("days", 30))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        signals: List[Signal] = []

        for claim in claims:
            group = str(claim.get("group", "unknown")).strip()
            target = str(claim.get("target", "")).strip()
            if not target:
                continue

            claimed_at = claim.get("claimed_at") or now_iso()
            try:
                claimed_dt = datetime.fromisoformat(
                    claimed_at.replace("Z", "+00:00"))
                if claimed_dt.tzinfo is None:
                    claimed_dt = claimed_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                claimed_dt = datetime.now(timezone.utc)
            if claimed_dt < cutoff:
                continue

            profile = self.KNOWN_GROUPS.get(group.lower(), {})
            reliability = profile.get("reliability", 0.35)
            verified = bool(claim.get("verified"))

            confidence = 0.9 if verified else reliability
            severity = (Severity.HIGH if verified else Severity.LOW)

            note = ("Independently verified." if verified else
                    f"Unverified claim. This group's past claims have held up "
                    f"roughly {reliability:.0%} of the time, and hacktivist "
                    f"claims are frequently recycled or exaggerated.")

            signals.append(Signal(
                signal_type=SignalType.HACKTIVISM,
                title=f"{group} claims {claim.get('claim_type', 'attack')} "
                      f"on {target}"[:280],
                description=(
                    f"{group} publicly claimed a "
                    f"{claim.get('claim_type', 'attack')} against {target}. "
                    f"{note} Evidence offered: "
                    f"{claim.get('evidence', 'none stated')}."),
                source="Hacktivist claim tracking",
                source_url=claim.get("source_url", ""),
                observed_at=claimed_dt.isoformat(),
                severity=severity,
                confidence=confidence,
                india_relevance=0.95,
                india_reason="claim explicitly names an Indian target",
                sectors=[claim["sector"]] if claim.get("sector") else [],
                entities=Entities(
                    domains=[target] if "." in target else [],
                    organisations=[target] if "." not in target else [],
                    actors=[group]),
                annexure_categories=(["viii"] if "ddos" in
                                     str(claim.get("claim_type", "")).lower()
                                     else ["iv"]),
                tags=["hacktivism", "claim",
                      "verified" if verified else "unverified"],
                raw=claim,
            ))

        return signals
