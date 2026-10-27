"""
Brand impersonation and phishing targeting Indian organisations.

Certificate transparency is the highest-signal free source here. When someone
registers sbi-netbanking-secure.in and gets a certificate for it, that
certificate is published within minutes — usually days before the phishing
page goes live. That is genuine early warning, not after-the-fact reporting.

Both sources are free and need no key.
"""

import asyncio
import re
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from typing import Dict, List, Set

from ..signals import Entities, Severity, Signal, SignalType, now_iso
from .base import BaseCollector, register

CRTSH_URL = "https://crt.sh/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

# Indian brands most impersonated in phishing. Extend in data/brands.txt.
DEFAULT_BRANDS: Dict[str, Dict] = {
    "sbi":            {"sector": "BFSI", "label": "State Bank of India"},
    "hdfcbank":       {"sector": "BFSI", "label": "HDFC Bank"},
    "icicibank":      {"sector": "BFSI", "label": "ICICI Bank"},
    "axisbank":       {"sector": "BFSI", "label": "Axis Bank"},
    "kotak":          {"sector": "BFSI", "label": "Kotak Mahindra Bank"},
    "pnbindia":       {"sector": "BFSI", "label": "Punjab National Bank"},
    "bankofbaroda":   {"sector": "BFSI", "label": "Bank of Baroda"},
    "canarabank":     {"sector": "BFSI", "label": "Canara Bank"},
    "unionbankofindia": {"sector": "BFSI", "label": "Union Bank of India"},
    "paytm":          {"sector": "BFSI", "label": "Paytm"},
    "phonepe":        {"sector": "BFSI", "label": "PhonePe"},
    "npci":           {"sector": "BFSI", "label": "NPCI / UPI"},
    "rbi":            {"sector": "BFSI", "label": "Reserve Bank of India"},
    "incometax":      {"sector": "GOVERNMENT", "label": "Income Tax Department"},
    "gst":            {"sector": "GOVERNMENT", "label": "GST portal"},
    "uidai":          {"sector": "GOVERNMENT", "label": "UIDAI / Aadhaar"},
    "digilocker":     {"sector": "GOVERNMENT", "label": "DigiLocker"},
    "epfindia":       {"sector": "GOVERNMENT", "label": "EPFO"},
    "irctc":          {"sector": "TRANSPORT", "label": "IRCTC"},
    "indianoil":      {"sector": "ENERGY", "label": "Indian Oil"},
    "airtel":         {"sector": "TELECOM", "label": "Airtel"},
    "jio":            {"sector": "TELECOM", "label": "Reliance Jio"},
    "vodafoneidea":   {"sector": "TELECOM", "label": "Vi"},
    "tatapower":      {"sector": "ENERGY", "label": "Tata Power"},
    "flipkart":       {"sector": "RETAIL_ECOM", "label": "Flipkart"},
    "myntra":         {"sector": "RETAIL_ECOM", "label": "Myntra"},
    "zomato":         {"sector": "RETAIL_ECOM", "label": "Zomato"},
    "swiggy":         {"sector": "RETAIL_ECOM", "label": "Swiggy"},
    "apollohospitals": {"sector": "HEALTHCARE", "label": "Apollo Hospitals"},
    "infosys":        {"sector": "IT_ITES", "label": "Infosys"},
    "tcs":            {"sector": "IT_ITES", "label": "TCS"},
    "wipro":          {"sector": "IT_ITES", "label": "Wipro"},
}

# Words that show up in credential-harvesting domains
PHISH_LURE_WORDS = [
    "login", "signin", "secure", "verify", "verification", "update",
    "account", "netbanking", "banking", "kyc", "otp", "alert", "support",
    "helpdesk", "refund", "reward", "claim", "portal", "auth", "wallet",
    "payment", "recover", "unlock", "suspend", "confirm",
]

LEGITIMATE_SUFFIXES = {
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "pnbindia.in", "bankofbaroda.in",
    "canarabank.com", "unionbankofindia.co.in", "paytm.com", "phonepe.com",
    "npci.org.in", "rbi.org.in", "incometax.gov.in", "gst.gov.in",
    "uidai.gov.in", "digilocker.gov.in", "epfindia.gov.in", "irctc.co.in",
    "iocl.com", "airtel.in", "jio.com", "myvi.in", "tatapower.com",
    "flipkart.com", "myntra.com", "zomato.com", "swiggy.com",
    "apollohospitals.com", "infosys.com", "tcs.com", "wipro.com",
}


def _registrable(host: str) -> str:
    host = host.lower().strip().lstrip("*.").rstrip(".")
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_legitimate(host: str) -> bool:
    reg = _registrable(host)
    return any(reg == s or host.lower().endswith("." + s)
               for s in LEGITIMATE_SUFFIXES)


def assess_lookalike(host: str, brand: str, brand_meta: Dict) -> Dict:
    """
    Score how likely a hostname is an impersonation of a brand.
    Returns dict with score and the reasons, so a bulletin can justify it.
    """
    host = host.lower().strip().lstrip("*.")
    if _is_legitimate(host):
        return {"score": 0.0, "reasons": ["legitimate brand domain"]}

    labels = host.split(".")
    name_part = "".join(labels[:-1]) if len(labels) > 1 else host
    reasons = []
    score = 0.0

    has_brand = False
    if len(brand) <= 3:
        if re.search(r"(?:^|[\.-])" + re.escape(brand) + r"(?:[\.-]|$|\d)", host):
            has_brand = True
    else:
        if brand in host:
            has_brand = True

    if has_brand:
        score += 0.5
        reasons.append(f"contains '{brand}'")

    lures = [w for w in PHISH_LURE_WORDS if w in host]
    if lures and has_brand:
        score += 0.3
        reasons.append(f"lure words: {', '.join(lures[:3])}")

    similarity = SequenceMatcher(None, brand, name_part).ratio()
    if 0.72 <= similarity < 1.0 and not has_brand:
        score += 0.35
        reasons.append(f"{similarity:.0%} similar to '{brand}'")

    if re.search(r"\d", name_part) and has_brand:
        score += 0.05
        reasons.append("digits in hostname")

    if host.count("-") >= 2 and has_brand:
        score += 0.1
        reasons.append("multiple hyphens")

    return {"score": min(score, 1.0), "reasons": reasons}


@register
class CertTransparencyCollector(BaseCollector):
    name = "crtsh_typosquat"
    description = "Certificate transparency lookalike domains for Indian brands"
    signal_types = ["typosquat", "phishing"]
    required_env: List[str] = []
    free = True
    timeout = 15

    async def collect(self) -> List[Signal]:
        days = int(self.options.get("days", 7))
        brands = self.options.get("brands") or DEFAULT_BRANDS
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        signals: List[Signal] = []
        seen: Set[str] = set()

        semaphore = asyncio.Semaphore(3)   # crt.sh is easily overloaded
        fail_count = 0

        async def check(client, brand: str, meta: Dict):
            nonlocal fail_count
            if fail_count >= 5:
                return
            async with semaphore:
                if fail_count >= 5:
                    return
                data = await self.get_json(
                    client, CRTSH_URL,
                    params={"q": f"%{brand}%", "output": "json"})
                if data is None:
                    fail_count += 1
                    return
                if not isinstance(data, list):
                    return

                for entry in data[:400]:
                    names = str(entry.get("name_value", "")).split("\n")
                    logged = entry.get("entry_timestamp", "")
                    try:
                        logged_dt = datetime.fromisoformat(
                            logged.replace("Z", "+00:00"))
                        if logged_dt.tzinfo is None:
                            logged_dt = logged_dt.replace(tzinfo=timezone.utc)
                    except (ValueError, AttributeError):
                        continue
                    if logged_dt < cutoff:
                        continue

                    for host in names:
                        host = host.strip().lower()
                        if not host or host in seen:
                            continue
                        verdict = assess_lookalike(host, brand, meta)
                        if verdict["score"] < 0.55:
                            continue
                        seen.add(host)

                        severity = (Severity.HIGH if verdict["score"] >= 0.75
                                    else Severity.MEDIUM)
                        signals.append(Signal(
                            signal_type=SignalType.TYPOSQUAT,
                            title=f"Lookalike domain for {meta['label']}: {host}"[:280],
                            description=(
                                f"A certificate was issued for {host}, which "
                                f"impersonates {meta['label']}. Reasons: "
                                f"{'; '.join(verdict['reasons'])}. "
                                f"Certificates are logged before a phishing "
                                f"page goes live, so this is early warning "
                                f"rather than incident reporting. Issuer: "
                                f"{entry.get('issuer_name', 'unknown')[:120]}"
                            ),
                            source="crt.sh",
                            source_url=f"https://crt.sh/?q={host}",
                            observed_at=logged_dt.isoformat(),
                            severity=severity,
                            confidence=round(verdict["score"], 2),
                            india_relevance=0.9,
                            india_reason=f"impersonates Indian brand "
                                         f"{meta['label']}",
                            sectors=[meta["sector"]],
                            entities=Entities(domains=[host],
                                              organisations=[meta["label"]]),
                            annexure_categories=["vii", "iv"],
                            tags=["typosquat", "brand-impersonation",
                                  meta["sector"].lower()],
                            raw={"issuer": entry.get("issuer_name", "")[:200]},
                        ))

        async with self.client() as client:
            await asyncio.gather(*(check(client, b, m) for b, m in brands.items()))

        if fail_count >= 5:
            self.errors.append("crt.sh timed out repeatedly; service may be overloaded or down")
        return signals


@register
class OpenPhishCollector(BaseCollector):
    name = "openphish"
    description = "OpenPhish community feed, filtered for Indian brands and TLDs"
    signal_types = ["phishing"]
    required_env: List[str] = []
    free = True

    async def collect(self) -> List[Signal]:
        brands = self.options.get("brands") or DEFAULT_BRANDS
        signals: List[Signal] = []

        async with self.client() as client:
            text = await self.get_text(client, OPENPHISH_FEED)
            if not text:
                return signals

            for line in text.splitlines():
                url = line.strip()
                if not url.startswith("http"):
                    continue
                lowered = url.lower()
                host = lowered.split("://", 1)[-1].split("/", 1)[0]

                matched_brand = None
                for brand, meta in brands.items():
                    if brand in lowered and not _is_legitimate(host):
                        matched_brand = (brand, meta)
                        break

                is_in_tld = re.search(r"\.in(?:/|$|:)", host + "/")

                if not matched_brand and not is_in_tld:
                    continue

                if matched_brand:
                    brand, meta = matched_brand
                    relevance, reason = 0.85, f"impersonates {meta['label']}"
                    sectors = [meta["sector"]]
                    orgs = [meta["label"]]
                    title = f"Phishing page impersonating {meta['label']}"
                else:
                    relevance, reason = 0.7, "phishing page on an Indian domain"
                    sectors, orgs = [], []
                    title = f"Phishing page on Indian domain: {host}"

                signals.append(Signal(
                    signal_type=SignalType.PHISHING,
                    title=title[:280],
                    description=(
                        f"OpenPhish listed an active phishing URL at {host}. "
                        f"{reason.capitalize()}."),
                    source="OpenPhish",
                    source_url="https://openphish.com/",
                    observed_at=now_iso(),
                    severity=Severity.HIGH,
                    confidence=0.75,
                    india_relevance=relevance,
                    india_reason=reason,
                    sectors=sectors,
                    entities=Entities(urls=[url], domains=[host],
                                      organisations=orgs),
                    annexure_categories=["vii"],
                    tags=["phishing", "openphish"],
                    raw={},
                ))

        return signals
