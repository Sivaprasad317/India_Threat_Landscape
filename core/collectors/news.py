"""
Security news watch.

Reads RSS/Atom feeds from security news outlets and keeps the stories that
name India or describe high-impact events (actively exploited flaws,
supply-chain compromises, breaches, ransomware). Stories land in the
intel_items table, not the signal store: they feed the bulletin's "Also in
the news" list and tell the analyst what deserves a headline entry in
data/headline_threats.json, but they never move sector scores.

Override the feed list with NEWS_FEEDS="Name|https://url,Name|https://url".
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional

from ..signals import Signal
from .base import BaseCollector, register
from .research_exposure import INDIA_TERMS

DEFAULT_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("MediaNama", "https://www.medianama.com/feed/"),
]

# Indian brands and systems that rarely appear with the word "India" itself
INDIA_BRANDS = re.compile(
    r"\b(sbi|state bank of india|hdfc|icici|axis bank|kotak|paytm|phonepe|"
    r"bhim|irctc|digilocker|cowin|bsnl|jio|airtel|infosys|wipro|tcs|"
    r"hcltech|tech mahindra|zomato|swiggy|flipkart|meity|nic\.in|gov\.in)\b",
    re.IGNORECASE)

CATEGORIES = [
    ("Supply chain", re.compile(
        r"supply[- ]chain|malicious (?:package|release|version)|pypi|npm|"
        r"typosquat|backdoor(?:ed)? (?:package|library|release)", re.I)),
    ("Vulnerability", re.compile(
        r"zero[- ]day|0-day|actively exploited|exploited in the wild|"
        r"remote code execution|\brce\b|cve-\d{4}-\d+|critical (?:flaw|bug|vulnerabilit)",
        re.I)),
    ("Data breach", re.compile(
        r"data breach|breach|leak(?:ed|s)?|exposed .*records|dark web|"
        r"stolen data|customer data", re.I)),
    ("Ransomware", re.compile(r"ransomware|extortion", re.I)),
    ("Malware", re.compile(
        r"malware|botnet|infostealer|stealer|trojan|\brat\b|loader", re.I)),
]


def classify_news(title: str, summary: str = "") -> Dict:
    """Category, India link and a 0-4 priority score for one story."""
    text = f"{title} {summary}"
    india_terms = sorted({m.group(0).lower() for m in INDIA_TERMS.finditer(text)} |
                         {m.group(0).lower() for m in INDIA_BRANDS.finditer(text)})
    category = next((name for name, rx in CATEGORIES if rx.search(text)), "")
    score = (2 if india_terms else 0) + (1 if category else 0)
    if re.search(r"actively exploited|in the wild|zero[- ]day|mass[- ]exploit",
                 text, re.I):
        score += 1
    return {"category": category or "Other", "india_terms": india_terms,
            "india_relevant": bool(india_terms), "score": score}


def _text(el: Optional[ET.Element]) -> str:
    return (el.text or "").strip() if el is not None else ""


def _parse_date(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _strip_html(raw: str) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", raw or "").split())


def parse_feed(xml_text: str, source: str) -> List[Dict]:
    """RSS 2.0 or Atom to a list of {title, url, published_at, summary}."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    atom = "{http://www.w3.org/2005/Atom}"
    items = []
    for it in root.iter("item"):
        items.append({
            "title": _text(it.find("title")),
            "url": _text(it.find("link")),
            "published": _text(it.find("pubDate")),
            "summary": _strip_html(_text(it.find("description"))),
        })
    for it in root.iter(f"{atom}entry"):
        link = it.find(f"{atom}link")
        items.append({
            "title": _text(it.find(f"{atom}title")),
            "url": link.get("href", "") if link is not None else "",
            "published": _text(it.find(f"{atom}published")) or _text(it.find(f"{atom}updated")),
            "summary": _strip_html(_text(it.find(f"{atom}summary"))),
        })

    out = []
    for i in items:
        if not i["title"] or not i["url"]:
            continue
        dt = _parse_date(i["published"])
        out.append({
            "title": i["title"],
            "url": i["url"],
            "source": source,
            "published_at": dt.astimezone(timezone.utc).isoformat() if dt else "",
            "summary": i["summary"][:400],
        })
    return out


@register
class SecurityNewsCollector(BaseCollector):
    name = "security_news"
    description = "Security news headlines (India and high-impact)"
    signal_types = ["news"]
    required_env: List[str] = []
    free = True

    def __init__(self, **options):
        super().__init__(**options)
        self.items: List[Dict] = []

    def feeds(self):
        raw = self.env("NEWS_FEEDS")
        if not raw:
            return DEFAULT_FEEDS
        pairs = [p.split("|", 1) for p in raw.split(",") if "|" in p]
        return [(n.strip(), u.strip()) for n, u in pairs]

    async def collect(self) -> List[Signal]:
        days = int(self.options.get("days", 14))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        async with self.client() as client:
            for source, url in self.feeds():
                text = await self.get_text(client, url)
                if not text:
                    continue
                for item in parse_feed(text, source):
                    if item["published_at"] and item["published_at"] < cutoff.isoformat():
                        continue
                    tags = classify_news(item["title"], item["summary"])
                    if tags["score"] == 0:
                        continue
                    item["india_relevant"] = tags["india_relevant"]
                    item["india_reason"] = ", ".join(tags["india_terms"])
                    self.items.append(item)
        # Stories are stored by the caller in intel_items, not as signals
        return []
