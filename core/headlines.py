"""
Headline threats: the incidents a CISO is already asking about.

Feeds score what they can see. A PHP engine RCE, a poisoned PyPI release or a
bank confirming leaked customer records reach readers through the news days
before they show up in any feed, and a bulletin that skips them reads as out
of date. Two inputs cover that gap:

  data/headline_threats.json   analyst-written entries: what happened, why it
                               matters in India, what to do, with sources
  intel_items table            security-news headlines from the security_news
                               collector, shown as a watch list

Neither feeds sector scoring. Headlines are analysis, not telemetry, and
mixing them in would make scores depend on what the press chose to cover.

Every entry records its evidence: a confidence rating, the date it was last
verified, a one-line evidence note, and for each source its type (primary:
the affected vendor or organisation, a regulator or a government CERT;
research: original technical analysis; news: reporting), publication date
and the date it was checked. "high" needs a primary source.
"""

import json
import re
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_PATH = "data/headline_threats.json"

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
REQUIRED_FIELDS = ("id", "title", "category", "severity", "date",
                   "summary", "actions", "sources", "confidence", "last_verified",
                   "evidence")
CONFIDENCE_LEVELS = ("high", "medium", "low")
NO_PRIMARY_NOTE = "No primary source located: based on research and news reporting."
SOURCE_TYPES = ("primary", "research", "news")


def _is_date(value) -> bool:
    try:
        date.fromisoformat(str(value)[:10])
        return len(str(value)) == 10
    except ValueError:
        return False


def validate_headline(entry: Dict) -> List[str]:
    """Problems that would stop an entry rendering correctly."""
    problems = [f"missing '{f}'" for f in REQUIRED_FIELDS if not entry.get(f)]
    if entry.get("severity") and entry["severity"] not in SEVERITY_ORDER:
        problems.append(f"severity '{entry['severity']}' is not one of "
                        f"{', '.join(SEVERITY_ORDER)}")
    if entry.get("date"):
        try:
            date.fromisoformat(str(entry["date"])[:10])
        except ValueError:
            problems.append(f"date '{entry['date']}' is not YYYY-MM-DD")
    if "india_direct" in entry and not isinstance(entry["india_direct"], bool):
        problems.append("india_direct must be true or false")
    if entry.get("confidence") and entry["confidence"] not in CONFIDENCE_LEVELS:
        problems.append(f"confidence '{entry['confidence']}' is not one of {', '.join(CONFIDENCE_LEVELS)}")
    if entry.get("last_verified") and not _is_date(entry["last_verified"]):
        problems.append(f"last_verified '{entry['last_verified']}' is not YYYY-MM-DD")
    sources = entry.get("sources") or []
    for src in sources:
        if not isinstance(src, dict) or not src.get("name") or not src.get("url"):
            problems.append("each source needs a name and a url")
            break
        if src.get("type") not in SOURCE_TYPES:
            problems.append(f"source '{src['name']}' type must be one of {', '.join(SOURCE_TYPES)}")
        for field in ("published", "retrieved"):
            if src.get(field) and not _is_date(src[field]):
                problems.append(f"source '{src['name']}' {field} '{src[field]}' is not YYYY-MM-DD")
    good = [s for s in sources if isinstance(s, dict)]
    if sources and not any(s.get("retrieved") for s in good):
        problems.append("no source has a retrieved date: verify at least one before publishing")
    if entry.get("confidence") == "high" and not any(s.get("type") == "primary" for s in good):
        problems.append("confidence 'high' needs a primary source")
    return problems


def primary_sources(entry: Dict) -> List[Dict]:
    return [s for s in entry.get("sources", []) if s.get("type") == "primary"]


def load_headline_threats(path: str = DEFAULT_PATH,
                          start: Optional[date] = None,
                          end: Optional[date] = None) -> List[Dict]:
    """Valid entries dated within [start, end]: most severe first, incidents
    hitting India directly ahead of global ones, then newest first.

    Invalid entries are skipped with a warning rather than failing the whole
    bulletin over one typo in a hand-edited file.
    """
    p = Path(path)
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"warning: {path} is not valid JSON ({exc}); headline threats skipped",
              file=sys.stderr)
        return []

    out = []
    for entry in raw if isinstance(raw, list) else []:
        problems = validate_headline(entry)
        if problems:
            print(f"warning: headline '{entry.get('id', '?')}' skipped: "
                  f"{'; '.join(problems)}", file=sys.stderr)
            continue
        d = date.fromisoformat(str(entry["date"])[:10])
        if (start and d < start) or (end and d > end):
            continue
        out.append(entry)

    out.sort(key=lambda e: (SEVERITY_ORDER[e["severity"]],
                            not e.get("india_direct", False),
                            -date.fromisoformat(e["date"][:10]).toordinal()))
    return out


def split_headlines(entries: List[Dict]):
    """Full cards for Critical or India-direct incidents; the rest go in a
    compact table so a busy month does not bury the ones that matter most."""
    cards = [e for e in entries if e["severity"] == "Critical" or e.get("india_direct")]
    brief = [e for e in entries if e not in cards]
    return cards, brief


def brief_text(entry: Dict) -> str:
    """One- or two-sentence summary for the compact table."""
    if entry.get("brief"):
        return entry["brief"]
    first = re.split(r"(?<=[.!?])\s+", entry["summary"].strip(), maxsplit=1)[0]
    return first


def headline_keywords(entries: List[Dict]) -> List[str]:
    """Lower-case terms used to drop news items a headline already covers."""
    terms = set()
    for e in entries:
        terms.update(k.lower() for k in e.get("keywords", []) if k)
        terms.update(c.lower() for c in e.get("cves", []) if c)
    return sorted(terms)


def news_watch(items: List[Dict], covered_terms: List[str],
               limit: int = 8) -> List[Dict]:
    """News items not already covered by a headline, India-relevant first."""
    patterns = [re.compile(rf"\b{re.escape(t)}\b") for t in covered_terms]

    def covered(item):
        title = (item.get("title") or "").lower()
        return any(p.search(title) for p in patterns)

    fresh = [i for i in items if not covered(i)]
    # Newest first, then a stable sort keeps that order within each tier
    fresh.sort(key=lambda i: i.get("published_at") or "", reverse=True)
    fresh.sort(key=lambda i: (-int(i.get("india_relevant") or 0),
                              -int(i.get("score") or 0)))
    return fresh[:limit]


def format_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso[:10]).strftime("%d %b %Y")
    except (TypeError, ValueError):
        return iso or ""
