"""
Analyst-reviewed corrections for named organisations.

Feeds give victim names as domains or fragments ("simplexengg", "licindia")
with loose or missing sector labels and no location. Corrections live in
data/entity_overrides.json, each with a reason and review date, so editorial
decisions are auditable and never buried in code. The pipeline only reads
the file.
"""

import json
import os
from functools import lru_cache
from typing import Dict, List, Optional

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "data", "entity_overrides.json")


@lru_cache(maxsize=4)
def _load(path: str) -> List[Dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    entries = doc.get("entries", []) if isinstance(doc, dict) else doc
    # Longest match string first, so "simplex engineering" beats "simplex"
    return sorted(entries, key=lambda e: -max(len(m) for m in e.get("match", [""])))


def entity_override(name: str, path: str = DEFAULT_PATH) -> Optional[Dict]:
    """The override for an organisation name, matched on the raw or cleaned name."""
    low = (name or "").strip().lower()
    if not low:
        return None
    for entry in _load(path):
        if entry.get("name") and low == entry["name"].lower():
            return entry
        for m in entry.get("match", []):
            m = m.lower()
            if (entry.get("exact") and low == m) or (not entry.get("exact") and m in low):
                return entry
    return None
