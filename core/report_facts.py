"""
Facts the bulletin narrates, computed from the signals in the window.

Every product name, CVE list, advisory row and example indicator in the
bulletin's prose comes from here, so a run on fresh data describes that data
and never a previous one.
"""

import re
from collections import Counter, defaultdict
from datetime import date
from typing import Dict, List, Optional

from .signals import Signal, SignalType

# Internet-facing VPN, firewall, gateway and remote-access products: the
# family the bulletin calls "edge". Matched against "<vendor> <product>".
EDGE_TERMS = (
    "fortinet", "fortios", "fortigate", "fortiproxy", "fortiweb", "fortimail",
    "fortimanager", "citrix", "netscaler", "sonicwall", "check point",
    "palo alto", "pan-os", "globalprotect", "ivanti", "pulse secure",
    "mikrotik", "f5", "big-ip", "juniper", "zyxel", "sophos", "watchguard",
    "beyondtrust", "array networks", "sangfor", "cisco asa", "firepower",
    "ios xe", "sd-wan", "adaptive security", "secure email",
)


def is_edge_product(vendor: str, product: str) -> bool:
    blob = f"{vendor} {product}".lower()
    return any(term in blob for term in EDGE_TERMS)


def _cve_sort_key(cve: str):
    parts = cve.split("-")
    try:
        return (int(parts[1]), int(parts[2]))
    except (IndexError, ValueError):
        return (0, 0)


def kev_by_product(signals: List[Signal]) -> List[Dict]:
    """CISA KEV signals grouped by vendor and product, most CVEs first."""
    groups: Dict[tuple, Dict] = {}
    for s in signals:
        if s.source != "CISA KEV":
            continue
        raw = s.raw if isinstance(s.raw, dict) else {}
        vendor = (raw.get("vendorProject") or "").strip()
        product = (raw.get("product") or "").strip()
        if not vendor and not product:
            continue
        key = (vendor.lower(), product.lower())
        g = groups.setdefault(key, {
            "vendor": vendor, "product": product,
            "label": product if product.lower().startswith(vendor.lower()) else f"{vendor} {product}".strip(),
            "cves": set(), "edge": is_edge_product(vendor, product),
            "ransomware": False, "latest": "",
        })
        g["cves"].update(s.entities.cves or [])
        if str(raw.get("knownRansomwareCampaignUse", "")).lower() == "known":
            g["ransomware"] = True
        g["latest"] = max(g["latest"], (raw.get("dateAdded") or s.observed_at or "")[:10])

    out = []
    for g in groups.values():
        g["cves"] = sorted(g["cves"], key=_cve_sort_key, reverse=True)
        g["count"] = len(g["cves"])
        out.append(g)
    out.sort(key=lambda g: (-g["count"], not g["edge"], g["label"].lower()))
    return out


def edge_cve_text(groups: List[Dict], max_groups: int = 4, max_cves: int = 3) -> str:
    """'Citrix NetScaler (CVE-a, CVE-b), MikroTik RouterOS (CVE-c)' for edge products."""
    parts = []
    for g in [g for g in groups if g["edge"]][:max_groups]:
        cves = ", ".join(g["cves"][:max_cves])
        parts.append(f"{g['label']} ({cves})" if cves else g["label"])
    return "; ".join(parts)


def edge_vendor_names(groups: List[Dict], limit: int = 4) -> List[str]:
    names = []
    for g in groups:
        if g["edge"] and g["vendor"] not in names:
            names.append(g["vendor"])
    return names[:limit]


def certin_advisories(signals: List[Signal], limit: int = 5) -> List[Dict]:
    """CERT-In notes in the window, the ones mapped to Annexure I categories first."""
    rows = []
    seen = set()
    for s in signals:
        if not s.source.startswith("CERT-In"):
            continue
        raw = s.raw if isinstance(s.raw, dict) else {}
        ref = raw.get("reference") or ""
        if not ref:
            m = re.search(r"(CI[A-Z]{2}-\d{4}-\d{4})", s.title)
            ref = m.group(1) if m else s.title[:20]
        if ref in seen:
            continue
        seen.add(ref)
        subject = raw.get("subject") or s.title.split(":", 1)[-1].strip()
        rows.append({
            "reference": ref,
            "date": (s.observed_at or "")[:10],
            "subject": subject,
            "severity": s.severity.value,
            "annexure": list(s.annexure_categories or []),
        })
    # Newest first, then a stable sort keeps that order within each group
    rows.sort(key=lambda r: r["date"], reverse=True)
    rows.sort(key=lambda r: not r["annexure"])
    return rows[:limit]


def top_states(victim_attributions: List[Dict], limit: int = 3) -> List[str]:
    counts = Counter(v["state"] for v in victim_attributions
                     if v.get("state") and v["state"] != "Location Unresolved")
    return [name for name, _ in counts.most_common(limit)]


def actor_posting_patterns(victim_attributions: List[Dict]) -> Dict[str, Dict]:
    """Per actor: unique organisations, postings and distinct posting dates."""
    out: Dict[str, Dict] = defaultdict(lambda: {"orgs": set(), "postings": 0, "dates": set(),
                                               "sectors": Counter()})
    for v in victim_attributions:
        for actor in v["actor"].split(", "):
            if not actor or actor == "Unattributed":
                continue
            a = out[actor]
            a["orgs"].add(v["victim"])
            a["postings"] += v.get("postings", 1)
            if v.get("date"):
                a["dates"].add(v["date"])
            a["sectors"][v["sector"]] += 1
    return out


def single_day_waves(patterns: Dict[str, Dict], min_orgs: int = 3) -> List[Dict]:
    """Actors whose postings in the window all landed on one date."""
    waves = []
    for actor, p in patterns.items():
        if len(p["orgs"]) >= min_orgs and len(p["dates"]) == 1:
            waves.append({"actor": actor, "orgs": len(p["orgs"]), "postings": p["postings"],
                          "date": next(iter(p["dates"]))})
    waves.sort(key=lambda w: -w["orgs"])
    return waves


def episodic_actors(patterns: Dict[str, Dict], min_dates: int = 3) -> List[Dict]:
    """Actors posting Indian victims on several separate dates."""
    out = []
    for actor, p in patterns.items():
        if len(p["dates"]) >= min_dates:
            out.append({"actor": actor, "orgs": len(p["orgs"]), "postings": p["postings"],
                        "dates": len(p["dates"]),
                        "sectors": [s for s, _ in p["sectors"].most_common(3)]})
    out.sort(key=lambda a: (-a["orgs"], -a["dates"]))
    return out


def ioc_technique_examples(iocs: List[Dict], limit: int = 3) -> List[Dict]:
    """Most common delivery techniques in the IOC set, each with one defanged example host."""
    counts = Counter(i.get("technique") for i in iocs if i.get("technique"))
    out = []
    for tech, count in counts.most_common(limit):
        ex = next(i for i in iocs if i.get("technique") == tech)
        host = ex.get("host", "")
        out.append({"technique": tech, "count": count,
                    "example": host.replace(".", "[.]") if host else ""})
    return out


def fmt_date(iso: str) -> str:
    try:
        return date.fromisoformat(iso[:10]).strftime("%d %b %Y")
    except (TypeError, ValueError):
        return iso or "n/a"
