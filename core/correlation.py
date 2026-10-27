"""
Cross-source correlation, with the evidence for every link.

A single source tells you something happened. Two independent sources
agreeing tells you it probably really happened. Two records that merely
share a name tell you very little, so matches are graded:

  strong        the same CVE, hash, domain, IP, URL or onion address
  organisation  the same named organisation (after name normalisation)
  weak          only an actor or malware-family name in common

Strong and organisation matches across two or more feeds are reported as
shared artefacts. Weak matches are listed separately as possible links and
never count as corroboration.

Feeds that share an upstream (CISA KEV and NVD; ransomware.live and
ransomlook.io; the abuse.ch feeds) are one family: agreement inside a family
is "seen in multiple feeds" but not independent corroboration, and only
independent corroboration raises a signal's confidence.

Three passes:

  Shared artefact   graded matches across feeds, with per-source evidence
  Actor chain       a group name seen in different kinds of signal (weak)
  Exploit-to-victim an actively exploited CVE affects a sector that is
                    concurrently seeing victims (co-occurrence, not cause)
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from .sectors import clean_victim_name
from .signals import Signal, SignalType


GENERIC_ARTEFACTS = {"unknown", "none", "n/a", "not found", "undefined", "generic", "null"}

STRONG_FIELDS = ("cves", "hashes", "domains", "ips", "urls", "onions")
ENTITY_FIELDS = ("organisations",)
WEAK_FIELDS = ("actors", "malware_families")

MATCH_LABEL = {"strong": "exact artefact", "organisation": "same organisation", "weak": "name only"}

# Feeds that share an upstream source count as one family
SOURCE_FAMILIES = {
    "CISA KEV": "cve-catalogue", "NVD": "cve-catalogue",
    "ransomware.live": "leak-site-trackers", "ransomlook.io": "leak-site-trackers",
    "abuse.ch ThreatFox": "abuse.ch", "abuse.ch URLhaus": "abuse.ch",
    "abuse.ch MalwareBazaar": "abuse.ch",
}

CONFIDENCE_UPLIFT = 1.15
CONFIDENCE_CAP = 0.85


def source_family(source: str) -> str:
    return SOURCE_FAMILIES.get(source, source)


def _normalise(field: str, value: str) -> str:
    v = (value or "").strip()
    if field == "cves":
        return v.upper()
    if field == "domains":
        v = v.lower()
        return v[4:] if v.startswith("www.") else v
    if field == "organisations":
        return clean_victim_name(v).strip().lower()
    return v.lower()


def _strength(field: str) -> str:
    if field in STRONG_FIELDS:
        return "strong"
    if field in ENTITY_FIELDS:
        return "organisation"
    return "weak"


def _artefact_index(signals: List[Signal]) -> Dict[Tuple[str, str], Set[str]]:
    """Map (field, normalised value) to the ids of signals carrying it."""
    index: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for sig in signals:
        for field in STRONG_FIELDS + ENTITY_FIELDS + WEAK_FIELDS:
            for value in getattr(sig.entities, field, []) or []:
                key = _normalise(field, value)
                if len(key) < 4 or key in GENERIC_ARTEFACTS:
                    continue
                index[(field, key)].add(sig.signal_id)
    return index


def _evidence(sigs: List[Signal]) -> List[Dict]:
    """The earliest record from each source that carries the artefact."""
    first: Dict[str, Signal] = {}
    for s in sorted(sigs, key=lambda x: x.observed_at or ""):
        first.setdefault(s.source, s)
    return [{"source": src, "observed_at": (s.observed_at or "")[:10],
             "title": s.title[:110], "url": s.source_url or ""}
            for src, s in sorted(first.items())]


def _graded_matches(signals: List[Signal], min_sources: int = 2) -> List[Dict]:
    by_id = {s.signal_id: s for s in signals}
    results = []
    for (field, artefact), ids in _artefact_index(signals).items():
        involved = [by_id[i] for i in ids if i in by_id]
        sources = sorted({s.source for s in involved})
        if len(sources) < min_sources:
            continue
        families = sorted({source_family(src) for src in sources})
        strength = _strength(field)
        results.append({
            "artefact": artefact,
            "field": field,
            "strength": strength,
            "match": MATCH_LABEL[strength],
            "source_count": len(sources),
            "sources": sources,
            "families": families,
            "independent": len(families) >= 2,
            "signal_ids": sorted(ids),
            "signal_count": len(involved),
            "signal_types": sorted({s.signal_type.value for s in involved}),
            "titles": [s.title[:110] for s in involved[:5]],
            "sectors": sorted({sec for s in involved for sec in s.sectors}),
            "max_severity": max(
                (s.severity.value for s in involved),
                key=lambda v: ["Informational", "Low", "Medium",
                               "High", "Critical"].index(v)),
            "evidence": _evidence(involved),
        })
    results.sort(key=lambda r: (["strong", "organisation", "weak"].index(r["strength"]),
                                not r["independent"], -r["source_count"], -r["signal_count"], r["artefact"]))
    return results


def find_shared_artefacts(signals: List[Signal],
                          min_sources: int = 2) -> List[Dict]:
    """Strong and organisation matches seen by more than one feed."""
    return [r for r in _graded_matches(signals, min_sources) if r["strength"] != "weak"]


def find_possible_links(signals: List[Signal], min_sources: int = 2) -> List[Dict]:
    """Name-only matches (actors, malware families): listed, never counted."""
    return [r for r in _graded_matches(signals, min_sources) if r["strength"] == "weak"]


def find_actor_chains(signals: List[Signal]) -> List[Dict]:
    """A single actor name appearing across different kinds of signal.

    This is a name match, not proof of one campaign: groups share names,
    affiliates rebrand, and feeds spell names differently."""
    by_actor: Dict[str, List[Signal]] = defaultdict(list)
    for sig in signals:
        for actor in sig.entities.actors:
            name = actor.strip().lower()
            if name and name not in ("unknown", "", "none"):
                by_actor[name].append(sig)

    chains = []
    for actor, sigs in by_actor.items():
        types = {s.signal_type for s in sigs}
        if len(types) < 2:
            continue
        sectors = sorted({sec for s in sigs for sec in s.sectors})
        chains.append({
            "actor": actor,
            "match": MATCH_LABEL["weak"],
            "signal_count": len(sigs),
            "signal_types": sorted(t.value for t in types),
            "sources": sorted({s.source for s in sigs}),
            "sectors": sectors,
            "victim_count": sum(1 for s in sigs
                                if s.signal_type == SignalType.VICTIM),
            "titles": [s.title[:110] for s in sigs[:6]],
        })

    chains.sort(key=lambda c: (-c["victim_count"], -c["signal_count"]))
    return chains


def find_exploit_to_victim_links(signals: List[Signal]) -> List[Dict]:
    """
    Sectors where an actively exploited CVE co-occurs with live extortion
    activity in the same reporting window. Identifies elevated attack-surface
    exposure for sector technology without over-claiming breach causality.
    """
    vulns = [s for s in signals
             if s.signal_type == SignalType.VULNERABILITY
             and "actively-exploited" in s.tags]
    victims = [s for s in signals if s.signal_type == SignalType.VICTIM]

    victims_by_sector: Dict[str, List[Signal]] = defaultdict(list)
    for v in victims:
        for sec in v.sectors:
            victims_by_sector[sec].append(v)

    links = []
    for vuln in vulns:
        cve_id = vuln.entities.cves[0] if vuln.entities.cves else ""
        raw_t = vuln.title.replace(cve_id, "").strip(" -–—: \t")
        if ":" in raw_t:
            parts = raw_t.split(":", 1)
            prod = parts[0].strip()
            rest = parts[1].strip()
            if rest.lower().startswith(prod.lower()):
                rest = rest[len(prod):].strip(" -–—: \t")
            clean_title = f"{prod}: {rest}"
        else:
            clean_title = raw_t

        for sector in vuln.sectors:
            hits = victims_by_sector.get(sector, [])
            if not hits:
                continue
            unique_org_names = {
                clean_victim_name(h.entities.organisations[0] if h.entities.organisations else h.title).strip().lower()
                for h in hits
            }
            links.append({
                "sector": sector,
                "cve": cve_id,
                "vuln_title": clean_title,
                "ransomware_linked": "ransomware-campaign-use" in vuln.tags,
                "edge_device": "edge-device" in vuln.tags,
                "victim_count": len(unique_org_names),
                "victim_examples": list(dict.fromkeys(
                    f"{clean_victim_name(h.entities.organisations[0])} ({h.entities.actors[0]})"
                    if (h.entities.actors and h.entities.actors[0] and h.entities.actors[0].strip().lower() not in ("unknown", "none", ""))
                    else clean_victim_name(h.entities.organisations[0])
                    for h in hits
                    if h.entities.organisations))[:4],
                "why": (f"{cve_id} affects technology mapped to this sector, and {len(unique_org_names)} "
                        f"organisation{'s' if len(unique_org_names) != 1 else ''} in the sector were named on leak "
                        f"sites in the same window. Co-occurrence, not evidence of the entry point."),
                "groups": sorted({g for h in hits for g in h.entities.actors
                                  if g and g.strip().lower() not in ("unknown", "")}),
            })

    links.sort(key=lambda l: (-int(l["ransomware_linked"]),
                              -l["victim_count"]))
    return links


def correlate(signals: List[Signal]) -> Dict:
    """Run every pass and return a bundle for the bulletin.

    Signals backed by an independent strong or organisation match get their
    confidence raised once (x1.15, capped at 0.85) and a cross_source_confirmed
    tag; this mutates the signals, so run it before scoring.
    """
    graded = _graded_matches(signals)
    shared = [r for r in graded if r["strength"] != "weak"]
    possible = [r for r in graded if r["strength"] == "weak"]
    chains = find_actor_chains(signals)
    links = find_exploit_to_victim_links(signals)

    by_id = {s.signal_id: s for s in signals}
    seen_multiple_ids: Set[str] = {sid for r in shared for sid in r["signal_ids"]}
    independent_ids: Set[str] = {sid for r in shared if r["independent"] for sid in r["signal_ids"]}

    for sid in seen_multiple_ids:
        sig = by_id.get(sid)
        if sig and "seen_multiple_feeds" not in sig.tags:
            sig.tags.append("seen_multiple_feeds")
    for sid in independent_ids:
        sig = by_id.get(sid)
        if sig and "cross_source_confirmed" not in sig.tags:
            sig.confidence = min(round(sig.confidence * CONFIDENCE_UPLIFT, 3), CONFIDENCE_CAP)
            sig.tags.append("cross_source_confirmed")

    return {
        "shared_artefacts": shared[:40],
        "shared_artefacts_count": len(shared),
        "independent_artefacts_count": sum(1 for r in shared if r["independent"]),
        "possible_links": possible[:20],
        "possible_links_count": len(possible),
        "actor_chains": chains[:20],
        "exploit_victim_links": links[:20],
        "corroborated_count": len(seen_multiple_ids),
        "seen_multiple_count": len(seen_multiple_ids),
        "independently_corroborated_count": len(independent_ids),
        "total_signals": len(signals),
    }
