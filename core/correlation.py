"""
Cross-source correlation.

This is what makes multiple sources worth more than the sum of their feeds.
A single source tells you something happened. Two independent sources
agreeing tells you it probably really happened, and three pointing at the
same CVE or actor tells you where to spend the week.

Three correlation passes:

  Shared artefact   the same CVE, domain, IP, hash or organisation appears
                    in signals from different sources
  Actor chain       a group named on a leak site also appears in malware
                    infrastructure or hacktivist claims
  Exploit-to-victim an actively exploited CVE affects a sector that is
                    concurrently seeing victims
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from .sectors import clean_victim_name
from .signals import Signal, SignalType


GENERIC_ARTEFACTS = {"unknown", "none", "n/a", "not found", "undefined", "generic", "null"}


def _artefact_index(signals: List[Signal]) -> Dict[str, Set[str]]:
    """Map each artefact value to the set of signal ids mentioning it."""
    index: Dict[str, Set[str]] = defaultdict(set)
    for sig in signals:
        for value in sig.entities.all_values():
            key = value.strip().lower()
            if len(key) < 4 or key in GENERIC_ARTEFACTS:
                continue
            index[key].add(sig.signal_id)
    return index


def find_shared_artefacts(signals: List[Signal],
                          min_sources: int = 2) -> List[Dict]:
    """Artefacts seen by more than one independent source."""
    by_id = {s.signal_id: s for s in signals}
    index = _artefact_index(signals)
    results = []

    for artefact, ids in index.items():
        if len(ids) < 2:
            continue
        sources = {by_id[i].source for i in ids if i in by_id}
        if len(sources) < min_sources:
            continue

        involved = [by_id[i] for i in ids if i in by_id]
        results.append({
            "artefact": artefact,
            "source_count": len(sources),
            "sources": sorted(sources),
            "signal_count": len(involved),
            "signal_types": sorted({s.signal_type.value for s in involved}),
            "titles": [s.title[:110] for s in involved[:5]],
            "sectors": sorted({sec for s in involved for sec in s.sectors}),
            "max_severity": max(
                (s.severity.value for s in involved),
                key=lambda v: ["Informational", "Low", "Medium",
                               "High", "Critical"].index(v)),
        })

    results.sort(key=lambda r: (-r["source_count"], -r["signal_count"]))
    return results


def find_actor_chains(signals: List[Signal]) -> List[Dict]:
    """A single actor appearing across different kinds of signal."""
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
                "victim_examples": [
                    f"{clean_victim_name(h.entities.organisations[0])} ({h.entities.actors[0]})"
                    if (h.entities.actors and h.entities.actors[0] and h.entities.actors[0].strip().lower() not in ("unknown", "none", ""))
                    else clean_victim_name(h.entities.organisations[0])
                    for h in hits[:4]
                    if h.entities.organisations],
                "groups": sorted({g for h in hits for g in h.entities.actors
                                  if g and g.strip().lower() not in ("unknown", "")}),
            })

    links.sort(key=lambda l: (-int(l["ransomware_linked"]),
                              -l["victim_count"]))
    return links


def correlate(signals: List[Signal]) -> Dict:
    """Run every pass and return a bundle for the bulletin."""
    shared = find_shared_artefacts(signals)
    chains = find_actor_chains(signals)
    links = find_exploit_to_victim_links(signals)

    # Feeds sharing common upstream parents do not receive an independence confidence uplift
    SHARED_PARENT_GROUPS = [
        {"CISA KEV", "NVD"},
        {"ransomware.live", "ransomlook.io"},
    ]

    seen_multiple_ids: Set[str] = set()
    by_id = {s.signal_id: s for s in signals}
    index = _artefact_index(signals)
    for artefact, ids in index.items():
        sources = {by_id[i].source for i in ids if i in by_id}
        if len(sources) >= 2:
            seen_multiple_ids.update(ids)
            # Only apply confidence uplift if sources span truly independent feed families
            is_shared_parent_only = any(sources.issubset(grp) for grp in SHARED_PARENT_GROUPS)
            if not is_shared_parent_only:
                for sid in ids:
                    sig = by_id.get(sid)
                    if sig:
                        sig.confidence = min(round(sig.confidence * 1.15, 3), 0.85)
                        if "cross_source_confirmed" not in sig.tags:
                            sig.tags.append("cross_source_confirmed")

    for sid in seen_multiple_ids:
        sig = by_id.get(sid)
        if sig and "seen_multiple_feeds" not in sig.tags:
            sig.tags.append("seen_multiple_feeds")

    return {
        "shared_artefacts": shared[:40],
        "shared_artefacts_count": len(shared),
        "actor_chains": chains[:20],
        "exploit_victim_links": links[:20],
        "corroborated_count": len(seen_multiple_ids),
        "seen_multiple_count": len(seen_multiple_ids),
        "total_signals": len(signals),
    }
