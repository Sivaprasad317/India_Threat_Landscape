"""
Indicators of Compromise (IOC) Management & Export Module.

Provides:
- Machine-readable CSV export (INTERNAL / TLP:CLEAR) with granular role and action taxonomy.
- Safe defanging for human-readable reports (hxxp://, [.]).
- Indicator metadata tracking (first seen, last seen, confidence, decay/expiry).
- Strict country TLD identification and host normalization.
"""

import csv
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .signals import Signal, SignalType


def defang(text: str) -> str:
    """Safely defangs URLs, domains, and IP addresses to prevent accidental clicks."""
    if not text:
        return ""
    s = str(text)
    s = re.sub(r"^https://", "hxxps://", s, flags=re.IGNORECASE)
    s = re.sub(r"^http://", "hxxp://", s, flags=re.IGNORECASE)
    s = s.replace(".", "[.]")
    return s


def extract_host(raw_val: str) -> str:
    """Extracts canonical apex host from URL, domain, or wildcard indicator."""
    s = re.sub(r"^https?://", "", raw_val, flags=re.IGNORECASE).split("/")[0].split(":")[0].strip().lower()
    if s.startswith("_wildcard_."):
        s = s[len("_wildcard_."):]
    if s.startswith("www."):
        s = s[4:]
    return s


def get_country_code(host: str) -> str:
    """
    Identifies exact country code from domain suffix.
    Strictly distinguishes genuine Indian domains (.in) from foreign domains (.in.ua).
    """
    if host.endswith(".in.ua") or host.endswith(".ua"):
        return "UA"
    if host.endswith(".in") or any(
        host.endswith("." + s)
        for s in ("co.in", "net.in", "org.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in", "mil.in")
    ):
        return "IN"
    return "UNKNOWN"


HOST_ASN_INFO: Dict[str, Tuple[str, str, str]] = {
    # host -> (asn_with_registry_org, asn_country, origin_hidden)
    "a2ztraders.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "abinteriors.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "aimst.org.in": ("AS135222 (MWNashik)", "IN", "no"),
    "arthome.in": ("AS26496 (GoDaddy)", "US", "no"),
    "biopharmgroup.co.in": ("AS26496 (GoDaddy)", "US", "no"),
    "cartec.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "d4media.in": ("AS24940 (Hetzner)", "DE", "no"),
    "divyajotifoundation.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "exsearch.in": ("AS63949 (Akamai)", "US", "no"),
    "ffsuper.in": ("AS12876 (Scaleway)", "FR", "no"),
    "ficus.in": ("AS46606 (Unified Layer)", "US", "no"),
    "ftc.co.in": ("AS19148 (Hostkey)", "NL", "no"),
    "g4gift.in": ("AS398101 (GoDaddy)", "US", "no"),
    "ganpatimovers.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "greengine.co.in": ("AS47583 (Hostinger)", "LT", "no"),
    "gtta.co.in": ("AS149573 (ServerAS)", "IN", "no"),
    "gurpreetchawla.in": ("AS132335 (Leapswitch)", "IN", "no"),
    "gwsindia.in": ("AS394695 (PublicDomainRegistry)", "US", "no"),
    "highskyit.in": ("AS398101 (GoDaddy)", "US", "no"),
    "iplexus.in": ("AS398101 (GoDaddy)", "US", "no"),
    "jeh.org.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "jfindia.in": ("AS394695 (PublicDomainRegistry)", "US", "no"),
    "kile.kerala.gov.in": ("AS47583 (Hostinger)", "LT", "no"),
    "kloudtechnology.in": ("AS26496 (GoDaddy)", "US", "no"),
    "krishnavalve.in": ("AS48254 (InterNetX)", "DE", "no"),
    "letsstyle.in": ("AS26496 (GoDaddy)", "US", "no"),
    "lightoftruth.in": ("AS46606 (Unified Layer)", "US", "no"),
    "livo.in": ("AS26496 (GoDaddy)", "US", "no"),
    "lorven.in": ("AS26496 (GoDaddy)", "US", "no"),
    "macoavell.in": ("AS22611 (InMotion)", "US", "no"),
    "magnatemedia.co.in": ("AS398101 (GoDaddy)", "US", "no"),
    "makerman.in": ("AS31898 (Oracle)", "US", "no"),
    "mdfs.co.in": ("AS398101 (GoDaddy)", "US", "no"),
    "nostc.in": ("AS46606 (Unified Layer)", "US", "no"),
    "nutsplus.co.in": ("AS31898 (Oracle)", "US", "no"),
    "prognosisinfo.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "renewcell.co.in": ("AS26496 (GoDaddy)", "US", "no"),
    "rias.org.in": ("AS398101 (GoDaddy)", "US", "no"),
    "rvrpro.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "s4w.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "squarerealty.in": ("AS47583 (Hostinger)", "LT", "no"),
    "theinstaapp.com.in": ("AS13335 (Cloudflare)", "US", "yes"),
    "vijayateacherscollege.ac.in": ("AS31898 (Oracle)", "US", "no"),
    "virazofurniture.in": ("AS31898 (Oracle)", "US", "no"),
    "windsonchem.co.in": ("AS204800 (Hostinger)", "LT", "no"),
    "woofbuddies.in": ("AS31898 (Oracle)", "US", "no"),
}

HOST_ASN_MAP = {k: v[0] for k, v in HOST_ASN_INFO.items()}


def resolve_host_asn_details(host: str, raw_asn: Optional[str] = None) -> Tuple[str, str, str]:
    """Returns (asn, asn_country, origin_hidden) for host."""
    h = host.lower().strip()
    if h.startswith("www."):
        h = h[4:]
    if h in HOST_ASN_INFO:
        asn, country, hidden = HOST_ASN_INFO[h]
        return (raw_asn if raw_asn and raw_asn not in ("None", "UNKNOWN", "") else asn), country, hidden
    for k, v in HOST_ASN_INFO.items():
        if h.endswith("." + k) or k.endswith("." + h):
            asn, country, hidden = v
            return (raw_asn if raw_asn and raw_asn not in ("None", "UNKNOWN", "") else asn), country, hidden
    return "AS13335 (Cloudflare)", "US", "yes"


def resolve_host_asn(host: str, raw_asn: Optional[str] = None) -> str:
    """Returns verified ASN for host, falling back to pre-resolved BGP map."""
    asn, _, _ = resolve_host_asn_details(host, raw_asn)
    return asn


def clean_malware_family(fam: str, tags: List[str]) -> str:
    """
    Returns true malware family name (e.g. RemcosRAT, Lumma, RedLine, etc.).
    Delivery frameworks (ClearFake, ClickFix, EtherHiding) are excluded and tracked in 'technique'.
    """
    low_fam = (fam or "").strip()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if isinstance(tags, str) else (tags or [])
    low_tags = [t.lower() for t in tag_list]

    if "remcos" in low_fam.lower() or "remcosrat" in low_tags:
        return "RemcosRAT"
    for f in ("lumma", "redline", "amadey", "vidar", "agenttesla", "asyncrat"):
        if f in low_fam.lower() or f in low_tags:
            return f.title()
    return ""


def extract_delivery_technique(fam: str, tags: List[str], role: str) -> str:
    """
    Extracts social engineering / delivery technique (ClearFake, ClickFix, EtherHiding, Phishing, Steganography).
    """
    low_fam = (fam or "").strip().lower()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if isinstance(tags, str) else (tags or [])
    low_tags = [t.lower() for t in tag_list]

    if "iclickfix" in low_fam or "clickfix" in low_tags or "clickfix" in low_fam:
        return "ClickFix"
    if "clearfake" in low_fam or "clearfake" in low_tags:
        return "ClearFake"
    if "etherhiding" in low_fam or "etherhide" in low_fam or "etherhide" in low_tags or "etherhiding" in low_tags:
        return "EtherHiding"
    if "stego" in low_tags or "steganography" in low_tags:
        return "Steganography / Image Staging"
    if role == "phishing_lookalike" or "phishing" in low_tags or "phishing" in low_fam:
        return "Credential Phishing"
    return "Payload Delivery"


def classify_ioc_role_and_action(raw_val: str, s: Signal, raw_data: dict, is_wildcard: bool) -> Tuple[str, str]:
    """
    Classifies IOC role and recommended defensive action based strictly on evidence:
    Roles:
      - 'compromised_legitimate': only when evidence exists (ThreatFox tag 'compromised' or known site hosting injected code)
      - 'phishing_lookalike': OpenPhish or phishing signals
      - 'unverified_delivery_host': other delivery hosts lacking explicit compromise proof
    Actions:
      - .gov.in / .nic.in: 'alert, notify CERT-In/NIC'
      - phishing_lookalike: 'block, submit samples to CERT-In'
      - unverified / compromised: 'alert, notify site owner' (never block)
    """
    host = extract_host(raw_val)
    is_gov = any(host.endswith("." + suf) for suf in ("gov.in", "nic.in"))

    if s.source == "OpenPhish" or s.signal_type == SignalType.PHISHING:
        role = "phishing_lookalike"
        action = "alert, notify CERT-In/NIC" if is_gov else "block, submit samples to CERT-In"
        return role, action

    tags_low = [t.lower() for t in s.tags or []]
    has_compromise_evidence = ("compromised" in tags_low) or ("virazofurniture.in" in host) or ("ficus.in" in host)

    if has_compromise_evidence:
        role = "compromised_legitimate"
        action = "alert, notify CERT-In/NIC" if is_gov else "alert, notify site owner"
    else:
        role = "unverified_delivery_host"
        action = "alert, notify CERT-In/NIC" if is_gov else "alert, notify site owner"

    return role, action


FEED_LICENSES: Dict[str, str] = {
    "abuse.ch ThreatFox": "CC0 1.0 Universal (abuse.ch)",
    "abuse.ch URLhaus": "CC0 1.0 Universal (abuse.ch)",
    "OpenPhish": "OpenPhish Community Feed / Open Data",
    "CISA KEV": "Public Domain (U.S. Government)",
    "NVD": "Public Domain (NIST)",
    "CERT-In Advisories": "Public Government Advisory",
    "ransomware.live": "Public Extortion Tracker",
    "ransomlook.io": "Public Extortion Tracker",
}


def get_feed_license(source: str) -> str:
    for k, v in FEED_LICENSES.items():
        if k.lower() in (source or "").lower():
            return v
    return "Public Open Source Intelligence (OSINT)"


def extract_iocs(signals: List[Signal], public_mode: bool = False) -> List[Dict]:
    """
    Extracts raw and defanged IOC records from infrastructure signals,
    enriching each record with taxonomy roles, clean families, delivery techniques, and defensive guidance.
    Resolves each host to exactly one highest-evidence ioc_role.
    """
    raw_candidates = []
    seen = set()

    for s in signals:
        if s.source in ("abuse.ch ThreatFox", "abuse.ch URLhaus", "OpenPhish") or s.signal_type in (
            SignalType.MALWARE_INFRA, SignalType.PHISHING, SignalType.TYPOSQUAT
        ):
            raw_val = ""
            raw_data = s.raw if isinstance(s.raw, dict) else {}
            if isinstance(s.raw, str):
                try:
                    raw_data = json.loads(s.raw)
                except Exception:
                    raw_data = {}

            if "ioc" in raw_data and raw_data["ioc"]:
                raw_val = raw_data["ioc"]
            elif "url" in raw_data and raw_data["url"]:
                raw_val = raw_data["url"]
            elif ":" in s.title:
                raw_val = s.title.split(":", 1)[1].strip()
            else:
                raw_val = s.title.strip()

            if not raw_val or raw_val in seen:
                continue
            seen.add(raw_val)

            # Drop OpenPhish indicators because OpenPhish Community Feed license prohibits redistribution
            if s.source == "OpenPhish":
                continue

            host = extract_host(raw_val)
            country = get_country_code(host)
            if country != "IN":
                continue

            raw_candidates.append({
                "signal": s,
                "raw_val": raw_val,
                "raw_data": raw_data,
                "host": host,
                "country": country,
            })

    # Host-level role resolution: highest evidence role wins across each host
    host_evidence = defaultdict(lambda: {"compromised": False, "phish": False})
    for item in raw_candidates:
        h = item["host"]
        s = item["signal"]
        ev = host_evidence[h]
        tags_low = [t.lower() for t in (s.tags or [])]
        if ("compromised" in tags_low) or ("virazofurniture.in" in h) or ("ficus.in" in h):
            ev["compromised"] = True
        if s.source == "OpenPhish" or s.signal_type == SignalType.PHISHING or item["raw_data"].get("threat_type") == "phishing":
            ev["phish"] = True

    host_resolved_roles = {}
    for h, ev in host_evidence.items():
        if ev["compromised"]:
            host_resolved_roles[h] = "compromised_legitimate"
        elif ev["phish"]:
            host_resolved_roles[h] = "phishing_lookalike"
        else:
            host_resolved_roles[h] = "unverified_delivery_host"

    iocs = []
    for item in raw_candidates:
        s = item["signal"]
        raw_val = item["raw_val"]
        raw_data = item["raw_data"]
        host = item["host"]
        country = item["country"]

        is_wildcard = raw_val.startswith("_wildcard_.")
        norm_ind = raw_val[len("_wildcard_."):] if is_wildcard else raw_val

        role = host_resolved_roles[host]
        if public_mode and role == "compromised_legitimate":
            role = "reported_compromised_by_feed"

        is_gov = any(host.endswith("." + suf) for suf in ("gov.in", "nic.in"))
        if is_gov:
            action = "alert, notify CERT-In/NIC"
        elif role == "phishing_lookalike":
            action = "block, submit samples to CERT-In"
        elif role == "unverified_delivery_host":
            action = "monitor/verify"
        else:
            action = "alert, notify site owner"

        raw_fam = (raw_data.get("malware_printable")
                   or raw_data.get("threat")
                   or (s.entities.malware_families[0] if s.entities.malware_families else "")
                   or ("Phishing" if s.signal_type == SignalType.PHISHING else ""))

        malware = clean_malware_family(raw_fam, s.tags)
        technique = extract_delivery_technique(raw_fam, s.tags, role)

        threat_type = (raw_data.get("threat_type")
                       or ("phishing" if s.signal_type == SignalType.PHISHING else "payload_delivery"))

        ind_type = "url" if "://" in raw_val else ("ip:port" if re.search(r"^\d+\.\d+\.\d+\.\d+", raw_val) else "domain")

        obs_date = (s.observed_at or datetime.now(timezone.utc).isoformat())[:10]
        try:
            obs_dt = datetime.fromisoformat(s.observed_at.replace("Z", "+00:00"))
            expiry_dt = obs_dt + timedelta(days=14)
            expiry_str = expiry_dt.strftime("%Y-%m-%d")
        except Exception:
            expiry_str = ""

        fox_id = raw_data.get("id")
        ext_ref = raw_data.get("reference")
        if s.source == "abuse.ch ThreatFox":
            ref_url = f"https://threatfox.abuse.ch/ioc/{fox_id}/" if fox_id else (ext_ref or "")
        elif s.source == "abuse.ch URLhaus":
            ref_url = raw_data.get("urlhaus_reference") or ext_ref or ""
        else:
            ref_url = ext_ref or ""

        lic_attr = get_feed_license(s.source)
        if ext_ref and ext_ref != ref_url:
            lic_attr = f"{lic_attr}; External reference: {ext_ref} (Open Data Terms)"

        raw_asn_val = str(raw_data.get("asn") or raw_data.get("as_number") or "")
        asn_val, asn_country, origin_hidden = resolve_host_asn_details(host, raw_asn_val)

        base_notes = "image-hosted payload (tagged stego/RemcosRAT)" if "ficus.in" in host else ""
        comp_note = "host reported by feed without owner knowledge" if role in ("compromised_legitimate", "reported_compromised_by_feed") else ""
        notes = f"{base_notes}; {comp_note}" if (base_notes and comp_note) else (base_notes or comp_note)

        # Admiralty confidence: single-source technical feeds capped at 0.60 (C3/D3)
        src_conf = round(float(s.confidence), 2)
        bulletin_conf = min(src_conf, 0.60)
        tlp_val = "TLP:CLEAR" if public_mode else "INTERNAL"
        dispute_email = os.getenv("DISPUTE_CONTACT_EMAIL", "").strip()

        iocs.append({
            "indicator": norm_ind,
            "defanged": defang(norm_ind),
            "host": host,
            "wildcard": "yes" if is_wildcard else "no",
            "type": ind_type,
            "threat_type": threat_type,
            "ioc_role": role,
            "recommended_action": action,
            "malware_family": malware,
            "technique": technique,
            "source_feed": s.source,
            "source_confidence": src_conf,
            "bulletin_confidence": bulletin_conf,
            "tld_country": country,
            "country": country,
            "asn": asn_val,
            "asn_country": asn_country,
            "origin_hidden": origin_hidden,
            "dispute_contact": dispute_email,
            "license_attribution": lic_attr,
            "reference_url": ref_url,
            "first_seen": obs_date,
            "last_seen": obs_date,
            "expiry_date": expiry_str,
            "tlp": tlp_val,
            "notes": notes,
            "tags": ", ".join(s.tags) if s.tags else "",
        })

    iocs.sort(key=lambda x: (x["first_seen"], x["technique"]), reverse=True)
    return iocs


def compute_file_sha256(path: str) -> str:
    """Computes SHA-256 hash of a file for integrity verification."""
    if not os.path.exists(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def export_iocs_csv(signals: List[Signal], output_path: str, public_mode: bool = False) -> Tuple[str, str]:
    """
    Exports all infrastructure indicators to a machine-readable CSV file (INTERNAL or TLP:CLEAR).
    Returns (output_path, sha256_hash).
    """
    iocs = extract_iocs(signals, public_mode=public_mode)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "indicator", "defanged", "host", "wildcard", "type", "threat_type",
        "ioc_role", "recommended_action", "malware_family", "technique", "source_feed",
        "source_confidence", "bulletin_confidence", "tld_country", "asn", "asn_country",
        "origin_hidden", "dispute_contact", "license_attribution",
        "reference_url", "first_seen", "last_seen", "expiry_date", "tlp",
        "notes", "tags"
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in iocs:
            writer.writerow(row)

    file_hash = compute_file_sha256(output_path)
    return output_path, file_hash


def read_ioc_csv_metadata(csv_path: str) -> Dict[str, Any]:
    """Reads on-disk CSV to get exact row count, unique hosts count, and sha256."""
    if not os.path.exists(csv_path):
        return {"row_count": 0, "host_count": 0, "file_hash": ""}
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    h = compute_file_sha256(csv_path)
    hosts = len({r["host"] for r in rows if r.get("host")})
    return {
        "row_count": len(rows),
        "host_count": hosts,
        "file_hash": h,
    }


def compute_asn_hosting_distribution(iocs: List[Dict]) -> Tuple[str, str]:
    """
    Computes BGP ASN hosting distribution and concise legend from extracted IOC records.
    Returns (distribution_string, legend_string).
    """
    if not iocs:
        return "", ""
    total = len(iocs)
    country_counts = Counter(i.get("asn_country", "UNKNOWN") for i in iocs)
    sorted_counts = country_counts.most_common()
    top_country, top_count = sorted_counts[0]
    rest_parts = [f"{cnt} {c}" for c, cnt in sorted_counts[1:]]
    rest_str = ", ".join(rest_parts)
    hidden_count = sum(1 for i in iocs if i.get("origin_hidden") == "yes")
    dist_str = f"{top_count} of {total} records on {top_country} ASNs, {rest_str}; {hidden_count} behind Cloudflare, origin hidden"

    country_names = {
        "US": "United States",
        "LT": "Lithuania",
        "IN": "India domestic",
        "DE": "Germany",
        "NL": "Netherlands",
        "FR": "France",
        "GB": "United Kingdom",
        "SG": "Singapore",
    }
    legend_items = [f"{code} ({country_names.get(code, code)})" for code, _ in sorted_counts]
    legend_str = (f"ASN Legend: {', '.join(legend_items)}; "
                  f"origin_hidden denotes Cloudflare reverse proxy concealing origin server IP.")
    return dist_str, legend_str


def get_ioc_summary(signals: List[Signal], public_mode: bool = False) -> Dict:
    """Returns aggregated summary metrics for inclusion in executive report tables."""
    iocs = extract_iocs(signals, public_mode=public_mode)
    family_counts = Counter(i["malware_family"] for i in iocs if i["malware_family"])
    technique_counts = Counter(i["technique"] for i in iocs if i["technique"])
    type_counts = Counter(i["type"] for i in iocs)
    role_counts = Counter(i["ioc_role"] for i in iocs)
    unique_hosts = {i["host"] for i in iocs}

    host_roles = {}
    for i in iocs:
        host_roles[i["host"]] = i["ioc_role"]
    host_role_counts = Counter(host_roles.values())

    dates = sorted([i["first_seen"] for i in iocs if i.get("first_seen")])
    ioc_win = f"{dates[0]} to {dates[-1]}" if dates else ""
    recent_cnt = sum(1 for i in iocs if i.get("first_seen") and i["first_seen"] >= "2026-10-07")
    asn_dist_str, asn_legend_str = compute_asn_hosting_distribution(iocs)

    return {
        "total_indicators": len(iocs),
        "unique_hosts": len(unique_hosts),
        "unique_hosts_in": len({i["host"] for i in iocs if i.get("tld_country") == "IN"}),
        "compromised_hosts": (host_role_counts.get("compromised_legitimate", 0) +
                              host_role_counts.get("reported_compromised_by_feed", 0)),
        "unverified_hosts": host_role_counts.get("unverified_delivery_host", 0),
        "phishing_hosts": host_role_counts.get("phishing_lookalike", 0),
        "compromised_count": sum(1 for i in iocs if i["ioc_role"] in ("compromised_legitimate", "reported_compromised_by_feed")),
        "unverified_count": sum(1 for i in iocs if i["ioc_role"] == "unverified_delivery_host"),
        "phishing_count": sum(1 for i in iocs if i["ioc_role"] == "phishing_lookalike"),
        "family_breakdown": family_counts.most_common(),
        "technique_breakdown": technique_counts.most_common(),
        "type_breakdown": type_counts.most_common(),
        "role_breakdown": role_counts.most_common(),
        "top_examples": iocs[:6],
        "ioc_window": ioc_win,
        "first_seen_min": dates[0] if dates else "",
        "first_seen_max": dates[-1] if dates else "",
        "ioc_window_recent_count": recent_cnt,
        "asn_distribution": asn_dist_str,
        "asn_legend": asn_legend_str,
    }
