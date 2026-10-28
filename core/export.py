"""
Export the IOC sheet for CTI platforms: STIX 2.1 bundle and MISP event.

Same indicators, roles, actions, confidence and expiry as the CSV, so a
SIEM or MISP instance gets exactly what the bulletin describes. Identifiers
are UUIDv5 from the indicator value, so re-exporting the same data gives the
same IDs and platforms update rather than duplicate.

Marking: the public edition is TLP:WHITE (the STIX 2.1 built-in marking,
equivalent to TLP 2.0 CLEAR); the internal edition is TLP:GREEN.

Both formats are meant to be loaded into detection, so expired indicators
(status "expired" in the CSV) are left out unless the caller asks for them;
when included, a MISP attribute for one is not marked for detection (to_ids).
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

NAMESPACE = uuid.UUID("6f1c2a0e-5d1b-4b8e-9a77-1f0c3e9d2b44")

# STIX 2.1 specification, section 7.2.1.4: predefined TLP marking definitions
TLP_MARKINGS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
}

ROLE_TEXT = {
    "compromised_legitimate": "Legitimate site reported compromised by the feed",
    "reported_compromised_by_feed": "Legitimate site reported compromised by the feed",
    "unverified_delivery_host": "Malware delivery host (not independently verified)",
    "phishing_lookalike": "Phishing or lookalike site",
}


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{key}')}"


def _ts(day: str) -> str:
    return f"{day[:10]}T00:00:00.000Z"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(ioc: Dict) -> str:
    value = ioc["indicator"]
    if ioc["type"] == "url":
        return f"[url:value = '{_escape(value)}']"
    if ioc["type"] == "ip:port":
        return f"[ipv4-addr:value = '{_escape(value.split(':')[0])}']"
    return f"[domain-name:value = '{_escape(value)}']"


def _description(ioc: Dict) -> str:
    parts = [ROLE_TEXT.get(ioc.get("ioc_role", ""), ioc.get("ioc_role", "")),
             f"technique: {ioc['technique']}" if ioc.get("technique") else "",
             f"malware: {ioc['malware_family']}" if ioc.get("malware_family") else "",
             f"source: {ioc.get('source_feed', '')}",
             f"recommended action: {ioc.get('recommended_action', '')}",
             ioc.get("notes", "")]
    return ". ".join(p for p in parts if p) + "."


def actionable(iocs: List[Dict], include_expired: bool = False) -> List[Dict]:
    """Indicators fit to load into detection: the active ones, unless told otherwise."""
    return list(iocs) if include_expired else [i for i in iocs if i.get("status") != "expired"]


def to_stix_bundle(iocs: List[Dict], producer: str, public_mode: bool = False,
                   include_expired: bool = False) -> Dict:
    iocs = actionable(iocs, include_expired)
    tlp = "white" if public_mode else "green"
    identity_id = _id("identity", producer)
    marking_id = TLP_MARKINGS[tlp]
    objects: List[Dict] = [
        {"type": "identity", "spec_version": "2.1", "id": identity_id,
         "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
         "name": producer, "identity_class": "individual",
         "description": "India Threat Landscape bulletin; independent analyst work, not affiliated with CERT-In."},
        {"type": "marking-definition", "spec_version": "2.1", "id": marking_id,
         "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
         "name": f"TLP:{tlp.upper()}", "definition": {"tlp": tlp}},
    ]
    seen = set()
    for ioc in iocs:
        key = f"{ioc['type']}:{ioc['indicator']}"
        if key in seen:
            continue
        seen.add(key)
        first = ioc.get("first_seen") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        indicator = {
            "type": "indicator", "spec_version": "2.1", "id": _id("indicator", key),
            "created": _ts(first), "modified": _ts(ioc.get("last_seen") or first),
            "name": f"{ioc.get('technique') or 'Malicious'} host {ioc.get('defanged', ioc['indicator'])}",
            "description": _description(ioc),
            "indicator_types": ["compromised"] if "compromised" in ioc.get("ioc_role", "") else ["malicious-activity"],
            "pattern": stix_pattern(ioc), "pattern_type": "stix", "pattern_version": "2.1",
            "valid_from": _ts(first),
            "confidence": int(round(float(ioc.get("bulletin_confidence") or 0) * 100)),
            "labels": [x for x in (ioc.get("technique"), ioc.get("malware_family")) if x],
            "created_by_ref": identity_id,
            "object_marking_refs": [marking_id],
        }
        expiry = ioc.get("expiry_date")
        if expiry and expiry[:10] > first[:10]:
            indicator["valid_until"] = _ts(expiry)
        if ioc.get("reference_url"):
            indicator["external_references"] = [{"source_name": ioc.get("source_feed", "feed"),
                                                 "url": ioc["reference_url"]}]
        objects.append(indicator)
    bundle_key = ",".join(sorted(o["id"] for o in objects))
    return {"type": "bundle", "id": _id("bundle", bundle_key), "objects": objects}


def misp_attribute_type(ioc: Dict) -> Dict:
    if ioc["type"] == "url":
        return {"type": "url", "value": ioc["indicator"]}
    if ioc["type"] == "ip:port":
        ip, _, port = ioc["indicator"].partition(":")
        return {"type": "ip-dst|port", "value": f"{ip}|{port}"} if port else {"type": "ip-dst", "value": ip}
    return {"type": "domain", "value": ioc["indicator"]}


def to_misp_event(iocs: List[Dict], producer: str, public_mode: bool = False,
                  event_date: Optional[str] = None, include_expired: bool = False) -> Dict:
    iocs = actionable(iocs, include_expired)
    event_date = event_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    edition = "public" if public_mode else "internal"
    attributes, seen = [], set()
    for ioc in iocs:
        key = f"{ioc['type']}:{ioc['indicator']}"
        if key in seen:
            continue
        seen.add(key)
        attr = misp_attribute_type(ioc)
        attr.update({
            "uuid": str(uuid.uuid5(NAMESPACE, f"misp-attribute:{key}")),
            "category": "Network activity",
            "to_ids": ioc.get("status") != "expired",
            "comment": _description(ioc)[:250],
        })
        if ioc.get("first_seen"):
            attr["first_seen"] = f"{ioc['first_seen'][:10]}T00:00:00+00:00"
        if ioc.get("last_seen"):
            attr["last_seen"] = f"{ioc['last_seen'][:10]}T00:00:00+00:00"
        attributes.append(attr)
    return {"Event": {
        "uuid": str(uuid.uuid5(NAMESPACE, f"misp-event:{edition}:{event_date}")),
        "info": f"India Threat Landscape IOCs ({edition} edition) {event_date}",
        "date": event_date,
        "threat_level_id": "2",
        "analysis": "1",
        "distribution": "3" if public_mode else "1",
        "published": False,
        "Orgc": {"name": producer},
        "Tag": [{"name": "tlp:clear" if public_mode else "tlp:green"},
                {"name": "india-threat-landscape"}],
        "Attribute": attributes,
    }}


def write_json(doc: Dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return path
