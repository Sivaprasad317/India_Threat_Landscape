"""
CERT-In compliance mapping.

Source: Directions under sub-section (6) of section 70B of the Information
Technology Act, 2000, No. 20(3)/2022-CERT-In, dated 28 April 2022, effective
after 60 days (27 June 2022).
https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf

The twenty Annexure I categories below are reproduced from that document.

This module is a planning aid, not legal advice. Whether a given incident is
reportable, and by whom, depends on facts this tool cannot see. Confirm with
counsel and with CERT-In's published reporting formats.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

DIRECTION_REF = "No. 20(3)/2022-CERT-In, dated 28 April 2022"
DIRECTION_URL = "https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf"
REPORTING_EMAIL = "incident@cert-in.org.in"
REPORTING_PHONE = "1800-11-4949"
REPORTING_WINDOW_HOURS = 6
LOG_RETENTION_DAYS = 180

# ---------------------------------------------------------------------------
# Annexure I — the twenty mandatorily reportable categories
# ---------------------------------------------------------------------------

ANNEXURE_I: Dict[str, Dict] = {
    "i": {
        "title": "Targeted scanning/probing of critical networks/systems",
        "keywords": ["scanning", "probing", "reconnaissance", "port scan",
                     "enumeration", "mass scanning"],
    },
    "ii": {
        "title": "Compromise of critical systems/information",
        "keywords": ["compromise", "critical system", "domain controller",
                     "active directory", "privileged access"],
    },
    "iii": {
        "title": "Unauthorised access of IT systems/data",
        "keywords": ["unauthorised access", "unauthorized access",
                     "initial access", "credential", "stolen credentials",
                     "valid accounts", "rdp access", "vpn access"],
    },
    "iv": {
        "title": ("Defacement of website or intrusion into a website and "
                  "unauthorised changes such as inserting malicious code, "
                  "links to external websites etc."),
        "keywords": ["defacement", "defaced", "website intrusion",
                     "web shell", "webshell", "injected script",
                     "malicious redirect", "skimmer", "magecart"],
    },
    "v": {
        "title": ("Malicious code attacks such as spreading of virus/worm/"
                  "Trojan/Bots/Spyware/Ransomware/Cryptominers"),
        "keywords": ["ransomware", "malware", "trojan", "worm", "virus",
                     "botnet", "spyware", "cryptominer", "cryptojacking",
                     "loader", "stealer", "backdoor", "implant", "rat",
                     "wiper", "encrypted"],
    },
    "vi": {
        "title": ("Attack on servers such as Database, Mail and DNS and "
                  "network devices such as Routers"),
        "keywords": ["database server", "mail server", "exchange server",
                     "dns", "router", "firewall appliance", "vpn appliance",
                     "edge device", "network device"],
    },
    "vii": {
        "title": "Identity Theft, spoofing and phishing attacks",
        "keywords": ["phishing", "spearphishing", "spear-phishing",
                     "identity theft", "spoofing", "impersonation",
                     "business email compromise", "bec", "smishing",
                     "vishing", "typosquat"],
    },
    "viii": {
        "title": ("Denial of Service (DoS) and Distributed Denial of Service "
                  "(DDoS) attacks"),
        "keywords": ["denial of service", "ddos", "dos attack",
                     "traffic flood", "amplification attack"],
    },
    "ix": {
        "title": ("Attacks on Critical infrastructure, SCADA and operational "
                  "technology systems and Wireless networks"),
        "keywords": ["scada", "ics", "operational technology", "ot network",
                     "plc", "critical infrastructure", "modbus",
                     "wireless network", "industrial control"],
    },
    "x": {
        "title": "Attacks on Application such as E-Governance, E-Commerce etc.",
        "keywords": ["e-governance", "egovernance", "e-commerce", "ecommerce",
                     "web application", "api abuse", "application attack",
                     "citizen portal"],
    },
    "xi": {
        "title": "Data Breach",
        "keywords": ["data breach", "breached", "records exposed",
                     "customer data stolen", "pii exposed",
                     "database stolen"],
    },
    "xii": {
        "title": "Data Leak",
        "keywords": ["data leak", "leak site", "leaked", "dump",
                     "exposed bucket", "public s3", "misconfigured storage",
                     "exfiltrat"],
    },
    "xiii": {
        "title": ("Attacks on Internet of Things (IoT) devices and associated "
                  "systems, networks, software, servers"),
        "keywords": ["iot", "internet of things", "smart device", "camera",
                     "cctv", "embedded device", "firmware"],
    },
    "xiv": {
        "title": "Attacks or incident affecting Digital Payment systems",
        "keywords": ["payment", "upi", "atm", "card data", "pos malware",
                     "point of sale", "payment gateway", "swift",
                     "npci", "digital payment"],
    },
    "xv": {
        "title": "Attacks through Malicious mobile Apps",
        "keywords": ["malicious app", "android malware", "apk", "ios malware",
                     "mobile malware", "banking trojan android"],
    },
    "xvi": {
        "title": "Fake mobile Apps",
        "keywords": ["fake app", "counterfeit app", "impersonating app",
                     "rogue application"],
    },
    "xvii": {
        "title": "Unauthorised access to social media accounts",
        "keywords": ["social media account", "account takeover",
                     "twitter account hijack", "facebook compromise",
                     "verified account hijack"],
    },
    "xviii": {
        "title": ("Attacks or malicious/suspicious activities affecting Cloud "
                  "computing systems/servers/software/applications"),
        "keywords": ["cloud", "aws", "azure", "gcp", "s3 bucket",
                     "kubernetes", "container", "saas compromise",
                     "cloud misconfiguration"],
    },
    "xix": {
        "title": ("Attacks or malicious/suspicious activities affecting "
                  "systems/servers/networks/software/applications related to "
                  "Big Data, Block chain, virtual assets, virtual asset "
                  "exchanges, custodian wallets, Robotics, 3D and 4D "
                  "Printing, additive manufacturing, Drones"),
        "keywords": ["blockchain", "crypto exchange", "virtual asset",
                     "custodian wallet", "defi", "smart contract",
                     "big data", "robotics", "drone", "3d printing"],
    },
    "xx": {
        "title": ("Attacks or malicious/suspicious activities affecting "
                  "systems/servers/software/applications related to "
                  "Artificial Intelligence and Machine Learning"),
        "keywords": ["artificial intelligence", "machine learning",
                     "llm", "ai model", "model poisoning",
                     "prompt injection", "ai agent", "genai"],
    },
}

# Sectors where an incident almost always touches a critical-infrastructure
# category as well, because of what the sector operates.
SECTOR_IMPLIED_CATEGORIES = {
    "ENERGY": ["ix"],
    "TELECOM": ["vi", "ix"],
    "TRANSPORT": ["ix"],
    "GOVERNMENT": ["ii", "x"],
    "BFSI": ["xiv"],
    "RETAIL_ECOM": ["x"],
}


_ANNEXURE_KEYWORD_PATTERNS: Dict[str, List[Tuple[str, re.Pattern]]] = {
    roman: [
        (kw, re.compile(
            r"\b" + re.escape(kw) + (r"\w*" if kw == "exfiltrat" else r"\b"),
            re.IGNORECASE))
        for kw in spec["keywords"]
    ]
    for roman, spec in ANNEXURE_I.items()
}


def map_to_annexure(text: str, sector: Optional[str] = None,
                    min_hits: int = 1) -> List[Dict]:
    """
    Map free text describing an incident onto Annexure I categories.

    Returns a list of {roman, title, matched_keywords, source} sorted by
    strength of match. Sector-implied categories are included but marked
    so a reader can tell inference from direct evidence.
    """
    blob = (text or "").lower()
    results: Dict[str, Dict] = {}

    for roman, patterns in _ANNEXURE_KEYWORD_PATTERNS.items():
        matched = [kw for kw, p in patterns if p.search(blob)]
        if len(matched) >= min_hits:
            results[roman] = {
                "roman": roman,
                "title": ANNEXURE_I[roman]["title"],
                "matched_keywords": matched,
                "source": "text match",
                "strength": len(matched),
            }

    if sector:
        for roman in SECTOR_IMPLIED_CATEGORIES.get(sector, []):
            if roman not in results:
                results[roman] = {
                    "roman": roman,
                    "title": ANNEXURE_I[roman]["title"],
                    "matched_keywords": [],
                    "source": f"implied by sector {sector}",
                    "strength": 0,
                }

    ordered = sorted(results.values(),
                     key=lambda r: (-r["strength"],
                                    list(ANNEXURE_I).index(r["roman"])))
    return ordered


def reporting_deadline(noticed_at: datetime) -> Dict:
    """
    Work out the 6-hour CERT-In reporting deadline.

    The clock starts when the incident is noticed or brought to notice, not
    when the investigation concludes, and it does not pause for nights,
    weekends or holidays.
    """
    # Callers should attach a timezone. A naive value is read as UTC here;
    # the CLI attaches IST before calling, because an Indian analyst typing
    # a bare time means local time.
    if noticed_at.tzinfo is None:
        noticed_at = noticed_at.replace(tzinfo=timezone.utc)

    deadline = noticed_at + timedelta(hours=REPORTING_WINDOW_HOURS)
    now = datetime.now(timezone.utc)
    remaining = deadline - now

    ist = timezone(timedelta(hours=5, minutes=30))

    return {
        "noticed_at_utc": noticed_at.astimezone(timezone.utc).isoformat(),
        "noticed_at_ist": noticed_at.astimezone(ist).strftime("%d %b %Y %H:%M IST"),
        "deadline_utc": deadline.astimezone(timezone.utc).isoformat(),
        "deadline_ist": deadline.astimezone(ist).strftime("%d %b %Y %H:%M IST"),
        "hours_remaining": round(remaining.total_seconds() / 3600, 2),
        "breached": remaining.total_seconds() < 0,
        "window_hours": REPORTING_WINDOW_HOURS,
    }


def log_retention_floor(reference: Optional[datetime] = None) -> Dict:
    """Earliest date whose ICT logs must still be retained."""
    reference = reference or datetime.now(timezone.utc)
    floor = reference - timedelta(days=LOG_RETENTION_DAYS)
    return {
        "retain_from": floor.strftime("%d %b %Y"),
        "rolling_days": LOG_RETENTION_DAYS,
        "jurisdiction": "India",
    }


def obligations_summary(sector: Optional[str] = None) -> List[Dict]:
    """The standing obligations from the Directions, for bulletin footers."""
    items = [
        {
            "obligation": "Incident reporting",
            "detail": (f"Report Annexure I incidents to CERT-In within "
                       f"{REPORTING_WINDOW_HOURS} hours of noticing them, or of "
                       f"being brought to notice. Email {REPORTING_EMAIL} or "
                       f"phone {REPORTING_PHONE}."),
        },
        {
            "obligation": "Log retention",
            "detail": (f"Enable logs on all ICT systems and retain them for a "
                       f"rolling {LOG_RETENTION_DAYS} days within Indian "
                       f"jurisdiction, to be produced when CERT-In directs."),
        },
        {
            "obligation": "Time synchronisation",
            "detail": ("Synchronise all ICT system clocks to NIC or NPL NTP "
                       "servers, or to servers traceable to them."),
        },
        {
            "obligation": "Point of contact",
            "detail": ("Designate a point of contact for CERT-In and keep the "
                       "Annexure II details current."),
        },
    ]
    if sector == "BFSI":
        items.append({
            "obligation": "Sector overlay",
            "detail": ("RBI, SEBI, IRDAI and NPCI reporting duties apply "
                       "alongside CERT-In and may run to different clocks."),
        })
    if sector in ("ENERGY", "TELECOM", "TRANSPORT", "GOVERNMENT"):
        items.append({
            "obligation": "Sector overlay",
            "detail": ("Designated Critical Information Infrastructure under "
                       "Section 70A. NCIIPC engagement is likely in addition "
                       "to CERT-In reporting."),
        })
    return items


DISCLAIMER = (
    "This mapping is an analytical aid based on the published text of the "
    "CERT-In Directions and is not legal advice. Whether an incident is "
    "reportable, and by which entity, depends on facts and contractual "
    "arrangements this tool cannot assess. Confirm with counsel and against "
    "CERT-In's current reporting formats before relying on it."
)
