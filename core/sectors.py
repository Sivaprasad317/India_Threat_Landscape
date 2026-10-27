"""
Indian sector taxonomy and classification.

Threat feeds label victims with loose, Western-centric activity strings
("Business Services", "Technology", "Not Found"). This module maps those onto
a taxonomy that matches how Indian industry and Indian regulators actually
divide things up, and flags the sectors designated as Critical Information
Infrastructure under Section 70A of the IT Act, 2000 (NCIIPC).
"""

import re
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Sector definitions
#
# nciipc_critical marks sectors that fall under the National Critical
# Information Infrastructure Protection Centre's protected categories:
# Power & Energy, Banking Financial Services & Insurance, Telecom,
# Transport, Government, and Strategic & Public Enterprises.
# ---------------------------------------------------------------------------

SECTORS: Dict[str, Dict] = {
    "BFSI": {
        "label": "Banking, Financial Services & Insurance",
        "nciipc_critical": True,
        "regulators": ["RBI", "SEBI", "IRDAI", "NPCI"],
        "keywords": [
            "bank", "banking", "financial", "finance", "insurance", "insurer",
            "nbfc", "credit union", "lending", "loan", "mutual fund",
            "asset management", "brokerage", "securities", "fintech",
            "payment", "wallet", "upi", "microfinance", "cooperative bank",
            "stock exchange", "depositor", "wealth management",
        ],
        "notes": "RBI cyber security framework applies in addition to CERT-In.",
    },
    "IT_ITES": {
        "label": "IT Services & Software",
        "nciipc_critical": False,
        "regulators": ["MeitY", "STPI"],
        "keywords": [
            "information technology", "it services", "software", "saas",
            "technology", "tech", "consulting", "outsourcing", "bpo", "kpo",
            "it consulting", "systems integrator", "managed services",
            "data center", "datacentre", "cloud", "engineering services",
            "product engineering", "computer",
        ],
        "notes": "India's largest export sector and a frequent supply-chain "
                 "pivot into overseas clients.",
    },
    "PHARMA": {
        "label": "Pharmaceutical & Life Sciences",
        "nciipc_critical": False,
        "regulators": ["CDSCO", "DoP"],
        "keywords": [
            "pharma", "pharmaceutical", "drug", "biotech", "biotechnology",
            "life sciences", "clinical", "vaccine", "api manufacturer",
            "formulation", "cro", "contract research",
        ],
        "notes": "High-value IP target. India supplies a large share of "
                 "global generics.",
    },
    "HEALTHCARE": {
        "label": "Healthcare & Hospitals",
        "nciipc_critical": False,
        "regulators": ["MoHFW", "NHA"],
        "keywords": [
            "hospital", "healthcare", "health care", "medical", "clinic",
            "diagnostic", "pathology", "nursing", "patient", "health",
            "ayushman", "medical college",
        ],
        "notes": "ABDM health data adds sensitivity beyond CERT-In duties.",
    },
    "MANUFACTURING": {
        "label": "Manufacturing & Automotive",
        "nciipc_critical": False,
        "regulators": ["DPIIT"],
        "keywords": [
            "manufacturing", "manufacturer", "automotive", "auto", "vehicle",
            "industrial", "factory", "machinery", "steel", "cement",
            "chemical", "textile", "engineering", "electronics manufacturing",
            "components", "foundry", "plant",
        ],
        "notes": "OT and IT convergence; ransomware halts physical production.",
    },
    "GOVERNMENT": {
        "label": "Government & Public Sector",
        "nciipc_critical": True,
        "regulators": ["MeitY", "NIC", "NCIIPC"],
        "keywords": [
            "government", "ministry", "municipal", "municipality", "public sector",
            "psu", "state government", "district", "panchayat", "police",
            "defence", "defense", "military", "army", "navy", "air force",
            "railway", "customs", "income tax", "election", "court",
            "judiciary", "nagar nigam", "corporation of",
        ],
        "notes": "Section 70A critical infrastructure. NCIIPC involvement "
                 "likely alongside CERT-In.",
    },
    "TELECOM": {
        "label": "Telecommunications",
        "nciipc_critical": True,
        "regulators": ["DoT", "TRAI"],
        "keywords": [
            "telecom", "telecommunication", "mobile operator", "isp",
            "internet service", "broadband", "cellular", "fiber", "fibre",
            "network operator", "tower",
        ],
        "notes": "DoT security directives apply in addition to CERT-In.",
    },
    "ENERGY": {
        "label": "Power, Energy & Utilities",
        "nciipc_critical": True,
        "regulators": ["CEA", "MNRE", "MoP"],
        "keywords": [
            "power", "energy", "electricity", "utility", "utilities", "grid",
            "oil", "gas", "petroleum", "refinery", "renewable", "solar",
            "wind", "coal", "nuclear", "discom", "transmission", "water",
            "wastewater",
        ],
        "notes": "Section 70A critical infrastructure. CEA cyber security "
                 "guidelines apply.",
    },
    "TRANSPORT": {
        "label": "Transport & Logistics",
        "nciipc_critical": True,
        "regulators": ["MoCA", "MoRTH", "DGCA"],
        "keywords": [
            "transport", "transportation", "logistics", "shipping", "port",
            "airport", "airline", "aviation", "freight", "cargo", "courier",
            "warehouse", "supply chain", "trucking", "maritime",
        ],
        "notes": "Section 70A critical infrastructure.",
    },
    "EDUCATION": {
        "label": "Education & Research",
        "nciipc_critical": False,
        "regulators": ["UGC", "AICTE", "MoE"],
        "keywords": [
            "education", "university", "college", "school", "institute",
            "academy", "academic", "research institute", "iit", "iim",
            "nit", "edtech", "learning",
        ],
        "notes": "Large personal-data holdings, typically thin security budgets.",
    },
    "RETAIL_ECOM": {
        "label": "Retail & E-commerce",
        "nciipc_critical": False,
        "regulators": ["DPIIT", "CCPA"],
        "keywords": [
            "retail", "e-commerce", "ecommerce", "online store", "marketplace",
            "consumer goods", "fmcg", "supermarket", "hospitality", "hotel",
            "restaurant", "travel", "tourism",
        ],
        "notes": "Payment data exposure invites Annexure I item xiv.",
    },
    "MEDIA": {
        "label": "Media & Entertainment",
        "nciipc_critical": False,
        "regulators": ["MIB"],
        "keywords": [
            "media", "entertainment", "broadcast", "television", "publishing",
            "newspaper", "news", "film", "gaming", "advertising",
        ],
        "notes": "",
    },
    "REAL_ESTATE": {
        "label": "Real Estate & Construction",
        "nciipc_critical": False,
        "regulators": ["RERA"],
        "keywords": [
            "real estate", "construction", "infrastructure", "property",
            "builder", "developer", "realty", "housing",
        ],
        "notes": "",
    },
    "NGO_LEGAL": {
        "label": "Professional, Legal & Non-profit",
        "nciipc_critical": False,
        "regulators": [],
        "keywords": [
            "law firm", "legal", "advocate", "accounting", "audit",
            "professional services", "consultancy", "ngo", "non-profit",
            "nonprofit", "trust", "foundation", "charity",
        ],
        "notes": "",
    },
    "UNCLASSIFIED": {
        "label": "Unclassified",
        "nciipc_critical": False,
        "regulators": [],
        "keywords": [],
        "notes": "Feed did not provide a usable sector label.",
    },
}

# Feed labels seen in the wild, mapped straight through. Checked before
# keyword matching because these are exact strings ransomware.live emits.
FEED_LABEL_MAP = {
    "financial services": "BFSI",
    "finance": "BFSI",
    "banking": "BFSI",
    "insurance": "BFSI",
    "technology": "IT_ITES",
    "it services": "IT_ITES",
    "business services": "IT_ITES",
    "telecommunications": "TELECOM",
    "healthcare": "HEALTHCARE",
    "health care": "HEALTHCARE",
    "hospital & health care": "HEALTHCARE",
    "pharmaceuticals": "PHARMA",
    "biotechnology": "PHARMA",
    "manufacturing": "MANUFACTURING",
    "industrial": "MANUFACTURING",
    "automotive": "MANUFACTURING",
    "construction": "REAL_ESTATE",
    "real estate": "REAL_ESTATE",
    "government & defense": "GOVERNMENT",
    "government": "GOVERNMENT",
    "public administration": "GOVERNMENT",
    "education": "EDUCATION",
    "retail & e-commerce": "RETAIL_ECOM",
    "retail": "RETAIL_ECOM",
    "consumer services": "RETAIL_ECOM",
    "hospitality": "RETAIL_ECOM",
    "transportation": "TRANSPORT",
    "transportation & logistics": "TRANSPORT",
    "logistics": "TRANSPORT",
    "energy": "ENERGY",
    "energy, utilities & waste": "ENERGY",
    "utilities": "ENERGY",
    "agriculture and food production": "MANUFACTURING",
    "media & internet": "MEDIA",
    "media": "MEDIA",
    "legal": "NGO_LEGAL",
    "law practice": "NGO_LEGAL",
    "professional services": "NGO_LEGAL",
    "non-profit": "NGO_LEGAL",
    "not found": "UNCLASSIFIED",
    "other": "UNCLASSIFIED",
    "": "UNCLASSIFIED",
}

# Indian TLDs and name fragments that raise confidence a victim is Indian
INDIA_DOMAIN_HINTS = re.compile(
    r"\.(?:in|co\.in|net\.in|org\.in|gov\.in|nic\.in|ac\.in|edu\.in|res\.in|"
    r"firm\.in|gen\.in|ind\.in|mil\.in)(?=[/:?\s]|$)",
    re.IGNORECASE,
)

INDIA_NAME_HINTS = re.compile(
    r"\b(?:india|indian|bharat|bharatiya|hindustan|pvt\.?\s*ltd|private limited|"
    r"mumbai|delhi|bengaluru|bangalore|hyderabad|chennai|kolkata|pune|"
    r"ahmedabad|gurgaon|gurugram|noida|jaipur|lucknow|kochi|cochin|"
    r"coimbatore|indore|nagpur|surat|vadodara|bhubaneswar|chandigarh|"
    r"thiruvananthapuram|visakhapatnam|mysuru|mysore)\b",
    re.IGNORECASE,
)


_SECTOR_KEYWORD_PATTERNS: Dict[str, List[re.Pattern]] = {
    key: [re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)
          for kw in spec["keywords"]]
    for key, spec in SECTORS.items() if key != "UNCLASSIFIED"
}


def classify_sector(activity: str = "", victim_name: str = "",
                    description: str = "") -> Tuple[str, float]:
    """
    Return (sector_key, confidence).

    Exact feed-label matches score 0.95. Keyword matches score by how many
    distinct keywords hit, capped at 0.85, because keyword inference on a
    company name is inherently weaker evidence than a declared label.
    """
    v_low = (victim_name or "").lower()
    # Explicit entity overrides for prominent Indian institutions and verified victims
    if any(k in v_low for k in ("roorkee", "iit", "indian institute of technology", "manipal", "university", "vit.ac.in", "sai.org.in", "vedantaainstitute", "college", "school")):
        return "EDUCATION", 0.98
    if any(k in v_low for k in ("jpmgroup", "jay packaging", "raajratna", "labindia", "simplexengg", "simplex engineering")):
        return "MANUFACTURING", 0.98
    if any(k in v_low for k in ("majestic holidays", "majestic", "praveg")):
        return "RETAIL_ECOM", 0.98
    if any(k in v_low for k in ("ags cinemas", "ags")):
        return "MEDIA", 0.98
    if "shalina" in v_low:
        return "PHARMA", 0.98
    if "licindia" in v_low:
        return "UNCLASSIFIED", 0.0
    if "incor" in v_low:
        return "REAL_ESTATE", 0.98

    label = (activity or "").strip().lower()
    if label in FEED_LABEL_MAP:
        sector = FEED_LABEL_MAP[label]
        if sector != "UNCLASSIFIED":
            return sector, 0.95

    haystack = " ".join([activity or "", victim_name or "",
                         description or ""]).lower()
    if not haystack.strip():
        return "UNCLASSIFIED", 0.0

    scores: Dict[str, int] = {}
    for key, patterns in _SECTOR_KEYWORD_PATTERNS.items():
        hits = sum(1 for p in patterns if p.search(haystack))
        if hits:
            scores[key] = hits

    if not scores:
        return "UNCLASSIFIED", 0.0

    best = max(scores, key=scores.get)
    confidence = min(0.45 + 0.15 * scores[best], 0.85)
    return best, round(confidence, 2)


def is_indian_entity(country: str = "", victim_name: str = "",
                     description: str = "") -> Tuple[bool, float, str]:
    """
    Decide whether a victim is an Indian organisation.

    Returns (is_indian, confidence, reason). A declared country code is
    strong evidence; a .in domain is near-certain; city or "Pvt Ltd" hints
    are weaker and flagged as such so a bulletin can mark them for review.
    """
    code = (country or "").strip().upper()
    if code in ("IN", "IND", "INDIA"):
        return True, 0.98, "country code from feed"

    blob = f"{victim_name} {description}"
    if INDIA_DOMAIN_HINTS.search(blob):
        return True, 0.90, "Indian TLD in victim identifier"

    if INDIA_NAME_HINTS.search(blob):
        # Only treat as Indian when no other country was declared
        if not code or code in ("", "UNKNOWN", "NOT FOUND"):
            return True, 0.55, "Indian city or entity-name hint, unconfirmed"
        return False, 0.0, f"name hints India but feed declares {code}"

    return False, 0.0, ""


def sector_label(key: str) -> str:
    return SECTORS.get(key, SECTORS["UNCLASSIFIED"])["label"]


SECTOR_SHORT_DISPLAY: Dict[str, str] = {
    "IT_ITES": "IT Services",
    "MANUFACTURING": "Manufacturing",
    "BFSI": "BFSI",
    "EDUCATION": "Education",
    "ENERGY": "Energy",
    "HEALTHCARE": "Healthcare",
    "RETAIL_ECOM": "Retail",
    "TRANSPORT": "Transport",
    "TELECOM": "Telecom",
    "GOVERNMENT": "Government",
    "PHARMA": "Pharma",
    "REAL_ESTATE": "Real Estate",
    "MEDIA": "Media",
    "NGO_LEGAL": "Legal/NGO",
    "UNCLASSIFIED": "Unclassified",
}


def short_sector_label(key: str) -> str:
    return SECTOR_SHORT_DISPLAY.get(key, sector_label(key).split("&")[0].strip())


def is_nciipc_critical(key: str) -> bool:
    return SECTORS.get(key, {}).get("nciipc_critical", False)


def sector_regulators(key: str) -> List[str]:
    return SECTORS.get(key, {}).get("regulators", [])


def all_sectors() -> List[str]:
    return [k for k in SECTORS if k != "UNCLASSIFIED"]


def clean_victim_name(name: str) -> str:
    name = (name or "").strip()
    low = name.lower()
    if "simplexengg" in low or low == "simplex engineering":
        return "Simplex Engineering Works Pvt. Ltd."
    if "raajratna" in low:
        return "Raajratna Metal Industries"
    if "sai.org.in" in low:
        return "Shri Saibaba Sansthan Trust"
    if "vit.ac.in" in low:
        return "Vellore Institute of Technology (VIT)"
    if "swadeshicipl" in low:
        return "Swadeshi Commercial Co. Ltd"
    if "vedantaa" in low:
        return "Vedanta Institute"
    if "southsign" in low:
        return "South Sign Systems"
    if "seashellhospital" in low:
        return "Sea Shell Hospital"
    if "karkinos" in low:
        return "Karkinos Healthcare"
    if "jindallife" in low:
        return "Jindal Life Sciences"
    if "shalina" in low:
        return "Shalina Healthcare"
    if "labindia" in low:
        return "Labindia Instruments Pvt. Ltd."
    if "qcpl" in low:
        return "Quality Control Products Ltd (QCPL)"
    if "jpmgroup" in low:
        return "JPM Group (Jay Packaging)"
    if "atomberg" in low:
        return "Atomberg Technologies"
    if "9altitudes" in low:
        return "9altitudes India"
    if "vi***in" in low:
        return "vi***in (Masked Logistics Entity)"
    if low == "licindia":
        return "Licindia (Unverified Domain Claim)"
    if low == "indic":
        return "Indic Inspirations"
    if low == "sancity":
        return "Sancity Developers"
    if "bonjour" in low:
        return "Bonjour Group"
    if "gindre" in low:
        return "Gindre India Pvt. Ltd."
    if "seasia" in low:
        return "Seasia Infotech Pvt. Ltd."
    if "university of delhi" in low or "(du)" in low:
        return "University of Delhi (DU)"
    if "manipal" in low:
        return "Manipal Academy of Higher Education"
    if "iit roorkee" in low:
        return "IIT Roorkee"
    return name

