"""
Vulnerability intelligence.

This is the single highest-value addition to a ransomware-only view. Knowing
that CVE-2024-XXXX is being actively exploited in the wild, and that it sits
in a product Indian BFSI runs, is more actionable than a list of victims,
because it is something a defender can act on before they are on a leak site.

Sources, all free and none requiring a key:
  CISA KEV   catalogue of vulnerabilities confirmed exploited in the wild
  EPSS       FIRST's probability that a CVE will be exploited in 30 days
  NVD        CVSS scores and product mapping (optional key raises rate limit)
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from ..report_facts import is_edge_product
from ..signals import Entities, Severity, Signal, SignalType, now_iso
from .base import BaseCollector, register

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Vendors and products with heavy Indian enterprise deployment. Used to
# decide which KEV entries are worth flagging for which sector, rather than
# dumping the whole catalogue into the bulletin every week.
SECTOR_TECH_FOOTPRINT: Dict[str, List[str]] = {
    "BFSI": ["oracle", "temenos", "finacle", "flexcube", "swift", "java",
             "weblogic", "jboss", "ibm", "websphere", "citrix", "f5",
             "fortinet", "palo alto", "vmware", "windows server",
             "active directory", "exchange"],
    "IT_ITES": ["atlassian", "jira", "confluence", "jenkins", "gitlab",
                "github", "docker", "kubernetes", "vmware", "citrix",
                "solarwinds", "manageengine", "zoho", "apache", "tomcat",
                "log4j", "spring", "nodejs", "python"],
    "GOVERNMENT": ["drupal", "wordpress", "joomla", "apache", "php",
                   "windows server", "exchange", "sharepoint", "nic",
                   "openssl", "linux kernel"],
    "HEALTHCARE": ["dicom", "pacs", "hl7", "windows", "citrix", "vmware",
                   "orthanc", "openemr"],
    "PHARMA": ["sap", "oracle", "labware", "veeva", "vmware", "windows"],
    "MANUFACTURING": ["sap", "siemens", "rockwell", "schneider", "mitsubishi",
                      "modbus", "scada", "wonderware", "ignition", "plc"],
    "ENERGY": ["siemens", "schneider", "abb", "ge digital", "scada",
               "iec 61850", "modbus", "dnp3", "hitachi energy"],
    "TELECOM": ["cisco", "juniper", "huawei", "nokia", "ericsson", "mikrotik",
                "bind", "asterisk", "openssl"],
    "TRANSPORT": ["sap", "oracle", "vmware", "windows server", "scada"],
    "EDUCATION": ["moodle", "wordpress", "drupal", "php", "mysql",
                  "windows server"],
    "RETAIL_ECOM": ["magento", "woocommerce", "shopify", "sap", "oracle",
                    "payment", "adobe commerce"],
}

# Edge devices are mapped to sectors with verified enterprise deployment footprint
EDGE_VENDOR_SECTORS: Dict[str, List[str]] = {
    "fortinet": ["BFSI", "IT_ITES"],
    "fortios": ["BFSI", "IT_ITES"],
    "fortimail": ["BFSI", "IT_ITES"],
    "citrix": ["BFSI", "IT_ITES", "HEALTHCARE"],
    "netscaler": ["BFSI", "IT_ITES"],
    "sonicwall": ["IT_ITES", "MANUFACTURING"],
    "checkpoint": ["BFSI", "IT_ITES"],
    "check point": ["BFSI", "IT_ITES"],
    "cisco": ["TELECOM", "IT_ITES", "BFSI"],
    "sharepoint": ["GOVERNMENT", "BFSI", "IT_ITES"],
    "struts": ["IT_ITES", "BFSI"],
    "ivanti": ["IT_ITES", "GOVERNMENT"],
    "palo alto": ["BFSI", "IT_ITES"],
    "exchange": ["GOVERNMENT", "BFSI", "IT_ITES"],
    "vcenter": ["IT_ITES", "BFSI"],
    "esxi": ["IT_ITES", "BFSI"],
}


def _sectors_for(text: str) -> List[str]:
    blob = text.lower()
    hits = set()
    for sector, terms in SECTOR_TECH_FOOTPRINT.items():
        if any(term in blob for term in terms):
            hits.add(sector)
    for term, sec_list in EDGE_VENDOR_SECTORS.items():
        if term in blob:
            hits.update(sec_list)
    return sorted(hits)


@register
class CISAKEVCollector(BaseCollector):
    name = "cisa_kev"
    description = "CISA Known Exploited Vulnerabilities, enriched with EPSS"
    signal_types = ["vulnerability"]
    required_env: List[str] = []
    free = True

    async def collect(self) -> List[Signal]:
        days = int(self.options.get("days", 60))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        signals: List[Signal] = []

        async with self.client() as client:
            data = await self.get_json(client, KEV_URL)
            if not data:
                return signals

            vulns = data.get("vulnerabilities", [])
            recent = []
            for v in vulns:
                added = v.get("dateAdded", "")
                try:
                    added_dt = datetime.strptime(added, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc)
                except ValueError:
                    continue
                if added_dt >= cutoff:
                    recent.append((v, added_dt))

            epss = await self._fetch_epss(
                client, [v.get("cveID") for v, _ in recent])

            for v, added_dt in recent:
                cve = v.get("cveID", "")
                vendor = v.get("vendorProject", "")
                product = v.get("product", "")
                name = v.get("vulnerabilityName", "")
                desc = v.get("shortDescription", "")
                ransomware_use = v.get("knownRansomwareCampaignUse", "Unknown")

                blob = f"{vendor} {product} {name} {desc}"
                sectors = _sectors_for(blob)

                score = epss.get(cve, {}).get("epss")
                percentile = epss.get(cve, {}).get("percentile")

                if ransomware_use.lower() == "known":
                    severity = Severity.CRITICAL
                elif score and float(score) > 0.5:
                    severity = Severity.CRITICAL
                elif score and float(score) > 0.1:
                    severity = Severity.HIGH
                else:
                    severity = Severity.HIGH

                epss_note = ""
                if score:
                    epss_note = (f" EPSS {float(score):.1%}"
                                 f" (percentile {float(percentile or 0):.0%}).")

                tags = ["kev", "actively-exploited"]
                if ransomware_use.lower() == "known":
                    tags.append("ransomware-campaign-use")
                if is_edge_product(vendor, product):
                    tags.append("edge-device")

                signals.append(Signal(
                    signal_type=SignalType.VULNERABILITY,
                    title=f"{cve} — {vendor} {product}: {name}"[:300],
                    description=(
                        f"{desc} Confirmed exploited in the wild; added to the "
                        f"CISA KEV catalogue on {v.get('dateAdded')}. "
                        f"Ransomware campaign use: {ransomware_use}.{epss_note} "
                        f"Required action: {v.get('requiredAction', 'n/a')}"
                    )[:1500],
                    source="CISA KEV",
                    source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    observed_at=added_dt.isoformat(),
                    severity=severity,
                    confidence=0.95,
                    # A KEV entry is globally relevant. It matters to Indian
                    # orgs to the extent they run the affected product, which
                    # the sector mapping expresses.
                    india_relevance=0.75 if sectors else 0.4,
                    india_reason="exploited vulnerability in technology "
                                 "commonly deployed by Indian organisations"
                                 if sectors else "globally exploited vulnerability",
                    sectors=sectors,
                    entities=Entities(cves=[cve] if cve else []),
                    annexure_categories=["ii", "iii"],
                    tags=tags,
                    raw=v,
                ))

        return signals

    async def _fetch_epss(self, client, cves: List[str]) -> Dict[str, Dict]:
        """EPSS accepts comma-separated CVEs; batch to keep URLs sane."""
        out: Dict[str, Dict] = {}
        cves = [c for c in cves if c]
        for i in range(0, len(cves), 80):
            batch = ",".join(cves[i:i + 80])
            data = await self.get_json(client, EPSS_URL, params={"cve": batch})
            if not data:
                continue
            for item in data.get("data", []):
                out[item.get("cve")] = {
                    "epss": item.get("epss"),
                    "percentile": item.get("percentile"),
                }
        return out


@register
class NVDRecentCollector(BaseCollector):
    name = "nvd_critical"
    description = "NVD critical-severity CVEs in Indian enterprise technology"
    signal_types = ["vulnerability"]
    required_env: List[str] = []   # NVD_API_KEY optional, raises rate limit
    free = True

    async def collect(self) -> List[Signal]:
        days = int(self.options.get("days", 14))
        start = (datetime.now(timezone.utc) - timedelta(days=days))
        signals: List[Signal] = []

        headers = {}
        api_key = self.env("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key

        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT23:59:59.999"),
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": 200,
        }

        async with self.client() as client:
            data = await self.get_json(client, NVD_URL, headers=headers,
                                       params=params)
            if not data:
                return signals

            for item in data.get("vulnerabilities", []):
                cve_obj = item.get("cve", {})
                cve = cve_obj.get("id", "")
                descs = cve_obj.get("descriptions", [])
                desc = next((d.get("value", "") for d in descs
                             if d.get("lang") == "en"), "")

                configs = cve_obj.get("configurations", [])
                products = []
                for cfg in configs:
                    for node in cfg.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            criteria = match.get("criteria", "")
                            parts = criteria.split(":")
                            if len(parts) > 5:
                                products.append(f"{parts[3]} {parts[4]}")
                product_blob = " ".join(sorted(set(products))[:20])

                sectors = _sectors_for(f"{desc} {product_blob}")
                if not sectors:
                    continue   # not obviously relevant to Indian deployments

                metrics = cve_obj.get("metrics", {})
                score = None
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if metrics.get(key) and isinstance(metrics[key], list) and len(metrics[key]) > 0:
                        score = metrics[key][0].get("cvssData", {}).get("baseScore")
                        break

                signals.append(Signal(
                    signal_type=SignalType.VULNERABILITY,
                    title=f"{cve} — critical vulnerability"
                          f"{' (CVSS ' + str(score) + ')' if score else ''}",
                    description=desc[:1200],
                    source="NVD",
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    observed_at=cve_obj.get("published", now_iso()),
                    severity=Severity.HIGH,
                    confidence=0.7,
                    india_relevance=0.45,
                    india_reason="critical CVE in technology used by Indian "
                                 "enterprises; exploitation not yet confirmed",
                    sectors=sectors,
                    entities=Entities(cves=[cve] if cve else []),
                    annexure_categories=["iii"],
                    tags=["nvd", "critical", "not-yet-known-exploited"],
                    raw={"products": sorted(set(products))[:20]},
                ))

        return signals
