"""
Automated Quality Assurance (QA) Gate for India Threat Landscape Bulletin.

Strictly verifies:
- Mathematical and numeric reconciliation across all data structures.
- Strict 100% reconciliation of Indian corporate victims and extortion postings.
- Accurate corridor regional sums.
- Zero raw enum leaks into executive text layers.
- Strict 11-page layout without orphan or overflow pages (1-page for Pulse).
- Machine-readable companion IOC CSV integrity, role actions, and SHA-256 hash match.
- Banned phrases, TLP designation, window label match, and dual-run scoring determinism.
- Deletion of PDF artifacts if any check fails.
"""

import csv
import hashlib
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import pymupdf

from .bulletin_multi import extract_victim_attributions
from .correlation import correlate
from .iocs import get_ioc_summary, compute_file_sha256, extract_iocs, extract_host
from .scoring_multi import rank_sectors_multi, assign_risk_band
from .sectors import sector_label
from .signals import Signal, SignalType


def run_qa_audit(signals: List[Signal], scored_sectors: List[Dict],
                 correlation: Dict, pdf_path: str, ioc_csv_path: str,
                 window_days: int = 60, public_mode: bool = False,
                 pulse_path: Optional[str] = None) -> bool:
    """
    Executes comprehensive QA audit gate.
    Returns True if all checks pass; deletes generated PDF and raises AssertionError on any failure.
    """
    mode_str = " (Public Edition)" if public_mode else " (Standard Edition)"
    print("\n" + "=" * 60)
    print(f"RUNNING AUTOMATED QA AUDIT GATE (Window: {window_days} Days{mode_str})")
    print("=" * 60)

    try:
        _perform_audit(
            signals=signals, scored_sectors=scored_sectors, correlation=correlation,
            pdf_path=pdf_path, ioc_csv_path=ioc_csv_path, window_days=window_days,
            public_mode=public_mode, pulse_path=pulse_path
        )
        print("  [PASS] All QA audit gate checks succeeded.")
        print("=" * 60)
        print("ALL QA AUDIT GATES PASSED (100% RECONCILED & COMPLIANT)")
        print("=" * 60 + "\n")
        return True
    except Exception as exc:
        print(f"\n[!] QA GATE FAILED: {exc}")
        print("    ENFORCING FAIL-SAFE: Deleting generated PDF outputs...")
        if os.path.exists(pdf_path):
            try:
                os.remove(pdf_path)
                print(f"    Deleted invalid PDF: {pdf_path}")
            except Exception as e:
                print(f"    Failed to remove PDF: {e}")
        if pulse_path and os.path.exists(pulse_path):
            try:
                os.remove(pulse_path)
                print(f"    Deleted invalid Pulse: {pulse_path}")
            except Exception as e:
                print(f"    Failed to remove Pulse: {e}")
        raise


def _perform_audit(signals: List[Signal], scored_sectors: List[Dict],
                   correlation: Dict, pdf_path: str, ioc_csv_path: str,
                   window_days: int = 60, public_mode: bool = False,
                   pulse_path: Optional[str] = None) -> None:
    # 1. Signal Telemetry Reconciliations
    if window_days == 60:
        assert len(signals) == 263, f"QA FAIL: Expected 263 signals, got {len(signals)}"
        sources = {s.source for s in signals}
        assert len(sources) == 9, f"QA FAIL: Expected 9 sources, got {len(sources)}"

        cisa_kev_count = sum(1 for s in signals if s.source == "CISA KEV")
        nvd_count = sum(1 for s in signals if s.source == "NVD")
        assert cisa_kev_count == 57, f"QA FAIL: Expected 57 CISA KEV, got {cisa_kev_count}"
        assert nvd_count == 68, f"QA FAIL: Expected 68 NVD, got {nvd_count}"

        all_cves = set()
        for s in signals:
            if s.entities and s.entities.cves:
                all_cves.update(s.entities.cves)
        assert len(all_cves) == 122, f"QA FAIL: Expected 122 distinct CVEs, got {len(all_cves)}"

        infra_signals = [s for s in signals if s.signal_type in (SignalType.MALWARE_INFRA, SignalType.PHISHING)]
        assert len(infra_signals) == 58, f"QA FAIL: Expected 58 infra signals in DB, got {len(infra_signals)}"

        print("  [PASS] Signal Telemetry & CVE Totals (263 signals, 9 sources, 122 CVEs, 58 infra)")
    else:
        assert len(signals) > 0, f"QA FAIL: Expected signals for {window_days}-day window, got {len(signals)}"
        sources = {s.source for s in signals}
        assert len(sources) > 0, f"QA FAIL: Expected sources for {window_days}-day window, got {len(sources)}"
        all_cves = set()
        for s in signals:
            if s.entities and s.entities.cves:
                all_cves.update(s.entities.cves)
        infra_signals = [s for s in signals if s.signal_type in (SignalType.MALWARE_INFRA, SignalType.PHISHING)]
        print(f"  [PASS] Signal Telemetry & CVE Totals ({len(signals)} signals, {len(sources)} sources, {len(all_cves)} CVEs, {len(infra_signals)} infra)")

    # 2. Victim & Corridor Reconciliations
    victims, total_posts, unique_orgs = extract_victim_attributions(signals)
    if window_days == 60:
        assert total_posts == 49, f"QA FAIL: Expected 49 postings, got {total_posts}"
        assert unique_orgs == 44, f"QA FAIL: Expected 44 unique victim entities, got {unique_orgs}"

        corridors_spec = [
            ("Western Industrial Hub", ["Gujarat", "Maharashtra"], 14, 14),
            ("Northern Administrative & Commercial Hub", ["Delhi NCR"], 9, 9),
            ("Southern Technology & Healthcare Corridor", ["Karnataka", "Tamil Nadu", "Telangana & AP"], 12, 13),
            ("Central & Eastern Industrial Corridor", ["Chhattisgarh"], 1, 4),
            ("Northern & Western Fringe", ["Haryana", "Punjab & Chandigarh", "Uttarakhand", "Rajasthan"], 4, 5),
            ("Location Unresolved / Corporate Cloud", ["Location Unresolved"], 4, 4),
        ]

        total_corridor_orgs = 0
        total_corridor_posts = 0
        for name, states, exp_orgs, exp_posts in corridors_spec:
            c_victims = [v for v in victims if v["state"] in states]
            o_cnt = len(c_victims)
            p_cnt = sum(v["postings"] for v in c_victims)
            total_corridor_orgs += o_cnt
            total_corridor_posts += p_cnt
            assert o_cnt == exp_orgs, f"QA FAIL: {name} expected {exp_orgs} orgs, got {o_cnt}"
            assert p_cnt == exp_posts, f"QA FAIL: {name} expected {exp_posts} posts, got {p_cnt}"

        assert total_corridor_orgs == 44, f"QA FAIL: Corridor orgs sum {total_corridor_orgs} != 44"
        assert total_corridor_posts == 49, f"QA FAIL: Corridor posts sum {total_corridor_posts} != 49"
        print("  [PASS] Indian Victim & Regional Corridor Reconciliation (44 orgs, 49 postings, 100% accounted)")
    else:
        corridors_spec = [
            ("Western Industrial Hub", ["Gujarat", "Maharashtra"]),
            ("Northern Administrative & Commercial Hub", ["Delhi NCR"]),
            ("Southern Technology & Healthcare Corridor", ["Karnataka", "Tamil Nadu", "Telangana & AP"]),
            ("Central & Eastern Industrial Corridor", ["Chhattisgarh"]),
            ("Northern & Western Fringe", ["Haryana", "Punjab & Chandigarh", "Uttarakhand", "Rajasthan"]),
            ("Location Unresolved / Corporate Cloud", ["Location Unresolved"]),
        ]
        total_corridor_orgs = 0
        total_corridor_posts = 0
        for name, states in corridors_spec:
            c_victims = [v for v in victims if v["state"] in states]
            total_corridor_orgs += len(c_victims)
            total_corridor_posts += sum(v["postings"] for v in c_victims)
        assert total_corridor_orgs == unique_orgs, f"QA FAIL: Corridor orgs sum {total_corridor_orgs} != {unique_orgs}"
        assert total_corridor_posts == total_posts, f"QA FAIL: Corridor posts sum {total_corridor_posts} != {total_posts}"
        print(f"  [PASS] Indian Victim & Regional Corridor Reconciliation ({unique_orgs} orgs, {total_posts} postings, 100% accounted)")

    # 3. Sector Scoring & Formula Integrity
    if window_days == 60:
        assert len(scored_sectors) == 14, f"QA FAIL: Expected 14 scored sectors, got {len(scored_sectors)}"
    else:
        assert len(scored_sectors) > 0, f"QA FAIL: Expected scored sectors, got {len(scored_sectors)}"
    for s in scored_sectors:
        c = s["components"]
        expected = (0.30 * c["impact"] + 0.20 * c["exploit"] + 0.15 * c["infra"] +
                    0.15 * c["criticality"] + 0.10 * c["pressure"] + 0.10 * c["exposure"])
        assert abs(s["risk_score"] - expected) <= 0.2, (
            f"QA FAIL: Formula divergence for {s['sector']}: score={s['risk_score']} vs calc={expected:.1f}"
        )
        assert s["risk_band"] == assign_risk_band(s["risk_score"]), (
            f"QA FAIL: Band label {s['risk_band']} does not match score {s['risk_score']} in {s['sector']}"
        )

    # 4. IOC Attribution Reconciliation
    extracted_iocs = extract_iocs(signals, public_mode=public_mode)
    host_to_sectors = {}
    for s in signals:
        if s.signal_type.value in ('malware_infra', 'phishing'):
            host = s.title.split(':')[-1].strip()
            if isinstance(s.raw, dict):
                host = s.raw.get('ioc') or s.raw.get('url') or host
            h = extract_host(host)
            if s.sectors:
                host_to_sectors[h] = s.sectors
    attributed_iocs = [i for i in extracted_iocs if i['host'] in host_to_sectors]
    unsectored_iocs = [i for i in extracted_iocs if i['host'] not in host_to_sectors]

    if window_days == 60:
        infra_col_sum = sum(s["infra_count"] for s in scored_sectors)
        assert infra_col_sum == 35, f"QA FAIL: Expected Infra column sum 35, got {infra_col_sum}"
        assert len(attributed_iocs) == 31, f"QA FAIL: Expected 31 attributed IOCs, got {len(attributed_iocs)}"
        assert len(unsectored_iocs) == 19, f"QA FAIL: Expected 19 unsectored IOCs, got {len(unsectored_iocs)}"
        assert len(attributed_iocs) + len(unsectored_iocs) == 50, f"QA FAIL: 31 + 19 != 50"

        high_plus = [s for s in scored_sectors if s["risk_band"] in ("Critical", "High")]
        assert len(high_plus) == 3, f"QA FAIL: Expected 3 High+ sectors, got {len(high_plus)}"
        assert {s["sector"] for s in high_plus} == {"IT_ITES", "MANUFACTURING", "BFSI"}
        print(f"  [PASS] Sector Scoring & Mathematical Weight Reconciliation ({len(attributed_iocs)} + {len(unsectored_iocs)} = {len(extracted_iocs)}, 3 High+ sectors)")
    else:
        assert len(attributed_iocs) + len(unsectored_iocs) == len(extracted_iocs), "QA FAIL: IOC attribution mismatch"
        print(f"  [PASS] Sector Scoring & Mathematical Weight Reconciliation ({len(attributed_iocs)} attributed + {len(unsectored_iocs)} unsectored = {len(extracted_iocs)} IOCs)")

    # 5. Multi-Source Cross Correlation
    if window_days == 60:
        assert correlation["corroborated_count"] == 10, (
            f"QA FAIL: Expected 10 corroborated signals, got {correlation['corroborated_count']}"
        )
        assert correlation["shared_artefacts_count"] == 6, (
            f"QA FAIL: Expected 6 shared artefacts, got {correlation['shared_artefacts_count']}"
        )
        print("  [PASS] Multi-Source Cross-Correlation (10 signals across 6 shared artefacts)")
    else:
        assert "corroborated_count" in correlation
        assert "shared_artefacts_count" in correlation
        print(f"  [PASS] Multi-Source Cross-Correlation ({correlation['corroborated_count']} signals across {correlation['shared_artefacts_count']} artefacts)")

    # 6. Companion IOC Artifact Audit
    assert os.path.exists(ioc_csv_path), f"QA FAIL: Companion IOC CSV missing at {ioc_csv_path}"
    with open(ioc_csv_path, "r", encoding="utf-8") as f:
        csv_rows = list(csv.DictReader(f))

    if csv_rows:
        for col in ("tld_country", "asn_country", "origin_hidden"):
            assert col in csv_rows[0], f"QA FAIL: Missing column '{col}' in CSV header"

        if public_mode:
            for col in ("dispute_contact", "license_attribution"):
                assert col in csv_rows[0], f"QA FAIL: Missing column '{col}' in CSV header for public mode"

        expected_dispute = os.getenv("DISPUTE_CONTACT_EMAIL", "").strip()
        for r in csv_rows:
            assert r["asn"].strip() != "", f"QA FAIL: Empty ASN field for host {r['host']}"
            assert "/" not in r["asn"], f"QA FAIL: Merged label in ASN for host {r['host']}: {r['asn']}"
            if public_mode:
                assert r["ioc_role"] in ("reported_compromised_by_feed", "unverified_delivery_host", "phishing_lookalike"), (
                    f"QA FAIL: Invalid ioc_role '{r['ioc_role']}' for host {r['host']} in public mode"
                )
            else:
                assert r["ioc_role"] in ("compromised_legitimate", "unverified_delivery_host", "phishing_lookalike"), (
                    f"QA FAIL: Invalid ioc_role '{r['ioc_role']}' for host {r['host']} in internal mode"
                )
            assert r["technique"].strip() != "", f"QA FAIL: Empty technique field for host {r['host']}"

            tlp_clean = r.get("tlp", "").strip()
            for fl in ("tlp:amber", "restricted distribution", "need-to-know"):
                assert fl not in tlp_clean.lower(), (
                    f"QA FAIL: Forbidden label '{fl}' found in CSV tlp column for host {r['host']}: '{tlp_clean}'"
                )
            row_str = " ".join(r.values()).lower()
            for b in ("confirmed victim", "confirmed victims", "confirmed extortion"):
                assert b not in row_str, f"QA FAIL: Banned phrase '{b}' found in CSV row for host {r['host']}"
            if public_mode:
                assert tlp_clean == "TLP:CLEAR", f"QA FAIL: Expected TLP:CLEAR in public CSV, got {tlp_clean}"
                assert r["dispute_contact"] == expected_dispute, f"QA FAIL: Dispute contact mismatch {r['dispute_contact']} vs expected {expected_dispute}"
                assert r["license_attribution"].strip() != "", f"QA FAIL: Missing license attribution for host {r['host']}"
            else:
                assert tlp_clean in ("", "INTERNAL"), f"QA FAIL: Expected blank or INTERNAL in internal CSV, got {tlp_clean}"

            if r["source_feed"] == "abuse.ch ThreatFox":
                assert r["reference_url"].startswith("https://threatfox.abuse.ch/ioc/"), (
                    f"QA FAIL: ThreatFox reference_url must be abuse.ch URL, got {r['reference_url']}"
                )

            if r["ioc_role"] in ("compromised_legitimate", "reported_compromised_by_feed", "unverified_delivery_host"):
                assert "block" not in r["recommended_action"].lower(), (
                    f"QA FAIL: Forbidden 'block' action for non-phishing host {r['host']}: {r['recommended_action']}"
                )
            if r["ioc_role"] == "unverified_delivery_host" and not any(r["host"].endswith("." + suf) for suf in ("gov.in", "nic.in")):
                assert "monitor/verify" in r["recommended_action"].lower() or "alert" in r["recommended_action"].lower(), (
                    f"QA FAIL: Unverified host {r['host']} missing monitor/verify action: {r['recommended_action']}"
                )
            if r["ioc_role"] == "phishing_lookalike" and not any(r["host"].endswith("." + suf) for suf in ("gov.in", "nic.in")):
                assert "block" in r["recommended_action"].lower(), (
                    f"QA FAIL: Missing 'block' action for phishing host {r['host']}: {r['recommended_action']}"
                )
            if any(r["host"].endswith("." + suf) for suf in ("gov.in", "nic.in")):
                assert r["recommended_action"] == "alert, notify CERT-In/NIC", (
                    f"QA FAIL: Gov host {r['host']} missing CERT-In/NIC alert action"
                )

    csv_hash = compute_file_sha256(ioc_csv_path)
    assert len(csv_hash) == 64, f"QA FAIL: Invalid SHA-256 hash length: {csv_hash}"

    if window_days == 60:
        ioc_sum = get_ioc_summary(signals, public_mode=public_mode)
        if public_mode:
            assert len(csv_rows) == 50, f"QA FAIL: Expected 50 CSV rows in public mode, got {len(csv_rows)}"
            assert ioc_sum["total_indicators"] == 50, f"QA FAIL: Expected 50 IOCs, got {ioc_sum['total_indicators']}"
            assert ioc_sum["unique_hosts"] == 43, f"QA FAIL: Expected 43 unique hosts, got {ioc_sum['unique_hosts']}"
            assert ioc_sum["compromised_hosts"] == 18, f"QA FAIL: Expected 18 compromised hosts, got {ioc_sum['compromised_hosts']}"
            assert ioc_sum["unverified_hosts"] == 25, f"QA FAIL: Expected 25 unverified hosts, got {ioc_sum['unverified_hosts']}"
            assert ioc_sum["phishing_hosts"] == 0, f"QA FAIL: Expected 0 phishing hosts in public mode, got {ioc_sum['phishing_hosts']}"
            print(f"  [PASS] Companion IOC CSV Integrity (50 records, 43 hosts, SHA-256: {csv_hash[:16]}...)")
        else:
            assert len(csv_rows) == 50, f"QA FAIL: Expected 50 CSV rows in internal mode, got {len(csv_rows)}"
            assert ioc_sum["total_indicators"] == 50, f"QA FAIL: Expected 50 IOCs, got {ioc_sum['total_indicators']}"
            assert ioc_sum["unique_hosts"] == 43, f"QA FAIL: Expected 43 unique hosts, got {ioc_sum['unique_hosts']}"
            assert ioc_sum["compromised_hosts"] == 18, f"QA FAIL: Expected 18 compromised hosts, got {ioc_sum['compromised_hosts']}"
            assert ioc_sum["unverified_hosts"] == 25, f"QA FAIL: Expected 25 unverified hosts, got {ioc_sum['unverified_hosts']}"
            assert ioc_sum["phishing_hosts"] == 0, f"QA FAIL: Expected 0 phishing hosts, got {ioc_sum['phishing_hosts']}"
            print(f"  [PASS] Companion IOC CSV Integrity (50 records, 43 hosts, SHA-256: {csv_hash[:16]}...)")
    else:
        print(f"  [PASS] Companion IOC CSV Integrity ({len(csv_rows)} records, SHA-256: {csv_hash[:16]}...)")

    # 7. Scoring Determinism Audit (Identical output across consecutive runs)
    scores_run1 = rank_sectors_multi(signals)
    scores_run2 = rank_sectors_multi(signals)
    assert scores_run1 == scores_run2, "QA FAIL: Scoring is non-deterministic between consecutive runs!"
    print("  [PASS] Scoring Engine Determinism (Run 1 == Run 2 under window end-date anchor)")

    # 8. PDF Layout & Content Integrity Audit
    assert os.path.exists(pdf_path), f"QA FAIL: PDF file not found at {pdf_path}"
    doc = pymupdf.open(pdf_path)
    page_count = len(doc)
    page_texts = [page.get_text() for page in doc]
    doc.close()
    assert page_count == 11, f"QA FAIL: Strict page count violation: expected 11 pages, got {page_count}"

    full_pdf_text = ""
    for idx, t in enumerate(page_texts):
        full_pdf_text += f"\n--- PAGE {idx+1} ---\n" + t

    # Recompute companion CSV SHA-256 and compare to hash printed on Page 8 and Page 11
    recomputed_csv_hash = compute_file_sha256(ioc_csv_path)
    assert len(recomputed_csv_hash) == 64, f"QA FAIL: Invalid recomputed CSV SHA-256 hash length: {recomputed_csv_hash}"
    assert csv_hash == recomputed_csv_hash, f"QA FAIL: CSV hash mismatch: expected {csv_hash}, got {recomputed_csv_hash}"
    assert recomputed_csv_hash in page_texts[7], (
        f"QA FAIL: Recomputed CSV SHA-256 hash {recomputed_csv_hash} not found on Page 8 of PDF!"
    )
    assert recomputed_csv_hash in page_texts[10], (
        f"QA FAIL: Recomputed CSV SHA-256 hash {recomputed_csv_hash} not found on Page 11 of PDF!"
    )
    print(f"  [PASS] CSV SHA-256 Hash Verification: Recomputed hash matches Page 8 and Page 11 ({recomputed_csv_hash[:16]}...)")

    # Enforce window label consistency
    end_date = datetime(2026, 10, 11).date()
    start_date = end_date - timedelta(days=window_days)
    expected_window_str = f"{start_date.strftime('%d %b %Y')} to {end_date.strftime('%d %b %Y')} ({window_days} days)"
    assert expected_window_str in full_pdf_text, (
        f"QA FAIL: Window label mismatch! Expected '{expected_window_str}' in PDF text layer"
    )

    # Enforce strictly no raw enum leaks
    RAW_ENUMS = [
        "IT_ITES", "RETAIL_ECOM", "NGO_LEGAL", "REAL_ESTATE", "DATA_LEAK", "MALWARE_INFRA"
    ]
    for enum_val in RAW_ENUMS:
        assert enum_val not in full_pdf_text, f"QA FAIL: Raw enum string leak detected in PDF: {enum_val}"

    # Banned strings checks
    BANNED_STRINGS = [
        "publicly confirmed",
        "confirmed compromised",
        "likely compromised",
        "dominate",
        "todo",
        "aligned to cert-in",
        "compliance review",
        "most hosts",
        "tlp:amber",
        "restricted distribution",
        "need-to-know",
        "confirmed victim",
        "confirmed victims",
        "confirmed extortion",
    ]
    if total_posts < 15:
        BANNED_STRINGS.extend(["primary geographic targets", "primary targets"])

    for b in BANNED_STRINGS:
        assert b not in full_pdf_text.lower(), f"QA FAIL: Banned string '{b}' detected in PDF text layer"

    # Regex checks for banned standalone tokens
    assert not re.search(r'\b(?:nan|NaN)\b', full_pdf_text), "QA FAIL: Banned token 'NaN'/'nan' detected in PDF text"
    assert not re.search(r'\bNone\b', full_pdf_text), "QA FAIL: Banned token 'None' detected in PDF text"
    assert not re.search(r'\bexample[s]?\b', full_pdf_text, re.IGNORECASE), "QA FAIL: Banned word 'example' detected in PDF text"
    assert not any(line.strip().endswith('[') for line in full_pdf_text.splitlines()), "QA FAIL: Truncated label ending in '[' detected in PDF"
    assert not any(line.strip().endswith('(') for line in full_pdf_text.splitlines()), "QA FAIL: Truncated label ending in '(' detected in PDF"
    assert not any(re.search(r'\b\w+[\(\[]\s*$', line.strip()) for line in full_pdf_text.splitlines()), "QA FAIL: Cut-off label detected in PDF text layer"
    assert "borderline" not in full_pdf_text.lower(), "QA FAIL: Banned term 'borderline' detected in PDF text"

    # Enforce author identity and obsolete terms
    assert ("Siva prasad Boddu" in full_pdf_text or "Analyst" in full_pdf_text), "QA FAIL: Author not found in PDF"
    assert "Client Pvt Ltd" not in full_pdf_text, "QA FAIL: Forbidden phrase 'Client Pvt Ltd' found in PDF"
    assert "hosted in Indian ASNs" not in full_pdf_text, "QA FAIL: Forbidden phrase 'hosted in Indian ASNs' found in PDF"
    assert "Mandatory remediation deadline" not in full_pdf_text, (
        "QA FAIL: Forbidden phrase 'Mandatory remediation deadline' found in PDF"
    )
    assert "highest-severity verified vulnerability exposure" not in full_pdf_text, (
        "QA FAIL: Obsolete phrase 'highest-severity verified vulnerability exposure' found in PDF"
    )
    assert "Exploited Vulnerability Vectors" not in full_pdf_text, (
        "QA FAIL: Obsolete chart title 'Exploited Vulnerability Vectors' found in PDF"
    )
    assert "Compromised Sites (Infra)" not in full_pdf_text, (
        "QA FAIL: Obsolete phrase 'Compromised Sites (Infra)' found in PDF"
    )
    assert "1 orgs" not in full_pdf_text, "QA FAIL: Pluralisation error '1 orgs' detected in PDF"
    assert "1 posts" not in full_pdf_text, "QA FAIL: Pluralisation error '1 posts' detected in PDF"
    assert "01-Sep-2026" not in full_pdf_text, "QA FAIL: Obsolete date '01-Sep-2026' detected in PDF text layer"

    # TLP label consistency
    for fl in ("tlp:amber", "restricted distribution", "need-to-know"):
        assert fl not in full_pdf_text.lower(), f"QA FAIL: Forbidden phrase '{fl}' leaked into PDF text layer"

    for forbidden_b in ("Limited Disclosure", "must not be published publicly", "Authorised for internal"):
        assert forbidden_b not in full_pdf_text, f"QA FAIL: Forbidden phrase '{forbidden_b}' found in PDF text layer"

    assert "Independent analyst work · Not affiliated with CERT-In" in full_pdf_text, "QA FAIL: Missing analyst disclaimer in PDF text layer"

    # Strict victim anonymization in all editions: no individual victim names permitted
    VICTIM_SAMPLES = [
        "Simplex Engineering", "Raajratna Metal", "Sea Shell Hospital",
        "Karkinos Healthcare", "Jindal Life Sciences", "Shalina Healthcare",
        "Labindia Instruments", "Quality Control Products", "Atomberg Technologies",
        "Manipal Academy of Higher Education", "IIT Roorkee", "vi***in", "Licindia",
        "Majestic Holidays", "Praveg Caves", "Indic Inspirations", "Sancity Developers"
    ]
    for v_name in VICTIM_SAMPLES:
        assert v_name.lower() not in full_pdf_text.lower(), f"QA FAIL: Individual victim name '{v_name}' leaked in PDF text layer"

    if public_mode:
        assert "TLP:CLEAR" in full_pdf_text, "QA FAIL: Expected 'TLP:CLEAR' in PDF text layer for public edition"
    else:
        assert "TLP:CLEAR" not in full_pdf_text, "QA FAIL: 'TLP:CLEAR' found in standard edition PDF"
        assert "Informational mapping to CERT-In Directions (not legal advice)" in full_pdf_text, "QA FAIL: Expected informational CERT-In section in standard edition"
        assert "Information Handling & Distribution Restrictions" not in full_pdf_text, "QA FAIL: Forbidden section 'Information Handling & Distribution Restrictions' found in standard edition"

    # Check key section headers on exact pages
    expected_page_headers = [
        (1, "India Threat Landscape Bulletin"),
        (2, "Executive Summary: Threat Judgements & Strategic Outlook"),
        (3, "India Threat Telemetry & Regional Hotspots"),
        (4, "Adversary Landscape & Targeted Technology Infrastructure"),
        (5, "Sector Risk Ranking & Assessment Matrix"),
        (6, "Granular Assessment by Sector (Top Risk Profiles)"),
        (7, "Cross-Source Correlation & Infrastructure Co-Occurrence"),
        (8, "Highest-Priority Signals"),
        (9, "Aggregated Indian Extortion Telemetry by Sector & Corridor"),
        (10, "Community Cyber Defence & Strategic Hardening Guidance" if public_mode else "Informational mapping to CERT-In Directions (not legal advice)"),
        (11, "Methodology Limitations & Analytical Framework"),
    ]
    for p_num, header_phrase in expected_page_headers:
        p_text = page_texts[p_num - 1]
        assert header_phrase in p_text, f"QA FAIL: Expected '{header_phrase}' on Page {p_num}"

    norm_full = " ".join(full_pdf_text.split())

    # Shared required architectural elements
    SHARED_REQUIRED = [
        "Observed Vulnerability Vectors (KEV)",
        "Priority Extortion Telemetry",
        "Priority Exploited Vulnerabilities (CISA KEV)",
        "Scoring Engine v2.5, data snapshot",
        "Delivery/Phishing Hosts (Infra)",
        "Purpose, Target Audience",
        "Technical Metadata & Pipeline Provenance:",
        "Intelligence Feed Snapshot Ingestion Dates (9 Feeds):",
    ]
    for phrase in SHARED_REQUIRED:
        norm_phrase = " ".join(phrase.split())
        assert norm_phrase in norm_full, f"QA FAIL: Required phrase missing from PDF text: '{phrase}'"

    if window_days == 60:
        REQUIRED_PHRASES_60 = [
            "12 Aug 2026 to 11 Oct 2026 (60 days)",
            "12-18 Aug",
            "07-10 Oct, 4 days",
            "07-10 Oct (partial)",
            "Data current to 10-Oct (CISA KEV and ransomlook.io: 08-Oct)",
            "2026-10-03 to 2026-10-10",
            "Active KEV exploitation",
            "Baseline (older CVE, still in KEV)",
            "Location Unresolved",
            "Ranking criteria: Sorted by aggregate disclosure volume",
            "Priority Extortion Telemetry (Disclosures by Sector & Threat Actor)",
            "Recommended target date: 17 Oct 2026",
            "Rankings are sensitive to the Infra component",
            "most frequently observed edge-device CVEs in KEV",
            "Krybit, TheGentlemen, Vexy, Clop",
            "referring to the domain suffix (.in ccTLDs), not hosting location",
            "CERT-In (09-Oct), CISA KEV (08-Oct), NVD (10-Oct)",
            "31 + 19 = 50",
            "18 compromised, 25 unverified, 0 phishing lookalikes (43 hosts, 50 records)",
            "23 of 50 indicators fell in the 07-10 Oct interval (4 days)",
            ioc_sum["asn_distribution"],
        ]
        if not public_mode:
            REQUIRED_PHRASES_60.append("Seen in multiple feeds")

        for phrase in REQUIRED_PHRASES_60:
            norm_phrase = " ".join(phrase.split())
            assert norm_phrase in norm_full, f"QA FAIL: Required phrase missing from PDF text: '{phrase}'"

    assert any(p in norm_full for p in ["No score changes vs previous run", "Changes vs. Previous Run:", "initialized under fixed window anchor"]), (
        "QA FAIL: Missing snapshot regression tracking note in PDF text"
    )

    # 9. Pulse Brief Audit (if provided)
    if pulse_path and os.path.exists(pulse_path):
        pdoc = pymupdf.open(pulse_path)
        pulse_page_count = len(pdoc)
        pulse_text = "".join(p.get_text() for p in pdoc)
        pdoc.close()

        assert pulse_page_count == 1, f"QA FAIL: Pulse brief must be strictly 1 page, got {pulse_page_count}"
        assert "TLP:CLEAR" in pulse_text, "QA FAIL: Expected 'TLP:CLEAR' in Pulse text layer"
        assert "TLP:AMBER" not in pulse_text, "QA FAIL: Forbidden phrase 'TLP:AMBER' found in Pulse text layer"
        assert any(c in pulse_text for c in ("Admiralty C3", "Admiralty B2")), "QA FAIL: Admiralty confidence rating missing in Pulse"

        # Check hash reflection (Pulse always reflects its companion public CSV)
        pub_csv_path = Path(str(ioc_csv_path).replace("_Internal_", "_Public_"))
        if not pub_csv_path.exists():
            pub_csv_path = Path(ioc_csv_path).parent / f"IOCs_India_Threat_Landscape_Public_{end_date.strftime('%Y-%m-%d')}.csv"
        target_csv_path = str(pub_csv_path) if pub_csv_path.exists() else ioc_csv_path
        target_pulse_hash = compute_file_sha256(target_csv_path)
        if target_pulse_hash:
            assert target_pulse_hash in pulse_text, (
                f"QA FAIL: Public CSV SHA-256 hash {target_pulse_hash} not found in Pulse text layer!"
            )
            print(f"  [PASS] Pulse Hash Verification: Pulse hash equals Public CSV hash ({target_pulse_hash})")

        # Check banned strings and label integrity in Pulse
        for b in BANNED_STRINGS:
            assert b not in pulse_text.lower(), f"QA FAIL: Banned string '{b}' detected in Pulse text layer"
        assert not re.search(r'\b(?:nan|NaN)\b', pulse_text), "QA FAIL: Banned token 'NaN' in Pulse"
        assert not re.search(r'\bNone\b', pulse_text), "QA FAIL: Banned token 'None' in Pulse"
        assert not any(line.strip().endswith('[') for line in pulse_text.splitlines()), "QA FAIL: Truncated label ending in '[' in Pulse"
        assert not any(line.strip().endswith('(') for line in pulse_text.splitlines()), "QA FAIL: Truncated label ending in '(' in Pulse"
        assert not any(re.search(r'\b\w+[\(\[]\s*$', line.strip()) for line in pulse_text.splitlines()), "QA FAIL: Cut-off label detected in Pulse"
        assert "Independent analyst work · Not affiliated with CERT-In" in pulse_text, "QA FAIL: Missing analyst disclaimer in Pulse"

        print("  [PASS] Pulse Brief Layout & Text Layer Audit (Strictly 1 page, TLP:CLEAR, Admiralty rated, Hash verified)")

    print("  [PASS] PDF Layout & Text Integrity (Strictly 11 pages, 0 enum leaks, all headers aligned)")


def run_public_qa_audit(signals: List[Signal], scored_sectors: List[Dict],
                       correlation: Dict, pdf_path: str, ioc_csv_path: str,
                       window_days: int = 60, pulse_path: Optional[str] = None) -> bool:
    """Convenience entry point for running the QA audit strictly in Public Edition mode."""
    return run_qa_audit(
        signals=signals, scored_sectors=scored_sectors, correlation=correlation,
        pdf_path=pdf_path, ioc_csv_path=ioc_csv_path, window_days=window_days,
        public_mode=True, pulse_path=pulse_path
    )
