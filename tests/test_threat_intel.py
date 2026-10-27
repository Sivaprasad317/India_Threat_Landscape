"""
Comprehensive test suite for India Threat Landscape Intelligence platform.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from core import database as db
from core.certin import (
    map_to_annexure,
    reporting_deadline,
    log_retention_floor,
    obligations_summary,
)
from core.correlation import (
    correlate,
    find_actor_chains,
    find_exploit_to_victim_links,
    find_shared_artefacts,
)
from core.scoring import rank_sectors, score_sector
from core.scoring_multi import rank_sectors_multi, score_sector_multi
from core.sectors import classify_sector, is_indian_entity, is_nciipc_critical
from core.signals import Entities, Severity, Signal, SignalType


class TestDatabaseAndSignals(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_threats.db")
        db.init_db(self.db_path)
        db.init_signals(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_upsert_signal_insert_vs_update(self):
        sig = Signal(
            signal_type=SignalType.VICTIM,
            title="Test Victim Incident",
            source="Test Feed",
            observed_at="2026-10-09T10:00:00Z",
            severity=Severity.HIGH,
            confidence=0.8,
            india_relevance=1.0,
            sectors=["BFSI"],
            entities=Entities(organisations=["Test Corp"]),
        )
        # First upsert must return True (newly added)
        is_new = db.upsert_signal(sig, db_path=self.db_path)
        self.assertTrue(is_new)

        # Second upsert of identical signal must return False (updated existing)
        is_new_again = db.upsert_signal(sig, db_path=self.db_path)
        self.assertFalse(is_new_again)

        # Verify record retrieved matches
        signals = db.get_signals(days=30, db_path=self.db_path)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["title"], "Test Victim Incident")

    def test_signal_serialization_and_id(self):
        sig = Signal(
            signal_type=SignalType.VULNERABILITY,
            title="Test CVE Vuln",
            source="NVD",
            observed_at="2026-10-09T10:00:00Z",
            entities=Entities(cves=["CVE-2026-9999"]),
        )
        row = sig.to_row()
        self.assertTrue(sig.signal_id)
        self.assertEqual(row["signal_id"], sig.signal_id)

        recovered = Signal.from_row(row)
        self.assertEqual(recovered.signal_id, sig.signal_id)
        self.assertEqual(recovered.signal_type, SignalType.VULNERABILITY)
        self.assertEqual(recovered.entities.cves, ["CVE-2026-9999"])


class TestSectorTaxonomy(unittest.TestCase):
    def test_exact_feed_label_mapping(self):
        sec, conf = classify_sector(activity="financial services")
        self.assertEqual(sec, "BFSI")
        self.assertEqual(conf, 0.95)

        sec, conf = classify_sector(activity="technology")
        self.assertEqual(sec, "IT_ITES")
        self.assertEqual(conf, 0.95)

    def test_keyword_word_boundaries_no_false_substrings(self):
        # "biotech" should match PHARMA, not IT_ITES (which has keyword "tech")
        sec, _ = classify_sector(victim_name="Bharat Biotech")
        self.assertEqual(sec, "PHARMA")

        # "customer support" should NOT match TRANSPORT (which has keyword "port")
        sec, _ = classify_sector(activity="customer support department")
        self.assertNotEqual(sec, "TRANSPORT")

        # "ICICI Bank" should match BFSI
        sec, _ = classify_sector(victim_name="ICICI Bank Limited")
        self.assertEqual(sec, "BFSI")

    def test_is_indian_entity(self):
        is_in, conf, reason = is_indian_entity(country="IN")
        self.assertTrue(is_in)
        self.assertGreaterEqual(conf, 0.9)

        is_in, conf, _ = is_indian_entity(victim_name="example.co.in")
        self.assertTrue(is_in)

        is_in, conf, _ = is_indian_entity(country="US", victim_name="Acme Corp")
        self.assertFalse(is_in)

    def test_geographic_state_classification(self):
        from core.geo_india import classify_state
        self.assertEqual(classify_state("Manipal Academy of Higher Edu", "Bangalore Karnataka"), "Karnataka")
        self.assertEqual(classify_state("IIT Roorkee", "Roorkee Uttarakhand"), "Uttarakhand")
        self.assertEqual(classify_state("Shree Saibaba Sansthan", "Shirdi Maharashtra"), "Maharashtra")
        self.assertEqual(classify_state("University of Delhi", "New Delhi"), "Delhi NCR")
        self.assertEqual(classify_state("Palsana Enviro", "Surat Gujarat"), "Gujarat")
        self.assertEqual(classify_state("VIT University", "Vellore Tamil Nadu"), "Tamil Nadu")
        self.assertEqual(classify_state("vi***in", "Designated critical infrastructure under Section 70A"), "Location Unresolved")


class TestCertInCompliance(unittest.TestCase):
    def test_annexure_mapping_precision(self):
        # Benign phrase must not falsely trigger category (v) via substring 'rat'
        res = map_to_annexure("Review of corporate operations strategy")
        self.assertEqual(len(res), 0)

        # Genuine RAT mention triggers category (v)
        res = map_to_annexure("Detected malicious RAT executable on compromised host")
        cats = [r["roman"] for r in res]
        self.assertIn("v", cats)

        # Platform mention should not trigger digital payments (xiv) via substring 'atm'
        res = map_to_annexure("Issue affecting web platform interface")
        cats = [r["roman"] for r in res]
        self.assertNotIn("xiv", cats)

        # Genuine payment / ATM attack triggers category (xiv)
        res = map_to_annexure("ATM card skimmer and UPI payment gateway tampering")
        cats = [r["roman"] for r in res]
        self.assertIn("xiv", cats)

    def test_reporting_deadline_utc_and_ist(self):
        ist = timezone(timedelta(hours=5, minutes=30))
        noticed = datetime(2026, 10, 9, 10, 0, tzinfo=ist)
        res = reporting_deadline(noticed)

        # noticed at 10:00 IST is 04:30 UTC
        self.assertTrue(res["noticed_at_utc"].endswith("+00:00") or res["noticed_at_utc"].endswith("Z"))
        self.assertIn("04:30:00", res["noticed_at_utc"])
        self.assertIn("10:30:00", res["deadline_utc"])
        self.assertEqual(res["window_hours"], 6)

    def test_log_retention_floor(self):
        ref = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
        res = log_retention_floor(reference=ref)
        self.assertEqual(res["rolling_days"], 180)
        self.assertIn("Apr 2026", res["retain_from"])


class TestCorrelationEngine(unittest.TestCase):
    def test_actor_chains_require_cross_signal_types(self):
        # Single actor with 5 victim signals only (same signal type)
        single_type_sigs = [
            Signal(
                signal_type=SignalType.VICTIM,
                title=f"Victim {i}",
                source="Source 1",
                observed_at="2026-10-09T00:00:00Z",
                entities=Entities(actors=["ActorAlpha"]),
            )
            for i in range(5)
        ]
        chains = find_actor_chains(single_type_sigs)
        self.assertEqual(len(chains), 0)

        # Actor spanning both VICTIM and MALWARE_INFRA
        multi_type_sigs = single_type_sigs + [
            Signal(
                signal_type=SignalType.MALWARE_INFRA,
                title="C2 infrastructure",
                source="Source 2",
                observed_at="2026-10-09T00:00:00Z",
                entities=Entities(actors=["ActorAlpha"]),
            )
        ]
        chains = find_actor_chains(multi_type_sigs)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["actor"], "actoralpha")
        self.assertEqual(len(chains[0]["signal_types"]), 2)

    def test_generic_artefacts_filtered(self):
        sigs = [
            Signal(
                signal_type=SignalType.VICTIM,
                title="Incident 1",
                source="Source 1",
                observed_at="2026-10-09T00:00:00Z",
                entities=Entities(actors=["unknown"]),
            ),
            Signal(
                signal_type=SignalType.VICTIM,
                title="Incident 2",
                source="Source 2",
                observed_at="2026-10-09T00:00:00Z",
                entities=Entities(actors=["unknown"]),
            ),
        ]
        shared = find_shared_artefacts(sigs)
        # "unknown" should be filtered out
        self.assertEqual(len(shared), 0)


class TestScoring(unittest.TestCase):
    def test_scoring_multi_zero_cap_guard(self):
        sig = Signal(
            signal_type=SignalType.VICTIM,
            title="Victim Incident",
            source="Test",
            observed_at="2026-10-09T00:00:00Z",
            india_relevance=1.0,
            sectors=["BFSI"],
        )
        # Should not raise ZeroDivisionError when cap is zero
        score = score_sector_multi("BFSI", [sig], caps={"impact": 0.0})
        self.assertIsInstance(score["risk_score"], float)

    def test_rank_sectors_multi(self):
        sig = Signal(
            signal_type=SignalType.VICTIM,
            title="Victim Incident",
            source="Test",
            observed_at="2026-10-09T00:00:00Z",
            india_relevance=1.0,
            sectors=["BFSI"],
        )
        ranked = rank_sectors_multi([sig])
        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0]["sector"], "BFSI")


class TestIOCManagement(unittest.TestCase):
    def test_country_code_and_host_extraction(self):
        from core.iocs import extract_host, get_country_code, defang
        self.assertEqual(extract_host("https://virazofurniture.in/path"), "virazofurniture.in")
        self.assertEqual(extract_host("_wildcard_.theinstaapp.com.in"), "theinstaapp.com.in")
        self.assertEqual(get_country_code("virazofurniture.in"), "IN")
        self.assertEqual(get_country_code("mdfs.co.in"), "IN")
        self.assertEqual(get_country_code("malware.in.ua"), "UA")
        self.assertEqual(get_country_code("randomsite.com"), "UNKNOWN")
        self.assertEqual(defang("https://test.in"), "hxxps://test[.]in")

    def test_malware_family_and_technique_split(self):
        from core.iocs import clean_malware_family, extract_delivery_technique
        self.assertEqual(clean_malware_family("remcos", ["rat"]), "RemcosRAT")
        self.assertEqual(clean_malware_family("ClearFake", []), "")
        self.assertEqual(extract_delivery_technique("ClearFake", [], ""), "ClearFake")
        self.assertEqual(extract_delivery_technique("ClickFix", [], ""), "ClickFix")
        self.assertEqual(extract_delivery_technique("etherhide", [], ""), "EtherHiding")

    def test_domestic_iocs_and_summary(self):
        from core.iocs import extract_iocs, get_ioc_summary
        sigs = [Signal.from_row(r) for r in db.get_signals(days=60)]
        iocs = extract_iocs(sigs)
        self.assertEqual(len(iocs), 50)
        self.assertTrue(all(i["country"] == "IN" for i in iocs))
        self.assertFalse(any(i["host"].endswith(".in.ua") for i in iocs))
        # Ensure all 50 IOCs have non-empty ASN
        self.assertTrue(all(len(i["asn"].strip()) > 0 for i in iocs))
        summary = get_ioc_summary(sigs)
        self.assertEqual(summary["total_indicators"], 50)
        self.assertEqual(summary["unique_hosts"], 43)
        self.assertEqual(summary["compromised_hosts"], 18)
        self.assertEqual(summary["unverified_hosts"], 25)
        self.assertEqual(summary["phishing_hosts"], 0)
        self.assertEqual(summary["ioc_window_recent_count"], 23)

    def test_scoring_determinism(self):
        sigs = [Signal.from_row(r) for r in db.get_signals(days=60)]
        run1 = rank_sectors_multi(sigs)
        run2 = rank_sectors_multi(sigs)
        self.assertEqual(run1, run2)


class TestBulletinQA(unittest.TestCase):
    def test_qa_audit_passes(self):
        from core.qa import run_qa_audit
        from core.bulletin_multi import build_multi_bulletin
        from core.iocs import export_iocs_csv
        sigs = [Signal.from_row(r) for r in db.get_signals(days=60)]
        scored = rank_sectors_multi(sigs)
        correl = correlate(sigs)
        by_src = db.signal_counts_by_source(days=60)
        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = os.path.join(tmp_dir, "test_bulletin.pdf")
            csv_path = os.path.join(tmp_dir, "test_iocs.csv")
            build_multi_bulletin(
                output_path=pdf_path, scored_sectors=scored, signals=sigs,
                correlation=correl, source_summary=by_src, window_days=60,
                prepared_by="Siva prasad Boddu"
            )
            export_iocs_csv(sigs, csv_path)
            res = run_qa_audit(sigs, scored, correl, pdf_path, csv_path)
            self.assertTrue(res)

    def test_pipeline_double_run_determinism(self):
        """Runs the pipeline twice and asserts identical output and no changes message."""
        import pymupdf
        from core.bulletin_multi import build_multi_bulletin
        from core.iocs import export_iocs_csv
        sigs = [Signal.from_row(r) for r in db.get_signals(days=60)]
        scored1 = rank_sectors_multi(sigs)
        correl = correlate(sigs)
        by_src = db.signal_counts_by_source(days=60)
        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = os.path.join(tmp_dir, "test_bulletin.pdf")
            csv_path = os.path.join(tmp_dir, "test_iocs.csv")
            # Run 1: establishes/saves snapshot
            build_multi_bulletin(
                output_path=pdf_path, scored_sectors=scored1, signals=sigs,
                correlation=correl, source_summary=by_src, window_days=60,
                prepared_by="Siva prasad Boddu"
            )
            # Run 2: immediately follows with identical inputs
            scored2 = rank_sectors_multi(sigs)
            self.assertEqual(scored1, scored2, "Sector scores differed between consecutive pipeline runs!")
            build_multi_bulletin(
                output_path=pdf_path, scored_sectors=scored2, signals=sigs,
                correlation=correl, source_summary=by_src, window_days=60,
                prepared_by="Siva prasad Boddu"
            )
            doc = pymupdf.open(pdf_path)
            full_text = "".join(page.get_text() for page in doc)
            doc.close()
            self.assertIn("No score changes vs previous run (snapshot ", full_text)

    def test_public_bulletin_qa_audit(self):
        """Verifies that Public Edition generates TLP:CLEAR, anonymizes victims, and passes public QA audit."""
        import csv
        import pymupdf
        from core.qa import run_public_qa_audit
        from core.bulletin_multi import build_multi_bulletin
        from core.iocs import export_iocs_csv
        sigs = [Signal.from_row(r) for r in db.get_signals(days=60)]
        scored = rank_sectors_multi(sigs)
        correl = correlate(sigs)
        by_src = db.signal_counts_by_source(days=60)
        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = os.path.join(tmp_dir, "test_bulletin_public.pdf")
            csv_path = os.path.join(tmp_dir, "test_iocs_public.csv")
            build_multi_bulletin(
                output_path=pdf_path, scored_sectors=scored, signals=sigs,
                correlation=correl, source_summary=by_src, window_days=60,
                prepared_by="Siva prasad Boddu", public_mode=True
            )
            export_iocs_csv(sigs, csv_path, public_mode=True)
            res = run_public_qa_audit(sigs, scored, correl, pdf_path, csv_path)
            self.assertTrue(res)

            # Check CSV properties
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                self.assertEqual(len(rows), 50)
                self.assertIn("dispute_contact", reader.fieldnames)
                self.assertIn("license_attribution", reader.fieldnames)
                exp_dispute = os.getenv("DISPUTE_CONTACT_EMAIL", "").strip()
                for r in rows:
                    self.assertEqual(r["tlp"], "TLP:CLEAR")
                    self.assertEqual(r["dispute_contact"], exp_dispute)
                    self.assertTrue(len(r["license_attribution"]) > 0)
                    self.assertIn(r["ioc_role"], ("reported_compromised_by_feed", "unverified_delivery_host", "phishing_lookalike"))
                    if r["source_feed"] == "abuse.ch ThreatFox":
                        self.assertTrue(r["reference_url"].startswith("https://threatfox.abuse.ch/ioc/"))

            # Check PDF text layers
            doc = pymupdf.open(pdf_path)
            self.assertEqual(len(doc), 11)
            full_text = "".join(page.get_text() for page in doc)
            doc.close()
            self.assertIn("TLP:CLEAR", full_text)
            self.assertNotIn("Limited Disclosure", full_text)
            self.assertNotIn("must not be published publicly", full_text)
            self.assertIn("Independent analyst work · Not affiliated with CERT-In", full_text)
            self.assertNotIn("Aligned to CERT-In", full_text)
            self.assertNotIn("TLP:AMBER", full_text)
            self.assertNotIn("RESTRICTED DISTRIBUTION", full_text)

    def test_threat_pulse_single_page(self):
        """Verifies that the standalone Threat Pulse brief is strictly 1 page and contains key strategic sections."""
        import pymupdf
        from core.pulse import build_threat_pulse
        sigs = [Signal.from_row(r) for r in db.get_signals(days=60)]
        scored = rank_sectors_multi(sigs)
        with tempfile.TemporaryDirectory() as tmp_dir:
            pulse_path = os.path.join(tmp_dir, "test_threat_pulse.pdf")
            build_threat_pulse(
                output_path=pulse_path, signals=sigs, scored_sectors=scored,
                window_days=7, prepared_by="Siva prasad Boddu"
            )
            doc = pymupdf.open(pulse_path)
            self.assertEqual(len(doc), 1, "Threat Pulse must be strictly 1 page!")
            text = doc[0].get_text()
            doc.close()
            self.assertIn("INDIA THREAT PULSE", text)
            self.assertIn("TLP:CLEAR", text)
            self.assertIn("Top 3 Strategic Findings", text)
            self.assertIn("PRIORITY DEFENSIVE ACTION", text)


if __name__ == "__main__":
    unittest.main()
