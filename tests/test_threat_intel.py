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

    def test_get_signals_excludes_signals_after_window_end(self):
        later = Signal(
            signal_type=SignalType.VICTIM,
            title="After Window Incident",
            source="Test Feed",
            observed_at="2026-10-20T10:00:00Z",
            india_relevance=1.0,
        )
        db.upsert_signal(later, db_path=self.db_path)
        in_window = db.get_signals(days=30, db_path=self.db_path,
                                   end_date=datetime(2026, 10, 11))
        self.assertEqual(in_window, [])
        moved = db.get_signals(days=30, db_path=self.db_path,
                               end_date=datetime(2026, 10, 27))
        self.assertEqual([r["title"] for r in moved], ["After Window Incident"])

    def test_intel_items_upsert_and_window(self):
        item = {"title": "PHP2Shell exploited", "url": "https://news.test/1",
                "source": "Test News", "published_at": "2026-10-22T10:00:00+00:00",
                "india_relevant": False, "india_reason": "", "summary": ""}
        self.assertTrue(db.upsert_intel_item(item, db_path=self.db_path))
        self.assertFalse(db.upsert_intel_item(item, db_path=self.db_path))
        rows = db.get_intel_items("2026-10-20", "2026-10-28", db_path=self.db_path)
        self.assertEqual([r["title"] for r in rows], ["PHP2Shell exploited"])
        self.assertEqual(db.get_intel_items("2026-10-23", "2026-10-28", db_path=self.db_path), [])

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
        # Compromise status comes from the feed's own is_compromised flag
        self.assertEqual(summary["compromised_hosts"], 35)
        self.assertEqual(summary["unverified_hosts"], 8)
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
            self.assertGreaterEqual(len(doc), 11)
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


class TestFreshDataBulletin(unittest.TestCase):
    """A bulletin built from data unlike the bundled sample must describe that
    data: no CVE, product, actor, host or date from the sample may appear."""

    SAMPLE_ONLY = ["CVE-2026-88779", "CVE-2026-76504", "MikroTik", "Citrix", "SonicWall",
                   "virazofurniture", "ficus", "Krybit", "Clop", "12-Aug", "17 Oct 2026",
                   "27 Sep - 04 Oct", "(9 Feeds)", "Delhi NCR, Gujarat"]

    def _signals(self):
        end = datetime(2026, 10, 11, tzinfo=timezone.utc)

        def at(days_ago):
            return (end - timedelta(days=days_ago)).isoformat()

        sigs = [
            Signal(signal_type=SignalType.VULNERABILITY, title="CVE-2026-55501 — Fortinet FortiOS: auth bypass",
                   source="CISA KEV", observed_at=at(3), severity=Severity.CRITICAL, confidence=0.95,
                   india_relevance=0.8, sectors=["BFSI", "IT_ITES"], entities=Entities(cves=["CVE-2026-55501"]),
                   raw={"vendorProject": "Fortinet", "product": "FortiOS", "dateAdded": at(3)[:10],
                        "knownRansomwareCampaignUse": "Known"}),
            Signal(signal_type=SignalType.VULNERABILITY, title="CVE-2026-55502 — Microsoft Windows: privilege escalation",
                   source="CISA KEV", observed_at=at(9), severity=Severity.HIGH, confidence=0.95,
                   india_relevance=0.6, sectors=["GOVERNMENT"], entities=Entities(cves=["CVE-2026-55502"]),
                   raw={"vendorProject": "Microsoft", "product": "Windows", "dateAdded": at(9)[:10]}),
            Signal(signal_type=SignalType.ADVISORY, title="CERT-In CIVN-2026-0999: Vulnerability in Fortinet FortiOS",
                   source="CERT-In", observed_at=at(2), severity=Severity.HIGH, confidence=0.95,
                   india_relevance=1.0, sectors=["BFSI"], annexure_categories=["vi"],
                   raw={"reference": "CIVN-2026-0999", "subject": "Vulnerability in Fortinet FortiOS"}),
            Signal(signal_type=SignalType.MALWARE_INFRA, title="ThreatFox: freshhost-example.in",
                   source="abuse.ch ThreatFox", observed_at=at(1), severity=Severity.HIGH, confidence=0.75,
                   india_relevance=0.9, tags=["threatfox", "payload_delivery", "ClickFix"],
                   entities=Entities(domains=["freshhost-sample.in"]),
                   raw={"id": 4242, "ioc": "freshhost-sample.in", "threat_type": "payload_delivery",
                        "ioc_type": "domain", "malware": "", "is_compromised": False}),
        ]
        for i, (org, actor, sector, days_ago) in enumerate([
                ("Pune Gears Pvt Ltd, Pune", "Akira", "MANUFACTURING", 4),
                ("Hyderabad Clinics, Hyderabad", "Akira", "HEALTHCARE", 6),
                ("Mumbai Brokers, Mumbai", "Qilin", "BFSI", 8)]):
            sigs.append(Signal(signal_type=SignalType.VICTIM, title=f"{org} listed by {actor}",
                               source="ransomware.live", observed_at=at(days_ago), severity=Severity.HIGH,
                               confidence=0.6, india_relevance=1.0, sectors=[sector],
                               entities=Entities(organisations=[org], actors=[actor])))
        return sigs

    def test_fresh_data_passes_qa_without_sample_text(self):
        import pymupdf
        from unittest import mock
        import core.snapshot as snapshot
        from core.iocs import export_iocs_csv
        from core.qa import run_qa_audit
        sigs = self._signals()
        scored, correl = rank_sectors_multi(sigs), correlate(sigs)
        by_source = {}
        for sg in sigs:
            row = by_source.setdefault((sg.source, sg.signal_type.value),
                                       {"source": sg.source, "signal_type": sg.signal_type.value,
                                        "n": 0, "avg_relevance": 0.0})
            row["n"] += 1
            row["avg_relevance"] += sg.india_relevance
        source_summary = [dict(r, avg_relevance=r["avg_relevance"] / r["n"]) for r in by_source.values()]
        import core.bulletin_multi as bm
        # Curated headline cards legitimately name products; this test is about telemetry text
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(snapshot, "SNAPSHOTS_DIR", tmp), \
                mock.patch.object(bm, "load_headline_threats", return_value=[]):
            pdf_path = os.path.join(tmp, "fresh_2026-10-27.pdf")
            csv_path = os.path.join(tmp, "IOCs_India_Threat_Landscape_Internal_2026-10-27.csv")
            bm.build_multi_bulletin(output_path=pdf_path, scored_sectors=scored, signals=sigs,
                                    correlation=correl, source_summary=source_summary, window_days=30)
            export_iocs_csv(sigs, csv_path)
            with mock.patch("core.qa.load_headline_threats", return_value=[]):
                self.assertTrue(run_qa_audit(sigs, scored, correl, pdf_path, csv_path, window_days=30))
            doc = pymupdf.open(pdf_path)
            text = " ".join(" ".join(p.get_text().split()) for p in doc)
            doc.close()
            with open(csv_path, encoding="utf-8") as f:
                csv_text = f.read()
        for needle in self.SAMPLE_ONLY:
            self.assertNotIn(needle, text, f"sample-only text '{needle}' leaked into a fresh-data bulletin")
        self.assertIn("Fortinet FortiOS (CVE-2026-55501)", text)
        self.assertIn("CIVN-2026-0999", text)
        self.assertIn("Akira", text)
        # A host with no recorded ASN lookup is reported as unresolved, never guessed
        self.assertIn("freshhost-sample.in", csv_text)
        self.assertIn("unresolved", csv_text)
        self.assertNotIn("AS13335", csv_text)


class TestSourceHealthAndValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "h.db")
        db.init_db(self.db_path)
        db.init_signals(self.db_path)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, collector, when, seen, errors=()):
        db.record_run(collector, when, when, seen, seen, list(errors), db_path=self.db_path)

    def _signal(self, source, when):
        db.upsert_signal(Signal(signal_type=SignalType.VULNERABILITY, title=f"{source} {when}",
                                source=source, observed_at=when), db_path=self.db_path)

    def test_status_per_feed(self):
        from core.health import problems, source_health
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        feeds = {
            "ok_feed":       {"source": "OK Feed", "max_age_days": 3},
            "old_records":   {"source": "Old Feed", "max_age_days": 3},
            "broken":        {"source": "Broken Feed", "max_age_days": 3},
            "flaky":         {"source": "Flaky Feed", "max_age_days": 3},
            "never":         {"source": "Never Feed", "max_age_days": 3},
            "manual":        {"source": None, "max_age_days": None},
        }
        self._run("ok_feed", "2026-10-27T01:00:00+00:00", 5)
        self._signal("OK Feed", "2026-10-26T00:00:00+00:00")
        self._run("old_records", "2026-10-27T01:00:00+00:00", 5)
        self._signal("Old Feed", "2026-09-01T00:00:00+00:00")
        self._run("broken", "2026-10-20T01:00:00+00:00", 5)
        self._run("broken", "2026-10-27T01:00:00+00:00", 0, ["timeout"])
        self._run("flaky", "2026-10-27T01:00:00+00:00", 5, ["HTTP 503 (attempt 1/3)"])
        self._signal("Flaky Feed", "2026-10-26T00:00:00+00:00")
        self._run("manual", "2026-10-01T01:00:00+00:00", 0)
        rows = {r["collector"]: r for r in source_health(now=now, db_path=self.db_path, feeds=feeds)}
        self.assertEqual(rows["ok_feed"]["status"], "OK")
        self.assertEqual(rows["old_records"]["status"], "STALE")  # fresh run, old data
        self.assertEqual(rows["broken"]["status"], "FAILING")
        self.assertEqual(rows["broken"]["last_collected"], "2026-10-20")
        self.assertEqual(rows["flaky"]["status"], "DEGRADED")
        self.assertEqual(rows["never"]["status"], "NOT COLLECTED")
        self.assertEqual(rows["manual"]["status"], "MANUAL")
        self.assertEqual({r["collector"] for r in problems(list(rows.values()))}, {"old_records", "broken"})

    def test_bundled_data_files_are_valid(self):
        from core.validate import validate_data_files
        self.assertEqual(validate_data_files(), {})

    def test_validation_catches_mistakes(self):
        import json
        from core.validate import validate_data_files
        files = {
            "hacktivist_claims.json": [{"group": "X", "target": "a.gov.in", "claimed_at": "yesterday",
                                        "sector": "BANKS", "verified": "no"}],
            "leak_observations.json": [{"forum": "BF", "target": "Bank", "observed_at": "2026-10-01T00:00:00Z",
                                        "claimed_records": "lots"}],
            "entity_overrides.json": {"entries": [{"match": ["acme"], "state": "Atlantis"}]},
            "headline_threats.json": [{"id": "a"}],
        }
        for name, doc in files.items():
            with open(os.path.join(self.tmp.name, name), "w", encoding="utf-8") as f:
                json.dump(doc, f)
        found = validate_data_files(self.tmp.name)
        self.assertEqual(set(found), set(files))
        self.assertTrue(any("claimed_at" in p for p in found["hacktivist_claims.json"]))
        self.assertTrue(any("BANKS" in p for p in found["hacktivist_claims.json"]))
        self.assertTrue(any("claimed_records" in p for p in found["leak_observations.json"]))
        self.assertTrue(any("Atlantis" in p for p in found["entity_overrides.json"]))
        self.assertTrue(any("reason" in p for p in found["entity_overrides.json"]))

    def test_collector_retries_transient_errors_only(self):
        import asyncio
        import httpx
        from core.collectors.base import BaseCollector

        calls = {"flaky": 0, "missing": 0}

        def handler(request):
            key = request.url.path.strip("/")
            calls[key] += 1
            if key == "flaky":
                return httpx.Response(503) if calls[key] < 3 else httpx.Response(200, json={"ok": True})
            return httpx.Response(404)

        class Probe(BaseCollector):
            name = "probe"
            backoff_seconds = 0.001

            async def collect(self):
                return []

        async def go(probe):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return (await probe.get_json(client, "http://feed.test/flaky"),
                        await probe.get_json(client, "http://feed.test/missing"))

        probe = Probe()
        flaky, missing = asyncio.run(go(probe))
        self.assertEqual(flaky, {"ok": True})
        self.assertIsNone(missing)
        self.assertEqual(calls, {"flaky": 3, "missing": 1})
        self.assertEqual(len(probe.errors), 3)


class TestHeadlineThreats(unittest.TestCase):
    def _entry(self, **overrides):
        entry = {
            "id": "t1", "title": "Test incident: detail", "category": "Data breach",
            "severity": "High", "date": "2026-10-21", "summary": "What happened.",
            "actions": ["Do the thing."],
            "sources": [{"name": "Test", "url": "https://news.test/1"}],
        }
        entry.update(overrides)
        return entry

    def test_bundled_headlines_are_valid(self):
        from core.headlines import DEFAULT_PATH, validate_headline
        import json
        with open(DEFAULT_PATH, encoding="utf-8") as f:
            entries = json.load(f)
        self.assertGreaterEqual(len(entries), 3)
        for e in entries:
            self.assertEqual(validate_headline(e), [], e.get("id"))

    def test_validation_flags_problems(self):
        from core.headlines import validate_headline
        self.assertEqual(validate_headline(self._entry()), [])
        bad = self._entry(severity="Severe", date="21/10/2026", sources=[{"name": "x"}])
        del bad["actions"]
        problems = " ".join(validate_headline(bad))
        for needle in ("actions", "severity", "date", "source"):
            self.assertIn(needle, problems)

    def test_load_filters_by_date_and_sorts_by_severity(self):
        import json
        from datetime import date
        from core.headlines import load_headline_threats
        entries = [
            self._entry(id="old", date="2026-08-01"),
            self._entry(id="high", severity="High", date="2026-10-22"),
            self._entry(id="crit", severity="Critical", date="2026-10-20"),
            self._entry(id="broken", severity="Nope"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "h.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entries, f)
            loaded = load_headline_threats(path, start=date(2026, 9, 1),
                                           end=date(2026, 10, 27))
        self.assertEqual([e["id"] for e in loaded], ["crit", "high"])

    def test_india_direct_sorts_first_and_split(self):
        import json
        from core.headlines import brief_text, load_headline_threats, split_headlines
        entries = [
            self._entry(id="global-high", date="2026-10-22"),
            self._entry(id="india-high", date="2026-10-10", india_direct=True),
            self._entry(id="global-crit", severity="Critical", date="2026-10-01",
                        summary="First sentence. Second sentence."),
            self._entry(id="bad-flag", india_direct="yes"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "h.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entries, f)
            loaded = load_headline_threats(path)
        self.assertEqual([e["id"] for e in loaded], ["global-crit", "india-high", "global-high"])
        cards, brief = split_headlines(loaded)
        self.assertEqual([e["id"] for e in cards], ["global-crit", "india-high"])
        self.assertEqual([e["id"] for e in brief], ["global-high"])
        self.assertEqual(brief_text(loaded[0]), "First sentence.")
        self.assertEqual(brief_text(self._entry(brief="Short.")), "Short.")

    def test_news_watch_drops_covered_stories(self):
        from core.headlines import headline_keywords, news_watch
        terms = headline_keywords([self._entry(keywords=["SBI"], cves=["CVE-2026-1"])])
        items = [
            {"title": "SBI leak update", "published_at": "2026-10-23", "india_relevant": 1},
            {"title": "Flaw CVE-2026-1 exploited", "published_at": "2026-10-23"},
            {"title": "Ransomware hits Mumbai firm", "published_at": "2026-10-22", "india_relevant": 1},
            {"title": "Global botnet takedown", "published_at": "2026-10-24", "india_relevant": 0},
            {"title": "Lesbian rights group site defaced", "published_at": "2026-10-21"},
        ]
        titles = [i["title"] for i in news_watch(items, terms)]
        self.assertEqual(titles[0], "Ransomware hits Mumbai firm")
        self.assertNotIn("SBI leak update", titles)
        self.assertNotIn("Flaw CVE-2026-1 exploited", titles)
        self.assertIn("Lesbian rights group site defaced", titles)


class TestSecurityNews(unittest.TestCase):
    RSS = """<rss><channel>
      <item><title>PHP2Shell flaws actively exploited</title><link>https://n.test/1</link>
        <pubDate>Thu, 22 Oct 2026 10:00:00 +0000</pubDate>
        <description>&lt;p&gt;Two critical bugs&lt;/p&gt;</description></item>
      <item><title>No link here</title></item>
    </channel></rss>"""
    ATOM = """<feed xmlns="http://www.w3.org/2005/Atom"><entry>
      <title>Malicious PyPI release steals keys</title><link href="https://n.test/2"/>
      <published>2026-10-21T12:00:00Z</published></entry></feed>"""

    def test_parse_rss_and_atom(self):
        from core.collectors.news import parse_feed
        rss = parse_feed(self.RSS, "RSS")
        self.assertEqual(len(rss), 1)
        self.assertEqual(rss[0]["url"], "https://n.test/1")
        self.assertEqual(rss[0]["summary"], "Two critical bugs")
        self.assertTrue(rss[0]["published_at"].startswith("2026-10-22T10:00"))
        atom = parse_feed(self.ATOM, "Atom")
        self.assertEqual(atom[0]["url"], "https://n.test/2")
        self.assertEqual(parse_feed("not xml", "x"), [])

    def test_classify_news(self):
        from core.collectors.news import classify_news
        sbi = classify_news("SBI confirms customer data on dark web")
        self.assertTrue(sbi["india_relevant"])
        self.assertEqual(sbi["category"], "Data breach")
        self.assertEqual(classify_news("Malicious PyPI release steals keys")["category"], "Supply chain")
        php = classify_news("PHP2Shell flaws actively exploited in the wild")
        self.assertEqual(php["category"], "Vulnerability")
        self.assertEqual(php["score"], 2)
        self.assertEqual(classify_news("Company launches new laptop")["score"], 0)


class TestBulletinThreatsInFocus(unittest.TestCase):
    def test_headlines_render_in_bulletin(self):
        import pymupdf
        from core.bulletin_multi import build_multi_bulletin
        # 60 days reuses the tracked snapshot instead of writing a new one
        sigs = [Signal.from_row(r) for r in db.get_signals(days=60)]
        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = os.path.join(tmp_dir, "b.pdf")
            build_multi_bulletin(
                output_path=pdf_path, scored_sectors=rank_sectors_multi(sigs), signals=sigs,
                correlation=correlate(sigs), source_summary=db.signal_counts_by_source(days=60),
                window_days=60)
            doc = pymupdf.open(pdf_path)
            pages = [" ".join(p.get_text().split()) for p in doc]
            doc.close()
        self.assertIn("In this report", pages[0])
        self.assertIn("Bottom line", pages[0])
        self.assertIn("01 Threats in Focus", pages[1])
        self.assertIn("This Month at a Glance", pages[1])
        full = " ".join(pages)
        for title in ("PHP2Shell: unauthenticated remote code execution in the PHP engine",
                      "LiteLLM supply-chain attack",
                      "SBI customer records on the dark web"):
            self.assertIn(title, full)
        # Headline actions lead the action matrix
        self.assertIn("PHP2Shell: Upgrade to PHP 8.5.12", full)

    def test_news_watch_renders_uncovered_stories(self):
        from unittest import mock
        import pymupdf
        import core.bulletin_multi as bm
        now = datetime.now(timezone.utc).isoformat()
        items = [
            {"title": "SBI customers hit by fake KYC SMS wave", "url": "https://n.test/a",
             "source": "MediaNama", "published_at": now, "india_relevant": 1, "summary": ""},
            {"title": "Ransomware gang claims attack on Pune manufacturer", "url": "https://n.test/b",
             "source": "The Record", "published_at": now, "india_relevant": 1, "summary": ""},
        ]
        sigs = [Signal.from_row(r) for r in db.get_signals(days=60)]
        with tempfile.TemporaryDirectory() as tmp_dir, \
                mock.patch.object(bm, "get_intel_items", return_value=items):
            pdf_path = os.path.join(tmp_dir, "b.pdf")
            bm.build_multi_bulletin(
                output_path=pdf_path, scored_sectors=rank_sectors_multi(sigs), signals=sigs,
                correlation=correlate(sigs), source_summary=db.signal_counts_by_source(days=60),
                window_days=60)
            doc = pymupdf.open(pdf_path)
            full = " ".join(" ".join(p.get_text().split()) for p in doc)
            doc.close()
        self.assertIn("Also in the News", full)
        self.assertIn("Ransomware gang claims attack on Pune manufacturer", full)
        self.assertNotIn("fake KYC SMS wave", full)


if __name__ == "__main__":
    unittest.main()
