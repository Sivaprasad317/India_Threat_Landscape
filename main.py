#!/usr/bin/env python3
"""
India Threat Landscape Intelligence - multi-source

Collects from ransomware leak sites, exploited-vulnerability catalogues,
malware infrastructure feeds, certificate transparency, phishing feeds,
CERT-In, hacktivist claim tracking and your own dark web notes, then scores
Indian sector risk across all of them.

Usage
-----
  python main.py sources                    what can run, what needs a key
  python main.py collect                    run every ready collector
  python main.py collect --only cisa_kev,crtsh_typosquat
  python main.py sectors --days 60 --verbose
  python main.py correlate                  cross-source findings
  python main.py bulletin --days 30 --prepared-by "Siva prasad Boddu"
  python main.py certin --incident "..." --sector BFSI
  python main.py clock --noticed "2026-09-05 08:30"
  python main.py stats
  python main.py health                     feed freshness and failures
  python main.py validate                   check hand-maintained data files
  python main.py backtest --write docs/BACKTEST.md
  python main.py export --format both --public   STIX 2.1 + MISP for CTI platforms
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

# Before the core imports: core.window reads SCORING_ANCHOR at import time
load_dotenv()

from core import database as db  # noqa: E402
from core.certin import (DISCLAIMER, log_retention_floor, map_to_annexure,  # noqa: E402
                         obligations_summary, reporting_deadline)
from core.sectors import SECTORS, sector_label  # noqa: E402
from core.signals import Signal  # noqa: E402

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[1m",
    "\033[0m")
if os.name == "nt" and not os.environ.get("WT_SESSION"):
    GREEN = RED = YELLOW = CYAN = DIM = BOLD = RESET = ""

BAND_COLOR = {"Critical": RED, "High": RED, "Moderate": YELLOW,
              "Low": GREEN, "Minimal": GREEN}


def _load_signals(days, min_relevance=0.0):
    return [Signal.from_row(r) for r in
            db.get_signals(days=days, min_relevance=min_relevance)]


def _import_collectors():
    """Give a usable message when dependencies are not installed yet."""
    try:
        from core.collectors import available_collectors
        return available_collectors
    except ModuleNotFoundError as exc:
        print(f"\n{RED}Missing dependency: {exc.name}{RESET}")
        print(f"  Run: {CYAN}pip install -r requirements.txt{RESET}\n")
        sys.exit(1)


def cmd_sources(args):
    info = _import_collectors()()
    ready = [n for n, i in info.items() if i["ready"]]
    blocked = [n for n, i in info.items() if not i["ready"]]

    print(f"\n{BOLD}Collectors{RESET}")
    print(f"{DIM}{'-' * 84}{RESET}")
    for name in sorted(ready):
        i = info[name]
        cost = f"{GREEN}free{RESET}" if i["free"] else f"{YELLOW}paid{RESET}"
        print(f"  {GREEN}ready{RESET}      {name:<22} "
              f"{i['description'][:44]:<46} {cost}")
    for name in sorted(blocked):
        i = info[name]
        print(f"  {YELLOW}needs key{RESET}  {name:<22} "
              f"{i['description'][:44]:<46} {DIM}{', '.join(i['missing_env'])}{RESET}")

    print(f"\n  {GREEN}{len(ready)} ready{RESET} - "
          f"{YELLOW}{len(blocked)} awaiting keys{RESET}")
    if blocked:
        print(f"\n{CYAN}Free keys worth getting{RESET}")
        print(f"  ABUSECH_AUTH_KEY   https://auth.abuse.ch/       "
              f"{DIM}ThreatFox + URLhaus + MalwareBazaar{RESET}")
        print(f"  OTX_API_KEY        https://otx.alienvault.com   "
              f"{DIM}campaign reporting{RESET}")
        print(f"  NVD_API_KEY        https://nvd.nist.gov/developers "
              f"{DIM}optional, raises rate limit{RESET}")
    print()


def cmd_collect(args):
    available_collectors = _import_collectors()
    db.init_db(); db.init_signals()
    info = available_collectors()
    selected = ([n.strip() for n in args.only.split(",")]
                if args.only else list(info))
    total_new = total_seen = 0

    print(f"\n{CYAN}Collecting{RESET}")
    for name in selected:
        if name not in info:
            print(f"  {RED}unknown collector: {name}{RESET}")
            continue
        meta = info[name]
        if not meta["ready"]:
            print(f"  {DIM}skip   {name:<22} needs "
                  f"{', '.join(meta['missing_env'])}{RESET}")
            continue

        started = datetime.now(timezone.utc).isoformat()
        collector = meta["class"](days=args.days)
        try:
            signals = collector.run()
        except Exception as exc:
            print(f"  {RED}fail   {name:<22} {type(exc).__name__}: {exc}{RESET}")
            db.record_run(name, started, datetime.now(timezone.utc).isoformat(),
                          0, 0, [f"{type(exc).__name__}: {exc}"])
            continue

        new = sum(1 for s in signals if db.upsert_signal(s))
        total_new += new; total_seen += len(signals)
        news = getattr(collector, "items", None)
        if news is not None:
            fresh = sum(1 for item in news if db.upsert_intel_item(item))
            colour = GREEN if news else DIM
            print(f"  {colour}ok     {name:<22} {len(news):>4} stories, "
                  f"{fresh:>4} new{RESET}")
        else:
            colour = GREEN if signals else DIM
            print(f"  {colour}ok     {name:<22} {len(signals):>4} signals, "
                  f"{new:>4} new{RESET}")
        for err in collector.errors[:2]:
            print(f"         {YELLOW}{err[:86]}{RESET}")
        db.record_run(name, started, datetime.now(timezone.utc).isoformat(),
                      new, len(signals), collector.errors)

    print(f"\n  {GREEN}{total_seen} signals collected, {total_new} new{RESET}")
    by_source = db.signal_counts_by_source(days=args.days)
    if by_source:
        print(f"\n{CYAN}Signals by source{RESET}")
        for row in by_source[:14]:
            print(f"  {row['source'][:32]:<34} {row['signal_type']:<16} "
                  f"{row['n']:>4}  {DIM}avg relevance "
                  f"{row['avg_relevance']:.2f}{RESET}")
    print()


def cmd_sectors(args):
    from core.scoring_multi import rank_sectors_multi, unsectored_signals
    db.init_signals()
    signals = _load_signals(args.days)
    if not signals:
        print(f"\n{YELLOW}No signals yet. Run: python main.py collect{RESET}\n")
        return

    scored = rank_sectors_multi(signals)
    print(f"\n{BOLD}Sector risk - last {args.days} days, "
          f"{len(signals)} signals{RESET}")
    print(f"{DIM}{'-' * 98}{RESET}")
    print(f"  {'Sector':<38} {'Score':>6} {'Band':<9} "
          f"{'Vic':>4} {'CVE':>4} {'Infra':>6} {'Src':>4}  CII")
    print(f"{DIM}{'-' * 98}{RESET}")
    for s in scored:
        colour = BAND_COLOR.get(s["risk_band"], "")
        print(f"  {s['label'][:37]:<38} {s['risk_score']:>6.1f} "
              f"{colour}{s['risk_band']:<9}{RESET} "
              f"{s['victim_count']:>4} {s['exploited_cve_count']:>4} "
              f"{s['infra_count']:>6} {s['source_count']:>4}  "
              f"{'yes' if s['nciipc_critical'] else '-'}")
        if args.verbose:
            print(f"    {DIM}{s['explanation']}{RESET}")
            c = s["components"]
            print(f"    {DIM}impact {c['impact']:.0f} | exploit {c['exploit']:.0f}"
                  f" | infra {c['infra']:.0f} | pressure {c['pressure']:.0f}"
                  f" | exposure {c['exposure']:.0f}{RESET}")
            if s["top_cves"]:
                print(f"    {DIM}CVEs: {', '.join(s['top_cves'][:4])}{RESET}")

    orphans = unsectored_signals(signals)
    if orphans:
        print(f"\n  {DIM}{len(orphans)} India-relevant signals carry no sector "
              f"(malicious hosts, unattributed infrastructure){RESET}")
    print()


def cmd_correlate(args):
    from core.correlation import correlate
    db.init_signals()
    signals = _load_signals(args.days)
    if not signals:
        print(f"\n{YELLOW}No signals yet. Run: python main.py collect{RESET}\n")
        return

    result = correlate(signals)
    print(f"\n{BOLD}Cross-source correlation - {result['total_signals']} signals{RESET}")
    print(f"  {result['corroborated_count']} signals seen in more than one feed "
          f"({result['shared_artefacts_count']} artefacts)")
    print(f"  {GREEN}{result['independently_corroborated_count']} signals independently corroborated "
          f"({result['independent_artefacts_count']} artefacts from separate feed families){RESET}")

    if result["exploit_victim_links"]:
        print(f"\n{CYAN}Exploited CVE meeting live victim activity{RESET}")
        print(f"{DIM}  Co-occurrence in the same sector: a known way in, not proof it was "
              f"the way in.{RESET}")
        for link in result["exploit_victim_links"][:8]:
            flag = f" {RED}[ransomware campaigns]{RESET}" if link["ransomware_linked"] else ""
            edge = f" {YELLOW}[edge device]{RESET}" if link["edge_device"] else ""
            print(f"\n  {sector_label(link['sector'])}{flag}{edge}")
            print(f"    {link['cve']}  {DIM}{link['vuln_title'][:70]}{RESET}")
            examples = (': ' + ', '.join(link['victim_examples'][:3])
                        if link['victim_examples'] else '')
            print(f"    {link['victim_count']} victim(s) in this sector{examples}")

    if result["shared_artefacts"]:
        print(f"\n{CYAN}Artefacts seen by more than one source{RESET}")
        for item in result["shared_artefacts"][:10]:
            indep = f"{GREEN}independent{RESET}" if item["independent"] else f"{DIM}shared upstream{RESET}"
            evidence = "; ".join(f"{e['source']} {e['observed_at']}" for e in item["evidence"])
            print(f"  {item['artefact'][:40]:<42} {item['match']:<18} {indep}")
            print(f"  {DIM}  {evidence[:90]}{RESET}")

    if result["possible_links"]:
        print(f"\n{CYAN}Possible links (name match only, not counted){RESET}")
        for item in result["possible_links"][:8]:
            print(f"  {item['artefact'][:40]:<42} {item['field']:<18} {DIM}{', '.join(item['sources'])}{RESET}")

    if result["actor_chains"]:
        print(f"\n{CYAN}Actor names appearing across signal types (name match only){RESET}")
        for chain in result["actor_chains"][:8]:
            print(f"  {chain['actor'][:26]:<28} {chain['signal_count']:>3} signals  "
                  f"{DIM}{', '.join(chain['signal_types'][:4])}{RESET}")
    print()


def cmd_bulletin(args):
    from core.bulletin_multi import build_multi_bulletin
    from core.correlation import correlate
    from core.scoring_multi import rank_sectors_multi
    db.init_signals()
    signals = _load_signals(args.days)
    if not signals:
        print(f"\n{YELLOW}No signals yet. Run: python main.py collect{RESET}\n")
        return

    correlation = correlate(signals)
    scored = rank_sectors_multi(signals)
    by_source = db.signal_counts_by_source(days=args.days)

    from core.window import window_end_date
    if db.latest_signal_date() > window_end_date().isoformat():
        print(f"\n{YELLOW}Note: the database has signals newer than the scoring window end "
              f"({window_end_date():%d %b %Y}). Set SCORING_ANCHOR=now in .env to include them.{RESET}")

    ist = timezone(timedelta(hours=5, minutes=30))
    now_ist = datetime.now(ist)
    today = now_ist.date()
    stamp = today.strftime("%Y-%m-%d")
    month_name = today.strftime("%b")        # "Oct"
    date_folder = today.strftime("%m-%d-%Y")  # "10-12-2026"

    # Output with Month and date folder: Output -> Oct -> MM-DD-YYYY
    if not getattr(args, "outdir", "") or args.outdir == "output":
        outdir = Path("output") / month_name / date_folder
    else:
        outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    public_mode = getattr(args, "public", False)
    bulletin_filename = f"India_Threat_Bulletin_Public_{stamp}.pdf" if public_mode else f"India_Threat_Bulletin_{stamp}.pdf"
    path = outdir / bulletin_filename

    prep_by = getattr(args, "prepared_by", "") or os.getenv("ANALYST_NAME", "Siva prasad Boddu")
    build_multi_bulletin(
        output_path=str(path), scored_sectors=scored, signals=signals,
        correlation=correlation, source_summary=by_source,
        window_days=args.days, org_name=args.org,
        prepared_by=prep_by,
        analyst=args.analyst or os.getenv("ANALYST_NAME", ""),
        public_mode=public_mode)

    from core.iocs import export_iocs_csv
    from core.qa import run_qa_audit
    ioc_filename = f"IOCs_India_Threat_Landscape_Public_{stamp}.csv" if public_mode else f"IOCs_India_Threat_Landscape_Internal_{stamp}.csv"
    ioc_path = outdir / ioc_filename
    _, file_hash = export_iocs_csv(signals, str(ioc_path), public_mode=public_mode)

    # Strict automated QA Gate enforcement
    try:
        run_qa_audit(
            signals=signals, scored_sectors=scored, correlation=correlation,
            pdf_path=str(path), ioc_csv_path=str(ioc_path),
            window_days=args.days, public_mode=public_mode
        )
    except AssertionError as err:
        print(f"\n{RED}QA AUDIT GATE FAILED:{RESET} {err}\n")
        sys.exit(1)

    print(f"\n{BOLD}{GREEN}{'=' * 68}{RESET}")
    print(f"{BOLD}{GREEN}  BULLETIN GENERATED & QA-VERIFIED{RESET}")
    print(f"{BOLD}{GREEN}{'=' * 68}{RESET}")
    print(f"  {CYAN}Folder:{RESET}        {outdir.resolve()}")
    print(f"  {CYAN}Bulletin PDF:{RESET}  {path.name}")
    print(f"  {CYAN}IOC sheet:{RESET}     {ioc_path.name} (SHA-256: {file_hash[:16]}...)")
    print(f"  {DIM}{len(signals)} signals | {len({s.source for s in signals})} sources | {len(scored)} sectors | Window: {args.days} days{RESET}")
    print(f"{BOLD}{GREEN}{'=' * 68}{RESET}\n")


def cmd_pulse(args):
    from core.pulse import build_threat_pulse
    from core.scoring_multi import rank_sectors_multi
    db.init_signals()
    signals = _load_signals(args.days)
    if not signals:
        print(f"\n{YELLOW}No signals yet. Run: python main.py collect{RESET}\n")
        return

    scored = rank_sectors_multi(signals)
    ist = timezone(timedelta(hours=5, minutes=30))
    now_ist = datetime.now(ist)
    stamp = now_ist.strftime("%Y-%m-%d")
    month_name = now_ist.strftime("%b")
    date_folder = now_ist.strftime("%m-%d-%Y")

    if not getattr(args, "outdir", "") or args.outdir == "output":
        outdir = Path("output") / month_name / date_folder
    else:
        outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    pulse_path = outdir / f"India_Threat_Pulse_{stamp}.pdf"

    from core.iocs import export_iocs_csv
    public_csv_path = outdir / f"IOCs_India_Threat_Landscape_Public_{stamp}.csv"
    export_iocs_csv(signals, str(public_csv_path), public_mode=True)

    prep_by = getattr(args, "prepared_by", "") or os.getenv("ANALYST_NAME", "Siva prasad Boddu")
    build_threat_pulse(
        output_path=str(pulse_path), signals=signals, scored_sectors=scored,
        window_days=args.days, prepared_by=prep_by, public_csv_path=str(public_csv_path)
    )

    print(f"\n{BOLD}{GREEN}{'=' * 68}{RESET}")
    print(f"{BOLD}{GREEN}  INDIA THREAT PULSE GENERATED (1-PAGE EXECUTIVE BRIEF){RESET}")
    print(f"{BOLD}{GREEN}{'=' * 68}{RESET}")
    print(f"  {CYAN}Output File:{RESET}       {pulse_path.resolve()} (Strictly 1 page)")
    print(f"  {CYAN}Classification:{RESET}    TLP:CLEAR (Public Intelligence)")
    print(f"  {CYAN}Confidence:{RESET}        Admiralty B2 / Moderate Confidence")
    print(f"  {DIM}{len(signals)} signals | {len(scored)} sectors | Window: {args.days} days{RESET}")
    print(f"{BOLD}{GREEN}{'=' * 68}{RESET}\n")


def cmd_certin(args):
    mapped = map_to_annexure(args.incident, sector=args.sector)
    print(f"\n{BOLD}CERT-In Annexure I mapping{RESET}")
    print(f"{DIM}{'-' * 72}{RESET}")
    if not mapped:
        print(f"  {YELLOW}No category matched. Review Annexure I directly - "
              f"this does not mean the incident is unreportable.{RESET}\n")
        return
    for m in mapped:
        marker = GREEN if m["source"] == "text match" else DIM
        print(f"\n  {marker}({m['roman']}){RESET} {m['title']}")
        if m["matched_keywords"]:
            print(f"      {DIM}matched: {', '.join(m['matched_keywords'][:6])}{RESET}")
        else:
            print(f"      {DIM}{m['source']}{RESET}")
    print(f"\n{CYAN}Standing obligations{RESET}")
    for item in obligations_summary(args.sector):
        print(f"  {item['obligation']}")
        print(f"    {DIM}{item['detail']}{RESET}")
    print(f"\n{DIM}{DISCLAIMER}{RESET}\n")


def cmd_clock(args):
    try:
        noticed = datetime.fromisoformat(args.noticed.replace("/", "-"))
    except ValueError:
        print(f"\n{RED}Could not parse '{args.noticed}'. Use YYYY-MM-DD HH:MM{RESET}\n")
        sys.exit(1)
    if noticed.tzinfo is None:
        ist = timezone(timedelta(hours=5, minutes=30))
        noticed = noticed.replace(tzinfo=ist)
        print(f"\n{DIM}Interpreting '{args.noticed}' as IST. "
              f"Append +00:00 for UTC.{RESET}")
    result = reporting_deadline(noticed)
    print(f"\n{BOLD}CERT-In 6-hour reporting clock{RESET}")
    print(f"{DIM}{'-' * 60}{RESET}")
    print(f"  Noticed at    {result['noticed_at_ist']}")
    print(f"  Deadline      {result['deadline_ist']}")
    if result["breached"]:
        print(f"  {RED}Status        WINDOW PASSED "
              f"({abs(result['hours_remaining']):.1f} hours ago){RESET}")
        print(f"  {YELLOW}Report immediately and document the delay.{RESET}")
    else:
        colour = RED if result["hours_remaining"] < 2 else YELLOW
        print(f"  {colour}Status        {result['hours_remaining']:.1f} hours remaining{RESET}")
    retention = log_retention_floor()
    print(f"\n  {DIM}Retain logs from {retention['retain_from']} onward "
          f"({retention['rolling_days']} rolling days, {retention['jurisdiction']}).{RESET}")
    print(f"\n{DIM}{DISCLAIMER}{RESET}\n")


def cmd_stats(args):
    db.init_db(); db.init_signals()
    s = db.signal_stats()
    print(f"\n{BOLD}Signal store{RESET}")
    print(f"  total signals              {s['total_signals']}")
    print(f"  distinct sources           {s['distinct_sources']}")
    print(f"  high India relevance       {s['high_relevance']}")
    if s["by_type"]:
        print(f"\n{CYAN}By signal type{RESET}")
        for stype, count in sorted(s["by_type"].items(), key=lambda x: -x[1]):
            print(f"  {stype:<22} {count}")
    print()


HEALTH_COLOR = {"OK": GREEN, "MANUAL": DIM, "DEGRADED": YELLOW, "NOT COLLECTED": DIM,
                "NO KEY": DIM, "STALE": YELLOW, "FAILING": RED}


def cmd_health(args):
    from core.health import problems, source_health
    db.init_db(); db.init_signals()
    rows = source_health()
    print(f"\n{BOLD}Source health{RESET}  {DIM}(last collected = last run that did not fail; "
          f"newest record = most recent item from the feed){RESET}")
    print(f"{DIM}{'-' * 96}{RESET}")
    print(f"  {'status':<14}{'feed':<20}{'last collected':<16}{'newest record':<16}{'limit':<8}last error")
    for r in rows:
        colour = HEALTH_COLOR.get(r["status"], "")
        limit = f"{r['max_age_days']}d" if r["max_age_days"] else "-"
        print(f"  {colour}{r['status']:<14}{RESET}{r['collector']:<20}{r['last_collected'] or '-':<16}"
              f"{r['newest_record'] or '-':<16}{limit:<8}{DIM}{r['last_error'][:40]}{RESET}")
    bad = problems(rows)
    no_key = [r["collector"] for r in rows if r["status"] == "NO KEY"]
    print()
    if no_key:
        print(f"  {DIM}{len(no_key)} feed(s) not configured on this machine (no API key, not counted "
              f"as a problem): {', '.join(no_key)}{RESET}")
    if bad:
        print(f"  {RED}{len(bad)} feed(s) failing or stale{RESET}: {', '.join(r['collector'] for r in bad)}\n")
        if args.fail_on_problems:
            sys.exit(1)
    else:
        print(f"  {GREEN}All collected feeds are current.{RESET}\n")


def cmd_backtest(args):
    from core.backtest import report_markdown, run_backtest, weight_sensitivity
    from core.scoring_multi import rank_sectors_multi
    db.init_signals()
    results = run_backtest(window_days=args.window, horizon_days=args.horizon, step_days=args.step)
    if not results["anchors"]:
        print(f"\n{YELLOW}Not enough victim history to backtest.{RESET}\n")
        return
    s = results["summary"]
    print(f"\n{BOLD}Scoring backtest{RESET}  {DIM}{len(results['anchors'])} anchors, "
          f"{results['settings']['first_anchor']} to {results['settings']['last_anchor']}, "
          f"{args.window}-day look-back, {args.horizon}-day outcome{RESET}")
    print(f"  {'ranking':<38}{'Spearman rho':>14}{'capture@3':>12}")
    labels = {"model": "this model", "model_no_cii": "activity score (no criticality)",
              "recent_victims": "recent victims only", "cii_only": "CII designation only",
              "random": "random (expected)"}
    for key, label in labels.items():
        m = s[key]
        print(f"  {label:<38}{str(m['spearman']):>14}{str(m['capture3']):>12}")
    print(f"\n  Model beat the recent-victims baseline at {s['model_beats_recent']} of "
          f"{len(results['anchors'])} anchors; anchors with data for all components: "
          f"{s['anchors_with_all_components']}.")
    if args.write:
        scored = rank_sectors_multi(_load_signals(60))
        text = report_markdown(results, weight_sensitivity(scored), "current 60-day ranking")
        Path(args.write).parent.mkdir(parents=True, exist_ok=True)
        Path(args.write).write_text(text, encoding="utf-8")
        print(f"  Report written to {args.write}")
    print()


def cmd_export(args):
    from core.export import actionable, to_misp_event, to_stix_bundle, write_json
    from core.iocs import extract_iocs
    db.init_signals()
    signals = _load_signals(args.days)
    stamp = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y-%m-%d")
    all_iocs = extract_iocs(signals, public_mode=args.public, as_of=stamp)
    iocs = actionable(all_iocs, args.include_expired)
    expired = len(all_iocs) - len(actionable(all_iocs))
    if not iocs:
        reason = (f"all {expired} indicators expired before {stamp}; refresh the feeds, "
                  f"or pass --include-expired for a historical export") if expired else \
            f"no indicators in the last {args.days} days"
        print(f"\n{YELLOW}Nothing exported: {reason}.{RESET}\n")
        return
    producer = args.prepared_by or os.getenv("ANALYST_NAME", "") or "India Threat Landscape"
    edition = "Public" if args.public else "Internal"
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    written = []
    if args.format in ("stix", "both"):
        path = outdir / f"IOCs_India_Threat_Landscape_{edition}_{stamp}.stix.json"
        written.append(write_json(to_stix_bundle(iocs, producer, args.public, include_expired=True), str(path)))
    if args.format in ("misp", "both"):
        path = outdir / f"IOCs_India_Threat_Landscape_{edition}_{stamp}.misp.json"
        written.append(write_json(to_misp_event(iocs, producer, args.public, stamp, include_expired=True), str(path)))
    print(f"\n{GREEN}Exported {len(iocs)} indicators{RESET}"
          + (f" ({expired} expired left out; --include-expired keeps them)" if expired and not args.include_expired
             else f" ({expired} of them expired)" if expired else ""))
    for path in written:
        print(f"  {path}")
    print()


def cmd_validate(args):
    from core.validate import validate_data_files
    results = validate_data_files()
    if not results:
        print(f"\n{GREEN}All data files are valid.{RESET}\n")
        return
    print()
    for name, found in results.items():
        print(f"{RED}{name}{RESET}")
        for problem in found:
            print(f"  - {problem}")
    print()
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="India Threat Landscape Intelligence (multi-source)")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("sources"); p.set_defaults(func=cmd_sources)

    p = sub.add_parser("collect")
    p.add_argument("--days", type=int, default=14)
    p.add_argument("--only", default="")
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("sectors")
    p.add_argument("--days", type=int, default=60)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_sectors)

    p = sub.add_parser("correlate")
    p.add_argument("--days", type=int, default=60)
    p.set_defaults(func=cmd_correlate)

    p = sub.add_parser("bulletin")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--outdir", default="output")
    p.add_argument("--org", default="")
    p.add_argument("--prepared-by", "--by", default="Siva prasad Boddu", dest="prepared_by")
    p.add_argument("--analyst", default="")
    p.add_argument("--public", action="store_true", help="Generate public edition with TLP:CLEAR and victim anonymization")
    p.set_defaults(func=cmd_bulletin)

    p = sub.add_parser("pulse")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--outdir", default="output")
    p.add_argument("--prepared-by", "--by", default="Siva prasad Boddu", dest="prepared_by")
    p.set_defaults(func=cmd_pulse)

    p = sub.add_parser("certin")
    p.add_argument("--incident", required=True)
    p.add_argument("--sector", default=None, choices=list(SECTORS))
    p.set_defaults(func=cmd_certin)

    p = sub.add_parser("clock")
    p.add_argument("--noticed", required=True)
    p.set_defaults(func=cmd_clock)

    p = sub.add_parser("stats"); p.set_defaults(func=cmd_stats)

    p = sub.add_parser("health", help="feed freshness and failures")
    p.add_argument("--fail-on-problems", action="store_true",
                   help="exit with code 1 when a feed is failing or stale (for CI)")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("backtest", help="test sector rankings against later victims")
    p.add_argument("--window", type=int, default=60, help="look-back days scored at each anchor")
    p.add_argument("--horizon", type=int, default=30, help="days of outcomes after each anchor")
    p.add_argument("--step", type=int, default=30, help="days between anchors")
    p.add_argument("--write", default="", help="write a Markdown report, e.g. docs/BACKTEST.md")
    p.set_defaults(func=cmd_backtest)

    p = sub.add_parser("export", help="IOC sheet as STIX 2.1 and/or MISP JSON")
    p.add_argument("--format", choices=["stix", "misp", "both"], default="both")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--public", action="store_true", help="public edition (TLP:CLEAR)")
    p.add_argument("--outdir", default="exports")
    p.add_argument("--prepared-by", "--by", default="", dest="prepared_by")
    p.add_argument("--include-expired", action="store_true",
                   help="also export indicators past their expiry date (not marked for detection)")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("validate", help="check the hand-maintained data files")
    p.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    if not args.command:
        parser.print_help(); sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}"); sys.exit(130)
