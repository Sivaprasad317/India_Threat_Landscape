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
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from core import database as db
from core.certin import (DISCLAIMER, log_retention_floor, map_to_annexure,
                         obligations_summary, reporting_deadline)
from core.sectors import SECTORS, sector_label
from core.signals import Signal

load_dotenv()

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
    print(f"  {GREEN}{result['corroborated_count']} signals corroborated by "
          f"a second source{RESET}")

    if result["exploit_victim_links"]:
        print(f"\n{CYAN}Exploited CVE meeting live victim activity{RESET}")
        print(f"{DIM}  A known way in, plus proof it is being used against "
              f"that sector now.{RESET}")
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
            print(f"  {item['artefact'][:44]:<46} {item['source_count']} sources  "
                  f"{DIM}{', '.join(item['signal_types'][:3])}{RESET}")

    if result["actor_chains"]:
        print(f"\n{CYAN}Actors appearing across signal types{RESET}")
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

    args = parser.parse_args()
    if not args.command:
        parser.print_help(); sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}"); sys.exit(130)
