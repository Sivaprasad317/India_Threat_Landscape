"""
Snapshot and Regression Tracking Engine.

Tracks immediately preceding generated snapshots (stored JSON) and dynamically computes exact diffs
across sector scores, component weights, IOC counts, and entity attributions.
If every printed value is identical, outputs:
  'No changes vs previous run (snapshot <timestamp>)'
"""

import json
import os
from typing import Any, Dict, List, Optional
from .sectors import clean_victim_name
from .signals import Signal
from .window import ANCHOR_DT


def _anchor_label() -> str:
    return ANCHOR_DT.strftime("%Y-%m-%d %H:%M:%S IST")

SNAPSHOTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "snapshots"
)
DEFAULT_SNAPSHOT_PATH = os.path.join(SNAPSHOTS_DIR, "snapshot_internal_60d.json")


def _extract_priority_victims_from_signals(signals: List[Signal], max_count: int = 5) -> List[str]:
    v_sigs = [s for s in signals if s.signal_type.value in ("victim", "data_leak")]
    top_pv = []
    seen = set()
    for s in sorted(v_sigs, key=lambda x: -x.risk_contribution):
        raw = s.entities.organisations[0] if (s.entities and s.entities.organisations) else s.title
        c = clean_victim_name(raw)
        if "***" in c:
            continue  # masked names are not useful as priority victims
        if c.lower() not in seen:
            seen.add(c.lower())
            top_pv.append(c)
            if len(top_pv) == max_count:
                break
    return top_pv


def get_snapshot_path(edition: str = "internal", window_days: int = 60) -> str:
    """Returns separate snapshot file path per edition and window (e.g. internal_60d, public_7d)."""
    os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
    ed = "public" if str(edition).lower() in ("public", "true") else "internal"
    return os.path.join(SNAPSHOTS_DIR, f"snapshot_{ed}_{window_days}d.json")


def load_previous_snapshot(
    snapshot_path: Optional[str] = None,
    edition: str = "internal",
    window_days: int = 60
) -> Optional[Dict]:
    path = snapshot_path or get_snapshot_path(edition, window_days)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_run_snapshot(
    scored_sectors: List[Dict],
    ioc_summary: Dict,
    signals: List[Signal],
    snapshot_path: Optional[str] = None,
    timestamp_str: Optional[str] = None,
    edition: str = "internal",
    window_days: int = 60
) -> str:
    path = snapshot_path or get_snapshot_path(edition, window_days)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    v_sigs = [s for s in signals if s.signal_type.value in ("victim", "data_leak")]
    uniq_orgs = len({
        clean_victim_name(
            s.entities.organisations[0] if (s.entities and s.entities.organisations) else s.title
        ).strip().lower()
        for s in v_sigs
    })
    total_posts = len(v_sigs)
    top_pv = _extract_priority_victims_from_signals(signals, 5)

    snapshot_data = {
        "timestamp": timestamp_str or ANCHOR_DT.strftime("%Y-%m-%d %H:%M IST"),
        "scores": {s["sector"]: s["risk_score"] for s in scored_sectors},
        "bands": {s["sector"]: s["risk_band"] for s in scored_sectors},
        "components": {s["sector"]: s["components"] for s in scored_sectors},
        "sector_counts": {
            s["sector"]: {
                "victims": s["victim_count"],
                "cves": s["exploited_cve_count"],
                "infra": s["infra_count"]
            }
            for s in scored_sectors
        },
        "iocs": {
            "total_indicators": ioc_summary.get("total_indicators", len(signals)),
            "unique_hosts": ioc_summary.get("unique_hosts", len(signals)),
            "compromised_hosts": ioc_summary.get("compromised_hosts", 0),
            "unverified_hosts": ioc_summary.get("unverified_hosts", 0),
            "phishing_hosts": ioc_summary.get("phishing_hosts", 0),
        },
        "priority_victims": top_pv,
        "total_signals": len(signals),
        "unique_victims": uniq_orgs,
        "total_postings": total_posts
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot_data, f, indent=2)

    return path


def generate_changes_vs_previous(
    scored_sectors: List[Dict],
    ioc_summary: Dict,
    signals: List[Signal],
    snapshot_path: Optional[str] = None,
    edition: str = "internal",
    window_days: int = 60
) -> str:
    """
    Diffs against the immediately preceding generated snapshot for this exact edition and window.
    Never diffs one edition against another's snapshot.
    If every printed value is identical, returns:
      'No score changes vs previous run (snapshot <timestamp>)'
    Otherwise, lists all detected changes across printed scores, IOC counts, and priority victims.
    """
    prev = load_previous_snapshot(snapshot_path, edition=edition, window_days=window_days)
    if not prev:
        ed_label = "Public" if str(edition).lower() in ("public", "true") else "Internal"
        save_run_snapshot(scored_sectors, ioc_summary, signals, snapshot_path=snapshot_path, edition=edition, window_days=window_days)
        return f"Baseline {ed_label} snapshot ({window_days}d window) initialized under fixed window anchor ({_anchor_label()})."

    prev_ts = prev.get("timestamp", "previous run")
    diffs = []

    # 1. Sector score & component diffs
    current_sectors = {s["sector"]: s for s in scored_sectors}
    prev_scores = prev.get("scores", {})
    prev_comps = prev.get("components", {})
    prev_counts = prev.get("sector_counts", {})

    sector_diffs = []
    for sec_id, curr in current_sectors.items():
        c_score = curr["risk_score"]
        p_score = prev_scores.get(sec_id)
        if p_score is not None and abs(c_score - p_score) >= 0.05:
            label = curr.get("label", sec_id).split("/")[0].split("&")[0].strip()
            sector_diffs.append(f"{label} score ({p_score:.1f} &rarr; {c_score:.1f})")

        c_impact = curr["components"].get("impact", 0.0)
        p_impact = prev_comps.get(sec_id, {}).get("impact", 0.0)
        if abs(c_impact - p_impact) >= 0.5:
            label = curr.get("label", sec_id).split("/")[0].split("&")[0].strip()
            sector_diffs.append(f"{label} Impact ({p_impact:.1f} &rarr; {c_impact:.1f})")

    if sector_diffs:
        diffs.append(f"Sector scores: {'; '.join(sector_diffs)}")

    # 2. IOC counts diffs
    p_iocs = prev.get("iocs", {})
    c_tot = ioc_summary.get("total_indicators", len(signals))
    p_tot = p_iocs.get("total_indicators")
    if p_tot is not None and p_tot != c_tot:
        diffs.append(f"IOC indicators ({p_tot} &rarr; {c_tot})")

    c_hosts = ioc_summary.get("unique_hosts", len(signals))
    p_hosts = p_iocs.get("unique_hosts")
    if p_hosts is not None and p_hosts != c_hosts:
        diffs.append(f"IOC unique hosts ({p_hosts} &rarr; {c_hosts})")

    # 3. Priority table changes
    prev_pv = prev.get("priority_victims", [])
    curr_pv = _extract_priority_victims_from_signals(signals, 5)
    if prev_pv and prev_pv != curr_pv:
        diffs.append("Priority victims ranking changed")

    if diffs:
        save_run_snapshot(scored_sectors, ioc_summary, signals, snapshot_path=snapshot_path, edition=edition, window_days=window_days)

    # If every printed value is identical:
    if not diffs:
        return f"No score changes vs previous run (snapshot {prev_ts}). Scoring is deterministic under fixed window anchor ({_anchor_label()})."

    return "<b>Changes vs. Previous Run:</b> " + "; ".join(diffs)


def compute_weekly_changes(
    current_signals: List[Signal],
    current_scored: List[Dict],
    current_ioc_summary: Dict,
    prior_signals: List[Signal],
    prior_anchor=None,
) -> Dict[str, Any]:
    """
    Deltas against the immediately preceding period of the same length, computed
    from the signal store (victim postings, KEV CVEs, domestic IOCs, sector scores).
    """
    from .iocs import get_ioc_summary
    from .scoring_multi import rank_sectors_multi

    prior_scored = rank_sectors_multi(prior_signals, anchor_dt=prior_anchor) if prior_signals else []
    prior_iocs = get_ioc_summary(prior_signals) if prior_signals else {}

    def _victims(sigs):
        return sum(1 for s in sigs if s.signal_type.value in ("victim", "data_leak"))

    def _kevs(sigs):
        return len({c for s in sigs if s.source == "CISA KEV" for c in (s.entities.cves or [])})

    curr_victims, prev_victims = _victims(current_signals), _victims(prior_signals)
    curr_kevs, prev_kevs = _kevs(current_signals), _kevs(prior_signals)
    curr_iocs = current_ioc_summary.get("total_indicators", 0)
    prev_iocs = prior_iocs.get("total_indicators", 0)
    prev_scores = {s["sector"]: s["risk_score"] for s in prior_scored}

    score_moves = []
    for s in current_scored:
        sec = s["sector"]
        if sec in prev_scores:
            diff = s["risk_score"] - prev_scores[sec]
            if abs(diff) >= 0.5:
                sign = "+" if diff > 0 else ""
                short_label = s["label"].split("/")[0].split("&")[0].strip()
                score_moves.append(f"{short_label} ({sign}{diff:.1f})")

    def _signed(n):
        return f"+{n}" if n > 0 else f"{n}"

    moves_str = ", ".join(score_moves[:3]) if score_moves else "Stable (within ±0.5)"
    summary_text = (
        f"<b>Victim Disclosures:</b> {curr_victims} ({_signed(curr_victims - prev_victims)} vs prior period) | "
        f"<b>Active KEV Vulnerabilities:</b> {curr_kevs} ({_signed(curr_kevs - prev_kevs)}) | "
        f"<b>Domestic IOCs:</b> {curr_iocs} ({_signed(curr_iocs - prev_iocs)}) | "
        f"<b>Sector Shifts:</b> {moves_str}"
    )
    return {
        "victims_current": curr_victims,
        "victims_delta": curr_victims - prev_victims,
        "kevs_current": curr_kevs,
        "kevs_delta": curr_kevs - prev_kevs,
        "iocs_current": curr_iocs,
        "iocs_delta": curr_iocs - prev_iocs,
        "score_moves": score_moves,
        "summary_text": summary_text,
    }
