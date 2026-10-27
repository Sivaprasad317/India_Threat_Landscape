"""
Backtest: do higher-ranked sectors go on to see more victims?

For a series of past anchor dates T, the model scores sectors using only
signals observed on or before T (no look-ahead), and the ranking is compared
with what happened next: the number of distinct organisations per sector
named on ransomware leak sites in the following `horizon` days.

Compared against three baselines:

  recent victims   rank by victim organisations in the same look-back window
                   (the single-source model this project started from)
  CII only         rank by Section 70A criticality alone (a static prior)
  random           expected value of a random ranking

Metrics per anchor, averaged across anchors:

  Spearman rho     rank correlation between score and next-period victims
                   across all sectors (1 = perfect order, 0 = no relation)
  capture@3        share of next-period victim organisations that fell in
                   the three sectors ranked highest

Caveat printed with every result: the outcome is leak-site postings, which
are a biased sample of real incidents, and early history only contains
some signal types, so a component with no history cannot be tested yet.
"""

from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from .database import DEFAULT_DB, connect, get_signals
from .scoring_multi import COMPONENT_TYPES, COMPONENT_WEIGHTS, rank_sectors_multi
from .sectors import SECTORS, clean_victim_name, is_nciipc_critical
from .signals import Signal, SignalType

IST = timezone(timedelta(hours=5, minutes=30))
SCORED_SECTORS = [k for k in SECTORS if k != "UNCLASSIFIED"]
VICTIM_TYPES = (SignalType.VICTIM, SignalType.DATA_LEAK)


def _end_of_day(d: date) -> datetime:
    return datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=IST)


def _ranks(values: List[float]) -> List[float]:
    """Average ranks (1 = smallest), ties share their mean rank."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2.0 + 1
        i = j + 1
    return ranks


def spearman(x: List[float], y: List[float]) -> Optional[float]:
    """Spearman rank correlation; None when either side has no variation."""
    if len(set(x)) < 2 or len(set(y)) < 2:
        return None
    rx, ry = _ranks(x), _ranks(y)
    n = len(x)
    mx, my = sum(rx) / n, sum(ry) / n
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    vx = sum((a - mx) ** 2 for a in rx) ** 0.5
    vy = sum((b - my) ** 2 for b in ry) ** 0.5
    return round(cov / (vx * vy), 3)


def kendall_tau(a: List[str], b: List[str]) -> float:
    """Kendall tau between two orderings of the same items."""
    pos = {item: i for i, item in enumerate(b)}
    items = [i for i in a if i in pos]
    n = len(items)
    if n < 2:
        return 1.0
    concordant = discordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            if pos[items[i]] < pos[items[j]]:
                concordant += 1
            else:
                discordant += 1
    return round((concordant - discordant) / (n * (n - 1) / 2), 3)


def capture_at_k(scores: Dict[str, float], actual: Dict[str, int], k: int = 3) -> Optional[float]:
    total = sum(actual.values())
    if not total:
        return None
    top = sorted(SCORED_SECTORS, key=lambda s: (-scores.get(s, 0.0), s))[:k]
    return round(sum(actual.get(s, 0) for s in top) / total, 3)


def victim_orgs_by_sector(signals: List[Signal]) -> Dict[str, int]:
    orgs: Dict[str, set] = defaultdict(set)
    for s in signals:
        if s.signal_type not in VICTIM_TYPES:
            continue
        name = clean_victim_name(s.entities.organisations[0] if s.entities.organisations else s.title).lower()
        for sec in s.sectors:
            if sec in SCORED_SECTORS:
                orgs[sec].add(name)
    return {sec: len(v) for sec, v in orgs.items()}


def evaluate_anchor(anchor: date, window_days: int = 60, horizon_days: int = 30,
                    db_path: str = DEFAULT_DB) -> Optional[Dict]:
    past = [Signal.from_row(r) for r in get_signals(days=window_days, end_date=anchor, db_path=db_path)]
    future_rows = get_signals(days=horizon_days, end_date=anchor + timedelta(days=horizon_days), db_path=db_path)
    future = [Signal.from_row(r) for r in future_rows if (r["observed_at"] or "")[:10] > anchor.isoformat()]
    actual = victim_orgs_by_sector(future)
    if not sum(actual.values()):
        return None

    scored = rank_sectors_multi(past, anchor_dt=_end_of_day(anchor))
    model = {s["sector"]: s["risk_score"] for s in scored}
    # Same model with the criticality weight removed and the rest renormalised
    no_cii_w = {c: w for c, w in COMPONENT_WEIGHTS.items() if c != "criticality"}
    total_w = sum(no_cii_w.values())
    model_no_cii = {s["sector"]: sum(s["components"][c] * w / total_w for c, w in no_cii_w.items())
                    for s in scored}
    recent = victim_orgs_by_sector(past)
    cii = {s: (1.0 if is_nciipc_critical(s) else 0.0) for s in SCORED_SECTORS}

    present = sorted(c for c, types in COMPONENT_TYPES.items()
                     if any(s.signal_type in types for s in past))
    y = [float(actual.get(s, 0)) for s in SCORED_SECTORS]

    def metrics(scores: Dict[str, float]) -> Dict:
        return {"spearman": spearman([scores.get(s, 0.0) for s in SCORED_SECTORS], y),
                "capture3": capture_at_k(scores, actual)}

    return {
        "anchor": anchor.isoformat(),
        "past_signals": len(past),
        "future_victims": int(sum(actual.values())),
        "components_with_data": present,
        "model": metrics(model),
        "model_no_cii": metrics(model_no_cii),
        "recent_victims": metrics({k: float(v) for k, v in recent.items()}),
        "cii_only": metrics(cii),
        "model_top3": sorted(SCORED_SECTORS, key=lambda s: (-model.get(s, 0.0), s))[:3],
        "actual_top3": sorted(SCORED_SECTORS, key=lambda s: (-actual.get(s, 0), s))[:3],
    }


def data_range(db_path: str = DEFAULT_DB) -> Tuple[Optional[date], Optional[date]]:
    """First and last dates with victim postings."""
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT MIN(observed_at) lo, MAX(observed_at) hi FROM signals "
            "WHERE signal_type IN ('victim', 'data_leak')").fetchone()
    if not row or not row["lo"]:
        return None, None
    return date.fromisoformat(row["lo"][:10]), date.fromisoformat(row["hi"][:10])


def _mean(values: List[Optional[float]]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 3) if vals else None


def run_backtest(start: Optional[date] = None, end: Optional[date] = None,
                 step_days: int = 30, window_days: int = 60, horizon_days: int = 30,
                 db_path: str = DEFAULT_DB) -> Dict:
    lo, hi = data_range(db_path)
    if not hi:
        return {"anchors": [], "summary": {}, "settings": {}}
    last_anchor = hi - timedelta(days=horizon_days)
    end = min(end or last_anchor, last_anchor)
    start = start or (end - timedelta(days=step_days * 23))

    anchors = []
    t = end
    while t >= start:
        anchors.append(t)
        t -= timedelta(days=step_days)
    rows = [r for r in (evaluate_anchor(a, window_days, horizon_days, db_path) for a in sorted(anchors)) if r]

    summary = {}
    for name in ("model", "model_no_cii", "recent_victims", "cii_only"):
        summary[name] = {"spearman": _mean([r[name]["spearman"] for r in rows]),
                         "capture3": _mean([r[name]["capture3"] for r in rows])}
    summary["random"] = {"spearman": 0.0, "capture3": round(3 / len(SCORED_SECTORS), 3)}
    summary["model_beats_recent"] = sum(
        1 for r in rows
        if r["model"]["spearman"] is not None and r["recent_victims"]["spearman"] is not None
        and r["model"]["spearman"] > r["recent_victims"]["spearman"])
    full = [r for r in rows if len(r["components_with_data"]) == len(COMPONENT_TYPES)]
    summary["anchors_with_all_components"] = len(full)

    return {
        "settings": {"window_days": window_days, "horizon_days": horizon_days, "step_days": step_days,
                     "first_anchor": rows[0]["anchor"] if rows else "", "last_anchor": rows[-1]["anchor"] if rows else "",
                     "victim_data_from": lo.isoformat(), "victim_data_to": hi.isoformat()},
        "anchors": rows,
        "summary": summary,
    }


def weight_sensitivity(scored: List[Dict], factors=(0.5, 1.5)) -> List[Dict]:
    """How much the ranking moves when one component's weight changes.

    Each component's weight is multiplied by each factor and the weights are
    renormalised to sum to 1; the new ranking is compared with the original.
    """
    if not scored:
        return []
    base_order = [s["sector"] for s in scored]
    base_top3 = set(base_order[:3])
    out = []
    for comp in COMPONENT_WEIGHTS:
        for f in factors:
            w = dict(COMPONENT_WEIGHTS)
            w[comp] *= f
            total_w = sum(w.values())
            w = {k: v / total_w for k, v in w.items()}
            rescored = sorted(scored, key=lambda s: -sum(s["components"][c] * w[c] for c in w))
            order = [s["sector"] for s in rescored]
            out.append({
                "component": comp,
                "factor": f,
                "kendall_tau": kendall_tau(order, base_order),
                "top3_changed": set(order[:3]) != base_top3,
                "new_top3": order[:3],
            })
    return out


def report_markdown(results: Dict, sensitivity: List[Dict], scored_label: str) -> str:
    s = results.get("summary", {})
    cfg = results.get("settings", {})
    rows = results.get("anchors", [])
    lines = [
        "# Scoring backtest",
        "",
        f"Generated by `python main.py backtest --write`. Anchors every {cfg.get('step_days')} days from "
        f"{cfg.get('first_anchor')} to {cfg.get('last_anchor')}; each scores sectors from the previous "
        f"{cfg.get('window_days')} days of signals and is compared with the distinct organisations per sector "
        f"named on leak sites in the next {cfg.get('horizon_days')} days. Victim data in the database runs from "
        f"{cfg.get('victim_data_from')} to {cfg.get('victim_data_to')}.",
        "",
        "## Results",
        "",
        "| Ranking | Mean Spearman rho | Mean capture@3 |",
        "|---|---|---|",
    ]
    names = {"model": "This model (v2.5 weights)",
             "model_no_cii": "This model without the criticality weight (ablation)",
             "recent_victims": "Recent victims only (baseline)",
             "cii_only": "CII designation only (baseline)", "random": "Random (expected)"}
    for key, label in names.items():
        m = s.get(key, {})
        lines.append(f"| {label} | {m.get('spearman')} | {m.get('capture3')} |")
    lines += [
        "",
        f"Anchors evaluated: {len(rows)}. The model's rank correlation beat the recent-victims baseline at "
        f"{s.get('model_beats_recent', 0)} of them. Anchors where all six components had data: "
        f"{s.get('anchors_with_all_components', 0)}.",
        "",
        "## What this can and cannot show",
        "",
        "- The outcome is leak-site postings. Organisations that pay quietly never appear, so the test measures "
        "agreement with a biased sample, not with all incidents.",
        "- Most anchors only had victim history: the exploit, infrastructure, pressure and exposure components "
        "have no stored history before late August 2026, so at those anchors the model reduces to impact plus "
        "criticality. Those four components are untested until scheduled collection builds history (the daily "
        "GitHub Actions run does this); re-run this backtest as it accumulates.",
        "- 14 sectors and roughly 10-30 victims a month make every anchor noisy; read the averages, not single rows.",
        "",
        "## Per-anchor results",
        "",
        "| Anchor | Next-period victims | Components with data | Model rho | Recent-victims rho | Model top 3 | Actual top 3 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['anchor']} | {r['future_victims']} | {', '.join(r['components_with_data'])} | "
            f"{r['model']['spearman']} | {r['recent_victims']['spearman']} | "
            f"{', '.join(r['model_top3'])} | {', '.join(r['actual_top3'])} |")
    lines += [
        "",
        f"## Weight sensitivity ({scored_label})",
        "",
        "Each component's weight multiplied by 0.5 and 1.5, weights renormalised, ranking compared with the "
        "published one. Kendall tau of 1.0 means the order did not change.",
        "",
        "| Component | Weight x | Kendall tau | Top 3 changed | New top 3 |",
        "|---|---|---|---|---|",
    ]
    for row in sensitivity:
        lines.append(f"| {row['component']} | {row['factor']} | {row['kendall_tau']} | "
                     f"{'yes' if row['top3_changed'] else 'no'} | {', '.join(row['new_top3'])} |")
    lines.append("")
    return "\n".join(lines)
