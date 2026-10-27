"""
India threat bulletin, rendered to PDF.

Layout note: line breaking uses wordWrap="CJK" on monospace styles. Do not
inject spaces or zero-width characters to force wrapping — it renders fine
but corrupts the PDF text layer, which breaks copy-paste and downstream
parsers.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from .certin import (DIRECTION_REF, DIRECTION_URL, DISCLAIMER,
                     REPORTING_EMAIL, REPORTING_PHONE, ANNEXURE_I,
                     obligations_summary)
from .sectors import sector_label

BAND_COLORS = {
    "Critical": (colors.HexColor("#501313"), colors.HexColor("#F7C1C1")),
    "High": (colors.HexColor("#791F1F"), colors.HexColor("#F09595")),
    "Moderate": (colors.HexColor("#633806"), colors.HexColor("#FAC775")),
    "Low": (colors.HexColor("#854F0B"), colors.HexColor("#FAEEDA")),
    "Minimal": (colors.HexColor("#27500A"), colors.HexColor("#C0DD97")),
}

DIRECTION_ARROW = {"rising": "up", "falling": "down",
                   "steady": "flat", "new": "new"}


def _esc(text) -> str:
    return (str(text).replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;"))


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("BTitle", parent=base["Title"],
                                fontName="Helvetica-Bold", fontSize=17,
                                leading=21, alignment=TA_LEFT, spaceAfter=4,
                                textColor=colors.HexColor("#111111")),
        "sub": ParagraphStyle("BSub", parent=base["Normal"],
                              fontName="Helvetica", fontSize=9.5, leading=13,
                              textColor=colors.HexColor("#5F5E5A")),
        "h2": ParagraphStyle("BH2", parent=base["Normal"],
                             fontName="Helvetica-Bold", fontSize=12,
                             leading=16, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("BBody", parent=base["Normal"],
                               fontName="Helvetica", fontSize=9.5, leading=13.5),
        "small": ParagraphStyle("BSmall", parent=base["Normal"],
                                fontName="Helvetica", fontSize=8, leading=11,
                                textColor=colors.HexColor("#5F5E5A")),
        "cell": ParagraphStyle("BCell", parent=base["Normal"],
                               fontName="Helvetica", fontSize=8.5, leading=11.5,
                               wordWrap="CJK", splitLongWords=True),
        "cellb": ParagraphStyle("BCellB", parent=base["Normal"],
                                fontName="Helvetica-Bold", fontSize=8.5,
                                leading=11.5, wordWrap="CJK",
                                splitLongWords=True),
    }


def _band_chip(band: str, st) -> Paragraph:
    fg, bg = BAND_COLORS.get(band, BAND_COLORS["Minimal"])
    return Paragraph(
        f'<font color="{fg.hexval()}"><b>{band}</b></font>', st["cell"])


def _table(rows, widths, st, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EFEDE6")))
    t.setStyle(TableStyle(style))
    return t


def build_bulletin(output_path: str, scored_sectors: List[Dict],
                   victims: List[Dict], groups: List[Dict],
                   window_days: int, movements: Optional[Dict] = None,
                   org_name: str = "", analyst: str = "",
                   collection_note: str = "") -> str:
    movements = movements or {}
    st = _styles()
    now = datetime.now(timezone.utc)
    ist = timezone(timedelta(hours=5, minutes=30))
    period_start = (now - timedelta(days=window_days)).strftime("%d %b %Y")
    period_end = now.strftime("%d %b %Y")

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title="India Threat Landscape Bulletin", author="Threat Research")

    story = []

    # ---------------- Header ----------------
    story.append(Paragraph("India Threat Landscape Bulletin", st["title"]))
    meta = [f"Reporting period: {period_start} to {period_end} ({window_days} days)",
            f"Generated: {now.astimezone(ist).strftime('%d %b %Y %H:%M IST')}"]
    if org_name:
        meta.insert(0, f"Prepared for: {org_name}")
    if analyst:
        meta.append(f"Analyst: {analyst}")
    story.append(Paragraph(" &nbsp;·&nbsp; ".join(_esc(m) for m in meta), st["sub"]))
    story.append(Spacer(1, 10))

    # ---------------- Summary numbers ----------------
    critical_victims = sum(1 for v in victims if v.get("nciipc_critical"))
    top_band = scored_sectors[0]["risk_band"] if scored_sectors else "n/a"
    summary_rows = [[
        Paragraph("<b>Indian victims</b><br/>" + str(len(victims)), st["cell"]),
        Paragraph("<b>Threat groups</b><br/>" + str(len(groups)), st["cell"]),
        Paragraph("<b>Sectors affected</b><br/>"
                  + str(len({v.get("sector") for v in victims})), st["cell"]),
        Paragraph("<b>Critical infrastructure</b><br/>" + str(critical_victims),
                  st["cell"]),
        Paragraph("<b>Highest sector risk</b><br/>" + top_band, st["cell"]),
    ]]
    story.append(_table(summary_rows, [35 * mm] * 5, st, header=False))
    story.append(Spacer(1, 4))
    if collection_note:
        story.append(Paragraph(_esc(collection_note), st["small"]))

    # ---------------- Sector risk ----------------
    story.append(Paragraph("Sector risk ranking", st["h2"]))
    story.append(Paragraph(
        "Scores are relative to observed activity in this window, not absolute "
        "probabilities. A sector ranks high when many Indian organisations in "
        "it were hit, by many different groups, recently.", st["small"]))
    story.append(Spacer(1, 5))

    rows = [[Paragraph("<b>Sector</b>", st["cellb"]),
             Paragraph("<b>Score</b>", st["cellb"]),
             Paragraph("<b>Band</b>", st["cellb"]),
             Paragraph("<b>Victims</b>", st["cellb"]),
             Paragraph("<b>Groups</b>", st["cellb"]),
             Paragraph("<b>Trend</b>", st["cellb"]),
             Paragraph("<b>CII</b>", st["cellb"])]]
    for s in scored_sectors:
        mv = movements.get(s["sector"], {})
        trend = DIRECTION_ARROW.get(mv.get("direction", "new"), "new")
        if mv.get("delta_score") is not None:
            trend = f"{trend} ({mv['delta_score']:+.1f})"
        rows.append([
            Paragraph(_esc(s["label"]), st["cell"]),
            Paragraph(f"{s['risk_score']:.1f}", st["cell"]),
            _band_chip(s["risk_band"], st),
            Paragraph(str(s["victim_count"]), st["cell"]),
            Paragraph(str(s["group_count"]), st["cell"]),
            Paragraph(_esc(trend), st["cell"]),
            Paragraph("Yes" if s["nciipc_critical"] else "-", st["cell"]),
        ])
    story.append(_table(rows, [52*mm, 15*mm, 20*mm, 17*mm, 17*mm, 26*mm, 13*mm], st))

    # ---------------- Sector detail ----------------
    if scored_sectors:
        story.append(Paragraph("Assessment by sector", st["h2"]))
        for s in scored_sectors[:6]:
            block = [
                Paragraph(f"<b>{_esc(s['label'])}</b> — {s['risk_band']} "
                          f"({s['risk_score']:.1f})", st["body"]),
                Paragraph(_esc(s["explanation"]), st["small"]),
            ]
            story.append(KeepTogether(block))
            story.append(Spacer(1, 6))

    # ---------------- Groups ----------------
    if groups:
        story.append(Paragraph("Groups active against Indian entities", st["h2"]))
        grows = [[Paragraph("<b>Group</b>", st["cellb"]),
                  Paragraph("<b>Indian victims</b>", st["cellb"]),
                  Paragraph("<b>Sectors</b>", st["cellb"]),
                  Paragraph("<b>Last observed</b>", st["cellb"])]]
        for g in groups[:15]:
            last = (g.get("last_hit") or "")[:10]
            grows.append([
                Paragraph(_esc(g.get("group_name", "unknown")), st["cell"]),
                Paragraph(str(g.get("victim_count", 0)), st["cell"]),
                Paragraph(str(g.get("sector_count", 0)), st["cell"]),
                Paragraph(_esc(last), st["cell"]),
            ])
        story.append(_table(grows, [60*mm, 30*mm, 30*mm, 40*mm], st))

    # ---------------- Victims ----------------
    if victims:
        story.append(PageBreak())
        story.append(Paragraph("Indian organisations named in this period",
                               st["h2"]))
        story.append(Paragraph(
            "Entries marked for review were identified by name or domain "
            "heuristics rather than a declared country field. Verify before "
            "acting on them.", st["small"]))
        story.append(Spacer(1, 5))

        vrows = [[Paragraph("<b>Organisation</b>", st["cellb"]),
                  Paragraph("<b>Group</b>", st["cellb"]),
                  Paragraph("<b>Sector</b>", st["cellb"]),
                  Paragraph("<b>Observed</b>", st["cellb"]),
                  Paragraph("<b>Confidence</b>", st["cellb"])]]
        for v in victims[:60]:
            conf = v.get("india_confidence", 0)
            flag = "Confirmed" if conf >= 0.9 else "Review"
            vrows.append([
                Paragraph(_esc(v.get("victim_name", ""))[:70], st["cell"]),
                Paragraph(_esc(v.get("group_name", "")), st["cell"]),
                Paragraph(_esc(sector_label(v.get("sector", "UNCLASSIFIED"))),
                          st["cell"]),
                Paragraph(_esc((v.get("discovered_at") or "")[:10]), st["cell"]),
                Paragraph(flag, st["cell"]),
            ])
        story.append(_table(vrows, [58*mm, 28*mm, 45*mm, 24*mm, 23*mm], st))

    # ---------------- CERT-In ----------------
    story.append(PageBreak())
    story.append(Paragraph("CERT-In reporting obligations", st["h2"]))
    story.append(Paragraph(
        f"Directions {_esc(DIRECTION_REF)}, issued under section 70B(6) of the "
        f"Information Technology Act, 2000.", st["small"]))
    story.append(Spacer(1, 6))

    orows = [[Paragraph("<b>Obligation</b>", st["cellb"]),
              Paragraph("<b>Requirement</b>", st["cellb"])]]
    for item in obligations_summary():
        orows.append([Paragraph(_esc(item["obligation"]), st["cell"]),
                      Paragraph(_esc(item["detail"]), st["cell"])])
    story.append(_table(orows, [38*mm, 140*mm], st))

    # Annexure categories observed
    observed = set()
    for v in victims:
        cats = v.get("annexure_categories") or []
        if isinstance(cats, str):
            try:
                import json
                cats = json.loads(cats)
            except Exception:
                cats = []
        observed.update(cats)

    if observed:
        story.append(Paragraph(
            "Annexure I categories engaged by activity in this period",
            st["h2"]))
        arows = [[Paragraph("<b>Item</b>", st["cellb"]),
                  Paragraph("<b>Category</b>", st["cellb"])]]
        for roman in ANNEXURE_I:
            if roman in observed:
                arows.append([
                    Paragraph(f"({roman})", st["cell"]),
                    Paragraph(_esc(ANNEXURE_I[roman]["title"]), st["cell"]),
                ])
        story.append(_table(arows, [16*mm, 162*mm], st))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"Reportable within 6 hours of noticing, to {_esc(REPORTING_EMAIL)} "
            f"or {_esc(REPORTING_PHONE)}.", st["body"]))

    story.append(Spacer(1, 12))
    story.append(Paragraph(_esc(DISCLAIMER), st["small"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Direction text: {_esc(DIRECTION_URL)}<br/>"
        "Victim data: ransomware.live leak-site monitoring.", st["small"]))

    doc.build(story)
    return output_path
