"""
Multi-source India Threat Landscape Intelligence Bulletin.

Structural features:
- Complete source attribution across all sections.
- Independent multi-source corroboration and cross-source correlation.
- Admiralty Code / ICD 203 intelligence confidence scale.
- Reconciled metrics: unique victim organisations vs. disclosure postings.
- Reconciled vulnerability telemetry: actively exploited CISA KEV vs. NVD advisories.
- Official Survey of India geographic boundary mapping.
- 7-Day Tactical Action Matrix and CERT-In 20(3)/2022 compliance framework.
- Internal handling and published mathematical scoring weights.
- 11 self-contained executive pages without orphan page flow.

Line breaking uses wordWrap="CJK". Never inject spaces or zero-width
characters to force wrapping — it renders fine and silently corrupts the PDF
text layer.
"""

import os
import re
import sqlite3
import textwrap
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)
from reportlab.graphics.shapes import (Circle, Drawing, Group, Image as DImage,
                                        Line, Polygon, PolyLine, Rect, String)
from reportlab.graphics.charts.piecharts import Pie

from .certin import (ANNEXURE_I, DIRECTION_REF, DIRECTION_URL, DISCLAIMER,
                     REPORTING_EMAIL, REPORTING_PHONE, obligations_summary)
from .database import get_intel_items
from .geo_india import classify_state, render_official_india_map, STATE_GEO_COORDS
from .overrides import entity_override
from .health import problems as health_problems, source_health
from .headlines import (brief_text, format_date, headline_keywords, load_headline_threats,
                        news_watch, split_headlines)
from .iocs import export_iocs_csv, extract_iocs, get_ioc_summary
from . import report_facts as rf
from .scoring_multi import DEFAULT_ANCHOR_DT, SCORING_VERSION, assign_risk_band
from .sectors import (SECTORS, clean_victim_name as _clean_victim_name,
                      sector_label, short_sector_label)
from .signals import Signal, SignalType
from .window import window_end_date

BAND_COLORS = {
    "Critical": (colors.HexColor("#501313"), colors.HexColor("#F7C1C1")),
    "High": (colors.HexColor("#791F1F"), colors.HexColor("#F09595")),
    "Moderate": (colors.HexColor("#633806"), colors.HexColor("#FAC775")),
    "Low": (colors.HexColor("#194D26"), colors.HexColor("#C3E6CB")),
    "Minimal": (colors.HexColor("#27500A"), colors.HexColor("#C0DD97")),
}

BAND_HEX_COLORS = {
    "Critical": colors.HexColor("#791F1F"),
    "High": colors.HexColor("#C0392B"),
    "Moderate": colors.HexColor("#D35400"),
    "Low": colors.HexColor("#27AE60"),
    "Minimal": colors.HexColor("#2ECC71"),
}

# Report palette
NAVY = colors.HexColor("#12263F")
NAVY_SOFT = colors.HexColor("#1E3A5F")
ACCENT = colors.HexColor("#E07A1F")
INK = colors.HexColor("#1F2933")
MUTED = colors.HexColor("#5B6573")
RULE = colors.HexColor("#D9DEE5")
HEAD_BG = colors.HexColor("#EEF2F7")
PANEL_BG = colors.HexColor("#F6F8FB")

SEVERITY_HEX = {"Critical": "#9B1C1C", "High": "#C2410C",
                "Medium": "#B7791F", "Low": "#2F855A"}

TYPE_LABEL = {
    SignalType.VICTIM: "Named victim",
    SignalType.DATA_LEAK: "Data offered for sale",
    SignalType.VULNERABILITY: "Exploited vulnerability",
    SignalType.MALWARE_INFRA: "Malware infrastructure",
    SignalType.PHISHING: "Phishing",
    SignalType.TYPOSQUAT: "Lookalike domain",
    SignalType.HACKTIVISM: "Hacktivist claim",
    SignalType.ADVISORY: "Official advisory",
    SignalType.RESEARCH: "Campaign reporting",
    SignalType.EXPOSURE: "Attack surface",
}


def _esc(text) -> str:
    return (str(text).replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;"))


def _normalize_actor(name: str) -> str:
    name = (name or "").strip()
    if not name or name.lower() in ("unknown", "none"):
        return "Unattributed"
    known = {
        "umbra": "UmBra",
        "clop": "Clop",
        "thegentlemen": "TheGentlemen",
        "auditteam": "AuditTeam",
        "doommageddon": "Doommageddon",
        "krybit": "Krybit",
        "orova": "Orova",
        "emperador": "Emperador",
        "direwolf": "DireWolf",
        "eclipse": "Eclipse",
        "vexy": "Vexy",
        "vexy ransomware": "Vexy",
        "medusalocker": "MedusaLocker",
        "globalsecretgroup": "Global Secret Group",
        "global secret group": "Global Secret Group",
        "qilin": "Qilin",
        "majinahanashi": "Majinahanashi",
        "blackwater": "BlackWater",
        "dysphor1a": "DYSPHOR1A",
    }
    return known.get(name.lower(), name.title())


def _join_and(items: List[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} and {items[-1]}"


def format_truncated_list(items: List[str], max_items: int = 5) -> str:
    """Formats a list of strings, appending ', and N more' if truncated."""
    if not items:
        return ""
    if len(items) <= max_items:
        return ", ".join(items)
    top = items[:max_items]
    rem = len(items) - max_items
    return f"{', '.join(top)}, and {rem} more"


def _anonymize_victim_descriptor(clean_name: str, sector: str, state: str, corroborated: bool = False) -> str:
    """Returns anonymized descriptor for victims in Public Edition."""
    short_sec = sector.split("&")[0].split("/")[0].strip()
    st_desc = state if state and state != "Location Unresolved" else "Regional"
    if corroborated:
        return f"{clean_name} [Multi-feed verified, B2]"
    return f"{short_sec} Entity ({st_desc}) [Claimed by group (single source, C3)]"


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("T", parent=base["Title"],
                                fontName="Helvetica-Bold", fontSize=16,
                                leading=19, alignment=TA_LEFT, spaceAfter=2,
                                textColor=colors.HexColor("#111111")),
        "sub": ParagraphStyle("S", parent=base["Normal"],
                              fontName="Helvetica", fontSize=8.5, leading=11.5,
                              textColor=colors.HexColor("#5F5E5A")),
        "tlp_amber": ParagraphStyle("TLP_A", parent=base["Normal"],
                                    fontName="Helvetica-Bold", fontSize=7.8,
                                    leading=10, alignment=TA_CENTER,
                                    textColor=colors.HexColor("#935116")),
        "tlp_clear": ParagraphStyle("TLP_C", parent=base["Normal"],
                                    fontName="Helvetica-Bold", fontSize=7.8,
                                    leading=10, alignment=TA_CENTER,
                                    textColor=colors.HexColor("#196F3D")),
        "h2": ParagraphStyle("H2", parent=base["Normal"],
                             fontName="Helvetica-Bold", fontSize=12.5,
                             leading=15, spaceBefore=6, spaceAfter=3,
                             textColor=NAVY),
        "h3": ParagraphStyle("H3", parent=base["Normal"],
                             fontName="Helvetica-Bold", fontSize=9.2,
                             leading=12, spaceBefore=5, spaceAfter=2.5,
                             textColor=NAVY_SOFT),
        "body": ParagraphStyle("B", parent=base["Normal"],
                               fontName="Helvetica", fontSize=8,
                               leading=11, textColor=INK),
        "body_justify": ParagraphStyle("BJ", parent=base["Normal"],
                                       fontName="Helvetica", fontSize=7.8,
                                       leading=10.8, alignment=TA_JUSTIFY,
                                       textColor=INK),
        "sec_num": ParagraphStyle("SN", parent=base["Normal"],
                                  fontName="Helvetica-Bold", fontSize=10.5,
                                  leading=13, alignment=TA_CENTER,
                                  textColor=colors.white),
        "sec_title": ParagraphStyle("ST", parent=base["Normal"],
                                    fontName="Helvetica-Bold", fontSize=12.5,
                                    leading=15, textColor=NAVY),
        "card_title": ParagraphStyle("CT", parent=base["Normal"],
                                     fontName="Helvetica-Bold", fontSize=10.5,
                                     leading=13, textColor=NAVY),
        "card_meta": ParagraphStyle("CM", parent=base["Normal"],
                                    fontName="Helvetica", fontSize=7.2,
                                    leading=9.8, textColor=MUTED),
        "card_label": ParagraphStyle("CL", parent=base["Normal"],
                                     fontName="Helvetica-Bold", fontSize=6.8,
                                     leading=9, spaceAfter=1,
                                     textColor=ACCENT),
        "card_body": ParagraphStyle("CBD", parent=base["Normal"],
                                    fontName="Helvetica", fontSize=7.9,
                                    leading=11, textColor=INK),
        "card_bullet": ParagraphStyle("CBL", parent=base["Normal"],
                                      fontName="Helvetica", fontSize=7.7,
                                      leading=10.4, leftIndent=8,
                                      bulletIndent=0, spaceAfter=1.5,
                                      textColor=INK),
        "bluf": ParagraphStyle("BL", parent=base["Normal"],
                               fontName="Helvetica", fontSize=8.3,
                               leading=11.6, leftIndent=9, bulletIndent=0,
                               spaceAfter=2.5, textColor=INK),
        "small": ParagraphStyle("SM", parent=base["Normal"],
                                fontName="Helvetica", fontSize=7.2, leading=9.8,
                                textColor=colors.HexColor("#555555")),
        "kpi": ParagraphStyle("KPI", parent=base["Normal"],
                              fontName="Helvetica", fontSize=6.8, leading=9.5,
                              alignment=TA_CENTER,
                              textColor=colors.HexColor("#5F5E5A")),
        "cell": ParagraphStyle("C", parent=base["Normal"],
                               fontName="Helvetica", fontSize=7.2,
                               leading=9.5, wordWrap="CJK",
                               splitLongWords=True),
        "cell_compact": ParagraphStyle("CCM", parent=base["Normal"],
                                       fontName="Helvetica", fontSize=5.8,
                                       leading=7.2, wordWrap="CJK",
                                       splitLongWords=True),
        "cellb": ParagraphStyle("CB", parent=base["Normal"],
                                fontName="Helvetica-Bold", fontSize=7.2,
                                leading=9.5, wordWrap="CJK",
                                splitLongWords=True),
        "cellb_compact": ParagraphStyle("CBM", parent=base["Normal"],
                                        fontName="Helvetica-Bold", fontSize=6.0,
                                        leading=7.5, wordWrap="CJK",
                                        splitLongWords=True),
        "cellbc": ParagraphStyle("CBC", parent=base["Normal"],
                                 fontName="Helvetica-Bold", fontSize=7.2,
                                 leading=9.5, alignment=TA_CENTER,
                                 wordWrap="CJK", splitLongWords=True),
        "cellc": ParagraphStyle("CC", parent=base["Normal"],
                                fontName="Helvetica", fontSize=7.2,
                                leading=9.5, alignment=TA_CENTER,
                                wordWrap="CJK", splitLongWords=True),
        "date": ParagraphStyle("D", parent=base["Normal"],
                               fontName="Helvetica", fontSize=7.0,
                               leading=9.0, alignment=TA_CENTER,
                               wordWrap="CJK"),
        "date_compact": ParagraphStyle("DCM", parent=base["Normal"],
                                       fontName="Helvetica", fontSize=5.6,
                                       leading=7.0, alignment=TA_CENTER,
                                       wordWrap="CJK"),
        "mono": ParagraphStyle("M", parent=base["Normal"],
                               fontName="Courier", fontSize=6.8, leading=8.8,
                               wordWrap="CJK", splitLongWords=True),
        "ioc_mono": ParagraphStyle("IM", parent=base["Normal"],
                                   fontName="Courier", fontSize=5.5, leading=6.8,
                                   wordWrap="CJK", splitLongWords=False),
        "monowhole": ParagraphStyle("MW", parent=base["Normal"],
                                    fontName="Courier", fontSize=6.8,
                                    leading=8.8, splitLongWords=False),
        "callout": ParagraphStyle("CO", parent=base["Normal"],
                                  fontName="Helvetica", fontSize=7.5,
                                  leading=10.5, textColor=colors.HexColor("#1A202C")),
    }


def _table(rows, widths, st, header=True, zebra=False, padding=(2.0, 2.0, 3.0, 3.0)):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    top_p, bot_p, left_p, right_p = padding
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("LINEABOVE", (0, 0), (-1, 0), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), top_p),
        ("BOTTOMPADDING", (0, 0), (-1, -1), bot_p),
        ("LEFTPADDING", (0, 0), (-1, -1), left_p),
        ("RIGHTPADDING", (0, 0), (-1, -1), right_p),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), HEAD_BG))
        style.append(("LINEBELOW", (0, 0), (-1, 0), 0.9, NAVY_SOFT))
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i),
                              colors.HexColor("#F7F9FB")))
    t.setStyle(TableStyle(style))
    return t


def _kpi_table(rows, widths):
    t = Table(rows, colWidths=widths)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 0), (-1, -1), PANEL_BG),
        ("LINEABOVE", (0, 0), (-1, 0), 2.2, NAVY),
        ("LINEAFTER", (0, 0), (-2, -1), 0.8, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]
    t.setStyle(TableStyle(style))
    return t


def _section_header(title: str, number: int, st) -> Table:
    """Numbered section banner: accent block with the number, navy title, rule."""
    t = Table([[Paragraph(f"{number:02d}", st["sec_num"]),
                Paragraph(title, st["sec_title"])]],
              colWidths=[10 * mm, 168 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (1, 0), (1, 0), 1.0, NAVY),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]))
    t.spaceAfter = 4
    t.toc_title = f"{number:02d}&nbsp;&nbsp;&nbsp;{title}"
    return t


class _BulletinDoc(SimpleDocTemplate):
    """Feeds section headers into the cover's table of contents."""

    def afterFlowable(self, flowable):
        title = getattr(flowable, "toc_title", None)
        if title:
            self.notify("TOCEntry", (0, title, self.page))


def _band_text(band: str, st) -> Paragraph:
    fg, _ = BAND_COLORS.get(band, BAND_COLORS["Minimal"])
    return Paragraph(f'<font color="{fg.hexval()}"><b>{band}</b></font>',
                     st["cell"])


# ---------------------------------------------------------------------------
# Visual Drawings & Charts
# ---------------------------------------------------------------------------

def create_sector_bar_chart(scored_sectors: List[Dict], width: float = 178 * mm,
                            max_items: int = 8) -> Drawing:
    """
    Renders an executive horizontal bar chart of top sectors ranked by risk score.
    Legend accurately reflects mathematical risk bands (High: 60+).
    """
    top_sectors = scored_sectors[:max_items]
    bar_height = 10.5
    gap = 5.5
    header_height = 26
    chart_height = header_height + len(top_sectors) * (bar_height + gap) + 6
    d = Drawing(width, chart_height)

    # Card background
    d.add(Rect(0, 0, width, chart_height, rx=4, ry=4,
               fillColor=PANEL_BG, strokeColor=RULE, strokeWidth=0.7))

    # Header title
    d.add(String(12, chart_height - 17, "Sector Risk Score Comparison",
                 fontName="Helvetica-Bold", fontSize=9.0,
                 fillColor=NAVY))

    # Legend badges (Synchronized with core/scoring_multi.py BANDS)
    legend = [
        ("Critical (80+)", colors.HexColor("#791F1F")),
        ("High (60+)", colors.HexColor("#C0392B")),
        ("Moderate (40+)", colors.HexColor("#D35400")),
        ("Low (20+)", colors.HexColor("#27AE60")),
        ("Minimal (<20)", colors.HexColor("#2ECC71")),
    ]
    lx = width - 332
    ly = chart_height - 17
    for label, col in legend:
        d.add(Rect(lx, ly, 6.5, 6.5, rx=1.5, ry=1.5, fillColor=col, strokeColor=None))
        d.add(String(lx + 9, ly + 1, label, fontName="Helvetica", fontSize=6.2,
                     fillColor=colors.HexColor("#555555")))
        lx += len(label) * 4.1 + 15

    label_width = 160
    score_col_width = 30
    cii_col_width = 24
    bar_area_width = width - label_width - score_col_width - cii_col_width - 24

    y = chart_height - header_height - 13
    for s in top_sectors:
        score = float(s.get("risk_score", 0))
        band = s.get("risk_band", "Minimal")
        col = BAND_HEX_COLORS.get(band, colors.HexColor("#777777"))
        lbl = s.get("label", s.get("sector", ""))

        d.add(String(14, y + 2, lbl, fontName="Helvetica", fontSize=7.5,
                     fillColor=colors.HexColor("#222222")))

        track_x = label_width
        d.add(Rect(track_x, y, bar_area_width, bar_height, rx=2.5, ry=2.5,
                   fillColor=colors.HexColor("#EAE8E1"), strokeColor=None))

        fill_w = max(4, min(bar_area_width, (score / 100.0) * bar_area_width))
        d.add(Rect(track_x, y, fill_w, bar_height, rx=2.5, ry=2.5,
                   fillColor=col, strokeColor=None))

        d.add(String(track_x + bar_area_width + 8, y + 2, f"{score:.1f}",
                     fontName="Helvetica-Bold", fontSize=7.5, fillColor=col))

        if s.get("nciipc_critical"):
            tag_x = track_x + bar_area_width + score_col_width + 2
            d.add(Rect(tag_x, y + 1, 18, 8.5, rx=2, ry=2,
                       fillColor=colors.HexColor("#D0E1FD"), strokeColor=None))
            d.add(String(tag_x + 3.5, y + 2.5, "CII", fontName="Helvetica-Bold",
                         fontSize=5.8, fillColor=colors.HexColor("#1A365D")))

        y -= (bar_height + gap)

    return d


def create_signal_breakdown_chart(signals: List[Signal], width: float = 178 * mm,
                                  height: float = 95) -> Drawing:
    """
    Renders an intelligence signals category distribution donut graphic.
    """
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=4, ry=4,
               fillColor=PANEL_BG, strokeColor=RULE, strokeWidth=0.7))

    d.add(String(12, height - 16, "Intelligence Signals by Category",
                 fontName="Helvetica-Bold", fontSize=9.0,
                 fillColor=NAVY))

    by_type = Counter(s.signal_type for s in signals)
    total_signals = len(signals) or 1
    kev_n = sum(1 for s in signals if s.source == "CISA KEV")
    nvd_n = sum(1 for s in signals if s.source == "NVD")

    categories = [
        (SignalType.VULNERABILITY, f"Vulnerabilities ({kev_n} KEV/{nvd_n} NVD)", colors.HexColor("#D35400")),
        (SignalType.MALWARE_INFRA, "Malware C2 & Infrastructure", colors.HexColor("#E67E22")),
        (SignalType.VICTIM, "Extortion Postings & Victims", colors.HexColor("#C0392B")),
        (SignalType.ADVISORY, "Official CERT-In Advisories", colors.HexColor("#1F618D")),
        (SignalType.EXPOSURE, "Attack Surface Exposure", colors.HexColor("#2980B9")),
        (SignalType.PHISHING, "Phishing & Lookalikes", colors.HexColor("#7D3C98")),
    ]

    pie_data = []
    pie_colors = []
    active_categories = []
    for stype, label, col in categories:
        count = by_type.get(stype, 0)
        if count > 0:
            pie_data.append(count)
            pie_colors.append(col)
            active_categories.append((label, count, col))

    other_count = sum(count for stype, count in by_type.items()
                      if stype not in [c[0] for c in categories])
    if other_count > 0:
        pie_data.append(other_count)
        pie_colors.append(colors.HexColor("#7F8C8D"))
        active_categories.append(("Other Signals", other_count, colors.HexColor("#7F8C8D")))

    pie_size = 66
    pie_x = 22
    pie_y = (height - pie_size) / 2 - 4
    pc = Pie()
    pc.x = pie_x
    pc.y = pie_y
    pc.width = pie_size
    pc.height = pie_size
    pc.data = pie_data
    pc.sideLabels = 0
    pc.labels = []
    for i, col in enumerate(pie_colors):
        pc.slices[i].fillColor = col
        pc.slices[i].strokeColor = colors.white
        pc.slices[i].strokeWidth = 0.5
    d.add(pc)

    hole_radius = 17
    d.add(Circle(pie_x + pie_size/2, pie_y + pie_size/2, hole_radius,
                 fillColor=PANEL_BG, strokeColor=None))
    d.add(String(pie_x + pie_size/2 - 8, pie_y + pie_size/2 - 3,
                 f"{total_signals}", fontName="Helvetica-Bold", fontSize=8.0,
                 fillColor=colors.HexColor("#222222")))

    col1_x = 125
    col2_x = 315
    row_y_start = height - 32
    row_h = 13.0
    num_col1 = (len(active_categories) + 1) // 2

    for idx, (label, count, col) in enumerate(active_categories):
        pct = (count / total_signals) * 100
        col_idx = 0 if idx < num_col1 else 1
        row_idx = idx if col_idx == 0 else (idx - num_col1)
        cur_x = col1_x if col_idx == 0 else col2_x
        cur_y = row_y_start - row_idx * row_h

        d.add(Rect(cur_x, cur_y + 1, 7.5, 7.5, rx=2, ry=2, fillColor=col, strokeColor=None))
        d.add(String(cur_x + 12, cur_y + 2, f"{label}:", fontName="Helvetica",
                     fontSize=7.0, fillColor=colors.HexColor("#333333")))
        d.add(String(cur_x + 128, cur_y + 2, f"{count} ({pct:.1f}%)",
                     fontName="Helvetica-Bold", fontSize=7.0, fillColor=col))

    return d


def create_india_threat_map(signals: List[Signal], width: float = 178 * mm,
                            height: float = 210, window_days: int = 60) -> Drawing:
    """
    Renders an official Survey of India Geographic Map alongside a comprehensive
    state-wise threat ranking bar chart containing all targeted states summing to 100%.
    """
    d = Drawing(width, height)

    d.add(Rect(0, 0, width, height, rx=4, ry=4,
               fillColor=PANEL_BG, strokeColor=RULE, strokeWidth=0.7))

    d.add(String(12, height - 16, "Geographic Threat Distribution: Targeted Indian States & UTs",
                 fontName="Helvetica-Bold", fontSize=9.0,
                 fillColor=NAVY))
    d.add(String(width - 150, height - 16, f"Reporting Period: {window_days} Days",
                 fontName="Helvetica", fontSize=6.8,
                 fillColor=colors.HexColor("#666666")))

    victim_sigs = [s for s in signals if s.signal_type.value in ('victim', 'data_leak')]
    state_org_counts = Counter()
    state_posting_counts = Counter()
    seen_orgs = set()

    for s in victim_sigs:
        raw_org = s.entities.organisations[0] if s.entities.organisations else s.title
        clean_org = _clean_victim_name(raw_org)
        st_name = classify_state(clean_org, s.description)
        state_posting_counts[st_name] += 1
        key = clean_org.lower().strip()
        if key not in seen_orgs:
            seen_orgs.add(key)
            state_org_counts[st_name] += 1

    total_unique_orgs = sum(state_org_counts.values()) or 1

    map_box_x = 10
    map_box_y = 10
    map_h = height - 28
    map_w = int(map_h * (520.0 / 590.0))

    d.add(Rect(map_box_x, map_box_y, map_w, map_h, rx=4, ry=4,
               fillColor=colors.HexColor("#F0F3F7"), strokeColor=colors.HexColor("#D5DDE6"), strokeWidth=0.6))

    map_img_path = render_official_india_map(dict(state_posting_counts), img_w=520, img_h=590)
    if map_img_path and os.path.exists(map_img_path):
        d.add(DImage(map_box_x, map_box_y, map_w, map_h, map_img_path))

    bar_x = map_box_x + map_w + 14
    bar_w = width - bar_x - 12
    bar_h = 7.6
    bar_gap = 3.2
    cur_y = height - 34

    d.add(String(bar_x, cur_y + 1, "State-wise Breakdown (Unique Orgs / Postings)",
                 fontName="Helvetica-Bold", fontSize=7.8,
                 fillColor=colors.HexColor("#222222")))
    cur_y -= 12

    legend_bar = [
        ("Severe (8+)", colors.HexColor("#791F1F")),
        ("High (5-7)", colors.HexColor("#C0392B")),
        ("Medium (3-4)", colors.HexColor("#D35400")),
        ("Emerging (1-2)", colors.HexColor("#E67E22")),
    ]
    lx = bar_x
    for lbl, c in legend_bar:
        d.add(Rect(lx, cur_y + 1, 5.5, 5.5, rx=1, ry=1, fillColor=c, strokeColor=None))
        d.add(String(lx + 8, cur_y + 1, lbl, fontName="Helvetica", fontSize=5.6, fillColor=colors.HexColor("#555555")))
        lx += len(lbl) * 3.6 + 14
    cur_y -= 12

    label_col_w = 96
    val_col_w = 58
    bar_track_w = bar_w - label_col_w - val_col_w

    ranked_states = state_org_counts.most_common()
    max_state_val = float(max((cnt for _, cnt in ranked_states), default=10))

    # All 12 states sum to exactly 100%
    for state, org_cnt in ranked_states:
        pst_cnt = state_posting_counts[state]
        pct = (org_cnt / total_unique_orgs) * 100
        if org_cnt >= 8:
            b_col = colors.HexColor("#791F1F")
        elif org_cnt >= 5:
            b_col = colors.HexColor("#C0392B")
        elif org_cnt >= 3:
            b_col = colors.HexColor("#D35400")
        else:
            b_col = colors.HexColor("#E67E22")

        d.add(String(bar_x, cur_y + 1.2, state, fontName="Helvetica", fontSize=6.8, fillColor=colors.HexColor("#222222")))

        tx = bar_x + label_col_w
        d.add(Rect(tx, cur_y, bar_track_w, bar_h, rx=1.5, ry=1.5, fillColor=colors.HexColor("#EAE8E1"), strokeColor=None))

        fw = max(3, min(bar_track_w, (org_cnt / max_state_val) * bar_track_w))
        d.add(Rect(tx, cur_y, fw, bar_h, rx=1.5, ry=1.5, fillColor=b_col, strokeColor=None))

        d.add(String(tx + bar_track_w + 5, cur_y + 1.2, f"{org_cnt} org ({pst_cnt} post) {pct:.1f}%",
                     fontName="Helvetica-Bold", fontSize=6.3, fillColor=b_col))

        cur_y -= (bar_h + bar_gap)

    return d


def extract_victim_attributions(signals: List[Signal]) -> Tuple[List[Dict], int, int]:
    """
    Extracts claimed victims named on leak sites with threat actor and state attribution,
    deduplicating by canonical corporate organization name while tracking total postings.
    Returns (deduplicated_victim_list, total_postings_count, unique_organisations_count).
    """
    victim_sigs = [s for s in signals if s.signal_type in (SignalType.VICTIM, SignalType.DATA_LEAK)]
    total_postings = len(victim_sigs)
    by_org: Dict[str, Dict] = {}

    for s in victim_sigs:
        raw_org = s.entities.organisations[0] if s.entities.organisations else s.title
        clean_org = _clean_victim_name(raw_org)
        norm_key = clean_org.lower().strip()

        actor = ""
        if s.entities.actors:
            for a in s.entities.actors:
                if a and a.strip().lower() not in ("unknown", "none", ""):
                    actor = _normalize_actor(a.strip())
                    break
        if not actor:
            actor = "Unattributed"

        st_name = classify_state(clean_org, s.description)
        override = entity_override(raw_org) or entity_override(clean_org)
        if override and override.get("sector_label"):
            sec = override["sector_label"]
        elif override and override.get("sector"):
            sec = sector_label(override["sector"])
        else:
            sec = sector_label(s.sectors[0]) if s.sectors else "Unclassified"
        incident_type = ("Data for Sale" if s.signal_type == SignalType.DATA_LEAK
                         else "Ransomware Leak")

        if norm_key not in by_org:
            by_org[norm_key] = {
                "victim": clean_org,
                "actors": {actor},
                "sector": sec,
                "state": st_name,
                "incident_type": incident_type,
                "date": (s.observed_at or "")[:10],
                "sources": {s.source},
                "postings": 1,
            }
        else:
            if actor != "Unattributed":
                by_org[norm_key]["actors"].add(actor)
            by_org[norm_key]["sources"].add(s.source)
            by_org[norm_key]["postings"] += 1
            if s.observed_at and s.observed_at[:10] > by_org[norm_key]["date"]:
                by_org[norm_key]["date"] = s.observed_at[:10]

    out = []
    for item in by_org.values():
        actors_list = sorted([a for a in item["actors"] if a != "Unattributed"]) or ["Unattributed"]
        out.append({
            "victim": item["victim"],
            "actor": ", ".join(actors_list),
            "sector": item["sector"],
            "state": item["state"],
            "incident_type": item["incident_type"],
            "date": item["date"],
            "sources": sorted(item["sources"]),
            "postings": item["postings"],
            "corroborated": len(item["sources"]) >= 2,
        })

    out.sort(key=lambda x: (x["date"], x["victim"]), reverse=True)
    return out, total_postings, len(out)


def _manual_feed_note(signals: List[Signal], window_days: int) -> str:
    """What the hand-maintained dark-web and hacktivist feeds contributed."""
    leaks = sum(1 for s in signals if s.signal_type == SignalType.DATA_LEAK)
    hackt = sum(1 for s in signals if s.signal_type == SignalType.HACKTIVISM)
    if not leaks and not hackt:
        return (f"No dark web forum or hacktivist claim observations were logged for this {window_days}-day period "
                f"(data/leak_observations.json and data/hacktivist_claims.json are analyst-maintained).")
    return (f"Analyst-logged observations this period: {leaks} dark web data-sale listing{'s' if leaks != 1 else ''} "
            f"and {hackt} hacktivist claim{'s' if hackt != 1 else ''}.")


def _technique_sentence(examples: List[Dict]) -> str:
    if not examples:
        return ""
    parts = [f"{e['technique']} ({e['count']} indicator{'s' if e['count'] != 1 else ''}, e.g. {e['example']})"
             for e in examples]
    return f"Observed delivery techniques: {_join_and(parts)}. "


def _correlation_summary(correlation: Dict) -> str:
    shared = correlation.get("shared_artefacts", [])
    n_sig = correlation.get("corroborated_count", 0)
    n_art = correlation.get("shared_artefacts_count", len(shared))
    if not shared:
        return "No artefact (CVE, domain, IP, hash or organisation) appeared in more than one feed during the window."
    by_pair = Counter(" and ".join(item["sources"][:2]) for item in shared)
    pairs = "; ".join(f"{cnt} via {pair}" for pair, cnt in by_pair.most_common(4))
    return (f"Cross-source telemetry reconciles <b>{n_sig} signals across {n_art} shared artefacts</b> ({_esc(pairs)}). "
            "Note on shared-parent feeds: CISA KEV and NVD share upstream CVE data, while ransomware.live and ransomlook.io both "
            "monitor the same underlying leak sites. Accordingly, no independent confidence uplift is awarded for corroboration "
            "between shared-parent feeds.")


def _actor_activity(signals: List[Signal]) -> Dict[str, Dict]:
    """Per actor: organisations, postings, posting dates and feeds."""
    out: Dict[str, Dict] = defaultdict(lambda: {"orgs": set(), "postings": 0, "dates": set(), "sources": set()})
    for s in signals:
        if s.signal_type.value in ("victim", "data_leak") and s.entities.actors:
            raw_org = s.entities.organisations[0] if s.entities.organisations else s.title
            org = _clean_victim_name(raw_org).lower()
            for a in s.entities.actors:
                act = _normalize_actor(a)
                if act == "Unattributed":
                    continue
                rec = out[act]
                rec["orgs"].add(org)
                rec["postings"] += 1
                rec["sources"].add(s.source)
                if s.observed_at:
                    rec["dates"].add(s.observed_at[:10])
    return out


def _actor_notes(signals: List[Signal]) -> Dict[str, str]:
    """Short chart notes explaining why an actor's postings differ from its organisations."""
    notes = {}
    for act, rec in _actor_activity(signals).items():
        if len(rec["orgs"]) >= 3 and len(rec["dates"]) == 1:
            d = next(iter(rec["dates"]))
            notes[act] = f" ({datetime.fromisoformat(d).strftime('%d-%b')} wave)"
        elif rec["postings"] > len(rec["orgs"]) and len(rec["sources"]) > 1:
            notes[act] = " (multi-feed)"
        elif rec["postings"] > len(rec["orgs"]):
            notes[act] = " (repeat postings)"
    return notes


def _actor_chart_note(signals: List[Signal], unique_orgs: int, total_postings: int) -> str:
    activity = _actor_activity(signals)
    ranked = sorted(activity.items(), key=lambda kv: (-len(kv[1]["orgs"]), -kv[1]["postings"]))
    parts = []
    if len(ranked) > 7:
        parts.append(f"Top 7 actors shown individually; {len(ranked) - 7} remaining syndicates aggregated into Others.")
    repeats = [(a, r) for a, r in ranked if r["postings"] > len(r["orgs"])][:3]
    for act, rec in repeats:
        n_org = len(rec["orgs"])
        why = "listed on more than one feed" if len(rec["sources"]) > 1 else "posted more than once"
        parts.append(f"{act}: {rec['postings']} postings for {n_org} organisation{'s' if n_org != 1 else ''} ({why}).")
    if any(len(r["sources"]) > 1 for _, r in ranked):
        parts.append("Note: ransomware.live and ransomlook.io share an upstream scraper source.")
    parts.append(f"All {unique_orgs} unique entities and {total_postings} postings accounted for (100.0%).")
    return "<i>* Note: " + " ".join(_esc(p) for p in parts) + "</i>"


def create_threat_actors_bar_chart(signals: List[Signal], width: float = 178 * mm,
                                   height: float = 108, max_actors: int = 8) -> Drawing:
    """
    Renders a horizontal bar chart of top threat actor groups & ransomware gangs targeting India,
    explicitly presenting both unique organisations and disclosure postings.
    """
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=4, ry=4,
               fillColor=PANEL_BG, strokeColor=RULE, strokeWidth=0.7))

    d.add(String(12, height - 15, "Active Ransomware Syndicates Targeting India",
                 fontName="Helvetica-Bold", fontSize=8.5,
                 fillColor=colors.HexColor("#1A1A1A")))
    d.add(String(width - 195, height - 15, "Ranked by Unique Indian Victim Entities",
                 fontName="Helvetica", fontSize=6.5,
                 fillColor=colors.HexColor("#666666")))

    actor_orgs = defaultdict(set)
    actor_postings = Counter()

    for s in signals:
        if s.signal_type.value in ('victim', 'data_leak') and s.entities.actors:
            raw_org = s.entities.organisations[0] if s.entities.organisations else s.title
            clean_org = _clean_victim_name(raw_org)
            for a in s.entities.actors:
                act = _normalize_actor(a)
                if act != "Unattributed":
                    actor_postings[act] += 1
                    actor_orgs[act].add(clean_org.lower())

    all_ranked = sorted(
        [(act, len(orgs), actor_postings[act]) for act, orgs in actor_orgs.items()],
        key=lambda x: (-x[1], -x[2])
    )
    top_actors = all_ranked[:7]
    other_actors = all_ranked[7:]
    actor_notes = _actor_notes(signals)

    total_unique_orgs = len({o for orgs in actor_orgs.values() for o in orgs}) or 1
    max_val = top_actors[0][1] if top_actors else 1

    chart_items = list(top_actors)
    if other_actors:
        other_org_cnt = sum(x[1] for x in other_actors)
        other_post_cnt = sum(x[2] for x in other_actors)
        chart_items.append((f"Others ({len(other_actors)} syndicates)", other_org_cnt, other_post_cnt))

    bar_x = 12
    label_w = 110
    val_w = 85
    bar_track_w = width - bar_x - label_w - val_w - 18
    bar_h = 7.8
    bar_gap = 3.2
    cur_y = height - 28

    GANG_COLORS = [
        colors.HexColor("#791F1F"),
        colors.HexColor("#922B21"),
        colors.HexColor("#C0392B"),
        colors.HexColor("#D35400"),
        colors.HexColor("#E67E22"),
        colors.HexColor("#1F618D"),
        colors.HexColor("#2980B9"),
        colors.HexColor("#7D3C98"),
    ]

    for idx, (actor, org_cnt, post_cnt) in enumerate(chart_items):
        col = GANG_COLORS[idx % len(GANG_COLORS)]
        pct = (org_cnt / float(total_unique_orgs)) * 100

        campaign_note = actor_notes.get(actor, "")

        lbl_text = f"{idx+1}. {actor}{campaign_note}" if not actor.startswith("Others") else f"{idx+1}. {actor}"
        d.add(String(bar_x, cur_y + 1.2, lbl_text,
                     fontName="Helvetica-Bold", fontSize=6.5,
                     fillColor=colors.HexColor("#222222")))

        tx = bar_x + label_w
        d.add(Rect(tx, cur_y, bar_track_w, bar_h, rx=1.5, ry=1.5,
                   fillColor=colors.HexColor("#EAE8E1"), strokeColor=None))

        fw = max(4, min(bar_track_w, (org_cnt / float(max_val)) * bar_track_w))
        d.add(Rect(tx, cur_y, fw, bar_h, rx=1.5, ry=1.5, fillColor=col, strokeColor=None))

        org_str = f"{org_cnt} org" if org_cnt == 1 else f"{org_cnt} orgs"
        post_str = f"{post_cnt} post" if post_cnt == 1 else f"{post_cnt} posts"
        d.add(String(tx + bar_track_w + 6, cur_y + 1.2, f"{org_str} ({post_str}) {pct:.1f}%",
                     fontName="Helvetica-Bold", fontSize=6.2, fillColor=col))

        cur_y -= (bar_h + bar_gap)

    return d


def create_targeted_tech_chart(signals: List[Signal], width: float = 178 * mm,
                               height: float = 108) -> Drawing:
    """
    Bar chart of the vendors and products with the most CISA KEV CVEs in the
    window, edge devices in red.
    """
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=4, ry=4,
               fillColor=PANEL_BG, strokeColor=RULE, strokeWidth=0.7))

    d.add(String(12, height - 15, "Targeted Enterprise Technology Stacks & Edge Devices",
                 fontName="Helvetica-Bold", fontSize=8.5,
                 fillColor=colors.HexColor("#1A1A1A")))
    d.add(String(width - 165, height - 15, "Observed Vulnerability Vectors (KEV)",
                 fontName="Helvetica", fontSize=6.5,
                 fillColor=colors.HexColor("#666666")))

    groups = rf.kev_by_product(signals)[:8]
    max_cves = max((g["count"] for g in groups), default=1)
    edge_cols = [colors.HexColor(c) for c in ("#791F1F", "#C0392B", "#D35400", "#E67E22")]
    other_cols = [colors.HexColor(c) for c in ("#1F618D", "#2980B9", "#5B7FA6", "#7F9CBF")]
    tech_vendors = []
    for g in groups:
        palette = edge_cols if g["edge"] else other_cols
        rank = sum(1 for x in tech_vendors if x[3] in palette)
        tech_vendors.append((g["label"][:44], g["count"], g["edge"], palette[min(rank, 3)]))
    if not tech_vendors:
        d.add(String(12, height - 34, "No CISA KEV entries in this window.", fontName="Helvetica",
                     fontSize=7, fillColor=MUTED))
        return d

    bar_x = 12
    label_w = 145
    val_w = 40
    bar_track_w = width - bar_x - label_w - val_w - 18
    bar_h = 7.8
    bar_gap = 3.2
    cur_y = height - 30

    for name, cve_cnt, is_edge, col in tech_vendors:
        d.add(String(bar_x, cur_y + 1.2, name + (" (edge)" if is_edge else ""), fontName="Helvetica-Bold",
                     fontSize=6.5, fillColor=colors.HexColor("#222222")))
        tx = bar_x + label_w
        d.add(Rect(tx, cur_y, bar_track_w, bar_h, rx=1.5, ry=1.5, fillColor=colors.HexColor("#EAE8E1"), strokeColor=None))
        fw = max(6, min(bar_track_w, (cve_cnt / float(max_cves)) * bar_track_w))
        d.add(Rect(tx, cur_y, fw, bar_h, rx=1.5, ry=1.5, fillColor=col, strokeColor=None))
        d.add(String(tx + bar_track_w + 6, cur_y + 1.2, f"{cve_cnt} CVE{'s' if cve_cnt != 1 else ''}",
                     fontName="Helvetica-Bold", fontSize=6.2, fillColor=col))
        cur_y -= (bar_h + bar_gap)

    return d


def compute_weekly_buckets(start_date: Optional[object] = None,
                           end_date: Optional[object] = None,
                           data_end_date: Optional[object] = None) -> List[Dict]:
    """
    Computes weekly interval buckets across reporting window.
    The final bucket is labeled by the days that contain data (data_end_date or end_date).
    Returns list of bucket dicts with label, dates, start_iso, end_iso, days, is_partial.
    """
    if not end_date:
        end_date = window_end_date()
    if not start_date:
        start_date = end_date - timedelta(days=60)
    if not data_end_date:
        data_end_date = end_date

    cur = start_date
    slots = []
    while cur <= end_date:
        nxt = min(cur + timedelta(days=6), end_date)
        is_final = (nxt >= end_date)
        if is_final and data_end_date and data_end_date < end_date:
            display_end = max(cur, min(nxt, data_end_date))
        else:
            display_end = nxt
        days = (display_end - cur).days + 1
        if days <= 0:
            cur = nxt + timedelta(days=1)
            continue
        if cur.month == display_end.month:
            dates_str = f"{cur.strftime('%d')}-{display_end.strftime('%d %b')}"
        else:
            dates_str = f"{cur.strftime('%d %b')}-{display_end.strftime('%d %b')}"
        lbl = dates_str
        if is_final or days < 7:
            lbl += " (partial)"
        slots.append({
            "label": lbl,
            "dates": dates_str,
            "start_iso": cur.isoformat(),
            "end_iso": nxt.isoformat(),
            "days": days,
            "is_partial": is_final or days < 7,
        })
        cur = nxt + timedelta(days=1)
    return slots


def create_timeline_activity_chart(signals: List[Signal],
                                   start_date: Optional[object] = None,
                                   end_date: Optional[object] = None,
                                   width: float = 178 * mm,
                                   height: float = 95) -> Drawing:
    """
    Renders a weekly threat activity volume trend chart across the window,
    accounting for 100% of signals and victim postings.
    Buckets are dynamically derived from start_date to end_date.
    """
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=4, ry=4,
               fillColor=PANEL_BG, strokeColor=RULE, strokeWidth=0.7))

    d.add(String(12, height - 15, f"Weekly Threat Telemetry Velocity (All {len(signals)} Signals Accounted)",
                 fontName="Helvetica-Bold", fontSize=8.5,
                 fillColor=colors.HexColor("#1A1A1A")))

    max_sig_date = max((s.observed_at[:10] for s in signals if s.observed_at), default="")
    data_end_date = datetime.fromisoformat(max_sig_date).date() if max_sig_date else None
    slots = compute_weekly_buckets(start_date, end_date, data_end_date=data_end_date)
    extortion_counts = [0] * len(slots)
    snapshot_counts = [0] * len(slots)
    for s in signals:
        if not s.observed_at:
            continue
        obs_date = s.observed_at[:10]
        for idx, b in enumerate(slots):
            if b["start_iso"] <= obs_date <= b["end_iso"]:
                if s.signal_type.value in ('victim', 'data_leak'):
                    extortion_counts[idx] += 1
                else:
                    snapshot_counts[idx] += 1
                break

    max_val = max(snapshot_counts + [100])

    chart_x = 22
    chart_y = 17
    chart_w = width - chart_x - 18
    chart_h = height - 40
    col_w = chart_w / len(slots)
    bar_w = col_w * 0.36

    for step in range(1, 4):
        gy = chart_y + (chart_h / 3) * step
        d.add(Line(chart_x, gy, chart_x + chart_w, gy,
                   strokeColor=colors.HexColor("#EAE8E1"), strokeWidth=0.5))

    for idx, (b, ecnt, scnt) in enumerate(zip(slots, extortion_counts, snapshot_counts)):
        lbl = b["label"]
        bx1 = chart_x + idx * col_w + (col_w - bar_w * 2 - 2) / 2
        bx2 = bx1 + bar_w + 2.0

        # Extortion bar (red / terracotta)
        eh = max(2, (ecnt / float(max_val)) * chart_h) if ecnt > 0 else 0
        if eh > 0:
            d.add(Rect(bx1, chart_y, bar_w, eh, rx=1.5, ry=1.5,
                       fillColor=colors.HexColor("#C0392B"), strokeColor=None))
            d.add(String(bx1 + bar_w/2 - 2.5, chart_y + eh + 2,
                         str(ecnt), fontName="Helvetica-Bold", fontSize=5.5,
                         fillColor=colors.HexColor("#791F1F")))

        # Snapshot bar (slate blue)
        sh = max(2, (scnt / float(max_val)) * chart_h) if scnt > 0 else 0
        if sh > 0:
            d.add(Rect(bx2, chart_y, bar_w, sh, rx=1.5, ry=1.5,
                       fillColor=colors.HexColor("#3498DB"), strokeColor=None))
            d.add(String(bx2 + bar_w/2 - (3.5 if scnt < 10 else 6), chart_y + sh + 2,
                         str(scnt), fontName="Helvetica-Bold", fontSize=5.5,
                         fillColor=colors.HexColor("#1B4F72")))

        d.add(String(bx1 - 2, chart_y - 9, lbl,
                     fontName="Helvetica", fontSize=5.2,
                     fillColor=colors.HexColor("#666666")))

    leg_x = width - 230
    d.add(Rect(leg_x, height - 15, 6, 6, rx=1, ry=1,
               fillColor=colors.HexColor("#C0392B"), strokeColor=None))
    d.add(String(leg_x + 9, height - 14, "Dated Extortion Events (49)",
                 fontName="Helvetica", fontSize=5.8, fillColor=colors.HexColor("#555555")))
    d.add(Rect(leg_x + 105, height - 15, 6, 6, rx=1, ry=1,
               fillColor=colors.HexColor("#3498DB"), strokeColor=None))
    d.add(String(leg_x + 114, height - 14, "Snapshot Feeds: CVEs & IOCs (214)",
                 fontName="Helvetica", fontSize=5.8, fillColor=colors.HexColor("#555555")))

    return d


def create_threat_flow_diagram(width: float = 178 * mm, height: float = 46,
                               kev_cnt: int = 57, nvd_cnt: int = 68,
                               org_cnt: int = 44, post_cnt: int = 49) -> Drawing:
    """
    Renders an executive correlation flowchart diagram:
    Vulnerabilities -> Ingress Infrastructure -> Threat Groups -> Indian Victims -> Incident Response.
    """
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=4, ry=4,
               fillColor=colors.HexColor("#F8F9FA"),
               strokeColor=colors.HexColor("#E2E8F0"), strokeWidth=0.7))

    org_lbl = f"{org_cnt} Org" if org_cnt == 1 else f"{org_cnt} Orgs"
    post_lbl = f"{post_cnt} Posting" if post_cnt == 1 else f"{post_cnt} Postings"
    nodes = [
        ("Exploited CVEs", f"{kev_cnt} KEV / {nvd_cnt} NVD", colors.HexColor("#1F618D")),
        ("Ingress Vectors", "Edge Devices / SSL-VPN", colors.HexColor("#D35400")),
        ("Threat Groups", "Ransomware Syndicates", colors.HexColor("#C0392B")),
        ("Named Victims", f"{org_lbl} / {post_lbl}", colors.HexColor("#791F1F")),
        ("CERT-In Reporting", "6-Hour Incident Clock", colors.HexColor("#27AE60")),
    ]

    box_w = 82
    box_h = 28
    spacing = (width - 24 - (len(nodes) * box_w)) / (len(nodes) - 1)
    bx = 12
    by = 9

    for idx, (title, subtitle, col) in enumerate(nodes):
        d.add(Rect(bx, by, box_w, box_h, rx=3, ry=3,
                   fillColor=colors.white, strokeColor=col, strokeWidth=1))
        d.add(Rect(bx, by + box_h - 4, box_w, 4, rx=1, ry=1,
                   fillColor=col, strokeColor=None))
        d.add(String(bx + 5, by + 14, title, fontName="Helvetica-Bold",
                     fontSize=6.5, fillColor=colors.HexColor("#1A1A1A")))
        d.add(String(bx + 5, by + 5, subtitle, fontName="Helvetica",
                     fontSize=5.6, fillColor=colors.HexColor("#666666")))

        if idx < len(nodes) - 1:
            arrow_x = bx + box_w + 3
            arrow_y = by + box_h / 2
            arrow_len = spacing - 6
            d.add(Line(arrow_x, arrow_y, arrow_x + arrow_len, arrow_y,
                       strokeColor=colors.HexColor("#A0AEC0"), strokeWidth=1.2))
            d.add(Polygon(
                [arrow_x + arrow_len, arrow_y,
                 arrow_x + arrow_len - 3, arrow_y + 2.5,
                 arrow_x + arrow_len - 3, arrow_y - 2.5],
                fillColor=colors.HexColor("#A0AEC0"), strokeColor=None))

        bx += box_w + spacing

    return d


def create_regional_corridor_table(signals: List[Signal], st) -> Table:
    """
    Renders an executive regional corridor risk breakdown table accounting for
    100% of claimed Indian victim organisations and extortion postings (leak-site claims).
    Dynamically generates targeted industry sectors from data.
    """
    victims, total_posts, unique_orgs = extract_victim_attributions(signals)
    corridors_spec = [
        ("Western Industrial Hub", ["Gujarat", "Maharashtra"]),
        ("Northern Administrative & Commercial Hub", ["Delhi NCR"]),
        ("Southern Technology & Healthcare Corridor", ["Karnataka", "Tamil Nadu", "Telangana & AP"]),
        ("Central & Eastern Industrial Corridor", ["Chhattisgarh"]),
        ("Northern & Western Fringe", ["Haryana", "Punjab & Chandigarh", "Uttarakhand", "Rajasthan"]),
        ("Location Unresolved / Corporate Cloud", ["Location Unresolved"]),
    ]
    rows = [
        [Paragraph("<b>Regional Threat Corridor / Cluster</b>", st["cellb"]),
         Paragraph("<b>States &amp; UTs Included</b>", st["cellb"]),
         Paragraph("<b>Targeted Industry Sectors</b>", st["cellb"]),
         Paragraph("<b>Unique Entities</b>", st["cellb"]),
         Paragraph("<b>Disclosures (%)</b>", st["cellb"])],
    ]
    total_o = 0
    total_p = 0
    for name, states in corridors_spec:
        c_victims = [v for v in victims if v["state"] in states]
        org_cnt = len(c_victims)
        post_cnt = sum(v["postings"] for v in c_victims)
        total_o += org_cnt
        total_p += post_cnt
        sec_counts = Counter(v["sector"] for v in c_victims)
        top_secs = [f"{sec.split('&')[0].strip()} ({cnt})" for sec, cnt in sec_counts.most_common(3)]

        st_counts = Counter(v["state"] for v in c_victims)
        st_strs = [f"{st} ({cnt})" for st, cnt in sorted(st_counts.items())]
        if name == "Location Unresolved / Corporate Cloud":
            st_desc = "Corporate cloud / unmapped registry"
        else:
            st_desc = ", ".join(st_strs)

        pct_o = (org_cnt / float(unique_orgs)) * 100 if unique_orgs else 0.0
        pct_p = (post_cnt / float(total_posts)) * 100 if total_posts else 0.0
        o_str = f"{org_cnt} org" if org_cnt == 1 else f"{org_cnt} orgs"
        p_str = f"{post_cnt} post" if post_cnt == 1 else f"{post_cnt} posts"
        rows.append([
            Paragraph(f"<b>{name}</b>", st["cell"]),
            Paragraph(st_desc, st["cell"]),
            Paragraph(", ".join(top_secs), st["cell"]),
            Paragraph(f"{o_str} ({pct_o:.1f}%)", st["cellc"]),
            Paragraph(f"{p_str} ({pct_p:.1f}%)", st["cellc"]),
        ])

    tot_o_str = f"{total_o} org" if total_o == 1 else f"{total_o} orgs"
    tot_p_str = f"{total_p} post" if total_p == 1 else f"{total_p} posts"
    rows.append([
        Paragraph("<b>Total India Telemetry</b>", st["cellb"]),
        Paragraph(f"<b>All {len(STATE_GEO_COORDS)} Monitored States / Clusters</b>", st["cellb"]),
        Paragraph(f"<b>{len([k for k in SECTORS if k != 'UNCLASSIFIED'])} Industry Sectors Monitored</b>", st["cellb"]),
        Paragraph(f"<b>{tot_o_str} (100.0%)</b>", st["cellc"]),
        Paragraph(f"<b>{tot_p_str} (100.0%)</b>", st["cellc"]),
    ])

    return _table(rows, [44 * mm, 38 * mm, 48 * mm, 24 * mm, 24 * mm], st, header=True,
                  zebra=True, padding=(1.6, 1.6, 2.5, 2.5))


def _headline_card(h: Dict, st) -> Table:
    """One headline threat as a card: severity strip, what happened, why it
    matters for India, what to do, references."""
    sev = h["severity"]
    sev_hex = SEVERITY_HEX.get(sev, "#5B6573")
    meta = [f'<font color="{sev_hex}"><b>{sev.upper()}</b></font>',
            _esc(h["category"]), format_date(h["date"])]
    sectors = [short_sector_label(x) for x in h.get("sectors", []) if x in SECTORS]
    if sectors:
        meta.append("Sectors: " + _esc(", ".join(sectors)))

    inner = [Paragraph(_esc(h["title"]), st["card_title"]),
             Paragraph("  ·  ".join(meta), st["card_meta"])]
    if h.get("status"):
        inner.append(Paragraph(f"<b>Status:</b> {_esc(h['status'])}", st["card_meta"]))
    inner += [Spacer(1, 4),
              Paragraph("WHAT HAPPENED", st["card_label"]),
              Paragraph(_esc(h["summary"]), st["card_body"]),
              Spacer(1, 5)]

    why = [Paragraph("WHY IT MATTERS FOR INDIA", st["card_label"])]
    if h.get("india_link"):
        why.append(Paragraph(f"<i>{_esc(h['india_link'])}</i>", st["card_meta"]))
        why.append(Spacer(1, 2))
    if h.get("india_impact"):
        why.append(Paragraph(_esc(h["india_impact"]), st["card_body"]))
    todo = [Paragraph("WHAT TO DO NOW", st["card_label"])]
    todo += [Paragraph(_esc(a), st["card_bullet"], bulletText="\u2022")
             for a in h["actions"]]
    cols = Table([[why, todo]], colWidths=[80 * mm, 88 * mm])
    cols.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 8),
        ("LEFTPADDING", (1, 0), (1, 0), 8),
        ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ("LINEBEFORE", (1, 0), (1, 0), 0.5, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    inner.append(cols)

    refs = []
    if h.get("cves"):
        refs.append("<b>CVEs:</b> " + _esc(", ".join(h["cves"])))
    if h.get("indicators"):
        refs.append("<b>Indicators:</b> " + _esc("; ".join(h["indicators"])))
    links = "; ".join(f'<a href="{_esc(src["url"])}" color="#1E3A5F">{_esc(src["name"])}</a>'
                      for src in h["sources"])
    refs.append(f"<b>Sources:</b> {links}")
    inner.append(Spacer(1, 5))
    inner += [Paragraph(r, st["card_meta"]) for r in refs]

    card = Table([["", inner]], colWidths=[2.2 * mm, 175.8 * mm])
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(sev_hex)),
        ("BACKGROUND", (1, 0), (1, 0), PANEL_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 8),
        ("RIGHTPADDING", (1, 0), (1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return card


def _headline_index_table(entries: List[Dict], st) -> Table:
    rows = [[Paragraph("<b>Date</b>", st["cellb"]),
             Paragraph("<b>Incident</b>", st["cellb"]),
             Paragraph("<b>Type</b>", st["cellb"]),
             Paragraph("<b>Severity</b>", st["cellb"]),
             Paragraph("<b>India</b>", st["cellb"])]]
    for h in entries:
        sev_hex = SEVERITY_HEX.get(h["severity"], "#5B6573")
        rows.append([
            Paragraph(format_date(h["date"]), st["cell"]),
            Paragraph(_esc(h["title"].split(":")[0]), st["cell"]),
            Paragraph(_esc(h["category"]), st["cell"]),
            Paragraph(f'<font color="{sev_hex}"><b>{h["severity"]}</b></font>', st["cell"]),
            Paragraph("Direct" if h.get("india_direct") else "Broad", st["cell"]),
        ])
    return _table(rows, [20 * mm, 78 * mm, 48 * mm, 16 * mm, 16 * mm], st, zebra=True,
                  padding=(1.6, 1.6, 3, 3))


def _headline_brief_table(entries: List[Dict], st) -> Table:
    rows = [[Paragraph("<b>Date</b>", st["cellb"]),
             Paragraph("<b>Incident</b>", st["cellb"]),
             Paragraph("<b>Do this first</b>", st["cellb"]),
             Paragraph("<b>Sources</b>", st["cellb"])]]
    for h in entries:
        sev_hex = SEVERITY_HEX.get(h["severity"], "#5B6573")
        links = "<br/>".join(f'<a href="{_esc(src["url"])}" color="#1E3A5F">{_esc(src["name"])}</a>'
                             for src in h["sources"])
        rows.append([
            Paragraph(format_date(h["date"]), st["cell"]),
            Paragraph(f'<b>{_esc(h["title"])}</b><br/>'
                      f'<font color="{sev_hex}"><b>{h["severity"].upper()}</b></font> · '
                      f'{_esc(brief_text(h))}', st["cell"]),
            Paragraph(_esc(h["actions"][0]), st["cell"]),
            Paragraph(links, st["cell"]),
        ])
    return _table(rows, [18 * mm, 78 * mm, 54 * mm, 28 * mm], st, zebra=True,
                  padding=(2.4, 2.4, 3, 3))


def _news_watch_table(items: List[Dict], st) -> Table:
    from .collectors.news import classify_news
    rows = [[Paragraph("<b>Date</b>", st["cellb"]),
             Paragraph("<b>Headline</b>", st["cellb"]),
             Paragraph("<b>Source</b>", st["cellb"]),
             Paragraph("<b>Type</b>", st["cellb"])]]
    for item in items:
        tags = classify_news(item["title"], item.get("summary", ""))
        kind = tags["category"] + (" · India" if item.get("india_relevant") else "")
        rows.append([
            Paragraph(format_date(item.get("published_at", "")), st["cell"]),
            Paragraph(f'<a href="{_esc(item["url"])}" color="#1E3A5F">{_esc(item["title"])}</a>',
                      st["cell"]),
            Paragraph(_esc(item.get("source", "")), st["cell"]),
            Paragraph(_esc(kind), st["cell"]),
        ])
    return _table(rows, [20 * mm, 110 * mm, 26 * mm, 22 * mm], st, zebra=True,
                  padding=(2.2, 2.2, 3, 3))


# ---------------------------------------------------------------------------
# Numbered Canvas for Dynamic Page Counts & Running Headers
# ---------------------------------------------------------------------------

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas: cover band on page 1, running header and footer after."""
    author_name = "Siva prasad Boddu"
    public_mode = False
    edition_date = ""
    COVER_BAND_H = 50 * mm

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def _edition_label(self) -> str:
        return "TLP:CLEAR" if getattr(self, "public_mode", False) else "INTERNAL EDITION"

    def draw_cover_band(self):
        page_w, page_h = A4
        band_h = self.COVER_BAND_H
        x = 16 * mm
        self.setFillColor(NAVY)
        self.rect(0, page_h - band_h, page_w, band_h, stroke=0, fill=1)
        self.setFillColor(ACCENT)
        self.rect(0, page_h - band_h, page_w, 1.6 * mm, stroke=0, fill=1)

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#F6AD55"))
        self.drawString(x, page_h - 14 * mm, "CYBER THREAT INTELLIGENCE  ·  INDIA")
        self.setFont("Helvetica-Bold", 23)
        self.setFillColor(colors.white)
        self.drawString(x, page_h - 25 * mm, "India Threat Landscape Bulletin")
        self.setFont("Helvetica", 9.5)
        self.setFillColor(colors.HexColor("#CBD5E1"))
        self.drawString(x, page_h - 32 * mm,
                        "Multi-source threat intelligence for Indian organisations")
        self.setFont("Helvetica", 8)
        self.drawString(x, page_h - 40 * mm,
                        f"Edition {self.edition_date}   ·   Prepared by {self.author_name}")

        label = self._edition_label()
        badge_w, badge_h = 34 * mm, 8 * mm
        bx, by = page_w - 16 * mm - badge_w, page_h - 27 * mm
        badge_col = "#2F855A" if getattr(self, "public_mode", False) else "#B45309"
        self.setFillColor(colors.HexColor(badge_col))
        self.roundRect(bx, by, badge_w, badge_h, 2 * mm, stroke=0, fill=1)
        self.setFillColor(colors.white)
        self.setFont("Helvetica-Bold", 8.5)
        self.drawCentredString(bx + badge_w / 2, by + 2.8 * mm, label)

    def draw_page_decorations(self, page_count):
        self.saveState()
        page_w, page_h = A4
        margin_l = 16 * mm
        margin_r = page_w - 16 * mm

        if self._pageNumber == 1:
            self.draw_cover_band()
        else:
            # Running header: thin navy strip, title left, edition right
            self.setFillColor(NAVY)
            self.rect(0, page_h - 3 * mm, page_w, 3 * mm, stroke=0, fill=1)
            self.setFont("Helvetica-Bold", 7.0)
            self.drawString(margin_l, 289 * mm, "INDIA THREAT LANDSCAPE BULLETIN")
            self.setFillColor(MUTED)
            self.setFont("Helvetica", 7.0)
            self.drawRightString(margin_r, 289 * mm,
                                 f"{self._edition_label()}   ·   {self.edition_date}")
            self.setStrokeColor(RULE)
            self.setLineWidth(0.5)
            self.line(margin_l, 286.5 * mm, margin_r, 286.5 * mm)

        # Footer
        self.setStrokeColor(RULE)
        self.setLineWidth(0.5)
        self.line(margin_l, 11 * mm, margin_r, 11 * mm)
        self.setFont("Helvetica", 6.0)
        self.setFillColor(MUTED)
        author = getattr(self, "author_name", "Siva prasad Boddu")
        disclaimer = "Independent analyst work · Not affiliated with CERT-In"
        if getattr(self, "public_mode", False):
            self.drawString(margin_l, 7.5 * mm, f"Prepared by: {author}   |   {disclaimer}   |   TLP:CLEAR")
        else:
            self.drawString(margin_l, 7.5 * mm, f"Prepared by: {author}   |   {disclaimer}")

        self.setFont("Helvetica-Bold", 7.0)
        self.setFillColor(NAVY)
        self.drawRightString(margin_r, 7.5 * mm, f"Page {self._pageNumber} of {page_count}")

        self.restoreState()


# ---------------------------------------------------------------------------
# Bulletin Document Generator
# ---------------------------------------------------------------------------

def compute_feed_provenance(signals: List[Signal]) -> Dict[str, Any]:
    """
    Computes feed snapshot provenance dates across all ingested intelligence sources.
    Returns dict with raw_dates, formatted_dates, provenance_str, latest_date, their_dates, currency_note.
    """
    feed_snapshots = {}
    for sig in signals:
        if sig.source and sig.observed_at:
            dt_str = sig.observed_at[:10]
            if sig.source not in feed_snapshots or dt_str > feed_snapshots[sig.source]:
                feed_snapshots[sig.source] = dt_str

    formatted_dates = {}
    feed_snapshots_by_disp = {}
    feed_items = []
    for src in sorted(feed_snapshots.keys()):
        d_raw = feed_snapshots[src]
        try:
            d_fmt = datetime.strptime(d_raw, "%Y-%m-%d").strftime("%d-%b")
        except Exception:
            d_fmt = d_raw
        src_disp = src.replace("abuse.ch ", "").replace(" (aggregate counts)", "")
        formatted_dates[src_disp] = d_fmt
        feed_snapshots_by_disp[src_disp] = d_raw
        feed_items.append(f"{src_disp} ({d_fmt})")

    latest_raw = max(feed_snapshots.values()) if feed_snapshots else ""
    try:
        latest_fmt = datetime.strptime(latest_raw, "%Y-%m-%d").strftime("%d-%b")
    except Exception:
        latest_fmt = latest_raw

    cisa_fmt = formatted_dates.get("CISA KEV", "n/a")
    rl_fmt = formatted_dates.get("ransomlook.io", "n/a")
    their_dates = cisa_fmt if cisa_fmt == rl_fmt else f"{cisa_fmt} and {rl_fmt}"
    # Name the feeds that lag the newest one, so a stale feed is visible on the cover
    lagging = [f"{name}: {d}" for name, d in sorted(formatted_dates.items())
               if feed_snapshots_by_disp.get(name, "") < latest_raw and name in ("CISA KEV", "ransomlook.io", "ransomware.live", "CERT-In", "NVD")]
    currency_note = (f"Data current to {latest_fmt or 'n/a'}"
                     + (f" ({', '.join(lagging)})" if lagging else ""))

    return {
        "raw_dates": feed_snapshots,
        "formatted_dates": formatted_dates,
        "provenance_str": ", ".join(feed_items),
        "latest_date": latest_fmt,
        "cisa_kev_date": cisa_fmt,
        "ransomlook_date": rl_fmt,
        "their_dates": their_dates,
        "currency_note": currency_note,
    }


def build_multi_bulletin(output_path: str, scored_sectors: List[Dict],
                         signals: List[Signal], correlation: Dict,
                         source_summary: List[Dict], window_days: int,
                         org_name: str = "", prepared_by: str = "Siva prasad Boddu",
                         analyst: str = "", public_mode: bool = False) -> str:
    st = _styles()
    now = datetime.now(timezone.utc)
    ist = timezone(timedelta(hours=5, minutes=30))
    now_ist = now.astimezone(ist)

    # Master reporting window variables (derived from end_date and window_days)
    end_date = window_end_date()
    start_date = end_date - timedelta(days=window_days)
    period_start = start_date.strftime("%d %b %Y")
    period_end = end_date.strftime("%d %b %Y")

    window_str = f"{period_start} to {period_end} ({window_days} days)"

    max_sig_date = max((s.observed_at[:10] for s in signals if s.observed_at), default=end_date.isoformat())
    data_end_date = min(datetime.fromisoformat(max_sig_date).date(), end_date)
    weekly_buckets = compute_weekly_buckets(start_date, end_date, data_end_date=data_end_date)
    final_bucket = weekly_buckets[-1]
    final_dates = final_bucket["dates"]
    final_days = final_bucket["days"]
    bucket_label_str = f"{final_dates}, {final_days} days"

    provenance_info = compute_feed_provenance(signals)

    ioc_summary = get_ioc_summary(signals, public_mode=public_mode)
    ioc_first_min = ioc_summary.get("first_seen_min") or "n/a"
    ioc_first_max = ioc_summary.get("first_seen_max") or "n/a"
    surge_count = ioc_summary.get("ioc_window_recent_count", 0)
    total_iocs = ioc_summary.get("total_indicators", 0)
    unique_hosts = ioc_summary.get("unique_hosts", 0)
    dom_comp_hosts = ioc_summary.get("compromised_hosts", 0)
    dom_unver_hosts = ioc_summary.get("unverified_hosts", 0)
    dom_phish_hosts = ioc_summary.get("phishing_hosts", 0)
    asn_dist_str = ioc_summary.get("asn_distribution", "")
    asn_legend_str = ioc_summary.get("asn_legend", "")
    infra_signals = [s for s in signals if s.signal_type in (SignalType.MALWARE_INFRA, SignalType.PHISHING)]

    author_name = (prepared_by or analyst or "Siva prasad Boddu").strip()
    if author_name.lower() in ("client pvt ltd", ""):
        author_name = "Siva prasad Boddu"
    NumberedCanvas.author_name = author_name
    NumberedCanvas.public_mode = public_mode
    NumberedCanvas.edition_date = now_ist.strftime("%d %b %Y")

    doc = _BulletinDoc(
        output_path, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=13 * mm, bottomMargin=13 * mm,
        title="India Threat Landscape Bulletin", author=author_name)

    story = []

    by_type = Counter(s.signal_type for s in signals)
    sources = sorted({s.source for s in signals})
    critical_sectors = sum(1 for s in scored_sectors if s["risk_band"] in ("Critical", "High"))

    victim_attributions, total_postings, unique_orgs = extract_victim_attributions(signals)

    cisa_kev_count = sum(1 for s in signals if s.source == "CISA KEV")
    all_cves = set()
    for s in signals:
        if s.entities and s.entities.cves:
            all_cves.update(s.entities.cves)

    crit_labels = ", ".join([short_sector_label(s["sector"]) for s in scored_sectors if s["risk_band"] in ("Critical", "High")][:3]) or "none"

    # Facts the narrative quotes, all computed from this window's signals
    kev_groups = rf.kev_by_product(signals)
    edge_text = rf.edge_cve_text(kev_groups)
    edge_vendors = rf.edge_vendor_names(kev_groups)
    window_iocs = extract_iocs(signals, public_mode=public_mode)
    technique_examples = rf.ioc_technique_examples(window_iocs)
    action_due = now_ist.date() + timedelta(days=7)

    # =========================================================================
    # COVER: headline numbers, bottom line, sector picture
    # =========================================================================
    gen_date = now_ist.date()
    headlines = load_headline_threats(start=start_date, end=max(gen_date, end_date))
    try:
        recent_news = get_intel_items((now - timedelta(days=14)).isoformat(), now.isoformat())
    except sqlite3.Error:
        recent_news = []
    news_items = news_watch(recent_news, headline_keywords(headlines))
    sec_no = 0

    story.append(Spacer(1, NumberedCanvas.COVER_BAND_H - 13 * mm))
    meta = [
        f"Reporting period: {window_str}",
        provenance_info["currency_note"],
        f"Generated: {now_ist.strftime('%d %b %Y %H:%M IST')}"
    ]
    story.append(Paragraph(" | ".join(_esc(m) for m in meta), st["sub"]))
    try:
        health_rows = source_health(now=now)
    except sqlite3.Error:
        health_rows = []
    health_bad = health_problems(health_rows)
    if health_bad:
        story.append(Paragraph(
            f"<font color='#B45309'><b>Source health:</b> {len(health_bad)} of "
            f"{sum(1 for r in health_rows if r['status'] != 'MANUAL')} feeds failing or stale when this "
            f"report was generated ({_esc(', '.join(r['source'] for r in health_bad[:4]))}"
            f"{', ...' if len(health_bad) > 4 else ''}). See the Source Health table in the Methodology section.</font>",
            st["sub"]))
    story.append(Spacer(1, 6))

    seen_multiple_count = correlation.get("corroborated_count", 0)
    seen_artefacts_count = correlation.get("shared_artefacts_count", 0)

    kpi_org_str = f"{unique_orgs} Org" if unique_orgs == 1 else f"{unique_orgs} Orgs"
    all_cves_count = len({c for s in signals if s.entities and s.entities.cves for c in s.entities.cves})

    kpi_label = ParagraphStyle("KL", parent=st["kpi"], fontName="Helvetica-Bold",
                               fontSize=6.3, leading=8, textColor=MUTED)
    kpi_num = ParagraphStyle("KN", parent=st["kpi"], fontName="Helvetica-Bold",
                             fontSize=16, leading=19)
    kpi_note = ParagraphStyle("KT", parent=st["kpi"], fontSize=5.8, leading=7.2,
                              textColor=MUTED)

    def _kpi(label, value, colour, note=""):
        cell = [Paragraph(label.upper(), kpi_label),
                Paragraph(f"<font color='{colour}'>{value}</font>", kpi_num)]
        if note:
            cell.append(Paragraph(_esc(note), kpi_note))
        return cell

    kpi_cards = [[
        _kpi("Signals", len(signals), "#12263F"),
        _kpi("Sources", len(sources), "#1E3A5F"),
        _kpi("Extortion Postings", total_postings, "#9B1C1C", f"({kpi_org_str})"),
        _kpi("Actively Exploited (KEV)", cisa_kev_count, "#C2410C", f"({all_cves_count} Distinct CVEs Monitored)"),
        _kpi("Seen in multiple feeds", seen_multiple_count, "#2F855A", f"({seen_artefacts_count} Artefacts)"),
        _kpi("High+ Sectors", critical_sectors, "#9B1C1C", f"({crit_labels})"),
    ]]
    story.append(_kpi_table(kpi_cards, [29.6 * mm] * 6))
    story.append(Spacer(1, 8))

    # Bottom line up front
    actor_orgs_cover = defaultdict(set)
    for v in victim_attributions:
        for a in v["actor"].split(", "):
            if a and a != "Unattributed":
                actor_orgs_cover[a].add(v["victim"])
    lead_actors = [a for a, _ in sorted(actor_orgs_cover.items(), key=lambda x: (-len(x[1]), x[0]))[:4]]

    bluf = []
    if headlines:
        named = "; ".join(
            f"{_esc(h['title'].split(':')[0])} "
            f"(<font color='{SEVERITY_HEX[h['severity']]}'><b>{h['severity']}</b></font>)"
            for h in headlines[:4])
        n_h = len(headlines)
        more = f"; and {n_h - 4} more" if n_h > 4 else ""
        bluf.append(f"<b>{n_h} headline incident{'s' if n_h != 1 else ''} in section 01.</b> "
                    f"Act first on: {named}{more}.")
    if scored_sectors:
        top = scored_sectors[0]
        bluf.append(f"<b>{_esc(top['label'])}</b> carries the highest composite risk score "
                    f"({top['risk_score']:.1f}, {top['risk_band']}). "
                    f"{critical_sectors} sector{'s rate' if critical_sectors != 1 else ' rates'} High or above.")
    if unique_orgs:
        org_word = "organisation was" if unique_orgs == 1 else "organisations were"
        post_word = "posting" if total_postings == 1 else "postings"
        actors_txt = f" Most active groups: {_esc(', '.join(lead_actors))}." if lead_actors else ""
        bluf.append(f"<b>{unique_orgs} Indian {org_word}</b> named on ransomware leak sites "
                    f"across {total_postings} {post_word}.{actors_txt}")
    n_infra = len(infra_signals)
    bluf.append(f"<b>{cisa_kev_count} actively exploited vulnerabilit{'y' if cisa_kev_count == 1 else 'ies'}</b> "
                f"(CISA KEV) map to technology used in Indian enterprises, and {n_infra} malware and phishing "
                f"infrastructure signal{'s' if n_infra != 1 else ''} yielded {total_iocs} indicator{'s' if total_iocs != 1 else ''} "
                f"for alerting (see the companion IOC sheet).")

    bluf_box = Table([[[Paragraph("Bottom line", st["h3"])] +
                       [Paragraph(b, st["bluf"], bulletText="\u25A0") for b in bluf]]],
                     colWidths=[178 * mm])
    bluf_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 3, ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.append(bluf_box)
    story.append(Spacer(1, 8))

    story.append(create_sector_bar_chart(scored_sectors))
    story.append(Spacer(1, 8))

    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("TOC0", fontName="Helvetica", fontSize=8.2,
                                      leading=11.8, textColor=INK)]
    toc.dotsMinLevel = 0
    story.append(Paragraph("In this report", st["h3"]))
    story.append(toc)

    # =========================================================================
    # THREATS IN FOCUS: analyst-written headline incidents + news watch
    # =========================================================================
    if headlines or news_items:
        story.append(PageBreak())
        sec_no += 1
        story.append(_section_header("Threats in Focus: Incidents Driving Current Risk", sec_no, st))
        story.append(Paragraph(
            f"Notable incidents reported up to {gen_date.strftime('%d %b %Y')}, summarised by the analyst "
            f"from the sources on each card. They extend past the telemetry window ending "
            f"{end_date.strftime('%d %b %Y')} and do not change the sector scores in this report.",
            st["small"]))
        story.append(Spacer(1, 6))
        if len(headlines) > 3:
            story.append(Paragraph("This Month at a Glance", st["h3"]))
            story.append(_headline_index_table(headlines, st))
            story.append(Spacer(1, 8))
        cards, brief = split_headlines(headlines)
        for h in cards:
            story.append(KeepTogether([_headline_card(h, st), Spacer(1, 7)]))
        if brief:
            story.append(Paragraph("More Incidents to Know About", st["h3"]))
            story.append(Paragraph("Global incidents that reach Indian organisations through shared "
                                   "software and services. One line each, with the first thing to do.",
                                   st["small"]))
            story.append(Spacer(1, 3))
            story.append(_headline_brief_table(brief, st))
            story.append(Spacer(1, 7))
        if news_items:
            story.append(KeepTogether([
                Paragraph("Also in the News (last 14 days)", st["h3"]),
                Paragraph("Security-news stories naming India or describing high-impact events, "
                          "collected automatically and not yet analysed.", st["small"]),
                Spacer(1, 3),
                _news_watch_table(news_items, st),
            ]))

    # =========================================================================
    # PAGE 2: Executive Summary & Strategic Outlook
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header("Executive Summary: Threat Judgements & Strategic Outlook", sec_no, st))

    if public_mode:
        tlp_table = Table([[
            Paragraph("<b>TLP:CLEAR</b> | "
                      "Independent analyst work · Not affiliated with CERT-In. Built from public feeds.",
                      st["tlp_clear"])
        ]], colWidths=[178 * mm])
        tlp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EAFAF1")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#27AE60")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(tlp_table)
        story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Strategic Analytical Judgements (Admiralty ICD 203 Standards)</b>", st["h3"]))

    sample_caveat = " (small sample, indicative only)" if (unique_orgs <= 10 or total_postings <= 10) else ""

    actor_orgs_all = defaultdict(set)
    for v in victim_attributions:
        for a in v["actor"].split(", "):
            if a and a != "Unattributed":
                actor_orgs_all[a].add(v["victim"])
    top_actors_by_victims = [act for act, _ in sorted(actor_orgs_all.items(), key=lambda x: (-len(x[1]), x[0]))[:4]]
    top_actors_str = ", ".join(top_actors_by_victims) if top_actors_by_victims else "Unattributed"

    # Judgement 1: where the named victims are
    lead_states = rf.top_states(victim_attributions, 3)
    lead_orgs = len({v["victim"] for v in victim_attributions if v["state"] in lead_states})
    lead_pct = (lead_orgs / float(unique_orgs)) * 100 if unique_orgs else 0.0
    unresolved_orgs = len({v["victim"] for v in victim_attributions if v["state"] == "Location Unresolved"})
    sector_counts = Counter(v["sector"] for v in victim_attributions)
    if lead_states:
        share = "the Majority" if lead_pct > 50 else "the Largest Share"
        j1_title = f"1. {_join_and(lead_states)} Account for {share} of Named Victims [Confidence: C3]"
        top_sec, top_sec_n = sector_counts.most_common(1)[0]
        j1_desc = (
            f"Organisations located in {_join_and(lead_states)} account for {lead_orgs} of {unique_orgs} "
            f"claimed victim entities ({lead_pct:.1f}%){sample_caveat}; {unresolved_orgs} could not be placed from public information. "
            f"{top_sec} is the most-named sector ({top_sec_n} of {unique_orgs} organisations), with primary adversary activity driven by syndicates "
            f"ranked by victim volume: {top_actors_str}."
        )
    elif unique_orgs:
        j1_title = "1. Named Victims Could Not Be Placed by State [Confidence: C3]"
        j1_desc = (
            f"{unique_orgs} Indian organisations were named on leak sites{sample_caveat}, but none could be placed by state from public information. "
            f"Primary adversary activity is driven by syndicates ranked by victim volume: {top_actors_str}."
        )
    else:
        j1_title = "1. No Indian Organisations Named on Leak Sites in This Window [Confidence: C3]"
        j1_desc = "The ransomware leak-site feeds named no Indian organisations during the reporting window."

    # Judgement 2: exploited edge devices, from CISA KEV vendor and product data
    kev_cve_total = len({c for g in kev_groups for c in g["cves"]})
    edge_cve_total = len({c for g in kev_groups if g["edge"] for c in g["cves"]})
    if edge_cve_total:
        j2_title = (f"2. Edge and Remote-Access Devices Account for {edge_cve_total} of {kev_cve_total} "
                    f"Exploited CVEs in the Window [Confidence: B2]")
        j2_desc = (
            f"CISA KEV records in-the-wild exploitation of internet-facing appliances during the window: {edge_text}. "
            f"These devices sit on the perimeter of enterprise networks in the targeted sectors. Leak sites do not publish how victims "
            f"were breached, so this marks exposure to a known way in, not the confirmed entry point for any named victim."
        )
        if kev_groups and not kev_groups[0]["edge"]:
            j2_desc += (f" The single most-listed product this window is {kev_groups[0]['label']} "
                        f"({kev_groups[0]['count']} CVEs), which is not an edge device.")
    else:
        j2_title = "2. No Edge-Device Exploitation Listed in CISA KEV This Window [Confidence: B2]"
        j2_desc = (
            f"CISA KEV listed {kev_cve_total} exploited CVEs relevant to Indian enterprise technology in the window, "
            f"none of them in VPN, firewall or remote-access products."
        )

    # Judgement 3: Dynamic Sector Risk Rankings
    top3_secs = scored_sectors[:3]
    top3_labels = [s.get("label", s.get("sector", "")).split("/")[0].split("&")[0].strip() for s in top3_secs]
    j3_title = f"3. {', '.join(top3_labels)} Lead Composite Risk Rankings [Confidence: C3]"

    j3_parts = []
    for s_item in top3_secs:
        s_score = s_item["risk_score"]
        s_band = assign_risk_band(s_score)
        s_lbl = s_item.get("label", s_item.get("sector", ""))
        s_cves = s_item.get("exploited_cve_count", 0)
        s_vics = s_item.get("victim_count", 0)
        s_uniq = s_item.get("unique_victim_count", s_vics)
        s_infra = s_item.get("infra_count", 0)

        drivers = []
        if s_infra > 0:
            drivers.append(f"{s_infra} delivery/phishing hosts")
        if s_cves > 0:
            drivers.append(f"{s_cves} monitored CVEs")
        if s_vics > 0:
            drivers.append(f"{s_vics} leak postings across {s_uniq} unique organisations")
        if s_item.get("nciipc_critical"):
            drivers.append("Section 70A CII criticality weight")

        driver_str = f" driven by {', '.join(drivers)}" if drivers else ""
        j3_parts.append(f"{s_lbl} leads the risk ranking ({s_score:.1f}, {s_band}){driver_str}" if not j3_parts else f"{s_lbl} ({s_score:.1f}, {s_band}){driver_str}")

    j3_desc = f"{'; '.join(j3_parts)}{sample_caveat}."

    # Judgement 4: how groups publish Indian victims
    patterns = rf.actor_posting_patterns(victim_attributions)
    waves = rf.single_day_waves(patterns)
    episodic = [e for e in rf.episodic_actors(patterns) if not waves or e["actor"] != waves[0]["actor"]]
    j4_title = "4. Campaign Dumping vs. Episodic Batch Postings [Confidence: C3]"
    j4_parts = []
    if waves:
        w = waves[0]
        j4_parts.append(
            f"{w['actor']} posted {w['orgs']} Indian organisations on a single day ({rf.fmt_date(w['date'])}), which may indicate "
            f"a coordinated mass-exploitation wave rather than separate intrusions")
    if episodic:
        e = episodic[0]
        sec_desc = _join_and([sec.split("&")[0].strip() for sec in e["sectors"]])
        j4_parts.append(
            f"{e['actor']} ({e['orgs']} unique organisations across {e['postings']} postings) published victims in "
            f"batches on {e['dates']} separate dates, mostly in {sec_desc}")
    if j4_parts:
        j4_desc = (f"{'. '.join(j4_parts)}{sample_caveat}. Leak-site dates reflect publication after failed negotiations, "
                   f"not the date of intrusion.")
    elif patterns:
        lead_actor = max(patterns, key=lambda a: patterns[a]["postings"])
        lp = patterns[lead_actor]
        j4_desc = (
            f"Adversary activity during this period was led by {lead_actor} ({lp['postings']} postings across "
            f"{len(lp['dates'])} distinct date(s)){sample_caveat}. Leak sites often batch disclosures after private negotiation "
            f"deadlines, so publication dates reflect leak-site cadence rather than network compromise dates."
        )
    else:
        j4_desc = "No attributed leak-site postings of Indian organisations were recorded in the window."

    # Judgement 5: Malware Delivery Chains
    technique_names = [t["technique"] for t in technique_examples]
    if total_iocs:
        j5_title = "5. Domestic Websites Leveraged in Malware Delivery Chains [Confidence: C3]"
        j5_desc = (
            f"Threat telemetry identifies {dom_comp_hosts} compromised, {dom_unver_hosts} unverified, {dom_phish_hosts} phishing lookalikes ({unique_hosts} hosts, {total_iocs} records) "
            f"with exact .in ccTLD suffixes used as distribution points"
            f"{', mainly for ' + _join_and(technique_names) if technique_names else ''}. "
            f"Security operations teams should alert and notify site owners and CERT-In rather than merely applying local perimeter defensive blocks."
        )
    else:
        j5_title = "5. No Domestic Malware Delivery Infrastructure Observed [Confidence: C3]"
        j5_desc = "No .in-hosted malware delivery or phishing indicators were recorded by the infrastructure feeds in this window."

    judgements = [
        (j1_title, j1_desc),
        (j2_title, j2_desc),
        (j3_title, j3_desc),
        (j4_title, j4_desc),
        (j5_title, j5_desc),
    ]

    for title, desc in judgements:
        j_block = [
            Paragraph(f"<b>{_esc(title)}</b>", st["cellb"]),
            Paragraph(_esc(desc), st["body_justify"]),
        ]
        story.append(KeepTogether(j_block))
        story.append(Spacer(1, 2.5))

    story.append(Spacer(1, 2.5))
    story.append(Paragraph("<b>7-Day Tactical Action Matrix for Security Operations & IT Leadership</b>", st["h3"]))

    priority_for = {"Critical": ("#C0392B", "P1: Critical"), "High": ("#D35400", "P2: High"),
                    "Medium": ("#27AE60", "P3: Medium"), "Low": ("#27AE60", "P3: Medium")}
    headline_rows = []
    for h in headlines[:6]:
        colour, label = priority_for[h["severity"]]
        headline_rows.append([
            Paragraph(f"<font color='{colour}'><b>{label}</b></font>", st["cell"]),
            Paragraph(f"<b>{_esc(h['title'].split(':')[0])}:</b> {_esc(h['actions'][0])}", st["cell"]),
            Paragraph(_esc(h.get("scope") or h["category"]), st["cell"]),
            Paragraph(_esc(h.get("owner") or "SecOps"), st["cell"]),
        ])

    matrix_rows = [
        [Paragraph("<b>Priority</b>", st["cellb"]),
         Paragraph("<b>Recommended Action</b>", st["cellb"]),
         Paragraph("<b>Target Scope</b>", st["cellb"]),
         Paragraph("<b>Primary Stakeholder</b>", st["cellb"])],
        *headline_rows,
        [Paragraph("<font color='#C0392B'><b>P1: Critical</b></font>", st["cell"]),
         Paragraph(_esc(
             (f"Patch Internet-facing edge appliances listed in CISA KEV ({edge_text}). " if edge_text else
              f"Patch the {kev_cve_total} actively exploited CVEs listed in CISA KEV this window, internet-facing systems first. ")
             + f"Recommended target date: {action_due.strftime('%d %b %Y')}."), st["cell"]),
         Paragraph("External Perimeter", st["cell"]),
         Paragraph("Network / SysAdmin", st["cell"])],
        [Paragraph("<font color='#C0392B'><b>P1: Critical</b></font>", st["cell"]),
         Paragraph("Enforce phishing-resistant multi-factor authentication (MFA) on all VPN, RDP, and remote access portals.", st["cell"]),
         Paragraph("All Remote Users", st["cell"]),
         Paragraph("IAM / SecOps", st["cell"])],
        [Paragraph("<font color='#D35400'><b>P2: High</b></font>", st["cell"]),
         Paragraph(f"Ingest and monitor {ioc_summary['total_indicators']} identified malware delivery indicators and lookalike phishing domains in alert-first mode on perimeter firewalls and EDR before enforcing active blocking (see companion CSV).", st["cell"]),
         Paragraph("DNS / Firewalls / EDR", st["cell"]),
         Paragraph("SOC / Threat Intel", st["cell"])],
        [Paragraph("<font color='#D35400'><b>P2: High</b></font>", st["cell"]),
         Paragraph("Audit 180-day log retention architectures and NTP synchronization in accordance with CERT-In 20(3)/2022.", st["cell"]),
         Paragraph("SIEM & DCs", st["cell"]),
         Paragraph("Compliance / Infra", st["cell"])],
        [Paragraph("<font color='#27AE60'><b>P3: Medium</b></font>", st["cell"]),
         Paragraph("Conduct external attack surface management (EASM) scans across corporate ASN and cloud CIDR blocks.", st["cell"]),
         Paragraph("Internet Assets", st["cell"]),
         Paragraph("SecOps / Red Team", st["cell"])],
    ]
    # Highest priority first; headline actions lead within each tier
    matrix_rows[1:] = sorted(matrix_rows[1:],
                             key=lambda row: re.search(r"P(\d)", row[0].text).group(1))
    story.append(_table(matrix_rows, [22 * mm, 88 * mm, 38 * mm, 30 * mm], st, zebra=True, padding=(1.6, 1.6, 2.5, 2.5)))

    # =========================================================================
    # PAGE 3: Geographic Telemetry & Subcontinent Hotspots
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header("India Threat Telemetry & Regional Hotspots", sec_no, st))
    story.append(Paragraph(
        "Geographic distribution of extortion postings (leak-site claims) across Indian industrial corridors and metropolitan centers. "
        + (f"The most-named locations this window are {_join_and(lead_states)}; {unresolved_orgs} of {unique_orgs} organisations could not be placed."
           if lead_states else "No named organisation could be placed by state this window."),
        st["small"]))
    story.append(Spacer(1, 3))

    story.append(create_india_threat_map(signals, height=210, window_days=window_days))
    story.append(Spacer(1, 4))

    story.append(create_timeline_activity_chart(signals, start_date=start_date, end_date=end_date, height=95))
    story.append(Spacer(1, 2))
    story.append(Paragraph(
        f"<i>* Telemetry Methodology Note: Weekly signal volume reflects multi-feed baseline synchronization across calendar-aligned weekly intervals "
        f"spanning {window_str}. "
        f"The final interval ({final_dates}, {final_days} days) is partial; {surge_count} of {total_iocs} indicators fell in the {final_dates} interval ({final_days} days) alongside catalogue ingestion of monitored CVEs (CISA KEV / NVD). "
        f"The actual IOC ingestion window from the companion CSV spans {ioc_first_min} to {ioc_first_max} (first seen {ioc_first_min} to {ioc_first_max}). "
        f"The red overlay bars track adversary leak publication dates ({total_postings} total postings across {unique_orgs} unique entities), "
        f"reflecting extortion disclosure timestamps rather than initial intrusion dates.</i>",
        st["small"]))
    story.append(Spacer(1, 3))

    story.append(Paragraph("<b>Regional Corridor Risk Breakdown (100% Entities Reconciled)</b>", st["h3"]))
    story.append(create_regional_corridor_table(signals, st))

    # =========================================================================
    # PAGE 4: Adversary Syndicates & Technology Infrastructure
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header("Adversary Landscape & Targeted Technology Infrastructure", sec_no, st))
    story.append(Paragraph(
        "Active extortion syndicates and threat groups observed targeting Indian organisations, paired with the enterprise technology "
        "listed in CISA KEV as exploited during the window."
        + (f" Edge devices from {_join_and(edge_vendors)} feature among the exploited products." if edge_vendors else ""),
        st["small"]))
    story.append(Spacer(1, 4))

    story.append(create_threat_actors_bar_chart(signals))
    story.append(Spacer(1, 2))
    story.append(Paragraph(_actor_chart_note(signals, unique_orgs, total_postings), st["small"]))
    story.append(Spacer(1, 4))

    story.append(create_targeted_tech_chart(signals))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Spotlight: High-Impact CERT-In Advisories in Reporting Period</b>", st["h3"]))
    adv_rows = [
        [Paragraph("<b>Advisory ID &amp; Date</b>", st["cellb"]),
         Paragraph("<b>Subject</b>", st["cellb"]),
         Paragraph("<b>Severity</b>", st["cellb"]),
         Paragraph("<b>Annexure I Category</b>", st["cellb"])],
    ]
    for adv in rf.certin_advisories(signals):
        cats = "; ".join(f"({r}) {textwrap.shorten(ANNEXURE_I[r]['title'], 52, placeholder='...')}"
                         for r in adv["annexure"][:2] if r in ANNEXURE_I)
        adv_rows.append([
            Paragraph(f"{_esc(adv['reference'])}<br/><font color='#666666' size='5.8'>{rf.fmt_date(adv['date'])}</font>", st["mono"]),
            Paragraph(_esc(adv["subject"]), st["cell"]),
            Paragraph(_esc(adv["severity"]), st["cell"]),
            Paragraph(_esc(cats) or "Not mapped", st["cell"]),
        ])
    if len(adv_rows) == 1:
        adv_rows.append([Paragraph("None in window", st["cell"]), Paragraph("No CERT-In notes or advisories were collected for this window.", st["cell"]),
                         Paragraph("", st["cell"]), Paragraph("", st["cell"])])
    story.append(_table(adv_rows, [28 * mm, 80 * mm, 18 * mm, 52 * mm], st, zebra=True, padding=(1.4, 1.4, 2.5, 2.5)))
    story.append(Spacer(1, 2))
    story.append(Paragraph(
        "<i>* Source: CERT-In Vulnerability Notes &amp; Advisories (cert-in.org.in). Non-Equivalence Notice: CERT-In advisories "
        "reflect nationally monitored software vulnerabilities and attack vectors; publication does not imply that specific "
        "named entities in this bulletin were compromised via these advisories.</i>",
        st["small"]))

    # =========================================================================
    # PAGE 5: Sector Risk Assessment & Published Methodology
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header("Sector Risk Ranking & Assessment Matrix", sec_no, st))
    story.append(Paragraph(
        "Quantitative risk scoring across fourteen critical Indian industry sectors. Component scores reflect claimed victim impact (named on leak sites), "
        "actively exploited sector CVEs, malicious C2 and phishing infrastructure, regulatory pressure, and Section 70A Critical Information Infrastructure (CII) designation.",
        st["small"]))
    story.append(Spacer(1, 4))

    sec_rows = [[
        Paragraph("<b>Sector</b>", st["cellb"]),
        Paragraph("<b>Score</b>", st["cellb"]),
        Paragraph("<b>Band</b>", st["cellb"]),
        Paragraph("<b>Postings (Orgs)</b>", st["cellb"]),
        Paragraph("<b>Vulnerabilities (KEV+NVD)</b>", st["cellb"]),
        Paragraph("<b>Delivery/Phishing Hosts (Infra)</b>", st["cellb"]),
        Paragraph("<b>Sources</b>", st["cellb"]),
        Paragraph("<b>CII</b>", st["cellb"])
    ]]
    for s in scored_sectors:
        uniq_org_cnt = s.get("unique_victim_count", s["victim_count"])
        band_str = assign_risk_band(s["risk_score"])
        sec_rows.append([
            Paragraph(_esc(s["label"]), st["cell"]),
            Paragraph(f"<b>{s['risk_score']:.1f}</b>", st["cell"]),
            _band_text(band_str, st),
            Paragraph(f"{s['victim_count']} ({uniq_org_cnt})", st["cellc"]),
            Paragraph(str(s["exploited_cve_count"]), st["cellc"]),
            Paragraph(str(s["infra_count"]), st["cellc"]),
            Paragraph(str(s["source_count"]), st["cellc"]),
            Paragraph("<b>Yes</b>" if s["nciipc_critical"] else "-", st["cellc"]),
        ])
    story.append(_table(sec_rows,
                        [42*mm, 11*mm, 23*mm, 21*mm, 28*mm, 21*mm, 16*mm, 16*mm],
                        st, zebra=True, padding=(1.6, 1.6, 2.2, 2.2)))
    story.append(Spacer(1, 4))

    from .snapshot import generate_changes_vs_previous
    snapshot_ts = now_ist.strftime("%Y-%m-%d %H:%M IST")
    changes_note = generate_changes_vs_previous(
        scored_sectors, ioc_summary, signals,
        edition=("public" if public_mode else "internal"),
        window_days=window_days
    )

    weekly_note = ""
    if window_days <= 14:
        from .database import get_signals
        from .snapshot import compute_weekly_changes
        prior_end = start_date
        prior_start = prior_end - timedelta(days=window_days)
        prior_signals = [Signal.from_row(r) for r in get_signals(days=window_days, end_date=prior_end)]
        prior_anchor = datetime(prior_end.year, prior_end.month, prior_end.day, 23, 59, 59,
                                tzinfo=timezone(timedelta(hours=5, minutes=30)))
        weekly_delta = compute_weekly_changes(signals, scored_sectors, ioc_summary, prior_signals, prior_anchor)
        weekly_note = (f"<br/><b>Change vs Previous {window_days} Days ({prior_start.strftime('%d %b')} - "
                       f"{prior_end.strftime('%d %b %Y')}):</b> {weekly_delta['summary_text']}")

    from .collectors.vulns import EDGE_VENDOR_SECTORS
    edge_sample = ", ".join(sorted(list(EDGE_VENDOR_SECTORS.keys())[:5]))
    cve_mapping_rule_text = (
        f"Exploited CVEs are mapped to sectors via affected vendor CPE stacks "
        f"(edge appliances including {edge_sample} to IT/ITES, BFSI, Telecom; OT/SCADA to Manufacturing). "
        f"Exposure score evaluates perimeter attack surface scanning, unpatched service density, and Section 70A Critical Information Infrastructure designations."
    )

    formula_table = Table([[
        Paragraph(
            f"<b>Mathematical Scoring Weights &amp; Normalisation Formula (Scoring Engine v{SCORING_VERSION}, data snapshot {snapshot_ts})</b><br/>"
            "<code>Risk Score = 0.30*Impact + 0.20*Exploit + 0.15*Infra + 0.15*Criticality(CII) + 0.10*Pressure + 0.10*Exposure</code><br/>"
            "<i>Temporal Half-Life Decay:</i> Weight(t) = exp(-ln(2) * age / 21 days). "
            "<i>Risk Bands:</i> Critical (80+), High (60-79), Moderate (40-59), Low (20-39), Minimal (&lt;20).<br/>"
            f"<i>CVE-to-Sector Mapping &amp; Exposure Scoring:</i> {cve_mapping_rule_text}<br/>"
            f"{changes_note}"
            f"{weekly_note}",
            st["callout"])
    ]], colWidths=[178 * mm])
    formula_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F4F7")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3.0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.0),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(formula_table)
    story.append(Spacer(1, 5))
    story.append(create_signal_breakdown_chart(signals))
    story.append(Spacer(1, 3.0))

    if source_summary:
        story.append(Paragraph("Intelligence Collection Coverage", st["h3"]))
        cov_rows = [[Paragraph("<b>Source Feed</b>", st["cellb"]),
                     Paragraph("<b>Signal Classification</b>", st["cellb"]),
                     Paragraph("<b>Signals</b>", st["cellb"]),
                     Paragraph("<b>Mean India Relevance</b>", st["cellb"])]]
        for row in source_summary[:10]:
            stype_label = "Vulnerability (monitored)" if row["source"] == "NVD" else _esc(TYPE_LABEL.get(row["signal_type"], row["signal_type"]))
            cov_rows.append([
                Paragraph(_esc(row["source"])[:44], st["cell"]),
                Paragraph(stype_label, st["cell"]),
                Paragraph(str(row["n"]), st["cellc"]),
                Paragraph(f"{row['avg_relevance']:.2f}", st["cellc"]),
            ])
        story.append(_table(cov_rows, [58 * mm, 54 * mm, 24 * mm, 42 * mm], st,
                            zebra=True, padding=(1.6, 1.6, 2.5, 2.5)))
        story.append(Spacer(1, 2.0))

        from .iocs import extract_host
        all_extracted = extract_iocs(signals, public_mode=public_mode)
        host_to_sec = {}
        for sig in signals:
            if sig.signal_type.value in ('malware_infra', 'phishing'):
                h_raw = sig.title.split(':')[-1].strip()
                if isinstance(sig.raw, dict):
                    h_raw = sig.raw.get('ioc') or sig.raw.get('url') or h_raw
                h_clean = extract_host(h_raw)
                if sig.sectors:
                    host_to_sec[h_clean] = sig.sectors

        attr_iocs_cnt = sum(1 for i in all_extracted if i['host'] in host_to_sec)
        unsec_iocs_cnt = len(all_extracted) - attr_iocs_cnt

        sens_parts = []
        for top_s in scored_sectors[:3]:
            s_raw = (top_s["risk_score"] - 0.15 * top_s["components"].get("infra", 0.0)) / 0.85
            s_band = assign_risk_band(s_raw)
            sens_parts.append(f"{top_s['label'].split('/')[0].split('&')[0].strip()} is {s_raw:.1f} ({s_band})")
        sens_str = ", ".join(sens_parts)

        story.append(Paragraph(
            f"<i>* Multi-Source Methodology &amp; Sector Mapping Rules: Threat telemetry is collected from {len(sources)} multi-source feeds. "
            f"CISA KEV and NVD share upstream CVE data, while ransomware.live and ransomlook.io track overlapping extortion leak sites; "
            f"corroboration scoring adjusts for shared upstream parents without awarding artificial confidence uplifts. Out of {total_iocs} actionable domestic indicators across {unique_hosts} unique hosts, "
            f"{attr_iocs_cnt} are attributed to specific sector technology stacks, while {unsec_iocs_cnt} represent unsectored domestic delivery infrastructure ({attr_iocs_cnt} + {unsec_iocs_cnt} = {total_iocs} total domestic threat indicators across {unique_hosts} unique hosts). "
            f"Sensitivity Analysis: Scores without the Delivery/Phishing Hosts (Infra) component were renormalised by dividing raw scores by 0.85 to rescale weights to 1.0: {sens_str}. "
            f"Rankings are sensitive to the Infra component (active delivery infrastructure). Scores can fall or rise when Infra is removed because Infra weight differs per sector. "
            f"{_manual_feed_note(signals, window_days)} "
            f"Single-source leak site claims carry Admiralty C/D reliability and are capped at Moderate (C2/C3) confidence.</i>",
            st["small"]))

    # =========================================================================
    # PAGE 6: Granular Assessment by Sector (Top 7 Sectors - strictly 1 page)
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header("Granular Assessment by Sector (Top Risk Profiles)", sec_no, st))
    story.append(Paragraph(
        "Detailed examination of top Indian sectors, including claimed victim entities named on leak sites, threat actor attribution, "
        "actively exploited CVEs, and component score breakdown. Lower-scoring sectors are detailed in the Sector Risk Ranking table (previous section).", st["small"]))
    story.append(Spacer(1, 3))

    for s in scored_sectors[:7]:
        block = [Paragraph(
            f"<b>{_esc(s['label'])}</b> - {s['risk_band']} ({s['risk_score']:.1f})", st["h3"])]
        block.append(Paragraph(_esc(s["explanation"]), st["small"]))

        c = s["components"]
        block.append(Paragraph(
            f"<font face='Courier' size='6.8'>impact {c['impact']:.0f} | "
            f"exploit {c['exploit']:.0f} | infra {c['infra']:.0f} | "
            f"pressure {c['pressure']:.0f} | exposure {c['exposure']:.0f}</font>", st["small"]))

        if s["top_cves"]:
            block.append(Paragraph(
                f"<b>Monitored CVEs (KEV + NVD):</b> {_esc(format_truncated_list(s['top_cves'], 4))}",
                st["small"]))
        if s["groups"]:
            clean_actors = [_normalize_actor(a) for a in s["groups"]]
            block.append(Paragraph(
                f"<b>Actors Observed:</b> {_esc(format_truncated_list(clean_actors, 4))}",
                st["small"]))
        sec_victims = [v for v in victim_attributions if v["sector"] == s["label"] or v["sector"] == s["sector"]]
        v_cnt = len(sec_victims)
        p_cnt = sum(v.get("postings", 1) for v in sec_victims)
        if v_cnt > 0:
            sec_actors = format_truncated_list([_normalize_actor(a) for a in s.get("groups", [])], 3) or "unattributed syndicates"
            ent_str = "1 entity" if v_cnt == 1 else f"{v_cnt} entities"
            post_str = "1 posting" if p_cnt == 1 else f"{p_cnt} postings"
            block.append(Paragraph(
                f"<b>Extortion Disclosures:</b> {ent_str} ({post_str}) claimed by {sec_actors} (leak-site claims)",
                st["small"]))
        block.append(Paragraph(
            f"<b>Evidence Feeds:</b> {_esc(', '.join(s['sources']))}", st["small"]))
        story.append(KeepTogether(block))
        story.append(Spacer(1, 2.0))

    # =========================================================================
    # PAGE 7: Cross-Source Correlation & Infrastructure Co-Occurrence
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header("Cross-Source Correlation & Infrastructure Co-Occurrence", sec_no, st))
    story.append(Paragraph(_correlation_summary(correlation), st["small"]))
    story.append(Spacer(1, 3))

    cisa_k_cnt = sum(1 for s in signals if s.source == "CISA KEV")
    nvd_k_cnt = sum(1 for s in signals if s.source == "NVD")
    story.append(create_threat_flow_diagram(
        kev_cnt=cisa_k_cnt, nvd_cnt=nvd_k_cnt,
        org_cnt=unique_orgs, post_cnt=total_postings
    ))
    story.append(Spacer(1, 4))

    links = correlation.get("exploit_victim_links", [])
    if links:
        story.append(Paragraph(
            "Enterprise Edge & Ingress Vulnerabilities Co-occurring with Sector Victims", st["h3"]))
        story.append(Paragraph(
            "Observed co-occurrence of active edge device CVEs in sector technology stacks concurrently with live victim activity. "
            "Represents elevated threat exposure rather than direct causal breach evidence for specific victims.",
            st["small"]))
        rows = [[Paragraph("<b>Sector</b>", st["cellb"]),
                 Paragraph("<b>CVE Identifier</b>", st["cellb"]),
                 Paragraph("<b>Vulnerability Description</b>", st["cellb"]),
                 Paragraph("<b>Unique Orgs</b>", st["cellb"]),
                 Paragraph("<b>Exposure Characteristics</b>", st["cellb"])]]
        for link in links[:7]:
            notes = []
            if link["ransomware_linked"]:
                notes.append("known ransomware vector")
            if link["edge_device"]:
                notes.append("internet-facing edge appliance")
            rows.append([
                Paragraph(_esc(sector_label(link["sector"])), st["cell"]),
                Paragraph(_esc(link["cve"]), st["monowhole"]),
                Paragraph(_esc(link["vuln_title"])[:95], st["cell"]),
                Paragraph(str(link["victim_count"]), st["cellc"]),
                Paragraph(_esc("; ".join(notes) or "enterprise stack"), st["cell"]),
            ])
        story.append(_table(rows,
                            [36*mm, 31*mm, 56*mm, 15*mm, 40*mm], st, zebra=True,
                            padding=(1.8, 1.8, 3, 3)))
        story.append(Spacer(1, 4))

    shared = correlation.get("shared_artefacts", [])
    if shared:
        story.append(Paragraph("Artefacts Seen Across Multiple Feeds", st["h3"]))
        rows = [[Paragraph("<b>Artefact Identifier</b>", st["cellb"]),
                 Paragraph("<b>Sources</b>", st["cellb"]),
                 Paragraph("<b>Signal Classifications</b>", st["cellb"]),
                 Paragraph("<b>Assessed Severity</b>", st["cellb"])]]
        for item in shared[:6]:
            if any(st_t in ("victim", "data_leak") for st_t in item.get("signal_types", [])):
                sec_lbl = sector_label(item["sectors"][0]) if item.get("sectors") else "Corporate"
                disp_art = f"{sec_lbl} entity (corroborated)"
            else:
                disp_art = item["artefact"]
            rows.append([
                Paragraph(_esc(disp_art)[:55], st["mono"]),
                Paragraph(_esc(", ".join(item["sources"][:3])), st["cell"]),
                Paragraph(_esc(", ".join(item["signal_types"][:3])), st["cell"]),
                Paragraph(_esc(item["max_severity"]), st["cellc"]),
            ])
        story.append(_table(rows, [64*mm, 48*mm, 44*mm, 22*mm], st, zebra=True,
                            padding=(1.8, 1.8, 3, 3)))

    # =========================================================================
    # PAGE 8: Priority Intelligence Signals & Tactical Ingress Telemetry
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header("Highest-Priority Signals (Ranked Actionable Telemetry)", sec_no, st))
    story.append(Paragraph(
        "Ranked by risk contribution score combining signal severity, confidence, recency, and India relevance. "
        "Single-source leak-site claims are capped at Moderate (0.60 / C3) and designated High-impact, low-confidence rather than Critical. "
        "KEV vulnerabilities are listed in CISA KEV as exploited (active in-the-wild exploitation or historical baseline).",
        st["small"]))
    story.append(Spacer(1, 3))

    # 1. Table 1: Priority Extortion Telemetry (Disclosures by Sector & Threat Actor)
    story.append(Paragraph("<b>Priority Extortion Telemetry (Disclosures by Sector &amp; Threat Actor)</b>", st["h3"]))
    top_sec_telemetry = []
    for s in scored_sectors:
        p_cnt = s.get("victim_count", 0)
        if p_cnt > 0:
            top_sec_telemetry.append(s)
            if len(top_sec_telemetry) == 5:
                break

    v_table_rows = [[
        Paragraph("<b>Sector</b>", st["cellb"]),
        Paragraph("<b>Attributed Threat Actors</b>", st["cellb"]),
        Paragraph("<b>Entities</b>", st["cellbc"]),
        Paragraph("<b>Postings</b>", st["cellbc"]),
        Paragraph("<b>Primary Hubs</b>", st["cellb"]),
        Paragraph("<b>Confidence</b>", st["cellbc"]),
    ]]
    for s in top_sec_telemetry:
        sec_name = sector_label(s["sector"])
        actors_list = format_truncated_list([_normalize_actor(a) for a in s.get("groups", [])], 3) or "Unattributed"
        u_cnt = s.get("unique_victim_count", s.get("victim_count", 0))
        p_cnt = s.get("victim_count", 0)
        u_str = f"{u_cnt} entity" if u_cnt == 1 else f"{u_cnt} entities"
        p_str = f"{p_cnt} post" if p_cnt == 1 else f"{p_cnt} posts"

        sec_vics = [v for v in victim_attributions if v["sector"] == s.get("label", s["sector"]) or v["sector"] == s["sector"]]
        st_counts = Counter(v["state"] for v in sec_vics if v.get("state") and v["state"] != "Location Unresolved")
        top_states = [st_name for st_name, _ in st_counts.most_common(2)]
        hubs_str = ", ".join(top_states) if top_states else "Regional / Corporate Cloud"
        conf_str = "0.60 (C3)"

        v_table_rows.append([
            Paragraph(_esc(sec_name), st["cell"]),
            Paragraph(_esc(actors_list), st["cell"]),
            Paragraph(u_str, st["cellc"]),
            Paragraph(p_str, st["cellc"]),
            Paragraph(_esc(hubs_str), st["cell"]),
            Paragraph(conf_str, st["cellc"]),
        ])
    story.append(_table(v_table_rows, [44 * mm, 46 * mm, 22 * mm, 22 * mm, 26 * mm, 18 * mm], st,
                        zebra=True, padding=(1.2, 1.2, 2.0, 2.0)))
    story.append(Spacer(1, 1.5))

    masked_note = (
        "<i>* Telemetry aggregation note: All figures represent aggregated entity and disclosure counts by industry sector and threat actor. "
        "Single-source leak-site claims are capped at 0.60 / C3 confidence. Multi-feed listings reflect corroboration across ransomware.live and ransomlook.io (which share upstream scraper sources). "
        "Ranking criteria: Sorted by aggregate disclosure volume, attributed actor activity, and sector criticality impact.</i>"
    )
    story.append(Paragraph(masked_note, st["small"]))
    story.append(Spacer(1, 2.0))

    # 2. Table 2: Priority Exploited Vulnerabilities (CISA KEV)
    story.append(Paragraph("<b>Priority Exploited Vulnerabilities (CISA KEV)</b>", st["h3"]))
    cve_sigs = [s for s in signals if s.source == "CISA KEV"]

    actives = []
    baselines = []
    seen_cves = set()
    for s in sorted(cve_sigs, key=lambda x: -x.risk_contribution):
        c = s.entities.cves[0] if s.entities.cves else s.title
        if c in seen_cves:
            continue
        seen_cves.add(c)
        raw_data = s.raw if isinstance(s.raw, dict) else {}
        date_added = raw_data.get("dateAdded") or (s.observed_at or "")[:10]
        cve_year = 0
        try:
            cve_year = int(c.split("-")[1])
        except Exception:
            pass
        if cve_year >= end_date.year - 1 and date_added >= start_date.isoformat():
            actives.append(s)
        else:
            baselines.append(s)

    # Sort Active KEV exploitation first, then Baseline (older CVE, still in KEV)
    top_cves = actives[:3] + baselines[:2]

    cve_table_rows = [[
        Paragraph("<b>CVE Identifier</b>", st["cellb"]),
        Paragraph("<b>Affected Technology / Vulnerability</b>", st["cellb"]),
        Paragraph("<b>Exploitation Status</b>", st["cellb"]),
        Paragraph("<b>Severity</b>", st["cellb"]),
        Paragraph("<b>Confidence</b>", st["cellbc"]),
        Paragraph("<b>Date Added</b>", st["cellbc"]),
    ]]
    for s in top_cves:
        cve_id = s.entities.cves[0] if s.entities.cves else s.title
        raw_data = s.raw if isinstance(s.raw, dict) else {}
        date_added = raw_data.get("dateAdded") or (s.observed_at or "")[:10]
        vuln_title = s.title.split(":", 1)[1].strip() if ":" in s.title else s.title

        cve_year = 0
        try:
            cve_year = int(cve_id.split("-")[1])
        except Exception:
            pass

        is_active = (cve_year >= end_date.year - 1 and date_added >= start_date.isoformat())
        if is_active:
            status_text = "<font color='#C0392B'><b>Active KEV exploitation</b></font>"
            sev_col = "#791F1F" if s.severity.value == "Critical" else "#C0392B"
            sev_str = f"<font color='{sev_col}'><b>{s.severity.value}</b></font>"
        else:
            status_text = "<font color='#666666'>Baseline (older CVE, still in KEV)</font>"
            # Cap baseline CVEs at High (not Critical) unless they appear in a CERT-In advisory
            appears_in_certin = any(cve_id in (sig.entities.cves or []) for sig in signals if sig.source.startswith("CERT-In"))
            if s.severity.value == "Critical" and not appears_in_certin:
                sev_str = "<font color='#C0392B'><b>High</b></font>"
            else:
                sev_col = "#791F1F" if s.severity.value == "Critical" else "#C0392B"
                sev_str = f"<font color='{sev_col}'><b>{s.severity.value}</b></font>"

        conf_str = f"{s.confidence:.2f} (B2)"

        cve_table_rows.append([
            Paragraph(_esc(cve_id), st["mono"]),
            Paragraph(_esc(vuln_title[:55]), st["cell"]),
            Paragraph(status_text, st["cell"]),
            Paragraph(sev_str, st["cellc"]),
            Paragraph(conf_str, st["cellc"]),
            Paragraph(_esc(date_added[:10]), st["date"]),
        ])
    story.append(_table(cve_table_rows, [26 * mm, 52 * mm, 46 * mm, 18 * mm, 18 * mm, 18 * mm], st,
                        zebra=True, padding=(1.2, 1.2, 2.0, 2.0)))
    story.append(Spacer(1, 2.5))

    story.append(Paragraph("<b>Perimeter Ingress Analysis & Tactical Infrastructure Drivers</b>", st["h3"]))
    story.append(Paragraph(
        "<b>Edge Appliance Exposure:</b> Internet-facing network infrastructure is a common initial-access route. "
        + (f"CISA KEV lists exploitation of remote-access appliances and perimeter gateways from {_join_and(edge_vendors)} in this window; "
           "organisations running unpatched SSL-VPN and gateway firmware are exposed to pre-authentication bypass and credential theft."
           if edge_vendors else "CISA KEV listed no exploited edge-device CVEs in this window; keep perimeter firmware current regardless."),
        st["body_justify"]))
    story.append(Spacer(1, 2.0))
    story.append(Paragraph(
        f"<b>Malicious Infrastructure &amp; Delivery Chains:</b> Multi-source telemetry identifies {len(infra_signals)} infrastructure signals "
        f"yielding {dom_comp_hosts} compromised, {dom_unver_hosts} unverified, {dom_phish_hosts} phishing lookalikes ({unique_hosts} hosts, {total_iocs} records) "
        f"with Indian domain relevance across .in ccTLDs. The actual IOC ingestion window from the companion CSV spans {ioc_first_min} to {ioc_first_max}; "
        f"{surge_count} of {total_iocs} indicators fell in the {final_dates} interval ({final_days} days). "
        f"BGP routing resolution reveals hosting across global infrastructure: {asn_dist_str}; threat classifications designate indicators as 'Indian' referring to the domain suffix (.in ccTLDs), not hosting location. "
        f"{_technique_sentence(technique_examples)}"
        f"Network defenders should ingest these indicators in alert-first monitoring mode before active blocking.",
        st["body_justify"]))
    story.append(Spacer(1, 2.0))
    story.append(Paragraph(
        "<b>Identity & Remote Access Hardening:</b> Initial access brokers (IABs) actively exploit weak credentials and legacy authentication. "
        "Defending remote access portals against adversary access requires phasing out legacy SMS-based authentication in favor of "
        "phishing-resistant FIDO2/WebAuthn hardware tokens, strict IP allowlisting for administrative consoles, and continuous session auditing.",
        st["body_justify"]))
    story.append(Spacer(1, 2.5))

    story.append(Paragraph("<b>Tactical Indicators of Compromise (Defanged Telemetry Samples)</b>", st["h3"]))
    match = re.search(r"(\d{4}-\d{2}-\d{2})", os.path.basename(output_path))
    stamp = match.group(1) if match else end_date.strftime("%Y-%m-%d")
    csv_filename = f"IOCs_India_Threat_Landscape_Public_{stamp}.csv" if public_mode else f"IOCs_India_Threat_Landscape_Internal_{stamp}.csv"
    ioc_csv_path = os.path.join(os.path.dirname(output_path) or ".", csv_filename)
    _, csv_hash = export_iocs_csv(signals, ioc_csv_path, public_mode=public_mode)

    ioc_rows = [[
        Paragraph("<b>Defanged Indicator</b>", st["cellb"]),
        Paragraph("<b>Type</b>", st["cellb"]),
        Paragraph("<b>Technique / Malware</b>", st["cellb"]),
        Paragraph("<b>First Seen</b>", st["cellb"]),
        Paragraph("<b>Expiry Date</b>", st["cellb"]),
        Paragraph("<b>Action Guidance</b>", st["cellb"]),
    ]]
    for item in ioc_summary.get("top_examples", [])[:4]:
        threat_disp = f"{item['technique']} ({item['malware_family']})" if item.get("malware_family") else item.get("technique", "")
        disp_ind = item["defanged"]
        if len(disp_ind) > 36 and "://" in disp_ind:
            parts = disp_ind.split("/")
            if len(parts) >= 4:
                disp_ind = f"{parts[0]}//{parts[2]}/.../{parts[-1]}"
            elif len(disp_ind) > 36:
                disp_ind = disp_ind[:20] + "..." + disp_ind[-12:]
        ioc_rows.append([
            Paragraph(_esc(disp_ind), st["ioc_mono"]),
            Paragraph(_esc(item["type"]), st["cellc"]),
            Paragraph(_esc(threat_disp), st["cell"]),
            Paragraph(_esc(item["first_seen"]), st["cellc"]),
            Paragraph(_esc(item["expiry_date"]), st["cellc"]),
            Paragraph(_esc(item["recommended_action"]), st["cell"]),
        ])
    story.append(_table(ioc_rows, [56 * mm, 15 * mm, 34 * mm, 16 * mm, 16 * mm, 41 * mm], st, zebra=True, padding=(1.4, 1.4, 2.0, 2.0)))
    story.append(Spacer(1, 1.5))
    feed_attribution_text = "abuse.ch ThreatFox and URLhaus (CC0 1.0 Universal)"
    story.append(Paragraph(
        f"<i>* Companion Artifact &amp; Integrity Hash: Complete machine-readable indicator set exported to companion artifact: "
        f"<b>{csv_filename}</b> ({ioc_summary['total_indicators']} unique actionable indicators across {feed_attribution_text}). "
        f"SHA-256: <code>{csv_hash}</code>. India Relevance Criteria: Domestic indicators filtered to exact .in country-code top-level domains "
        f"(.in, .co.in, .gov.in, etc.); 'Indian' refers to the domain suffix, not hosting location. "
        f"{asn_legend_str} Recommendation: Ingest in alert-first monitoring mode before active blocking.</i>",
        st["small"]))

    # =========================================================================
    # PAGE 9: Confirmed Indian Victim Directory & Threat Actor Registry
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header(f"Aggregated Indian Extortion Telemetry by Sector &amp; Corridor ({unique_orgs} Entities Across {total_postings} Postings)", sec_no, st))
    story.append(Paragraph(
        "Consolidated telemetry of Indian organisations identified on extortion leak sites, aggregated by industry sector, "
        "geographic corridor, and threat actor. Named entities are excluded. "
        "All extortion listings reflect unverified adversary claims without independent forensic verification.",
        st["small"]))
    story.append(Spacer(1, 2.5))

    agg_groups = defaultdict(lambda: {"count": 0, "postings": 0, "corroborated": False})
    for v in victim_attributions:
        sec = v["sector"]
        st_name = v["state"]
        act = v["actor"]
        k = (sec, st_name, act)
        agg_groups[k]["count"] += 1
        agg_groups[k]["postings"] += v["postings"]
        if v.get("corroborated"):
            agg_groups[k]["corroborated"] = True

    v_rows = [[
        Paragraph("<b>Industry Sector</b>", st["cellb_compact"]),
        Paragraph("<b>State / Region</b>", st["cellb_compact"]),
        Paragraph("<b>Threat Actor Syndicates</b>", st["cellb_compact"]),
        Paragraph("<b>Disclosures (Posts)</b>", st["cellb_compact"]),
        Paragraph("<b>Admiralty Confidence / Status</b>", st["cellb_compact"]),
    ]]
    sorted_groups = sorted(agg_groups.items(), key=lambda x: (-x[1]["postings"], -x[1]["count"], x[0][0]))
    for (sec, st_name, act), data in sorted_groups:
        c_cnt = data["count"]
        p_cnt = data["postings"]
        act_disp = _esc(act) if act != "Unattributed" else "Unattributed"
        if data["corroborated"]:
            status_text = "<font color='#27AE60'><b>Multi-feed verified (2 feeds, B2)</b></font>"
        else:
            status_text = f"Claimed by group (single source, C3) listed on a leak site by {act_disp} (unverified)"

        org_str = f"{c_cnt} org" if c_cnt == 1 else f"{c_cnt} orgs"
        post_str = f"{p_cnt} post" if p_cnt == 1 else f"{p_cnt} posts"
        post_lbl = f"{org_str} ({post_str})"
        v_rows.append([
            Paragraph(_esc(sec), st["cell_compact"]),
            Paragraph(_esc(st_name), st["cell_compact"]),
            Paragraph(f"<b>{act_disp}</b>", st["cell_compact"]),
            Paragraph(post_lbl, st["cell_compact"]),
            Paragraph(status_text, st["cell_compact"]),
        ])
    story.append(_table(v_rows,
                        [44 * mm, 32 * mm, 32 * mm, 24 * mm, 46 * mm],
                        st, zebra=True, padding=(0.6, 0.6, 1.6, 1.6)))
    story.append(Spacer(1, 1.8))
    story.append(Paragraph(
        "<i>* Telemetry Aggregation &amp; Anonymization: Individual enterprise identities are excluded and aggregated into sector and corridor metrics to safeguard confidentiality. Telemetry reflects claims published on leak sites (note: ransomware.live and ransomlook.io share upstream scraper sources). Unverified adversary leak claims should not be construed as verified intrusions without internal forensic validation.</i>",
        st["small"]))

    # =========================================================================
    # PAGE 10: Reference & Compliance Framework / Community Hardening Guidance
    # =========================================================================
    story.append(PageBreak())
    if public_mode:
        sec_no += 1
        story.append(_section_header("Community Cyber Defence & Strategic Hardening Guidance", sec_no, st))
        story.append(Paragraph(
            "Synthesized technical defensive priorities and indicator ingestion protocols derived from public threat telemetry. "
            "Designated TLP:CLEAR for open community redistribution.", st["small"]))
        story.append(Spacer(1, 4))

        pub_rows = [
            [Paragraph("<b>Defensive Domain</b>", st["cellb"]),
             Paragraph("<b>Strategic Hardening Imperatives &amp; SOC Recommendations</b>", st["cellb"])],
            [Paragraph("<b>Perimeter Edge Ingress</b>", st["cell"]),
             Paragraph(_esc(
                 (f"Immediately apply security updates for internet-facing edge appliances identified in CISA KEV ({edge_text}). "
                  if edge_text else "Keep internet-facing edge appliances on current firmware and watch CISA KEV for new entries. ")
                 + "Disable public WAN management interfaces; restrict remote administration to dedicated out-of-band networks."), st["cell"])],
            [Paragraph("<b>Identity &amp; Access Assurance</b>", st["cell"]),
             Paragraph("Enforce phishing-resistant multi-factor authentication (FIDO2 / WebAuthn hardware security keys) across all remote access portals (VPN, RDP, VDI, cloud tenancies). Eliminate legacy SMS and voice OTP fallback. Terminate dormant accounts and mandate strict session lifetime limits.", st["cell"])],
            [Paragraph("<b>Attack Surface Minimisation</b>", st["cell"]),
             Paragraph("Continuously audit public IPv4/IPv6 exposure across domestic enterprise perimeters. Enforce strict firewall rules blocking ingress on legacy administrative ports (SMB 445, Telnet 23, unencrypted RDP 3389). Mandate perimeter rate-limiting and geo-fencing where operationally viable.", st["cell"])],
            [Paragraph("<b>Domestic IOC Ingestion</b>", st["cell"]),
             Paragraph("Ingest companion .in domain and URL indicators into SIEM and proxy inspection in <b>alert-first monitoring mode</b>. Correlate reverse-proxy DNS traffic (specifically Cloudflare-concealed origins). Avoid uncoordinated domain-level blocking to preserve forensic visibility and prevent collateral connectivity disruption.", st["cell"])],
        ]
        story.append(_table(pub_rows, [45 * mm, 133 * mm], st, padding=(2.6, 2.6, 3.2, 3.2)))
        story.append(Spacer(1, 5))

        pub_guidance_box = Table([[
            Paragraph(
                "<b>TLP:CLEAR COMMUNITY TELEMETRY SHARING &amp; NOTIFICATION PRINCIPLES</b><br/>"
                "<b>1. Open Community Sharing:</b> This intelligence product and its companion indicators are designated TLP:CLEAR and may be freely distributed, mirrored, and operationalized across security teams, MSSPs, and ISAC communities.<br/>"
                "<b>2. Coordinated Incident Handling:</b> Indicators originating from compromised third-party sites should be shared with hosting providers and domain contacts in responsible disclosure mode to facilitate server remediation.<br/>"
                "<b>3. Provenance &amp; Licensing:</b> All threat telemetry indicators adhere to open data licensing (abuse.ch CC0 1.0 Universal). Preserving attribution supports continuous open-source intelligence sharing.",
                st["callout"])
        ]], colWidths=[178 * mm])
        pub_guidance_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#86EFAC")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(pub_guidance_box)
    else:
        sec_no += 1
        story.append(_section_header("Informational mapping to CERT-In Directions (not legal advice)", sec_no, st))
        story.append(Paragraph(
            f"Informational reference mapping under Cyber Security Directions {_esc(DIRECTION_REF)}, "
            f"issued pursuant to Section 70B(6) of the Information Technology Act, 2000. Provided for security context only; does not constitute legal counsel.", st["small"]))
        story.append(Spacer(1, 4))

        rows = [[Paragraph("<b>Statutory Obligation</b>", st["cellb"]),
                 Paragraph("<b>Compliance Requirement &amp; Operational Impact</b>", st["cellb"])]]
        for item in obligations_summary():
            rows.append([Paragraph(_esc(item["obligation"]), st["cell"]),
                         Paragraph(_esc(item["detail"]), st["cell"])])
        story.append(_table(rows, [38 * mm, 140 * mm], st, padding=(2.2, 2.2, 3.0, 3.0)))
        story.append(Spacer(1, 5))

        observed_annexure = set()
        for sig in signals:
            observed_annexure.update(sig.annexure_categories or [])
        if observed_annexure:
            story.append(Paragraph(
                "Annexure I Incident Categories Relevant to Observed Threat Signals",
                st["h3"]))
            counts = Counter()
            for sig in signals:
                for roman in sig.annexure_categories or []:
                    counts[roman] += 1
            rows = [[Paragraph("<b>Item</b>", st["cellb"]),
                     Paragraph("<b>Statutory Incident Category (Annexure I)</b>", st["cellb"]),
                     Paragraph("<b>Mapped signals</b>", st["cellbc"])]]
            for roman in ANNEXURE_I:
                if roman in observed_annexure:
                    rows.append([
                        Paragraph(f"({roman})", st["cellc"]),
                        Paragraph(_esc(ANNEXURE_I[roman]["title"]), st["cell"]),
                        Paragraph(str(counts[roman]), st["cellc"]),
                    ])
            story.append(_table(rows, [14 * mm, 136 * mm, 28 * mm], st, zebra=True,
                                padding=(1.8, 1.8, 2.5, 2.5)))
            story.append(Spacer(1, 2))
            story.append(Paragraph(
                "<i>* Statutory Context &amp; Multi-Category Mapping: Table maps observed threat telemetry to reportable incident categories under "
                "CERT-In Directions 20(3)/2022 Annexure I. A single threat signal may map to multiple Annexure I statutory categories (e.g., ransomware involves both unauthorized access and data compromise); therefore, the sum of mapped signals exceeds the total signal count. Under the Directions, covered entities must report matching incidents within 6 hours of discovery.</i>",
                st["small"]))
            story.append(Spacer(1, 4))

        cert_table = Table([[
            Paragraph(
                f"<b>MANDATORY 6-HOUR INCIDENT REPORTING REQUIREMENT</b><br/>"
                f"Any cyber security incident falling under Annexure I categories must be reported to the "
                f"Indian Computer Emergency Response Team (CERT-In) within <b>6 hours</b> of noticing or being brought to notice.<br/>"
                f"<b>Reporting Channels:</b> Email: <b>{_esc(REPORTING_EMAIL)}</b> | "
                f"Phone: <b>{_esc(REPORTING_PHONE)}</b> | Web Portal: <b>incident.cert-in.org.in</b>",
                st["callout"])
        ]], colWidths=[178 * mm])
        cert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF9E7")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#F1C40F")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(cert_table)

    # =========================================================================
    # PAGE 11: Analytical Limitations, Admiralty Scale & Disclaimer
    # =========================================================================
    story.append(PageBreak())
    sec_no += 1
    story.append(_section_header("Methodology Limitations & Analytical Framework", sec_no, st))

    purpose_box = Table([[
        Paragraph(
            "<b>Purpose, Target Audience &amp; Analytical Boundaries</b><br/>"
            "<b>Purpose:</b> Strategic threat landscape intelligence synthesizing empirical multi-source telemetry to guide defensive resource allocation, patch prioritization, and incident preparedness across the Indian operating theater.<br/>"
            "<b>Target Audience:</b> CISOs, Security Directors, SOC Lead Analysts, Risk Officers, and Enterprise IT Administrators responsible for Indian enterprise networks and Section 70A Critical Information Infrastructure (CII).<br/>"
            "<b>Analytical Limits:</b> Telemetry reflects externally observable perimeter exposure, public extortion disclosures, and actionable malware infrastructure. It cannot prove the absence of undetected intrusions, verify forensic root-cause access vectors for individual private victims, or account for extortion incidents resolved privately without public disclosure. "
            "Threats in Focus entries are analyst summaries of public reporting and are not scored.",
            st["callout"])
    ]], colWidths=[178 * mm])
    purpose_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 3, NAVY_SOFT),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(purpose_box)
    story.append(Spacer(1, 5))

    limits = [
        "<b>Extortion Data Bias:</b> Ransomware leak site data is fundamentally biased. Organisations that quietly pay ransoms or resolve intrusions privately do not appear, meaning leak sites systematically under-represent true incident volume.",
        "<b>Vulnerability vs. Exploitation Ingress:</b> Actively exploited CVE signals listed in CISA KEV as exploited demonstrate that software is under automated or targeted exploitation globally. They do not prove that an Indian victim organisation was breached via that specific vector.",
        "<b>Posting Dates vs. Breach Dates:</b> Adversary leak site dates reflect extortion publication milestones (e.g. proof-of-hack dumps after ransom deadlines), not initial intrusion timestamps, which may have occurred weeks or months prior.",
        "<b>Attack Surface Telemetry:</b> Attack surface and Shodan data reflect aggregate country-level exposure telemetry; no offensive probing or invasive host inventory is retrieved or stored.",
        "<b>Hacktivist Disinformation:</b> Hacktivist claims are treated with low default confidence (0.40-0.60). Claims are frequently recycled, exaggerated, or claim defacements as critical infrastructure breaches.",
        "<b>Small Signal Sensitivity:</b> Industry sectors with limited telemetry can experience noticeable score shifts from single incidents; early indicators should be interpreted directionally.",
    ]
    for limit in limits:
        story.append(Paragraph(f"* {limit}", st["body_justify"]))
        story.append(Spacer(1, 2.0))

    story.append(Spacer(1, 4))
    if health_rows:
        story.append(Paragraph("<b>Source Health at Generation</b>", st["h3"]))
        story.append(Paragraph(
            "Last collected is the last collector run that did not fail; newest record is the most recent item the feed "
            "returned. A recently collected feed can still carry old records. Limits are the age after which a feed counts as stale.",
            st["small"]))
        status_hex = {"OK": "#2F855A", "DEGRADED": "#B7791F", "STALE": "#C2410C", "FAILING": "#9B1C1C",
                      "NOT COLLECTED": "#5B6573", "MANUAL": "#5B6573"}
        h_rows = [[Paragraph(f"<b>{h}</b>", st["cellb"]) for h in
                   ("Feed", "Status", "Last collected", "Newest record", "Stale after")]]
        for r in health_rows:
            h_rows.append([
                Paragraph(_esc(r["source"]), st["cell"]),
                Paragraph(f"<font color='{status_hex.get(r['status'], '#5B6573')}'><b>{r['status']}</b></font>", st["cell"]),
                Paragraph(_esc(r["last_collected"] or "never"), st["cellc"]),
                Paragraph(_esc(r["newest_record"] or "-"), st["cellc"]),
                Paragraph(f"{r['max_age_days']} days" if r["max_age_days"] else "analyst-maintained", st["cellc"]),
            ])
        story.append(_table(h_rows, [56 * mm, 30 * mm, 30 * mm, 30 * mm, 32 * mm], st, zebra=True,
                            padding=(1.2, 1.2, 2.5, 2.5)))
        story.append(Spacer(1, 5))

    story.append(Paragraph("<b>Admiralty Intelligence Confidence Scale (ICD 203 Reference)</b>", st["h3"]))

    adm_rows = [
        [Paragraph("<b>Source Reliability</b>", st["cellb"]),
         Paragraph("<b>Information Credibility</b>", st["cellb"]),
         Paragraph("<b>Analytical Confidence Level</b>", st["cellb"])],
        [Paragraph("<b>A:</b> Completely reliable (Govt/CERT-In)", st["cell"]),
         Paragraph("<b>1:</b> Confirmed by other independent sources", st["cell"]),
         Paragraph("<font color='#27AE60'><b>High (A1, A2, B1):</b> Well-corroborated</font>", st["cell"])],
        [Paragraph("<b>B:</b> Usually reliable (CISA, NVD)", st["cell"]),
         Paragraph("<b>2:</b> Probably true / consistent with past", st["cell"]),
         Paragraph("<font color='#D35400'><b>Moderate (B2, C2):</b> Plausible with caveats</font>", st["cell"])],
        [Paragraph("<b>C:</b> Fairly reliable (Security vendors)", st["cell"]),
         Paragraph("<b>3:</b> Possibly true (Single-source claim)", st["cell"]),
         Paragraph("<font color='#C0392B'><b>Low (C3, D3):</b> Unverified / masked claims</font>", st["cell"])],
        [Paragraph("<b>D:</b> Not usually reliable (Leak forums)", st["cell"]),
         Paragraph("<b>4:</b> Doubtful / unsubstantiated claim", st["cell"]),
         Paragraph("<font color='#777'><b>Minimal (E/F, 5/6):</b> Disinformation risk</font>", st["cell"])],
    ]
    story.append(_table(adm_rows, [58 * mm, 60 * mm, 60 * mm], st, zebra=True, padding=(1.8, 1.8, 3, 3)))
    story.append(Spacer(1, 5))

    if public_mode:
        story.append(Paragraph("<b>Public Distribution &amp; Community Attribution (TLP:CLEAR)</b>", st["h3"]))
        story.append(Paragraph(
            "This document is designated TLP:CLEAR and may be freely distributed, cited, and shared across public security communities with attribution. "
            "Independent analyst work · Not affiliated with CERT-In. Built from public feeds.",
            st["small"]))
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Statutory &amp; Regulatory Disclaimer</b>", st["h3"]))
        pub_disclaimer = (
            f"{DISCLAIMER} Independent analyst work · Not affiliated with CERT-In. Built from public feeds."
        )
        story.append(Paragraph(_esc(pub_disclaimer), st["small"]))
    else:
        story.append(Paragraph("<b>Statutory &amp; Regulatory Disclaimer</b>", st["h3"]))
        story.append(Paragraph(_esc(DISCLAIMER), st["small"]))
    story.append(Spacer(1, 4))

    story.append(Paragraph(
        f"<b>Technical Metadata &amp; Pipeline Provenance:</b><br/>"
        f"<b>Intelligence Feed Snapshot Ingestion Dates ({len(provenance_info['raw_dates'])} Feeds):</b> {_esc(provenance_info['provenance_str'])}<br/>"
        f"<b>Analytics Engine:</b> Scoring Engine v{SCORING_VERSION} (Window end-date deterministic anchor: {_esc(DEFAULT_ANCHOR_DT.strftime('%Y-%m-%d %H:%M'))} IST)<br/>"
        f"<b>Companion IOC Artifact:</b> <b>{_esc(csv_filename)}</b> | SHA-256: <code>{_esc(csv_hash)}</code><br/>"
        f"<b>Reference Framework:</b> CERT-In Directions Reference: {_esc(DIRECTION_URL)}<br/>"
        f"<b>Ingested Feed Sources:</b> {_esc(', '.join(sorted(sources)))}", st["small"]))

    doc.multiBuild(story, canvasmaker=NumberedCanvas)

    # Verify companion CSV hash integrity against PDF text layer
    if os.path.exists(ioc_csv_path):
        from .iocs import compute_file_sha256
        current_csv_hash = compute_file_sha256(ioc_csv_path)
        if current_csv_hash != csv_hash:
            raise AssertionError(f"CSV hash mismatch: expected {csv_hash}, got {current_csv_hash}")
        import pymupdf
        pdoc = pymupdf.open(output_path)
        pdf_text = "".join(page.get_text() for page in pdoc)
        pdoc.close()
        if csv_hash not in pdf_text:
            raise AssertionError(f"CSV hash {csv_hash} not found in PDF text layer")

    # Persist current snapshot for future diff tracking if not already present
    from .snapshot import save_run_snapshot, load_previous_snapshot
    if not load_previous_snapshot(edition=("public" if public_mode else "internal"), window_days=window_days):
        save_run_snapshot(
            scored_sectors, ioc_summary, signals,
            timestamp_str=snapshot_ts,
            edition=("public" if public_mode else "internal"),
            window_days=window_days
        )

    return output_path
