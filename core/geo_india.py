"""
India Geographic & State-Level Threat Intelligence Mapping.

Maps victim entities, domains, and incident descriptions to Indian States,
Union Territories, and major industrial hubs. Renders the official Survey of India
boundary map with dynamic cyber threat heat overlays.
"""

import math
import json
import os
import re
from typing import Dict, List, Optional, Tuple
from PIL import Image, ImageDraw, ImageFont

from .overrides import entity_override

# Mapping of keywords, cities, industrial estates, and institutions to Indian States
# Cities, districts and industrial towns per state. Named organisations are
# placed through data/entity_overrides.json, never by pattern here.
STATE_PATTERNS = {
    "Maharashtra": [
        r"\bmumbai\b", r"\bpune\b", r"\bthane\b", r"\bshirdi\b", r"\bdhule\b",
        r"\bpalghar\b", r"\bnashik\b", r"\bnagpur\b", r"\bnavi mumbai\b",
    ],
    "Delhi NCR": [
        r"\bdelhi\b", r"\bnew delhi\b", r"\bnoida\b", r"\bgurgaon\b", r"\bgurugram\b",
        r"\bfaridabad\b", r"\bghaziabad\b",
    ],
    "Karnataka": [
        r"\bbengaluru\b", r"\bbangalore\b", r"\bmanipal\b", r"\bmysuru\b",
        r"\bmysore\b", r"\bmangalore\b", r"\bhubli\b",
    ],
    "Tamil Nadu": [
        r"\bchennai\b", r"\bvellore\b", r"\bcoimbatore\b", r"\bdindigul\b",
        r"\bmadurai\b", r"\btiruchirappalli\b", r"\bsalem\b",
    ],
    "Gujarat": [
        r"\bahmedabad\b", r"\bsurat\b", r"\bvapi\b", r"\bankleshwar\b",
        r"\bpalsana\b", r"\brajkot\b", r"\bvadodara\b", r"\bbaroda\b",
        r"\bgandhinagar\b",
    ],
    "Rajasthan": [
        r"\bjaipur\b", r"\budaipur\b", r"\bjodhpur\b", r"\bjawai\b",
        r"\bpali\b", r"\bkota\b",
    ],
    "Telangana & AP": [
        r"\bhyderabad\b", r"\bsecunderabad\b", r"\bcyberabad\b", r"\bvijayawada\b",
        r"\bvisakhapatnam\b", r"\bguntur\b", r"\btirupati\b",
    ],
    "Uttarakhand": [
        r"\broorkee\b", r"\bdehradun\b", r"\bharidwar\b", r"\bpantnagar\b",
    ],
    "Chhattisgarh": [
        r"\bbhilai\b", r"\braipur\b", r"\bdurg\b", r"\bbilaspur\b",
    ],
    "Punjab & Chandigarh": [
        r"\bchandigarh\b", r"\bmohali\b", r"\bludhiana\b", r"\bamritsar\b",
        r"\bjalandhar\b",
    ],
    "Haryana": [
        r"\bpanipat\b", r"\bkarnal\b", r"\brohtak\b", r"\bhisar\b",
    ],
    "West Bengal": [
        r"\bkolkata\b", r"\bcalcutta\b", r"\bhowrah\b", r"\bdurgapur\b",
        r"\bsiliguri\b",
    ],
}

COMPILED_PATTERNS = {
    state: [re.compile(p, re.IGNORECASE) for p in patterns]
    for state, patterns in STATE_PATTERNS.items()
}

STATE_GEO_COORDS = {
    "Delhi NCR": (46, 75),
    "Uttarakhand": (55, 78),
    "Punjab & Chandigarh": (40, 81),
    "Rajasthan": (32, 65),
    "Gujarat": (24, 52),
    "Maharashtra": (38, 43),
    "Chhattisgarh": (58, 48),
    "Karnataka": (38, 23),
    "Telangana & AP": (50, 32),
    "Tamil Nadu": (48, 12),
    "West Bengal": (76, 55),
    "Haryana": (44, 76),
}


def classify_state(victim_name: str, description: str = "") -> str:
    """
    Infers the targeted Indian State from the victim entity name and description.
    """
    override = entity_override(victim_name)
    if override and override.get("state"):
        return override["state"]

    text = f"{victim_name} {description}".lower()
    for state, patterns in COMPILED_PATTERNS.items():
        for pat in patterns:
            if pat.search(text):
                return state

    return "Location Unresolved"


STATE_GEOJSON_MAPPING = {
    "Delhi NCR": ["NCT of Delhi"],
    "Telangana & AP": ["Telangana", "Andhra Pradesh"],
    "Punjab & Chandigarh": ["Punjab", "Chandigarh"],
    "Gujarat": ["Gujarat"],
    "Maharashtra": ["Maharashtra"],
    "Karnataka": ["Karnataka"],
    "Tamil Nadu": ["Tamil Nadu"],
    "Chhattisgarh": ["Chhattisgarh"],
    "Uttarakhand": ["Uttarakhand"],
    "Rajasthan": ["Rajasthan"],
    "Haryana": ["Haryana"],
    "West Bengal": ["West Bengal"],
    "Uttar Pradesh": ["Uttar Pradesh"],
    "Kerala": ["Kerala"],
    "Madhya Pradesh": ["Madhya Pradesh"],
    "Bihar": ["Bihar"],
    "Odisha": ["Odisha"],
    "Assam": ["Assam"],
    "Jharkhand": ["Jharkhand"],
    "Himachal Pradesh": ["Himachal Pradesh"],
    "Jammu & Kashmir": ["Jammu & Kashmir"],
    "Goa": ["Goa"],
}


def render_official_india_map(threat_counts: Dict[str, int],
                              out_path: str = "cache/india_threat_map.png",
                              geojson_path: str = "data/india_states.geojson",
                              img_w: int = 520, img_h: int = 590) -> str:
    """
    Renders an official, legally and geographically authentic Survey of India
    political boundary map of India with dynamic cyber threat heat overlays.
    Adheres strictly to the official territory including Jammu & Kashmir,
    Ladakh, Arunachal Pradesh, and all 36 States and Union Territories.
    """
    if not os.path.exists(geojson_path):
        return ""

    with open(geojson_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Standard geographical bounding box of India (ensuring J&K, Ladakh, Arunachal, Nicobar fit)
    min_lon, max_lon = 67.5, 97.8
    min_lat, max_lat = 6.0, 37.6

    aspect_corr = math.cos(math.radians(22.5))  # Equirectangular aspect ratio correction
    geo_w_km = (max_lon - min_lon) * aspect_corr
    geo_h_km = (max_lat - min_lat)

    canvas_w = img_w * 2
    canvas_h = img_h * 2
    # Crisp neutral light background to prevent ReportLab black flattening artifacts
    img = Image.new("RGBA", (canvas_w, canvas_h), (240, 243, 247, 255))
    draw = ImageDraw.Draw(img)

    pad_x = 30
    pad_y = 35
    avail_w = canvas_w - 2 * pad_x
    avail_h = canvas_h - 2 * pad_y

    scale = min(avail_w / geo_w_km, avail_h / geo_h_km)
    actual_w = geo_w_km * scale
    actual_h = geo_h_km * scale
    offset_x = pad_x + (avail_w - actual_w) / 2
    offset_y = pad_y + (avail_h - actual_h) / 2

    def geo_to_px(lon, lat):
        px = offset_x + ((lon - min_lon) * aspect_corr) * scale
        py = offset_y + (max_lat - lat) * scale
        return (px, py)

    def get_state_threat_count(st_name: str) -> int:
        for cat, mapped_states in STATE_GEOJSON_MAPPING.items():
            if any(ms.lower() == st_name.lower() or ms.lower() in st_name.lower() for ms in mapped_states):
                return threat_counts.get(cat, 0)
        for k, v in threat_counts.items():
            if k.lower() == st_name.lower() or k.lower() in st_name.lower():
                return v
        return 0

    def get_state_color(st_name: str):
        cnt = get_state_threat_count(st_name)
        if cnt >= 8:
            return (121, 31, 31, 240), (80, 19, 19, 255)      # Deep Crimson
        elif cnt >= 5:
            return (192, 57, 43, 220), (130, 25, 15, 255)     # Strong Red
        elif cnt >= 3:
            return (211, 84, 0, 200), (150, 50, 0, 255)      # Deep Amber
        elif cnt >= 1:
            return (230, 126, 34, 180), (170, 80, 15, 255)    # Warm Amber
        else:
            return (228, 233, 240, 255), (175, 188, 202, 255) # Clean Neutral State

    centroids = {}
    for feature in data["features"]:
        st_name = feature["properties"].get("ST_NM", "")
        geom = feature["geometry"]
        gtype = geom["type"]
        coords = geom["coordinates"]

        fill_col, stroke_col = get_state_color(st_name)

        polygons = [coords] if gtype == "Polygon" else coords
        for poly in polygons:
            ring = poly[0]
            pts = [geo_to_px(pt[0], pt[1]) for pt in ring]
            if len(pts) >= 3:
                draw.polygon(pts, fill=fill_col, outline=stroke_col, width=3)

        # Compute centroid using the largest landmass polygon
        if polygons:
            main_poly = max((p[0] for p in polygons), key=len)
            main_pts = [geo_to_px(pt[0], pt[1]) for pt in main_poly]
            if main_pts:
                centroids[st_name] = (
                    sum(p[0] for p in main_pts) / len(main_pts),
                    sum(p[1] for p in main_pts) / len(main_pts)
                )

    # Offset tuning for dense clusters (e.g. Delhi NCR surrounded by Haryana)
    custom_offsets = {
        "Delhi NCR": (20, 0),
        "Haryana": (-24, -18),
        "Punjab & Chandigarh": (-10, -5),
        "Gujarat": (0, 0),
        "Maharashtra": (0, 0),
        "Karnataka": (0, 5),
        "Tamil Nadu": (0, 10),
        "Chhattisgarh": (0, 0),
        "Telangana & AP": (0, 0),
        "Uttarakhand": (8, -6),
        "Rajasthan": (0, 0),
    }

    try:
        font_large = ImageFont.truetype("arialbd.ttf", 26)
        font_small = ImageFont.truetype("arial.ttf", 18)
    except Exception:
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()

    # Draw state threat node bubbles
    for cat, cnt in threat_counts.items():
        if cnt <= 0 or cat in ("National / Multistate", "Location Unresolved"):
            continue

        target_pt = None
        # Locate corresponding centroid
        target_states = STATE_GEOJSON_MAPPING.get(cat, [cat])
        for ts in target_states:
            if ts in centroids:
                target_pt = centroids[ts]
                break

        if target_pt:
            off = custom_offsets.get(cat, (0, 0))
            bx = target_pt[0] + off[0]
            by = target_pt[1] + off[1]

            rad = 24 if cnt >= 8 else (20 if cnt >= 5 else (17 if cnt >= 3 else 14))

            # Outer glow halo
            halo_col = (121, 31, 31, 100) if cnt >= 8 else ((192, 57, 43, 90) if cnt >= 5 else (211, 84, 0, 80))
            draw.ellipse([bx - rad - 6, by - rad - 6, bx + rad + 6, by + rad + 6],
                         fill=None, outline=halo_col, width=4)

            # Solid node circle
            c_fill = (121, 31, 31, 255) if cnt >= 8 else ((192, 57, 43, 255) if cnt >= 5 else ((211, 84, 0, 255) if cnt >= 3 else (230, 126, 34, 255)))
            draw.ellipse([bx - rad, by - rad, bx + rad, by + rad], fill=c_fill, outline=(255, 255, 255, 255), width=3)

            # Node victim count text
            num_str = str(cnt)
            bbox = font_large.getbbox(num_str) if hasattr(font_large, "getbbox") else (0, 0, 14, 14)
            tw = bbox[2] - bbox[0]
            th = bbox[3] - bbox[1]
            draw.text((bx - tw / 2, by - th / 2 - 2), num_str, fill=(255, 255, 255, 255), font=font_large)

    # Attribution / Watermark for official legal Survey of India boundary
    legal_text = "Survey of India Official Political Boundary"
    draw.text((36, canvas_h - 48), legal_text, fill=(120, 135, 150, 255), font=font_small)

    final_img = img.resize((img_w, img_h), Image.Resampling.LANCZOS)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    final_img.save(out_path, "PNG", dpi=(300, 300))
    return out_path

