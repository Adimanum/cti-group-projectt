#!/usr/bin/env python3
"""Draw the Atomic Red Team results: per technique, detected or not -> atomic_results.png
Also (re)writes atomic_layer.json, an ATT&CK Navigator layer coloured by test outcome.
Low-colour: one blue accent for DETECTED, grey for out-of-scope."""
import json
import re
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

HERE = Path(__file__).resolve().parent
SURF, INK, INK2 = "#ffffff", "#1a1d21", "#6b7280"
ACCENT, MUTED = "#2a6fb0", "#9aa0a6"

# parse the analysis block of atomic_results.txt
rows = []
for ln in (HERE / "atomic_results.txt").read_text().splitlines():
    m = re.match(r"\s*\[([T0-9.]+)\s*\]\s+(.+?)\s+->\s+(DETECTED|not detected)\s+via\s+(.+?)\s*$", ln)
    if m:
        rows.append((m.group(1).strip(), m.group(2).strip(), m.group(3) == "DETECTED", m.group(4).strip()))

fig, ax = plt.subplots(figsize=(13, 0.95 * len(rows) + 2.2), facecolor=SURF)
ax.set_xlim(0, 13); ax.set_ylim(0, len(rows) + 1.3); ax.axis("off"); ax.set_facecolor(SURF)
fig.suptitle("Week 9 - Atomic Red Team: each test vs our detections", x=0.01, ha="left",
             fontsize=15, color=INK, weight="bold")
ax.text(0.1, len(rows) + 0.75, "6 atomic tests run safely, recorded in the SIEM, then analysed. "
        "Blue = our detection fired; grey = out of our SIEM scope.", fontsize=9.5, color=INK2)

for i, (tech, name, det, by) in enumerate(reversed(rows)):
    y = i + 0.15
    col = ACCENT if det else MUTED
    ax.add_patch(FancyBboxPatch((0.1, y), 12.8, 0.8, boxstyle="round,pad=0.02,rounding_size=0.05",
                                facecolor=SURF, edgecolor=col, linewidth=1.5))
    ax.text(0.35, y + 0.4, tech, fontsize=11, color=INK, weight="bold", va="center")
    ax.text(2.1, y + 0.4, name[:46], fontsize=9.6, color=INK, va="center")
    ax.text(8.1, y + 0.4, ("DETECTED" if det else "not detected"), fontsize=10, color=col,
            weight="bold", va="center")
    ax.text(10.0, y + 0.4, by[:34], fontsize=8.2, color=INK2, va="center")

fig.tight_layout(rect=(0, 0.01, 1, 0.93))
fig.savefig(HERE / "atomic_results.png", dpi=140, facecolor=SURF)
print("saved atomic_results.png")

# ---- ATT&CK Navigator layer ----
techs = []
for tech, name, det, by in rows:
    techs.append({"techniqueID": tech, "score": 1 if det else 0,
                  "color": ACCENT if det else MUTED, "enabled": True,
                  "comment": ("DETECTED by " + by) if det else "tested, out of SIEM scope (endpoint/EDR)"})
layer = {
    "name": "Tycoon2FA - Week 9 Atomic Red Team results",
    "versions": {"navigator": "5.3.2", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Atomic tests we ran; blue = caught by our detections, grey = out of our SIEM scope.",
    "techniques": techs,
    "gradient": {"colors": ["#9aa0a6", "#2a6fb0"], "minValue": 0, "maxValue": 1},
    "legendItems": [{"label": "Detected by our SIEM", "color": ACCENT},
                    {"label": "Tested, not detected (endpoint/EDR)", "color": MUTED}],
    "layout": {"layout": "side", "showID": True, "showName": True},
}
(HERE / "atomic_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")
print("saved atomic_layer.json")
