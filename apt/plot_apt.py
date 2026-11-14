#!/usr/bin/env python3
"""Draw APT29 vs Tycoon2FA as two overlapping sets of ATT&CK techniques -> apt29_overlap.png
Low-colour: grey circles, one blue accent for the shared core."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, FancyBboxPatch

HERE = Path(__file__).resolve().parent
T = json.loads((HERE / "apt29_ttps.json").read_text())["techniques"]
SURF, INK, INK2 = "#ffffff", "#1a1d21", "#6b7280"
ACCENT, MUTED, LINE = "#2a6fb0", "#9aa0a6", "#c9ccd0"

shared = [t for t in T if t["overlap_tycoon2fa"] in ("shared", "related")]
apt_only = [t for t in T if t["overlap_tycoon2fa"] == "apt29_only"]

fig, ax = plt.subplots(figsize=(13.5, 8), facecolor=SURF)
ax.set_xlim(0, 13.5); ax.set_ylim(0, 8); ax.axis("off"); ax.set_facecolor(SURF)
fig.suptitle("Week 10 - APT29 vs Tycoon2FA: shared identity-attack core", x=0.01, ha="left",
             fontsize=15, color=INK, weight="bold")

# two overlapping circles (grey outlines, no fill clutter)
ax.add_patch(Circle((4.6, 4.0), 3.3, facecolor="none", edgecolor=MUTED, linewidth=2))
ax.add_patch(Circle((8.9, 4.0), 3.3, facecolor=ACCENT, alpha=0.06, edgecolor=ACCENT, linewidth=2))
ax.text(2.7, 7.2, "Tycoon2FA (our kit)", color=INK2, fontsize=12, weight="bold")
ax.text(9.6, 7.2, "APT29 (SVR)", color=ACCENT, fontsize=12, weight="bold")

ax.text(3.0, 4.0, "Tycoon2FA's whole\nchain sits inside\nthe shared core",
        ha="center", va="center", fontsize=9, color=INK2, style="italic")

# shared (middle) - the one accent
ax.text(6.75, 6.4, "SHARED - we already detect", ha="center", fontsize=10.5, weight="bold", color=ACCENT)
y = 6.0
for t in shared:
    mark = "+" if t["overlap_tycoon2fa"] == "shared" else "~"
    ax.text(6.75, y, f"{mark} {t['attack_id']}  {t['name'][:30]}", ha="center", fontsize=7.8, color=INK)
    y -= 0.42

# apt29-only (right) - grey
ax.text(10.9, 6.4, "APT29-ONLY - gaps", ha="center", fontsize=10.5, weight="bold", color=INK2)
y = 6.0
for t in apt_only:
    ax.text(10.9, y, f"{t['attack_id']}  {t['name'][:26]}", ha="center", fontsize=7.6, color=INK2)
    y -= 0.42

ax.add_patch(FancyBboxPatch((0.4, 0.3), 12.7, 0.95, boxstyle="round,pad=0.03,rounding_size=0.06",
                            facecolor=SURF, edgecolor=ACCENT, linewidth=1.2))
ns = sum(1 for t in T if t["overlap_tycoon2fa"] == "shared")
nr = sum(1 for t in T if t["overlap_tycoon2fa"] == "related")
na = len(apt_only)
ax.text(6.75, 0.77, f"{ns} shared + {nr} related techniques: our Tycoon2FA detections (Weeks 3/5/7/8) "
        f"already cover part of APT29.  {na} APT29-only techniques are gaps = future work.",
        ha="center", va="center", fontsize=9.2, color=INK)

fig.tight_layout(rect=(0, 0.02, 1, 0.94))
fig.savefig(HERE / "apt29_overlap.png", dpi=140, facecolor=SURF)
print("saved apt29_overlap.png")
