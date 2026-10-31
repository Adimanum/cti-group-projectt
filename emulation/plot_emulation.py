#!/usr/bin/env python3
"""Draw the emulation plan as phases with ATT&CK steps + whether we detect each -> emulation_plan.png"""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

HERE = Path(__file__).resolve().parent
steps = json.loads((HERE / "emulation_plan.json").read_text())["steps"]
SURF, INK, INK2, BOX = "#fcfcfb", "#0b0b0b", "#52514e", "#efe9f6"
PURPLE, GOOD, WARN = "#7a3fb0", "#0ca30c", "#eb6834"

phases = []
for s in steps:
    if not phases or phases[-1][0] != s["phase"]:
        phases.append((s["phase"], []))
    phases[-1][1].append(s)

fig, ax = plt.subplots(figsize=(15, 8.4), facecolor=SURF)
ax.set_xlim(0, 15); ax.set_ylim(0, 9); ax.axis("off"); ax.set_facecolor(SURF)
fig.suptitle("Week 8 — Tycoon2FA adversary emulation plan (initial access → persistence → exfiltration)",
             x=0.01, ha="left", fontsize=14, color=INK)

n = len(phases)
pw = 15.0 / n
for pi, (name, ss) in enumerate(phases):
    x = pi * pw + 0.15
    w = pw - 0.3
    # phase header chevron
    ax.add_patch(FancyBboxPatch((x, 7.9), w, 0.75, boxstyle="round,pad=0.02,rounding_size=0.08",
                                facecolor=PURPLE, edgecolor="none"))
    ax.text(x + w / 2, 8.27, name, ha="center", va="center", color="white", fontsize=10.5, weight="bold")
    # steps stacked
    y = 7.4
    for s in ss:
        h = 1.15
        ax.add_patch(FancyBboxPatch((x, y - h), w, h - 0.12, boxstyle="round,pad=0.02,rounding_size=0.06",
                                    facecolor=BOX, edgecolor="none"))
        ax.text(x + 0.12, y - 0.22, f"{s['order']:02d}  {s['attack_id']}", fontsize=9.2, color=INK,
                weight="bold", va="top")
        ax.text(x + 0.12, y - 0.48, s["attack_name"][:30], fontsize=7.6, color=INK, va="top")
        detected = "Inferred" not in s["our_detection"]
        col = GOOD if detected else WARN
        ax.text(x + 0.12, y - 0.78, ("✓ detected" if detected else "~ inferred"),
                fontsize=8, color=col, weight="bold", va="top")
        y -= h

ax.text(0.15, 0.3, "9 steps across 5 phases → 9 ATT&CK techniques. 8/9 map to a detection we built "
        "(Weeks 3, 5, 7). Written as a MITRE CALDERA profile (caldera/); every command is a safe placeholder.",
        fontsize=9, color=INK2)
fig.tight_layout(rect=(0, 0.02, 1, 0.95))
fig.savefig(HERE / "emulation_plan.png", dpi=140, facecolor=SURF)
print("saved emulation_plan.png")
