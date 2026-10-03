#!/usr/bin/env python3
"""
Week 4 - Cyber Kill Chain + MITRE ATT&CK mapping for Tycoon2FA.

Single source of truth: killchain_mapping.json (stage -> behaviour -> ATT&CK techniques -> our detections)
Builds:
  tycoon2fa_attack_layer.json  - layer for MITRE ATT&CK Navigator
                                 (https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer -> Upload)
  coverage.csv                 - technique-level table: stage, tactic, technique, covered by our detection?
  kill_chain_diagram.png       - the 7 stages with techniques and our coverage

Usage: python3 killchain/build_killchain.py      (matplotlib needed for the diagram)
"""
import csv
import json
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
data = json.loads((HERE / "killchain_mapping.json").read_text(encoding="utf-8"))
covered = set(data["covered_techniques"])
# stage coverage is derived from the technique coverage, never typed by hand
for st in data["stages"]:
    c = sum(1 for t in st["techniques"] if t["id"] in covered)
    st["coverage"] = "covered" if c == len(st["techniques"]) else "gap" if c == 0 else "partial"

GOOD, CRIT, WARN = "#0ca30c", "#d03b3b", "#fab219"

# ---------------- ATT&CK Navigator layer ----------------
techniques = []
for st in data["stages"]:
    for t in st["techniques"]:
        is_cov = t["id"] in covered
        techniques.append({
            "techniqueID": t["id"],
            "tactic": t["tactic"],
            "score": 2 if is_cov else 1,
            "color": "#7fd17f" if is_cov else "#f4a3a3",
            "comment": f"{st['stage']}: {'covered by our detection' if is_cov else 'observed, NOT covered yet'}",
            "enabled": True,
            "showSubtechniques": True,
        })
layer = {
    "name": "Tycoon2FA - Kill Chain mapping (CS-2426)",
    "versions": {"attack": "17", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Techniques observed in Tycoon2FA campaigns (Microsoft, Elastic, Sekoia, Trustwave, eSentire). "
                   "Green = covered by our Week 3 detections (IOCs, YARA, Sigma); red = observed but not yet covered.",
    "techniques": techniques,
    "gradient": {"colors": ["#f4a3a3", "#7fd17f"], "minValue": 1, "maxValue": 2},
    "legendItems": [{"label": "Observed, not covered", "color": "#f4a3a3"},
                    {"label": "Covered by our detection", "color": "#7fd17f"}],
    "hideDisabled": False,
    "layout": {"layout": "side", "showName": True, "showID": True},
}
(HERE / "tycoon2fa_attack_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

# ---------------- coverage table ----------------
with open(HERE / "coverage.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["kill_chain_stage", "attack_tactic", "technique_id", "technique_name", "covered", "our_detection"])
    for st in data["stages"]:
        for t in st["techniques"]:
            w.writerow([st["stage"], t["tactic"], t["id"], t["name"], "yes" if t["id"] in covered else "no",
                        "; ".join(st["our_detection"]) if t["id"] in covered else ""])

n_all = len(techniques)
n_cov = sum(1 for t in techniques if t["techniqueID"] in covered)
stages_cov = {s["coverage"] for s in data["stages"]}
print(f"techniques mapped : {n_all}")
print(f"covered by us     : {n_cov} ({n_cov * 100 // n_all}%)")
for s in data["stages"]:
    c = sum(1 for t in s["techniques"] if t["id"] in covered)
    print(f"  {s['stage']:<26} {c}/{len(s['techniques'])}  -> {s['coverage']}")

# ---------------- diagram ----------------
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon

SURF, INK, INK2, BOX, LINE = "#fcfcfb", "#0b0b0b", "#52514e", "#eeedea", "#c9c8c2"
fig, ax = plt.subplots(figsize=(19, 9.2), facecolor=SURF)
fig.subplots_adjust(left=0.005, right=0.995, top=0.93, bottom=0.01)
ax.set_xlim(0, 18.95); ax.set_ylim(0, 9.4); ax.axis("off"); ax.set_facecolor(SURF)
fig.suptitle("Tycoon2FA through the Lockheed Martin Cyber Kill Chain → MITRE ATT&CK, with our detection coverage",
             x=0.01, ha="left", color=INK, fontsize=15)

STATUS = {"covered": (GOOD, "✓ covered"), "partial": (WARN, "~ partial"), "gap": (CRIT, "✗ gap")}
w, gap = 2.5, 0.14
for i, st in enumerate(data["stages"]):
    x = 0.25 + i * (w + gap)
    # chevron header
    pts = [(x, 8.4), (x + w - 0.25, 8.4), (x + w, 8.85), (x + w - 0.25, 9.3), (x, 9.3), (x + 0.25, 8.85)]
    ax.add_patch(Polygon(pts, closed=True, facecolor="#2a78d6", edgecolor=SURF, linewidth=2))
    head = st["stage"].replace("Command & Control", "Command &\nControl").replace("Actions on Objectives", "Actions on\nObjectives")
    ax.text(x + w / 2 + 0.05, 8.85, head, ha="center", va="center", color="white", fontsize=10, weight="bold", linespacing=1.0)
    # behaviour
    beh = textwrap.fill(st["tycoon2fa"], 31)
    ax.add_patch(FancyBboxPatch((x, 5.75), w, 2.45, boxstyle="round,pad=0.02,rounding_size=0.08",
                                facecolor=BOX, edgecolor="none"))
    ax.text(x + 0.08, 8.1, beh, ha="left", va="top", fontsize=9, color=INK, linespacing=1.25)
    # techniques
    y = 5.5
    for t in st["techniques"]:
        is_cov = t["id"] in covered
        mark, col = ("✓", GOOD) if is_cov else ("✗", CRIT)
        ax.text(x + 0.05, y, mark, color=col, fontsize=10, va="top", weight="bold")
        ax.text(x + 0.32, y, t["id"], color=INK, fontsize=8.6, va="top", weight="bold")
        ax.text(x + 0.32, y - 0.22, textwrap.shorten(t["name"].split(": ")[-1], 30), color=INK2, fontsize=7.4, va="top")
        y -= 0.5
    # stage status pill
    col, label = STATUS[st["coverage"]]
    ax.add_patch(FancyBboxPatch((x + 0.55, 0.38), w - 1.1, 0.42, boxstyle="round,pad=0.02,rounding_size=0.2",
                                facecolor=col, edgecolor="none"))
    ax.text(x + w / 2, 0.59, label, ha="center", va="center", fontsize=10, color=INK, weight="bold")

ax.text(0.25, 0.05, f"{n_cov} of {n_all} mapped techniques are covered by our Week 3 detections "
        "(✓ = IOC / YARA / Sigma coverage, ✗ = observed but not yet detected). "
        "Gaps (Reconnaissance, Installation) become hunting hypotheses in Week 5.",
        fontsize=9.5, color=INK2, va="bottom")
fig.savefig(HERE / "kill_chain_diagram.png", dpi=140, facecolor=SURF, bbox_inches="tight")
print("saved kill_chain_diagram.png, tycoon2fa_attack_layer.json, coverage.csv")
