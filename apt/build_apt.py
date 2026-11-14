#!/usr/bin/env python3
"""
Week 10 - build the APT29 TTP analysis from apt29_ttps.json. Produces:

  apt29_ttps.csv    - the TTP table (tactic, ATT&CK id, name, APT29 use, overlap with Tycoon2FA, our detection)
  apt29_layer.json  - ATT&CK Navigator layer of APT29 techniques, coloured by overlap with our Tycoon2FA work
  prints a short overlap summary.

Run: python3 apt/build_apt.py
"""
import csv
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
data = json.loads((HERE / "apt29_ttps.json").read_text())
T = data["techniques"]

# ---- CSV ----
with open(HERE / "apt29_ttps.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["tactic", "attack_id", "technique", "apt29_use", "overlap_tycoon2fa", "our_detection"])
    for t in T:
        w.writerow([t["tactic"], t["attack_id"], t["name"], t["apt29_use"],
                    t["overlap_tycoon2fa"], t["our_detection"]])

# ---- ATT&CK Navigator layer (APT29, low-colour: blue shades by overlap) ----
COLOR = {"shared": "#2a6fb0", "related": "#8fb4d8", "apt29_only": "#c9ccd0"}
SCORE = {"shared": 2, "related": 1, "apt29_only": 0}
seen, techs = set(), []
for t in T:
    if t["attack_id"] in seen:
        continue
    seen.add(t["attack_id"])
    ov = t["overlap_tycoon2fa"]
    techs.append({"techniqueID": t["attack_id"], "tactic": t["tactic"], "enabled": True,
                  "color": COLOR[ov], "score": SCORE[ov],
                  "comment": f"{ov}: {t['our_detection']}"})
layer = {
    "name": "APT29 TTPs vs Tycoon2FA (Week 10)",
    "versions": {"navigator": "5.3.2", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "APT29 techniques. Dark blue = also used by Tycoon2FA and covered by our detections; "
                   "light blue = related to our coverage; grey = APT29-only, beyond a PhaaS kit.",
    "techniques": techs,
    "legendItems": [{"label": "Shared with Tycoon2FA (we detect)", "color": COLOR["shared"]},
                    {"label": "Related to our coverage", "color": COLOR["related"]},
                    {"label": "APT29-only (gap / future work)", "color": COLOR["apt29_only"]}],
    "layout": {"layout": "side", "showID": True, "showName": True},
    "hideDisabled": False,
}
(HERE / "apt29_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

c = Counter(t["overlap_tycoon2fa"] for t in T)
print(f"APT29 techniques analysed : {len(T)}")
print(f"  shared with Tycoon2FA   : {c['shared']}  (our detections already cover these)")
print(f"  related                 : {c['related']}")
print(f"  APT29-only              : {c['apt29_only']}  (beyond a commodity PhaaS kit)")
print("wrote apt29_ttps.csv, apt29_layer.json")
