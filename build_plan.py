#!/usr/bin/env python3
"""
Week 8 - build the Tycoon2FA adversary emulation plan from one source of truth
(emulation_plan.json). Produces:

  emulation_plan.csv              - the plan as a table (phase, ATT&CK, procedure, safe command, our detection)
  caldera/adversary_tycoon2fa.yml - a MITRE CALDERA adversary profile (atomic_ordering)
  caldera/abilities/*.yml         - one CALDERA ability per step (benign placeholder command)
  emulation_layer.json            - ATT&CK Navigator layer of the plan's techniques
  run_emulation.py is a separate, SAFE dry-run that "executes" the benign steps in order.

Nothing here runs a real attack: every CALDERA command is a harmless echo.
Run: python3 emulation/build_plan.py
"""
import csv
import json
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
plan = json.loads((HERE / "emulation_plan.json").read_text())
steps = plan["steps"]
(HERE / "caldera" / "abilities").mkdir(parents=True, exist_ok=True)

# deterministic UUIDs so the files are stable across runs
def ab_id(order):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"tycoon2fa-emu-ability-{order}"))

# ---- CSV ----
with open(HERE / "emulation_plan.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["order", "phase", "attack_id", "attack_technique", "procedure", "safe_command", "our_detection"])
    for s in steps:
        w.writerow([s["order"], s["phase"], s["attack_id"], s["attack_name"],
                    s["procedure"], s["safe_command"], s["our_detection"]])

# ---- CALDERA abilities (benign) ----
ability_ids = []
for s in steps:
    aid = ab_id(s["order"])
    ability_ids.append(aid)
    name = s["attack_name"].replace('"', "'")
    yml = f"""- id: {aid}
  name: "{s['order']:02d} {name}"
  description: "{s['procedure']}"
  tactic: {s['tactic']}
  technique:
    attack_id: {s['attack_id']}
    name: "{name}"
  platforms:
    linux:
      sh:
        command: |
          {s['safe_command']}
    darwin:
      sh:
        command: |
          {s['safe_command']}
"""
    (HERE / "caldera" / "abilities" / f"{s['order']:02d}_{s['attack_id']}.yml").write_text(yml, encoding="utf-8")

# ---- CALDERA adversary profile ----
adv_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, "tycoon2fa-emu-adversary"))
adv = f"""id: {adv_id}
name: Tycoon2FA Emulation (CS-2426)
description: >
  Safe emulation of Tycoon2FA, ordered initial access -> persistence -> data exfiltration.
  Every ability runs a harmless placeholder command. Load the abilities/ folder as a stockpile
  and run this profile in a CALDERA range to generate telemetry for the blue team.
atomic_ordering:
"""
for aid in ability_ids:
    adv += f"  - {aid}\n"
(HERE / "caldera" / "adversary_tycoon2fa.yml").write_text(adv, encoding="utf-8")

# ---- ATT&CK Navigator layer ----
techniques = []
seen = set()
for s in steps:
    if s["attack_id"] in seen:
        continue
    seen.add(s["attack_id"])
    techniques.append({"techniqueID": s["attack_id"], "tactic": s["tactic"], "score": 1,
                       "color": "#8e44ad", "enabled": True,
                       "comment": f"Step {s['order']} ({s['phase']}): {s['attack_name']}"})
layer = {
    "name": "Tycoon2FA - Week 8 emulation plan",
    "versions": {"navigator": "5.3.2", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Techniques in our Week 8 adversary emulation plan (initial access -> persistence -> exfiltration).",
    "techniques": techniques,
    "legendItems": [{"label": "In the emulation plan", "color": "#8e44ad"}],
    "layout": {"layout": "side", "showID": True, "showName": True},
    "hideDisabled": False,
}
(HERE / "emulation_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

from collections import Counter
print(f"steps                : {len(steps)}")
print(f"unique ATT&CK techniques: {len(seen)}")
for ph, n in Counter(s["phase"] for s in steps).items():
    print(f"  {ph:<22}{n}")
print("wrote emulation_plan.csv, caldera/adversary_tycoon2fa.yml, "
      f"{len(steps)} abilities, emulation_layer.json")
