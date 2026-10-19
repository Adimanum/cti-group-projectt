#!/usr/bin/env python3
"""
Week 6 - map the simulated attack run (attack_events.ndjson) to MITRE ATT&CK.

Builds:
  attack_mapping.csv        - one row per simulated attacker action -> ATT&CK technique
  attack_run_layer.json     - ATT&CK Navigator layer of the techniques this run exercised
                              (open at https://mitre-attack.github.io/attack-navigator/)
"""
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
events = [json.loads(l) for l in (HERE / "attack_events.ndjson").read_text().splitlines()]

# tactic for each technique seen in the run (for the Navigator layer)
TACTIC = {
    "T1557": "credential-access", "T1111": "credential-access", "T1539": "credential-access",
    "T1567": "exfiltration", "T1550.004": "defense-evasion",
}

with open(HERE / "attack_mapping.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["step", "timestamp", "simulated_action", "attack_id", "attack_technique", "detail"])
    for i, e in enumerate(events, 1):
        w.writerow([i, e["ts"], e["action"], e["attack_id"], e["attack_name"], e["detail"]])

seen = {}
for e in events:
    seen.setdefault(e["attack_id"], e["attack_name"])

techniques = [{
    "techniqueID": tid,
    "tactic": TACTIC.get(tid, ""),
    "score": 1,
    "color": "#e34949",
    "comment": f"Exercised by the Week 6 localhost T1557 simulation: {name}",
    "enabled": True,
} for tid, name in seen.items()]

layer = {
    "name": "Tycoon2FA - Week 6 T1557 simulation",
    "versions": {"navigator": "5.3.2", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Techniques exercised by our safe localhost Adversary-in-the-Middle simulation "
                   "(attack_sim/aitm_lab.py). Red = reproduced in the lab.",
    "techniques": techniques,
    "gradient": {"colors": ["#ffe766", "#e34949"], "minValue": 0, "maxValue": 1},
    "legendItems": [{"label": "Reproduced in the simulation", "color": "#e34949"}],
    "layout": {"layout": "side", "showID": True, "showName": True},
    "hideDisabled": False,
}
(HERE / "attack_run_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

print(f"events mapped : {len(events)}")
print(f"unique ATT&CK techniques in the run : {len(seen)}")
for tid, name in seen.items():
    print(f"  {tid:<11} {name}")
print("wrote attack_mapping.csv, attack_run_layer.json")
