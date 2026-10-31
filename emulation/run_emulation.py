#!/usr/bin/env python3
"""
Week 8 - SAFE dry-run of the adversary emulation plan.

This mimics what MITRE CALDERA does when it runs an adversary profile: it executes each ability
in order on an agent and records the result. Here every "ability" is a harmless echo, so running
this produces the same kind of ordered execution log a real CALDERA operation would, with NO real
attack. Each line also shows the ATT&CK technique and which of OUR detections should fire - so the
emulation doubles as a test of our blue-team coverage.

Run: python3 emulation/run_emulation.py
"""
import json
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
plan = json.loads((HERE / "emulation_plan.json").read_text())

log = [f"# Emulation run: {plan['name']}  (group {plan['group']})",
       "# SAFE dry-run - every command is a harmless placeholder. No real attack is performed.", ""]
phase = None
for s in plan["steps"]:
    if s["phase"] != phase:
        phase = s["phase"]
        log.append(f"==================== PHASE: {phase} ====================")
    # run only the benign echo abilities here; the python lab line is shown, not executed again
    cmd = s["safe_command"]
    if cmd.startswith("echo "):
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
    else:
        out = f"(step references: {cmd})"
    log.append(f"[{s['order']:02d}] {s['attack_id']:<11} {s['attack_name']}")
    log.append(f"     procedure : {s['procedure']}")
    log.append(f"     result    : {out}")
    log.append(f"     DETECTED BY: {s['our_detection']}")
    log.append("")
    time.sleep(0.02)

covered = sum(1 for s in plan["steps"] if s["our_detection"] and "Inferred" not in s["our_detection"])
log.append(f"# {len(plan['steps'])} steps emulated across "
           f"{len({s['phase'] for s in plan['steps']})} phases.")
log.append(f"# {covered}/{len(plan['steps'])} steps map to a detection we built in Weeks 3, 5 and 7.")
(HERE / "emulation_run.log").write_text("\n".join(log) + "\n", encoding="utf-8")
print("\n".join(log))
