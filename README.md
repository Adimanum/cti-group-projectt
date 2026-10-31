# Week 8 — Adversary Emulation Plan (CALDERA style)

A simple, **safe** adversary emulation plan for Tycoon2FA, ordered **initial access → persistence → data exfiltration**, mapped to MITRE ATT&CK and written in the **MITRE CALDERA** adversary-profile format. The full write-up is in [`../week8_emulation_plan_en.md`](../week8_emulation_plan_en.md).

> **Safety:** this is a *plan*, not an attack. Every CALDERA ability runs a harmless placeholder (an `echo` that just logs the step). Nothing here rebuilds or runs Tycoon2FA, and no real email, proxy, account or data is touched.

## Files

| File | What it is |
|---|---|
| `emulation_plan.json` | The plan — one source of truth. 9 steps, each with phase, ATT&CK tactic/technique, procedure, a safe command, and which of our detections covers it. |
| `emulation_plan.csv` | The same plan as a table (generated). |
| `caldera/adversary_tycoon2fa.yml` | A MITRE CALDERA **adversary profile** (`atomic_ordering` of the 9 abilities). |
| `caldera/abilities/*.yml` | One CALDERA **ability** per step, each a benign placeholder command tagged with its ATT&CK tactic + technique. |
| `emulation_layer.json` | ATT&CK Navigator layer of the 9 techniques. |
| `emulation_plan.png` | Diagram of the plan by phase. |
| `emulation_run.log` | Output of the safe dry-run. |
| `build_plan.py` | Rebuilds the CSV, the CALDERA profile + abilities, and the Navigator layer from `emulation_plan.json`. |
| `run_emulation.py` | Safe dry-run: "executes" the plan in order the way CALDERA would, logging each step and the detection that should fire. |
| `plot_emulation.py` | Draws `emulation_plan.png`. |

## Reproduce

```bash
python3 emulation/build_plan.py      # CSV + CALDERA profile/abilities + Navigator layer
python3 emulation/run_emulation.py   # safe dry-run -> emulation_run.log
python3 emulation/plot_emulation.py  # diagram
```

## The plan at a glance

9 steps across 5 phases → 9 ATT&CK techniques (T1566.002, T1557, T1111, T1539, T1098.005, T1087.004, T1114.002, T1564.008, T1567). **8 of 9 steps map to a detection we built in Weeks 3, 5 and 7**, so running the emulation also validates our own defences (a purple-team test). The only step with no direct detection — T1111 (MFA interception) — is caught one step later by its result (Week 5 hunt H1).

## Running it for real (optional)

To run it in a MITRE CALDERA range: copy `caldera/abilities/` into a CALDERA stockpile, import `caldera/adversary_tycoon2fa.yml` as an adversary profile, and run it against a CALDERA agent. Because every command is a benign `echo`, it is safe to run anywhere and produces telemetry the blue team can test detections against.
