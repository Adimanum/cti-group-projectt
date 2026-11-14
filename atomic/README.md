# Week 9 — Atomic Red Team (safe tests + SIEM analysis)

Atomic Red Team–style tests for the Tycoon2FA case: run selected atomic tests, **record** them in a SIEM, and **analyse** which of our detections fire. Full write-up: [`../week9_atomic_red_team_en.md`](../week9_atomic_red_team_en.md).

> **Safety:** every executor command is a harmless `echo`. We do not reproduce the real weaponised atomic tests — only their references. No real attack, no real data (fake tenant `contoso.example`).

## Files

| File | What it is |
|---|---|
| `atomics_tycoon2fa.yaml` | The test suite in Atomic Red Team format (technique, description, platforms, executor). 6 tests. |
| `run_atomics.py` | Runs the tests safely → writes `atomic_siem_events.ndjson`, then runs our Week 5 detections over them → `atomic_results.txt`. |
| `atomic_siem_events.ndjson` | The recorded SIEM events (37), same 16-field schema as the Week 5 hunt index. |
| `atomic_results.txt` | The analysis: which test each detection caught. |
| `analyze_esql.txt` | The same analysis as ES\|QL + SPL, to run in a real SIEM (Elastic index `atomic-tycoon2fa`). |
| `atomic_results.png` | Results chart (blue = detected, grey = out of scope). |
| `atomic_layer.json` | ATT&CK Navigator layer coloured by outcome. |
| `plot_atomic.py` | Draws the chart and (re)writes the Navigator layer. |

## Reproduce

```bash
python3 atomic/run_atomics.py    # run tests, record SIEM events, analyse
python3 atomic/plot_atomic.py    # chart + Navigator layer
```

## Result

6 atomic tests → **4 detected** by our identity/cloud detections (T1550.004, T1098.005, T1564.008, T1087.004), **2 not detected** (the generic endpoint examples T1059.001 and T1003.001, which belong to EDR, not our SIEM). The misses are the useful part: they mark exactly where our identity-focused coverage ends.
