# Kill Chain — Tycoon2FA (Week 4)

| File | Description |
|---|---|
| `killchain_mapping.json` | Single source of truth: 7 Kill Chain stages → Tycoon2FA behaviour → 23 ATT&CK techniques → our detections |
| `build_killchain.py` | Builds the three files below from the mapping |
| `tycoon2fa_attack_layer.json` | Layer for [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (*Open Existing Layer → Upload from local*) |
| `coverage.csv` | One row per technique: stage, tactic, ID, name, covered by our detection? |
| `kill_chain_diagram.png` | Diagram of the 7 stages with techniques and coverage |

```bash
python3 killchain/build_killchain.py
```

Result: 23 techniques mapped, 11 (47%) covered by the Week 3 detections. The report is [`../week4_kill_chain_en.md`](../week4_kill_chain_en.md).
