# Attack simulation — T1557 Adversary-in-the-Middle (Week 6)

A **safe, self-contained** lab that reproduces the *mechanism* of MITRE ATT&CK T1557, the
defining technique of Tycoon2FA. No real phishing, brand, domain, credential or malware: all
three parties run on `127.0.0.1` with dummy data, using only the Python standard library.

| File | Description |
|---|---|
| `aitm_lab.py` | Starts a fake ACME identity server + an attacker reverse proxy + a scripted victim, all on localhost, and captures the session cookie |
| `sim_capture.log` | Human-readable transcript of the run |
| `attack_events.ndjson` | The 7 attacker actions, one JSON per line |
| `map_to_attack.py` | Maps the run to ATT&CK → `attack_mapping.csv`, `attack_run_layer.json` |
| `attack_mapping.csv` | One row per action → ATT&CK technique |
| `attack_run_layer.json` | ATT&CK Navigator layer of the techniques exercised |
| `plot_t1557.py`, `t1557_mechanism.png` | Mechanism diagram |
| `stolen_cookie.txt` | Artefact written by the run (the "stolen" dummy cookie) |

```bash
python3 attack_sim/aitm_lab.py
python3 attack_sim/map_to_attack.py
python3 attack_sim/plot_t1557.py
```

Result: 7 attacker actions → 5 ATT&CK techniques (T1557, T1111, T1539, T1567, T1550.004).
Report: [`../week6_attack_technique_en.md`](../week6_attack_technique_en.md).
