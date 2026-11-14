# Week 10 — Learning APT Techniques (APT29)

Analysis of **APT29** (Cozy Bear / Midnight Blizzard, Russian SVR) TTPs mapped to MITRE ATT&CK, and compared with our Tycoon2FA case. Full write-up: [`../week10_apt_techniques_en.md`](../week10_apt_techniques_en.md).

## Files

| File | What it is |
|---|---|
| `apt29_ttps.json` | APT29 TTPs — source of truth: 16 techniques with tactic, ATT&CK id, APT29 usage, overlap with Tycoon2FA, and our detection. |
| `apt29_ttps.csv` | The same as a table (generated). |
| `apt29_layer.json` | ATT&CK Navigator layer of APT29, coloured by overlap (dark blue = shared with Tycoon2FA, light blue = related, grey = APT29-only). |
| `apt29_overlap.png` | Diagram: APT29 vs Tycoon2FA shared identity-attack core. |
| `build_apt.py` | Builds the CSV + Navigator layer from the JSON. |
| `plot_apt.py` | Draws the overlap diagram. |

## Reproduce

```bash
python3 apt/build_apt.py    # CSV + Navigator layer
python3 apt/plot_apt.py     # overlap diagram
```

## Key result

APT29 and Tycoon2FA share **7 techniques (+2 related)** — Tycoon2FA's whole kill chain sits inside APT29's identity playbook. So our Week 3/5/7/8 detections already cover part of a nation-state actor. The **7 APT29-only techniques** (Golden SAML, OAuth-app persistence, admin-role grants, supply chain) are honest gaps and our future-work roadmap.
