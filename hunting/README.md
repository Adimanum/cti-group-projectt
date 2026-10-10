# Threat hunting — Tycoon2FA (Week 5)

| File | Description |
|---|---|
| `generate_logs.py` | Builds the synthetic tenant (`contoso.example`, 7 days, 62 accounts) with 3 hidden Tycoon2FA intrusions and 3 false-positive traps |
| `hunt_logs.ndjson` | The dataset: 4,858 events (`signin`, `audit`, `mailbox`, `graph`), one JSON per line, ready for Elastic or Splunk upload |
| `ground_truth.json` | Answer key (used only to score the hunts) |
| `queries_esql.txt` | Hunts H0–H3 for Elastic (ES\|QL, plus exact EQL sequences); tested in Elastic Cloud |
| `queries_spl.txt` | The same hunts for Splunk (SPL) |
| `run_hunts.py` | Runs the same hunts locally with SQLite and scores them |
| `hunt_results.txt` | Output of `run_hunts.py` |
| `plot_timeline.py`, `hunt_timeline.png` | Attack timeline: which hunt catches which step |
| `elastic_h1_result.png`, `elastic_h3_result.png` | Hunts H1 and H3 executed in Elastic Cloud (Discover → ES\|QL) |
| `sigma_new_mfa_after_nonbrowser_signin.yml` | Sigma correlation rule created from hunt H1 |

Run: `python3 hunting/generate_logs.py && python3 hunting/run_hunts.py && python3 hunting/plot_timeline.py`

Result: all 3 compromised accounts found, 0 false positives. The report is [`../week5_threat_hunting_en.md`](../week5_threat_hunting_en.md).
