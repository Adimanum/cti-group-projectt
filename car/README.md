# MITRE CAR analytic (Week 7)

Implementation of MITRE CAR analytic **CAR-2013-02-008 "Simultaneous Logins"**, adapted from its
original Windows-host form to cloud identity logs (Entra ID / Microsoft 365 sign-ins).

| File | Description |
|---|---|
| `car_simultaneous_logins.py` | Runs the analytic over `../hunting/hunt_logs.ndjson` and scores it |
| `car_results.txt` | Output of the run (2/3 compromised accounts, 0 false positives) |
| `car_queries_esql.txt` | The analytic as Elastic ES\|QL and Splunk SPL queries |

```bash
python3 car/car_simultaneous_logins.py
```

Idea: the same account active from 2+ distinct ASNs (at least one external) within one hour =
overlapping sessions = the AiTM hallmark. Maps to ATT&CK T1078.004, T1557, T1550.004.
Report: [`../week7_mitre_car_en.md`](../week7_mitre_car_en.md).
