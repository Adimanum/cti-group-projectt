# Dataset — Tycoon2FA IOCs

![Dataset overview](dataset_overview.png)

## Contents

| File | Week | Description |
|---|---|---|
| `esentire_tycoon2fa_2025-03-27.txt` | 2 | Raw public IOC list from eSentire TRU (phishing URLs, "check" URLs, ASN) |
| `esentire_tycoon2fa_2025-04-10.txt` | 2 | Raw public IOC list from eSentire TRU ("check" URLs) |
| `esentire_tycoon2fa_2026-03-23.txt` | 2 | Raw public IOC list from eSentire TRU (login egress IPs + "check" URLs) |
| `enrichment_ip.csv` | 2 | Shodan InternetDB + RIPEstat results for the 14 IPv4 egress IPs (2026-09-26) |
| `enrichment_domain.csv` | 2 | RDAP registration data for the 6 `.com` domains, with our assessment (2026-09-26) |
| `maltego_import.csv` | 2 | 34 entity links for Maltego (*Import Graph from Table*) |
| `infra_graph.png` | 2 | Link graph: ASN → IP → Shodan fingerprint, registrar ← domain → DNS |
| `osint_enrich.py` | 2 | Re-runs the Shodan / RIPEstat / RDAP queries (+ VirusTotal with `VT_API_KEY`) |
| `plot_infra_graph.py` | 2 | Draws `infra_graph.png` |
| **`tycoon2fa_iocs.csv`** | 3 | **Main dataset**: 667 normalized, deduplicated, filtered and defanged indicators |
| `misp_event_tycoon2fa.json` | 3 | The same indicators plus the YARA and Sigma rules as a MISP event (refanged, ready to import) |
| `normalize_iocs.py` | 3 | Filtering and normalization script that builds the CSV and the MISP JSON |
| `plot_dataset.py` | 3 | Draws `dataset_overview.png` |

Source of the raw data: eSentire Threat Response Unit, public IOC repository <https://github.com/eSentire/iocs/tree/main/Tycoon2FA>. We collected these files; we did not produce the indicators ourselves.
The kit-level patterns (JS/CSS names, Unicode obfuscation, WebSocket relay) come from the vendor reports listed in the main README.

## Processing steps (Week 3: filtering and normalization)

1. **Parse**: read each raw file section by section (URLs, IP table, ASN list).
2. **Clean**: trim whitespace, refang `[.]` → `.`, convert hostnames to lower case, drop malformed IP rows.
3. **Enrich**: extract the *hostname* and the *registered domain* from every URL. Keep the ASN and User-Agent for every IP.
4. **Deduplicate**: merge indicators that appear in several reports. For each one, keep the first and last report date and the number of reports.
5. **Filter**: exclude from detection the indicators that the Week 2 enrichment showed to be stale or false positives (`EXCLUDE_FROM_IDS`).
6. **Classify**: assign a MISP type, category and `to_ids` flag.
7. **Export**: write a defanged CSV (safe to publish) and a refanged MISP JSON (for import into MISP only), with the rules from `../detection/` attached.

```bash
python3 dataset/normalize_iocs.py   # rebuilds CSV + MISP JSON
python3 dataset/plot_dataset.py     # rebuilds dataset_overview.png
python3 dataset/osint_enrich.py     # refreshes the enrichment CSVs (results change over time)
```

## Result in numbers

| Metric | Value |
|---|---|
| Raw records parsed | 377 |
| Duplicate raw rows merged | 71 |
| Unique indicators in the dataset | 667 |
| URLs / hostnames / registered domains | 229 / 225 / 131 |
| Egress IP addresses (IPv4 + IPv6) | 76 |
| Indicators seen in more than one report | 168 |
| Marked for detection (`to_ids = True`) | 657 |
| Excluded by filtering (stale / compromised legit site) | 5 |
| Top TLD | `.ru` (96 of 131 domains) |
| Top egress hosting provider (eSentire label) | M247 Europe SRL (46 of 76 IPs) |

## Column description (`tycoon2fa_iocs.csv`)

| Column | Meaning |
|---|---|
| `id` | Row number |
| `misp_type` | MISP attribute type (`url`, `hostname`, `domain`, `ip-src`, `AS`, `filename`, `filename-pattern`, `text`) |
| `category` | MISP category |
| `value_defanged` | Indicator value, defanged (`[.]`, `hxxps[://]`) so it cannot be clicked |
| `to_ids` | `True` if the indicator should be used for detection (IDS/SIEM) |
| `comment` | Context: role of the URL, ASN and User-Agent of the IP, `FILTERED` reason, and so on |
| `first_seen_report` / `last_seen_report` | Earliest and latest report date in which the indicator appears |
| `report_count` | Number of raw reports that contain the indicator |
| `sources` | Raw file names (or vendor report) the indicator came from |

## Safety note

All values are defanged in the CSV. The egress IPs belong to VPS/hosting providers and change owner over time. Use them for hunting historical sign-in logs, not for permanent blocking. Do not open the URLs outside an isolated sandbox.
